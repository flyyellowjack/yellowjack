package main

import (
	"fmt"
	"strings"
	"time"
)

// The durable half of alert email (#32 Phase C / C4c): one row per condition we have
// already mailed about. Created by migrate() alongside the other tables.
//
// This is the ONLY alert state that is persisted, and it exists for exactly one reason —
// so a restart, or a second sweep a minute later, does not mail the operator again about a
// condition that has not changed. The alerts themselves are still evaluated on read (see
// alerts.go), so nothing here can cause the console to display a stale opinion.
//
// There is no severity, no message text and no resolved_at column, deliberately. Storing
// the rendered message would tempt a future reader into treating this as an alert history
// — a different feature, with different retention and privacy questions — when it is a
// dedup ledger whose rows are meant to be deleted the moment the condition clears.
func (s *pgStore) migrateAlertNotifications() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS alert_notifications (
			alert_key   TEXT PRIMARY KEY,
			notified_at TIMESTAMPTZ NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("migrate alert_notifications: %w", err)
	}
	return nil
}

// ClaimAlertNotification takes the claim for one condition, reporting whether this caller
// won it.
//
// INSERT ... ON CONFLICT DO NOTHING is the whole mechanism, and it must stay a single
// statement. A SELECT-then-INSERT would leave a window in which two sweeps — or two
// control-plane replicas behind a load balancer — both see no row and both send. Postgres
// resolves the race inside one statement, and RowsAffected tells us which caller won:
// exactly one gets 1, everyone else gets 0.
func (s *pgStore) ClaimAlertNotification(key string, at time.Time) (bool, error) {
	res, err := s.db.Exec(`
		INSERT INTO alert_notifications (alert_key, notified_at)
		VALUES ($1, $2)
		ON CONFLICT (alert_key) DO NOTHING`,
		key, at.UTC())
	if err != nil {
		return false, fmt.Errorf("claim alert notification: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		// If we cannot tell whether we won the claim, report NOT claimed. The cost of
		// that choice is a missed email for one sweep (the next one retries, since the
		// row either exists or does not); claiming optimistically instead could mark a
		// condition notified that nobody was ever told about.
		return false, fmt.Errorf("claim alert notification (rows affected): %w", err)
	}
	return n == 1, nil
}

// ReleaseAlertNotification drops a claim whose send failed, so the next sweep retries.
func (s *pgStore) ReleaseAlertNotification(key string) error {
	if _, err := s.db.Exec(`DELETE FROM alert_notifications WHERE alert_key = $1`, key); err != nil {
		return fmt.Errorf("release alert notification: %w", err)
	}
	return nil
}

// ForgetResolvedAlerts removes the claims for every condition that is no longer active,
// which is what allows a recurrence to be notified rather than silently suppressed forever.
//
// An EMPTY active set legitimately means "nothing is wrong", so it clears the whole table.
// That is correct, and it is also why the caller must only reach here with a successfully
// evaluated set — see sweepOnce, where both storage reads return early on error precisely
// so a failed read can never arrive here looking like a clean bill of health.
//
// The key list is expanded into placeholders rather than passed as an array parameter:
// database/sql has no portable array binding, and the set here is the number of ACTIVE
// alerts (a handful — one per replica plus a few global), not an unbounded input.
func (s *pgStore) ForgetResolvedAlerts(active []string) (int64, error) {
	var res interface {
		RowsAffected() (int64, error)
	}
	var err error

	if len(active) == 0 {
		res, err = s.db.Exec(`DELETE FROM alert_notifications`)
	} else {
		placeholders := make([]string, len(active))
		args := make([]any, len(active))
		for i, k := range active {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
			args[i] = k
		}
		res, err = s.db.Exec(
			`DELETE FROM alert_notifications WHERE alert_key NOT IN (`+
				strings.Join(placeholders, ", ")+`)`, args...)
	}
	if err != nil {
		return 0, fmt.Errorf("forget resolved alerts: %w", err)
	}
	return res.RowsAffected()
}
