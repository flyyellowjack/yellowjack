package main

import (
	"fmt"
	"time"
)

// Storage for false-positive reports (#142): the memStore half and the pgStore half of
// the two Store methods declared in store.go. Same shape as events -- append-only, an id
// assigned by the store, newest-first reads -- because a report is a ledger entry: the
// operator said this block was wrong, at this time, in these words.

const defaultFalsePositiveLimit = 200

// ── memStore ──────────────────────────────────────────────────────────────────────

func (m *memStore) AddFalsePositive(r FalsePositiveReport) (FalsePositiveReport, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextFPID++
	r.ID = m.nextFPID
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	m.fps = append(m.fps, r)
	return r, nil
}

func (m *memStore) ListFalsePositives(limit int) ([]FalsePositiveReport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 {
		limit = defaultFalsePositiveLimit
	}
	out := make([]FalsePositiveReport, 0, min(limit, len(m.fps)))
	for i := len(m.fps) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, m.fps[i])
	}
	return out, nil
}

// ── pgStore ───────────────────────────────────────────────────────────────────────

func (s *pgStore) migrateFalsePositives() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS false_positives (
			id          BIGSERIAL PRIMARY KEY,
			event_id    BIGINT NOT NULL DEFAULT 0,
			package     TEXT NOT NULL,
			ecosystem   TEXT NOT NULL DEFAULT '',
			reason      TEXT NOT NULL DEFAULT '',
			source      TEXT NOT NULL DEFAULT '',
			deny_kind   TEXT NOT NULL DEFAULT '',
			rule        TEXT NOT NULL DEFAULT '',
			note        TEXT NOT NULL DEFAULT '',
			reported_by TEXT NOT NULL DEFAULT '',
			at          TIMESTAMPTZ NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("migrate false_positives: %w", err)
	}
	return nil
}

func (s *pgStore) AddFalsePositive(r FalsePositiveReport) (FalsePositiveReport, error) {
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	err := s.db.QueryRow(`
		INSERT INTO false_positives (event_id, package, ecosystem, reason, source, deny_kind, rule, note, reported_by, at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id`,
		r.EventID, r.Package, r.Ecosystem, r.Reason, r.Source, r.DenyKind, r.Rule, r.Note, r.ReportedBy, r.At,
	).Scan(&r.ID)
	if err != nil {
		return FalsePositiveReport{}, fmt.Errorf("insert false positive: %w", err)
	}
	return r, nil
}

func (s *pgStore) ListFalsePositives(limit int) ([]FalsePositiveReport, error) {
	if limit <= 0 {
		limit = defaultFalsePositiveLimit
	}
	rows, err := s.db.Query(`
		SELECT id, event_id, package, ecosystem, reason, source, deny_kind, rule, note, reported_by, at
		FROM false_positives ORDER BY id DESC LIMIT ` + fmt.Sprint(limit))
	if err != nil {
		return nil, fmt.Errorf("list false positives: %w", err)
	}
	defer rows.Close()
	var out []FalsePositiveReport
	for rows.Next() {
		var r FalsePositiveReport
		if err := rows.Scan(&r.ID, &r.EventID, &r.Package, &r.Ecosystem, &r.Reason, &r.Source, &r.DenyKind, &r.Rule, &r.Note, &r.ReportedBy, &r.At); err != nil {
			return nil, fmt.Errorf("scan false positive: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
