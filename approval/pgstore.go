package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	// pgx's database/sql driver. We code against the standard library's
	// database/sql interface (transferable knowledge) and let pgx implement the
	// Postgres wire protocol underneath. The blank import registers the driver
	// under the name "pgx" for sql.Open.
	_ "github.com/jackc/pgx/v5/stdlib"
)

// pgStore is the Postgres-backed Store: real, crash-safe persistence. Postgres
// being its own process/container is what satisfies the architecture's "separate,
// crash-safe database service" requirement — if this approval service dies, the
// data is safe in Postgres.
type pgStore struct {
	db *sql.DB
}

func newPGStore(dsn string) (*pgStore, error) {
	return newPGStoreWithin(dsn, dbConnectWindow())
}

// dbConnectWindow is how long startup keeps retrying the first connection before
// giving up. APPROVAL_DB_CONNECT_TIMEOUT, default 60s; 0 means one attempt.
func dbConnectWindow() time.Duration {
	if v := os.Getenv("APPROVAL_DB_CONNECT_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 0 {
			return d
		}
		log.Printf("APPROVAL_DB_CONNECT_TIMEOUT=%q is not a duration; using the 60s default", v)
	}
	return 60 * time.Second
}

// newPGStoreWithin opens the store, retrying the FIRST connection for up to `within`.
//
// WHY RETRY AT ALL. This used to Ping once and fail fast, and on a host install that
// is right: a wrong DSN should be discovered at startup. Under an orchestrator it is
// wrong. The first real `helm install` of this stack started approval before the
// postgres Service name resolved --
//
//	database init failed: ping db: ... lookup yj-yellowjack-postgres ... server misbehaving
//
// -- and the pod exited 1 and restarted FIVE times before the database came up. Pod
// start order is not something Kubernetes promises, so a service that dies on a
// dependency that is not there YET crash-loops on every fresh install, and with
// several replicas it does so several times over. The chart could hide this with an
// initContainer that waits for the database; that would fix the symptom in one
// packaging and leave the service wrong everywhere else (D133: it has to behave
// correctly under Kubernetes, not be babysat by it).
//
// WHY BOUNDED. Retrying forever would turn a misconfigured DSN into a pod that is
// Running and never Ready, which is harder to diagnose than a crash with the error in
// its log. After the window the last error is returned and main() still exits with
// it, so a genuinely wrong DSN is still discovered at startup -- just not at second one.
// Every failed attempt is logged with its error, so the log during the wait says
// exactly what it is waiting for.
func newPGStoreWithin(dsn string, within time.Duration) (*pgStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// sql.Open doesn't actually connect; Ping forces a real connection.
	deadline := time.Now().Add(within)
	backoff := 500 * time.Millisecond
	for attempt := 1; ; attempt++ {
		err = db.Ping()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("ping db (gave up after %d attempt(s) over %s): %w", attempt, within, err)
		}
		log.Printf("database not reachable yet (attempt %d, retrying in %s): %v", attempt, backoff, err)
		time.Sleep(backoff)
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
	s := &pgStore{db: db}
	if err := s.migrateLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// migrateBootstrapLockKey identifies the schema bootstrap to pg_advisory_lock. Any
// fixed value works as long as every replica uses the same one; this is "yjboot" as a
// number, chosen so it cannot collide with a lock some other tool takes by habit (0, 1).
const migrateBootstrapLockKey = 0x796a626f6f74

// migrateLocked runs migrate() while holding a SESSION-level advisory lock on a
// dedicated connection, so N replicas bootstrapping the same empty database at the
// same moment take turns instead of racing.
//
// WHY. migrate() is a chain of CREATE TABLE / CREATE INDEX ... IF NOT EXISTS, which is
// idempotent within ONE process and NOT race-safe across several: Postgres lets two
// sessions both pass the existence check, and the loser dies with
//
//	duplicate key value violates unique constraint "pg_type_typname_nsp_index"
//
// which newPGStore returns and main() turns into log.Fatalf("database init failed").
// On Kubernetes that is a crash loop on first boot -- every replica starts at once
// against an empty database. Measured before this existed by
// TestConcurrentBootstrapDoesNotRace: 67 of 80 simultaneous bootstraps failed.
//
// WHY A SESSION LOCK ON ITS OWN CONNECTION rather than one transaction around the
// migration: migrate() and the six sub-migrations issue their statements through the
// pool, each on whatever connection it hands out, and rewriting all of them onto a
// single *sql.Tx is a larger change than the defect deserves. A session lock held on a
// pinned connection for the duration serialises the CALLS across processes, which is
// the property that matters; within one process the DDL was always sequential. The
// lock is released in a defer so an error in the middle of a migration cannot leave the
// other replicas waiting forever, and closing the connection releases it regardless.
func (s *pgStore) migrateLocked() error {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migrate: acquire connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrateBootstrapLockKey); err != nil {
		return fmt.Errorf("migrate: advisory lock: %w", err)
	}
	defer conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", migrateBootstrapLockKey) //nolint:errcheck // closing the connection releases it anyway
	return s.migrate()
}

// migrate creates the schema if it doesn't exist. Idempotent, so it's safe to run
// on every startup — a simple migration strategy that suits a single small table.
func (s *pgStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS decisions (
			package    TEXT PRIMARY KEY,
			verdict    TEXT NOT NULL,
			repo_url   TEXT NOT NULL DEFAULT '',
			note       TEXT NOT NULL DEFAULT '',
			decided_by TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMPTZ NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	// first_seen is the enqueue time and never moves (see Decision.FirstSeen). Added
	// by ALTER rather than being written into the CREATE above, because CREATE TABLE
	// IF NOT EXISTS is a no-op against a deployment that already has this table — the
	// column would silently never appear there, and #50's age would read as zero on
	// exactly the long-lived deployments whose queues are worth measuring.
	//
	// Deliberately NULLABLE: pre-existing rows have no enqueue time and there is no
	// honest value to invent for them. Reads COALESCE to updated_at, which for an
	// undecided row IS when it was queued, and is the closest lower bound otherwise.
	_, err = s.db.Exec(`ALTER TABLE decisions ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ`)
	if err != nil {
		return fmt.Errorf("migrate decisions.first_seen: %w", err)
	}
	// The L2 score cache (D18). A NULLABLE score column carries the negative
	// marker: a row with score IS NULL means "scanned, could not score" — which
	// stops the firewall re-launching a scan for that repo on every pull.
	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS scores (
			repo       TEXT PRIMARY KEY,
			score      DOUBLE PRECISION,
			updated_at TIMESTAMPTZ NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("migrate scores: %w", err)
	}
	// Coverage columns (#133). Older rows read 0/0/'' -- "unknown", not "partial".
	for _, col := range []string{
		"scored_checks INTEGER NOT NULL DEFAULT 0",
		"total_checks INTEGER NOT NULL DEFAULT 0",
		"computed_without TEXT NOT NULL DEFAULT ''",
	} {
		if _, err := s.db.Exec(`ALTER TABLE scores ADD COLUMN IF NOT EXISTS ` + col); err != nil {
			return fmt.Errorf("migrate scores (%s): %w", col, err)
		}
	}
	// The append-only audit log (D10 #3). BIGSERIAL gives each event a monotonic
	// id we both return to the caller and order reads by. There is no UPDATE or
	// DELETE statement against this table anywhere in the store, so it is
	// insert-only in practice — the immutability an audit trail requires. The score
	// column is nullable to carry "no score was available".
	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			id         BIGSERIAL PRIMARY KEY,
			package    TEXT NOT NULL,
			ecosystem  TEXT NOT NULL DEFAULT '',
			action     TEXT NOT NULL,
			score      DOUBLE PRECISION,
			reason     TEXT NOT NULL DEFAULT '',
			source_ip  TEXT NOT NULL DEFAULT '',
			at         TIMESTAMPTZ NOT NULL,
			-- The verdict's inputs (#28). threshold is NULLABLE and that is load-bearing:
			-- NULL means "no threshold was in play", which is the truth for a verdict
			-- decided before any scoring (a known-malware refusal). A NOT NULL DEFAULT 0
			-- would render as "the bar was zero", the most misleading value available.
			threshold     DOUBLE PRECISION,
			policy_digest TEXT NOT NULL DEFAULT ''
		)`)
	if err != nil {
		return fmt.Errorf("migrate events: %w", err)
	}
	// source_ip (#41) was added after the events table first shipped. CREATE TABLE IF
	// NOT EXISTS above is a no-op on a database that already has the older table, so it
	// would NOT add the column — an existing deployment would keep crashing on every
	// INSERT that names source_ip. ADD COLUMN IF NOT EXISTS makes the migration
	// idempotent for both a fresh DB (column already created above) and an upgraded one.
	_, err = s.db.Exec(`ALTER TABLE events ADD COLUMN IF NOT EXISTS source_ip TEXT NOT NULL DEFAULT ''`)
	if err != nil {
		return fmt.Errorf("migrate events source_ip: %w", err)
	}
	// threshold and policy_digest (#28) arrived after the events table shipped, so they
	// need the same ALTER treatment source_ip did above and for the identical reason:
	// CREATE TABLE IF NOT EXISTS is a no-op on an existing database, so the columns
	// would never appear there and every INSERT naming them would fail. Existing rows
	// keep NULL / '' — honestly, since nothing recorded those inputs at the time.
	_, err = s.db.Exec(`ALTER TABLE events ADD COLUMN IF NOT EXISTS threshold DOUBLE PRECISION`)
	if err != nil {
		return fmt.Errorf("migrate events threshold: %w", err)
	}
	_, err = s.db.Exec(`ALTER TABLE events ADD COLUMN IF NOT EXISTS policy_digest TEXT NOT NULL DEFAULT ''`)
	if err != nil {
		return fmt.Errorf("migrate events policy_digest: %w", err)
	}
	// Score coverage (#154): what the verdict's score was computed over. Older rows
	// read 0/0/'' -- "unknown", never "partial".
	for _, col := range []string{
		"scored_checks INTEGER NOT NULL DEFAULT 0",
		"total_checks INTEGER NOT NULL DEFAULT 0",
		"computed_without TEXT NOT NULL DEFAULT ''",
	} {
		if _, err := s.db.Exec(`ALTER TABLE events ADD COLUMN IF NOT EXISTS ` + col); err != nil {
			return fmt.Errorf("migrate events (%s): %w", col, err)
		}
	}
	// The flow dataset (#32 Phase C) lives in its own tables, never in events — see
	// flowstore.go for the three reasons. Kept in its own migration function so the
	// telemetry schema and the audit schema stay visibly separate.
	// The gate's structured attribution (D182), stored from #142 on. Rows written before
	// then read back as '' -- "not recorded", which the console must never render as
	// "no source", so the column is a plain string and '' is its own state.
	for _, col := range []string{"deny_kind", "rule", "source", "taken", "mode", "override"} {
		if _, err := s.db.Exec(`ALTER TABLE events ADD COLUMN IF NOT EXISTS ` + col + ` TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("migrate events %s: %w", col, err)
		}
	}
	// The Overview's tally (SummarizeEvents) filters on time. Without an index every
	// page load would scan the whole audit log, which only ever grows.
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS events_at_idx ON events (at)`); err != nil {
		return fmt.Errorf("migrate events_at_idx: %w", err)
	}
	if err := s.migrateFlow(); err != nil {
		return err
	}
	if err := s.migrateHealth(); err != nil {
		return err
	}
	if err := s.migrateAlertNotifications(); err != nil {
		return err
	}
	return s.migrateFalsePositives()
}

func (s *pgStore) Get(pkg string) (Decision, bool, error) {
	var (
		d       Decision
		verdict string
	)
	err := s.db.QueryRow(
		`SELECT package, verdict, repo_url, note, decided_by, updated_at,
		        COALESCE(first_seen, updated_at)
		 FROM decisions WHERE package = $1`, pkg,
	).Scan(&d.Package, &verdict, &d.RepoURL, &d.Note, &d.DecidedBy, &d.UpdatedAt, &d.FirstSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return Decision{}, false, nil // not found is not an error
	}
	if err != nil {
		return Decision{}, false, err
	}
	d.Verdict = Verdict(verdict)
	return d, true, nil
}

// Put upserts a decision: insert, or update if the package already has one. The
// ON CONFLICT clause makes "record or replace" a single atomic statement.
func (s *pgStore) Put(d Decision) (Decision, error) {
	d.UpdatedAt = time.Now().UTC()
	if d.FirstSeen.IsZero() {
		d.FirstSeen = d.UpdatedAt
	}
	// RETURNING first_seen is what makes this correct under concurrency: the stored
	// enqueue time is authoritative, and the row we hand back must carry the value
	// the table actually holds, not the one this caller proposed. Note the update
	// branch reads decisions.first_seen (the EXISTING row), never EXCLUDED — writing
	// EXCLUDED here is precisely how the wait would silently reset to zero on every
	// human ruling, which is the failure #50 exists to make impossible.
	err := s.db.QueryRow(`
		INSERT INTO decisions (package, verdict, repo_url, note, decided_by, updated_at, first_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (package) DO UPDATE SET
			verdict    = EXCLUDED.verdict,
			repo_url   = EXCLUDED.repo_url,
			note       = EXCLUDED.note,
			decided_by = EXCLUDED.decided_by,
			updated_at = EXCLUDED.updated_at,
			first_seen = COALESCE(decisions.first_seen, EXCLUDED.first_seen)
		RETURNING COALESCE(first_seen, updated_at)`,
		d.Package, string(d.Verdict), d.RepoURL, d.Note, d.DecidedBy, d.UpdatedAt, d.FirstSeen,
	).Scan(&d.FirstSeen)
	if err != nil {
		return Decision{}, err
	}
	return d, nil
}

func (s *pgStore) GetScore(repo string) (ScoreRecord, bool, error) {
	var (
		rec     ScoreRecord
		score   sql.NullFloat64
		without string
	)
	err := s.db.QueryRow(
		`SELECT repo, score, updated_at, scored_checks, total_checks, computed_without FROM scores WHERE repo = $1`, repo,
	).Scan(&rec.Repo, &score, &rec.UpdatedAt, &rec.ScoredChecks, &rec.TotalChecks, &without)
	if errors.Is(err, sql.ErrNoRows) {
		return ScoreRecord{}, false, nil // no row: never scanned (cold)
	}
	if err != nil {
		return ScoreRecord{}, false, err
	}
	// A NULL score column is the negative marker; leave rec.Score nil for it.
	if score.Valid {
		rec.Score = &score.Float64
	}
	rec.ComputedWithout = splitChecks(without)
	return rec, true, nil
}

// The check names ride in one TEXT column, comma-joined: Scorecard's names are
// hyphenated identifiers with no commas or spaces, and a list column would be the
// first array type in this schema for a value nothing ever queries by element.
func joinChecks(names []string) string { return strings.Join(names, ",") }

func splitChecks(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// PutScore upserts a repo's cached score. A nil rec.Score writes SQL NULL (the
// negative "scanned-but-unscorable" marker); a present score writes the number.
func (s *pgStore) PutScore(rec ScoreRecord) (ScoreRecord, error) {
	rec.UpdatedAt = time.Now().UTC()
	var score sql.NullFloat64
	if rec.Score != nil {
		score = sql.NullFloat64{Float64: *rec.Score, Valid: true}
	}
	_, err := s.db.Exec(`
		INSERT INTO scores (repo, score, updated_at, scored_checks, total_checks, computed_without)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (repo) DO UPDATE SET
			score            = EXCLUDED.score,
			updated_at       = EXCLUDED.updated_at,
			scored_checks    = EXCLUDED.scored_checks,
			total_checks     = EXCLUDED.total_checks,
			computed_without = EXCLUDED.computed_without`,
		rec.Repo, score, rec.UpdatedAt, rec.ScoredChecks, rec.TotalChecks, joinChecks(rec.ComputedWithout))
	if err != nil {
		return ScoreRecord{}, err
	}
	return rec, nil
}

// DeleteScore removes a repo's cached row so the next pull is cold and re-scans
// (issue #12's operator-triggered re-scan). RowsAffected tells us whether a row was
// actually there, so the handler can distinguish a real clear from a no-op.
func (s *pgStore) DeleteScore(repo string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM scores WHERE repo = $1`, repo)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *pgStore) List() ([]Decision, error) {
	rows, err := s.db.Query(
		`SELECT package, verdict, repo_url, note, decided_by, updated_at,
		        COALESCE(first_seen, updated_at)
		 FROM decisions ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Decision, 0)
	for rows.Next() {
		var (
			d       Decision
			verdict string
		)
		if err := rows.Scan(&d.Package, &verdict, &d.RepoURL, &d.Note, &d.DecidedBy, &d.UpdatedAt, &d.FirstSeen); err != nil {
			return nil, err
		}
		d.Verdict = Verdict(verdict)
		out = append(out, d)
	}
	return out, rows.Err()
}

// AppendEvent inserts one immutable audit event and returns it with the id
// Postgres assigned (via RETURNING). A nil Score writes SQL NULL ("no score
// available"). There is intentionally no companion update/delete — the trail only
// grows.
func (s *pgStore) AppendEvent(e AuditEvent) (AuditEvent, error) {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	var score sql.NullFloat64
	if e.Score != nil {
		score = sql.NullFloat64{Float64: *e.Score, Valid: true}
	}
	// Same NULL-carries-meaning treatment as score: a nil threshold writes SQL NULL
	// ("this verdict weighed no threshold"), never 0.
	var threshold sql.NullFloat64
	if e.Threshold != nil {
		threshold = sql.NullFloat64{Float64: *e.Threshold, Valid: true}
	}
	err := s.db.QueryRow(`
		INSERT INTO events (package, ecosystem, action, score, reason, source_ip, at, threshold, policy_digest, deny_kind, rule, source, taken, mode, scored_checks, total_checks, computed_without, override)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		RETURNING id`,
		e.Package, e.Ecosystem, string(e.Action), score, e.Reason, e.SourceIP, e.At, threshold, e.PolicyDigest, e.DenyKind, e.Rule, e.Source, e.Taken, e.Mode, e.ScoredChecks, e.TotalChecks, joinChecks(e.ComputedWithout), e.Override,
	).Scan(&e.ID)
	if err != nil {
		return AuditEvent{}, err
	}
	return e, nil
}

// ListEvents returns the most recent MATCHING events first (ORDER BY id DESC),
// capped at f.Limit. The WHERE clause is assembled from whichever filter fields are
// set; every value is a bound parameter ($1, $2, …), never string-concatenated, so
// there is no SQL-injection surface — the operator's search text is pure data.
// Because filtering and the LIMIT are both in SQL, "most recent N matching across
// the full table" is done by Postgres, not by post-truncation in Go — the same
// cross-window correctness the memStore comment describes. A non-positive limit
// falls back to the default so a caller can never trigger LIMIT 0 or an unbounded scan.
func (s *pgStore) ListEvents(f EventFilter) ([]AuditEvent, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = defaultEventLimit
	}
	where, args := eventWhere(f)
	args = append(args, limit)
	q := `SELECT ` + eventColumns + ` FROM events` +
		where + fmt.Sprintf(" ORDER BY id DESC LIMIT $%d", len(args))

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]AuditEvent, 0)
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// StreamEvents yields every matching event to fn, oldest-first (ORDER BY id ASC) and
// with NO LIMIT — the compliance export must be complete. It streams straight off the
// row cursor and hands each event to fn, so a large export never materializes in
// memory. Same parameterized WHERE as ListEvents; the difference is only ordering and
// the absence of a cap.
func (s *pgStore) StreamEvents(f EventFilter, fn func(AuditEvent) error) error {
	where, args := eventWhere(f)
	q := `SELECT ` + eventColumns + ` FROM events` +
		where + " ORDER BY id ASC"

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// DownloadsByIP aggregates matching events by source_ip in SQL: COUNT for the tally
// and MAX(at) for recency, GROUP BY source_ip, most-frequent-first with a stable IP
// tiebreak. No LIMIT — the count must be complete (see the interface). Same
// parameterized WHERE as ListEvents/StreamEvents, so the three can't diverge in what
// they match.
func (s *pgStore) DownloadsByIP(f EventFilter) ([]IPCount, error) {
	where, args := eventWhere(f)
	// ORDER BY: most-frequent first; the unobserved bucket ('') sorts LAST — Postgres
	// orders FALSE before TRUE, so (source_ip = '') ASC puts the real IPs (FALSE) above
	// the empty one (TRUE) — then a lexical tiebreak for stable order. Mirrors memStore.
	q := `SELECT source_ip, COUNT(*), MAX(at) FROM events` + where +
		` GROUP BY source_ip ORDER BY COUNT(*) DESC, (source_ip = '') ASC, source_ip ASC`

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]IPCount, 0)
	for rows.Next() {
		var c IPCount
		if err := rows.Scan(&c.IP, &c.Count, &c.LastAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SummarizeEvents is two aggregate queries over the window, both served by
// events_at_idx: the verdict tally grouped the way EventSummary.add needs it, and the
// distinct observed sources. Not one transaction -- an event landing between the two can
// put Sources one ahead of the tally, which is harmless on a page that refreshes.
func (s *pgStore) SummarizeEvents(since time.Time) (EventSummary, error) {
	out := EventSummary{Since: since, ByDenyKind: map[string]int{}}
	rows, err := s.db.Query(`SELECT action, deny_kind, taken, COUNT(*) FROM events
		WHERE at >= $1 GROUP BY action, deny_kind, taken`, since)
	if err != nil {
		return EventSummary{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var action, kind, taken string
		var n int
		if err := rows.Scan(&action, &kind, &taken, &n); err != nil {
			return EventSummary{}, err
		}
		out.add(AuditAction(action), kind, taken, n)
	}
	if err := rows.Err(); err != nil {
		return EventSummary{}, err
	}
	err = s.db.QueryRow(`SELECT COUNT(DISTINCT source_ip) FROM events
		WHERE at >= $1 AND source_ip <> ''`, since).Scan(&out.Sources)
	if err != nil {
		return EventSummary{}, err
	}
	return out, nil
}

// LastSeenByPackage groups over the WHOLE matching table (no LIMIT — a recency window
// would drop precisely the quiet packages this query exists to find) and orders
// oldest-last-event first, mirroring memStore. GROUP BY is on both columns because a
// package identity is (name, ecosystem) — see PackageActivity.
func (s *pgStore) LastSeenByPackage(f EventFilter) ([]PackageActivity, error) {
	where, args := eventWhere(f)
	q := `SELECT package, ecosystem, COUNT(*), MAX(at) FROM events` + where +
		` GROUP BY package, ecosystem ORDER BY MAX(at) ASC, package ASC, ecosystem ASC`

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]PackageActivity, 0)
	for rows.Next() {
		var a PackageActivity
		if err := rows.Scan(&a.Package, &a.Ecosystem, &a.Events, &a.LastAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// eventWhere assembles the parameterized WHERE clause (leading " WHERE ", or "" when
// no filter is set) and its bound args from an EventFilter. Shared by ListEvents and
// StreamEvents so the two can never diverge in what they match. Every value is a
// bound parameter — the operator's search text is data, never concatenated SQL.
func eventWhere(f EventFilter) (string, []any) {
	var where []string
	var args []any
	if f.Ecosystem != "" {
		args = append(args, f.Ecosystem)
		where = append(where, fmt.Sprintf("ecosystem = $%d", len(args)))
	}
	if f.Action != "" {
		args = append(args, string(f.Action))
		where = append(where, fmt.Sprintf("action = $%d", len(args)))
	}
	if f.Package != "" {
		// ILIKE '%text%' = case-insensitive substring. Any % or _ the caller typed is
		// treated as a LIKE wildcard, but it is still a bound value (not injectable),
		// and real package names contain neither, so this is a harmless nuance.
		args = append(args, "%"+f.Package+"%")
		where = append(where, fmt.Sprintf("package ILIKE $%d", len(args)))
	}
	if len(where) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(where, " AND "), args
}

// eventColumns is the one column list every events read uses, in scanEvent's order. A
// column added to the table has to be added here AND to scanEvent, and the round-trip
// test is what proves the two agree.
const eventColumns = `id, package, ecosystem, action, score, reason, source_ip, at, threshold, policy_digest, deny_kind, rule, source, taken, mode, scored_checks, total_checks, computed_without, override`

// scanEvent reads one events row into an AuditEvent, mapping the nullable score
// column to the nil-means-no-score pointer. Shared by ListEvents and StreamEvents.
func scanEvent(rows *sql.Rows) (AuditEvent, error) {
	var (
		e         AuditEvent
		action    string
		score     sql.NullFloat64
		threshold sql.NullFloat64
		without   string
	)
	if err := rows.Scan(&e.ID, &e.Package, &e.Ecosystem, &action, &score, &e.Reason, &e.SourceIP, &e.At,
		&threshold, &e.PolicyDigest, &e.DenyKind, &e.Rule, &e.Source, &e.Taken, &e.Mode,
		&e.ScoredChecks, &e.TotalChecks, &without, &e.Override); err != nil {
		return AuditEvent{}, err
	}
	e.Action = AuditAction(action)
	e.ComputedWithout = splitChecks(without)
	if score.Valid {
		e.Score = &score.Float64
	}
	// A NULL threshold stays nil rather than becoming 0 — the round trip has to
	// preserve "no threshold was in play", or the export re-invents a bar that was
	// never applied. Same reason score is handled this way directly above.
	if threshold.Valid {
		e.Threshold = &threshold.Float64
	}
	return e, nil
}
