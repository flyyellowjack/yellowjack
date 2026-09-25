package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The SQL half of the flow dataset (#32 Phase C / C2). Types, rationale and the
// memStore twin live in flowstore.go; this file must aggregate identically to it, and
// the shared store test suite runs against both to keep them honest.

// migrateFlow creates the two flow tables. Called from migrate().
//
// TWO TABLES, NOT ONE (D92): keying a single table by (…, package, kind, source_ip)
// would be a cross product whose row count is distinct-packages × distinct-IPs per
// bucket. The two marginal aggregations answer D81 Q1/Q2/Q4 at a fraction of that, and
// the joint question is already answered by DownloadsByIP over the audit log.
func (s *pgStore) migrateFlow() error {
	// The primary key IS the upsert key: one row per (bucket, instance, ecosystem,
	// package, kind), so a second report for the same key ADDS rather than inserting a
	// duplicate. package/kind are part of the key, not nullable extras, because '' is a
	// meaningful value here (the unattributed bucket) and NULL would silently drop out
	// of GROUP BY comparisons.
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS flow_buckets (
			bucket_start     TIMESTAMPTZ NOT NULL,
			instance         TEXT NOT NULL,
			ecosystem        TEXT NOT NULL DEFAULT '',
			package          TEXT NOT NULL DEFAULT '',
			kind             TEXT NOT NULL DEFAULT 'infra',
			requests         BIGINT NOT NULL DEFAULT 0,
			bytes_upstream   BIGINT NOT NULL DEFAULT 0,
			bytes_client     BIGINT NOT NULL DEFAULT 0,
			truncated        BIGINT NOT NULL DEFAULT 0,
			relay_errors     BIGINT NOT NULL DEFAULT 0,
			transport_errors BIGINT NOT NULL DEFAULT 0,
			upstream_status  BIGINT NOT NULL DEFAULT 0,
			meta_errors      BIGINT NOT NULL DEFAULT 0,
			retries          BIGINT NOT NULL DEFAULT 0,
			integrity_mismatches BIGINT NOT NULL DEFAULT 0,
			PRIMARY KEY (bucket_start, instance, ecosystem, package, kind)
		)`)
	if err != nil {
		return fmt.Errorf("migrate flow_buckets: %w", err)
	}
	// #64's integrity counter, added to a table that already exists in deployments.
	// DEFAULT 0 is the honest backfill: a bucket written before this shipped was
	// never checked, and 0 is what "no mismatch was observed" means for it too. The
	// two readings coincide, which is the only reason a default is safe here.
	if _, err := s.db.Exec(`ALTER TABLE flow_buckets ADD COLUMN IF NOT EXISTS integrity_mismatches BIGINT NOT NULL DEFAULT 0`); err != nil {
		return fmt.Errorf("migrate flow_buckets integrity_mismatches: %w", err)
	}
	// Every read is time-scoped, and the retention sweep deletes by time, so the range
	// scan is the access pattern worth an index. The PK's leading column is
	// bucket_start, so this is partly redundant with it today — it is here so that
	// reordering the PK later (e.g. to put instance first) cannot silently turn every
	// dashboard query into a sequential scan.
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS flow_buckets_start_idx ON flow_buckets (bucket_start)`); err != nil {
		return fmt.Errorf("migrate flow_buckets index: %w", err)
	}

	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS flow_ip_buckets (
			bucket_start   TIMESTAMPTZ NOT NULL,
			instance       TEXT NOT NULL,
			ecosystem      TEXT NOT NULL DEFAULT '',
			source_ip      TEXT NOT NULL DEFAULT '',
			requests       BIGINT NOT NULL DEFAULT 0,
			bytes_upstream BIGINT NOT NULL DEFAULT 0,
			bytes_client   BIGINT NOT NULL DEFAULT 0,
			PRIMARY KEY (bucket_start, instance, ecosystem, source_ip)
		)`)
	if err != nil {
		return fmt.Errorf("migrate flow_ip_buckets: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS flow_ip_buckets_start_idx ON flow_ip_buckets (bucket_start)`); err != nil {
		return fmt.Errorf("migrate flow_ip_buckets index: %w", err)
	}
	return nil
}

// AddFlow merges a batch, ADDING to any existing row with the same key.
//
// ON CONFLICT … DO UPDATE SET col = table.col + EXCLUDED.col is the additive upsert:
// several replicas report the same key independently, and one replica may flush the same
// bucket repeatedly as it accrues. The consequence is that this is NOT idempotent — a
// re-delivered batch double-counts — which is precisely why the firewall emits
// fire-and-forget and never retries (a dropped batch under-reports; under-reporting never
// invents traffic that did not happen).
//
// The whole batch runs in ONE transaction so a partially-applied batch can't leave the
// package and IP aggregations disagreeing about the same traffic.
func (s *pgStore) AddFlow(pkgs []FlowBucket, ips []FlowIPBucket) error {
	if len(pkgs) == 0 && len(ips) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op once committed

	for _, b := range pkgs {
		_, err := tx.Exec(`
			INSERT INTO flow_buckets (bucket_start, instance, ecosystem, package, kind,
				requests, bytes_upstream, bytes_client,
				truncated, relay_errors, transport_errors, upstream_status, meta_errors, retries,
				integrity_mismatches)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
			ON CONFLICT (bucket_start, instance, ecosystem, package, kind) DO UPDATE SET
				requests         = flow_buckets.requests         + EXCLUDED.requests,
				bytes_upstream   = flow_buckets.bytes_upstream   + EXCLUDED.bytes_upstream,
				bytes_client     = flow_buckets.bytes_client     + EXCLUDED.bytes_client,
				truncated        = flow_buckets.truncated        + EXCLUDED.truncated,
				relay_errors     = flow_buckets.relay_errors     + EXCLUDED.relay_errors,
				transport_errors = flow_buckets.transport_errors + EXCLUDED.transport_errors,
				upstream_status  = flow_buckets.upstream_status  + EXCLUDED.upstream_status,
				meta_errors      = flow_buckets.meta_errors      + EXCLUDED.meta_errors,
				retries          = flow_buckets.retries          + EXCLUDED.retries,
				integrity_mismatches = flow_buckets.integrity_mismatches + EXCLUDED.integrity_mismatches`,
			b.BucketStart.UTC(), b.Instance, b.Ecosystem, b.Package, b.Kind,
			b.Requests, b.BytesUpstream, b.BytesClient,
			b.Truncated, b.RelayErrors, b.TransportErrors, b.UpstreamStatus, b.MetaErrors, b.Retries,
			b.IntegrityMismatches)
		if err != nil {
			return fmt.Errorf("insert flow bucket: %w", err)
		}
	}

	for _, b := range ips {
		_, err := tx.Exec(`
			INSERT INTO flow_ip_buckets (bucket_start, instance, ecosystem, source_ip,
				requests, bytes_upstream, bytes_client)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (bucket_start, instance, ecosystem, source_ip) DO UPDATE SET
				requests       = flow_ip_buckets.requests       + EXCLUDED.requests,
				bytes_upstream = flow_ip_buckets.bytes_upstream + EXCLUDED.bytes_upstream,
				bytes_client   = flow_ip_buckets.bytes_client   + EXCLUDED.bytes_client`,
			b.BucketStart.UTC(), b.Instance, b.Ecosystem, b.SourceIP,
			b.Requests, b.BytesUpstream, b.BytesClient)
		if err != nil {
			return fmt.Errorf("insert flow ip bucket: %w", err)
		}
	}
	return tx.Commit()
}

// flowWhere builds the shared time/ecosystem/instance predicate with BOUND parameters
// (never string-concatenated — the ecosystem and instance are caller data). The time
// range is half-open [From, To) to match memStore, so adjacent windows cannot
// double-count a boundary bucket.
func flowWhere(f FlowFilter, col string) (string, []any) {
	var conds []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, strings.Replace(cond, "?", "$"+strconv.Itoa(len(args)), 1))
	}
	if !f.From.IsZero() {
		add(col+" >= ?", f.From.UTC())
	}
	if !f.To.IsZero() {
		add(col+" < ?", f.To.UTC())
	}
	if f.Ecosystem != "" {
		add("ecosystem = ?", f.Ecosystem)
	}
	if f.Instance != "" {
		add("instance = ?", f.Instance)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func (s *pgStore) FlowSummary(f FlowFilter) (FlowSummary, error) {
	where, args := flowWhere(f, "bucket_start")
	// COALESCE because SUM over zero rows is NULL, and an empty window is a normal
	// answer ("nothing moved"), not an error.
	q := `SELECT
			COALESCE(SUM(requests),0), COALESCE(SUM(bytes_upstream),0), COALESCE(SUM(bytes_client),0),
			COALESCE(SUM(truncated),0), COALESCE(SUM(relay_errors),0), COALESCE(SUM(transport_errors),0),
			COALESCE(SUM(upstream_status),0), COALESCE(SUM(meta_errors),0), COALESCE(SUM(retries),0),
			COALESCE(SUM(integrity_mismatches),0),
			COUNT(DISTINCT (ecosystem, package)) FILTER (WHERE package <> '')
		  FROM flow_buckets` + where

	var out FlowSummary
	err := s.db.QueryRow(q, args...).Scan(
		&out.Requests, &out.BytesUpstream, &out.BytesClient,
		&out.Truncated, &out.RelayErrors, &out.TransportErrors,
		&out.UpstreamStatus, &out.MetaErrors, &out.Retries, &out.IntegrityMismatches, &out.Packages)
	return out, err
}

func (s *pgStore) FlowTopPackages(f FlowFilter, limit int) ([]FlowPackage, error) {
	where, args := flowWhere(f, "bucket_start")
	// GROUP BY collapses the kind split — the question is which PACKAGE dominates, and
	// one row per kind would split a package's own total across rows and push it down
	// the ranking. ORDER BY puts the unattributed bucket ('') LAST: Postgres orders
	// FALSE before TRUE, so (package = '') ASC ranks real names above the empty one.
	q := `SELECT package, ecosystem,
			SUM(requests), SUM(bytes_upstream), SUM(bytes_client)
		  FROM flow_buckets` + where + `
		  GROUP BY package, ecosystem
		  ORDER BY (package = '') ASC, SUM(bytes_client) DESC, ecosystem ASC, package ASC`
	if limit > 0 {
		args = append(args, limit)
		q += " LIMIT $" + strconv.Itoa(len(args))
	}

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]FlowPackage, 0)
	for rows.Next() {
		var p FlowPackage
		if err := rows.Scan(&p.Package, &p.Ecosystem, &p.Requests, &p.BytesUpstream, &p.BytesClient); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *pgStore) FlowTopSources(f FlowFilter, limit int) ([]FlowSource, error) {
	where, args := flowWhere(f, "bucket_start")
	q := `SELECT source_ip, SUM(requests), SUM(bytes_upstream), SUM(bytes_client)
		  FROM flow_ip_buckets` + where + `
		  GROUP BY source_ip
		  ORDER BY (source_ip = '') ASC, SUM(bytes_client) DESC, source_ip ASC`
	if limit > 0 {
		args = append(args, limit)
		q += " LIMIT $" + strconv.Itoa(len(args))
	}

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]FlowSource, 0)
	for rows.Next() {
		var p FlowSource
		if err := rows.Scan(&p.SourceIP, &p.Requests, &p.BytesUpstream, &p.BytesClient); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// FlowSeries re-buckets into coarser steps.
//
// The gap-filling (emitting zero rows for empty steps) is done in Go rather than with a
// generate_series join, deliberately: it keeps the SQL simple and, more importantly, it
// keeps the gap-filling logic in ONE place shared with memStore, so the two backends
// cannot disagree about whether a quiet minute is a zero or a missing point. A chart that
// omits quiet steps draws a straight line across an outage — the exact moment someone is
// looking at it.
func (s *pgStore) FlowSeries(f FlowFilter, step time.Duration) ([]FlowPoint, error) {
	if step <= 0 {
		step = time.Minute
	}
	where, args := flowWhere(f, "bucket_start")
	q := `SELECT bucket_start, SUM(requests), SUM(bytes_upstream), SUM(bytes_client)
		  FROM flow_buckets` + where + ` GROUP BY bucket_start ORDER BY bucket_start ASC`

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	agg := make(map[time.Time]*FlowPoint)
	var min, max time.Time
	for rows.Next() {
		var at time.Time
		var p FlowPoint
		if err := rows.Scan(&at, &p.Requests, &p.BytesUpstream, &p.BytesClient); err != nil {
			return nil, err
		}
		start := truncateTo(at, step)
		cur := agg[start]
		if cur == nil {
			cur = &FlowPoint{Start: start}
			agg[start] = cur
		}
		cur.Requests += p.Requests
		cur.BytesUpstream += p.BytesUpstream
		cur.BytesClient += p.BytesClient
		if min.IsZero() || start.Before(min) {
			min = start
		}
		if max.IsZero() || start.After(max) {
			max = start
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return fillFlowSeries(agg, f, step, min, max), nil
}

// fillFlowSeries turns a sparse map of steps into a dense, ordered series. Shared by both
// backends so gap-filling can never drift between them.
func fillFlowSeries(agg map[time.Time]*FlowPoint, f FlowFilter, step time.Duration, min, max time.Time) []FlowPoint {
	from, to := min, max
	if !f.From.IsZero() {
		from = truncateTo(f.From, step)
	}
	if !f.To.IsZero() {
		to = truncateTo(f.To.Add(-time.Nanosecond), step)
	}
	if from.IsZero() || to.IsZero() || to.Before(from) {
		return []FlowPoint{}
	}
	out := []FlowPoint{}
	for t := from; !t.After(to); t = t.Add(step) {
		if p := agg[t]; p != nil {
			out = append(out, *p)
			continue
		}
		out = append(out, FlowPoint{Start: t})
	}
	return out
}

// PurgeFlowBefore drops buckets older than cutoff from BOTH tables and returns the total
// rows removed. Uniform, untiered retention (D88).
func (s *pgStore) PurgeFlowBefore(cutoff time.Time) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var total int64
	for _, table := range []string{"flow_buckets", "flow_ip_buckets"} {
		res, err := tx.Exec(`DELETE FROM `+table+` WHERE bucket_start < $1`, cutoff.UTC())
		if err != nil {
			return 0, fmt.Errorf("purge %s: %w", table, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, tx.Commit()
}

// migrateHealth creates the per-replica heartbeat table (#32 Phase C / C4a). Called from
// migrate() alongside migrateFlow.
//
// One row PER INSTANCE, not per instance per interval: this is the latest reading of a
// gauge, so history would just be a slowly-growing table nobody queries. The primary key
// is the instance alone, which is what makes the write an upsert-REPLACE — see
// UpsertInstanceHealth for why replacing (and not adding) is the correct semantic for
// cumulative counters.
func (s *pgStore) migrateHealth() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS instance_health (
			instance      TEXT PRIMARY KEY,
			ecosystem     TEXT NOT NULL DEFAULT '',
			reported_at   TIMESTAMPTZ NOT NULL,
			started_at    TIMESTAMPTZ,
			audit_dropped BIGINT NOT NULL DEFAULT 0,
			flow_dropped  BIGINT NOT NULL DEFAULT 0
		)`)
	if err != nil {
		return fmt.Errorf("migrate instance_health: %w", err)
	}
	// The reported policy (#32 Phase D / D4) was added after instance_health first
	// shipped. CREATE TABLE IF NOT EXISTS above is a no-op on a database that already has
	// the older table, so it would NOT add these columns and every heartbeat INSERT would
	// fail on an upgraded deployment — which presents as every replica going silent at
	// once, i.e. as a total outage rather than as a migration bug. Same idempotent
	// ADD COLUMN IF NOT EXISTS the events table uses for source_ip.
	//
	// TEXT rather than JSONB: this service stores the document verbatim and never queries
	// inside it (see InstanceHealth.Policy). JSONB would buy indexing we do not use and
	// would reject a malformed document at write time, turning a reporting problem into a
	// lost heartbeat.
	_, err = s.db.Exec(`ALTER TABLE instance_health ADD COLUMN IF NOT EXISTS policy TEXT NOT NULL DEFAULT ''`)
	if err != nil {
		return fmt.Errorf("migrate instance_health policy: %w", err)
	}
	_, err = s.db.Exec(`ALTER TABLE instance_health ADD COLUMN IF NOT EXISTS policy_digest TEXT NOT NULL DEFAULT ''`)
	if err != nil {
		return fmt.Errorf("migrate instance_health policy_digest: %w", err)
	}
	return nil
}

// UpsertInstanceHealth writes one replica's heartbeat, replacing any previous row.
//
// Note the deliberate absence of `+` anywhere in the DO UPDATE clause. Every other upsert
// in the flow dataset accumulates (`requests = flow_buckets.requests + EXCLUDED.requests`)
// because those are per-interval deltas. These columns are process-lifetime totals the
// firewall re-sends unchanged every heartbeat, so accumulating them would multiply a
// standing count of 3 dropped batches into hundreds within the hour — an alert storm
// about data loss that never happened.
func (s *pgStore) UpsertInstanceHealth(h InstanceHealth) error {
	var startedAt any
	if !h.StartedAt.IsZero() {
		startedAt = h.StartedAt.UTC()
	}
	_, err := s.db.Exec(`
		INSERT INTO instance_health
			(instance, ecosystem, reported_at, started_at, audit_dropped, flow_dropped,
			 policy, policy_digest)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (instance) DO UPDATE SET
			ecosystem     = EXCLUDED.ecosystem,
			reported_at   = EXCLUDED.reported_at,
			started_at    = EXCLUDED.started_at,
			audit_dropped = EXCLUDED.audit_dropped,
			flow_dropped  = EXCLUDED.flow_dropped,
			policy        = EXCLUDED.policy,
			policy_digest = EXCLUDED.policy_digest`,
		h.Instance, h.Ecosystem, h.ReportedAt.UTC(), startedAt, h.AuditDropped, h.FlowDropped,
		string(h.Policy), h.PolicyDigest)
	if err != nil {
		return fmt.Errorf("upsert instance health: %w", err)
	}
	return nil
}

// ListInstanceHealth returns every replica that has ever reported, newest first.
// No staleness filter, on purpose — see the memStore implementation for why the row an
// operator most needs is precisely the one a "recent only" filter would hide.
func (s *pgStore) ListInstanceHealth() ([]InstanceHealth, error) {
	rows, err := s.db.Query(`
		SELECT instance, ecosystem, reported_at, started_at, audit_dropped, flow_dropped,
		       policy, policy_digest
		FROM instance_health
		ORDER BY reported_at DESC, instance ASC`)
	if err != nil {
		return nil, fmt.Errorf("list instance health: %w", err)
	}
	defer rows.Close()

	var out []InstanceHealth
	for rows.Next() {
		var h InstanceHealth
		var startedAt sql.NullTime
		var policy string
		if err := rows.Scan(&h.Instance, &h.Ecosystem, &h.ReportedAt, &startedAt,
			&h.AuditDropped, &h.FlowDropped, &policy, &h.PolicyDigest); err != nil {
			return nil, fmt.Errorf("scan instance health: %w", err)
		}
		if startedAt.Valid {
			h.StartedAt = startedAt.Time
		}
		// Left nil when empty rather than becoming the JSON literal `""`, so a replica
		// that never reported a policy is absent from the view instead of appearing to
		// have reported an empty one.
		if policy != "" {
			h.Policy = json.RawMessage(policy)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
