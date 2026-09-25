package main

import (
	"encoding/json"
	"sort"
	"time"
)

// InstanceHealth is one firewall replica's self-report: "I am alive as of this moment,
// and here is what I have failed to deliver." (#32 Phase C / C4a.)
//
// WHY THIS EXISTS RATHER THAN INFERRING LIVENESS FROM TRAFFIC. The capacity design
// specifies a "no traffic at all" alert as the is-the-firewall-even-alive signal. Inferred
// from the flow dataset alone that alert cannot tell a DEAD firewall from an IDLE one — a
// quiet Sunday, a team on holiday, a CI queue that drained — so it fires on healthy
// instances. An alert that cries wolf on a normal weekend is worse than no alert: it
// trains the operator to dismiss it, which is precisely the outcome D81's "already
// running when the incident hits" is trying to buy. A heartbeat separates the two
// questions: "is it reporting?" (this record) and "is traffic flowing?" (the flow
// dataset). Only the first is a liveness question.
//
// THE COUNTERS ARE CUMULATIVE, AND THAT IS WHY THIS IS AN UPSERT-REPLACE, NOT AN ADD.
// AuditDropped and FlowDropped are the firewall's own process-lifetime totals
// (atomic.Int64 counters that only grow). The flow buckets next door are additive
// precisely because they are per-interval deltas; these are not. Adding them would
// compound a running total on every heartbeat and invent losses that never happened —
// the same class of error as re-sending an undrained counter. Replace is the correct
// semantic for "the latest reading of a gauge".
type InstanceHealth struct {
	// Instance is the replica's identity (its hostname — see the firewall's
	// flowInstanceID for why hostname and not a random per-boot ID).
	Instance  string `json:"instance"`
	Ecosystem string `json:"ecosystem,omitempty"`

	// ReportedAt is when the firewall says it sent this. Set by the SERVER on ingest,
	// not taken from the client: a replica with a skewed clock would otherwise appear
	// permanently stale (or permanently fresh) and there is no way for an operator to
	// tell which. The server's clock is the one the operator's "last seen 4m ago" is
	// measured against, so it is the one that must be authoritative.
	ReportedAt time.Time `json:"reported_at"`

	// StartedAt is the process start time as the firewall reports it. Unlike ReportedAt
	// this IS the client's value, because it is the client's fact — and it is what makes
	// a restart visible: a replica whose StartedAt jumps has restarted, which is the
	// context an operator needs when the drop counters reset to zero.
	StartedAt time.Time `json:"started_at,omitempty"`

	// The firewall's own delivery failures, process-lifetime cumulative.
	// AuditDropped: audit events dropped because the emitter's buffer was full.
	// FlowDropped: capacity batches lost because the sink could not be reached.
	// Both are "we know we lost data" counters — any non-zero value is worth surfacing,
	// which is why they need no threshold.
	AuditDropped int64 `json:"audit_dropped"`
	FlowDropped  int64 `json:"flow_dropped"`

	// Policy is what this replica reports it is ENFORCING (#32 Phase D / D4), stored
	// OPAQUELY as the JSON the firewall sent.
	//
	// Deliberately NOT re-declared as a typed struct here. This service does not interpret
	// the policy — it stores it and hands it to the console, which renders it. A parallel
	// type would be a second definition to keep in step with the firewall's, for no gain,
	// and the day the two drifted the control plane would silently drop fields it did not
	// know about. Opaque storage cannot lose a field it never named.
	Policy json.RawMessage `json:"policy,omitempty"`

	// PolicyDigest is pulled OUT of that document on ingest and kept on its own, so "are
	// these replicas enforcing the same policy?" is one string comparison rather than a
	// deep compare of three rule chains on every read. It is the firewall's digest, taken
	// at face value: this service never recomputes it, because it deliberately does not
	// model the policy well enough to do so.
	PolicyDigest string `json:"policy_digest,omitempty"`
}

// UpsertInstanceHealth records one replica's heartbeat, REPLACING any previous reading
// for that instance. See the type comment for why replace and not add.
func (s *memStore) UpsertInstanceHealth(h InstanceHealth) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.health == nil {
		s.health = make(map[string]InstanceHealth)
	}
	s.health[h.Instance] = h
	return nil
}

// ListInstanceHealth returns every replica that has ever reported, newest heartbeat
// first.
//
// It deliberately does NOT filter out stale instances. A replica that stopped reporting
// is the single most interesting row here — dropping it because it is old would make a
// dead firewall disappear from the very view that exists to notice dead firewalls. The
// staleness judgement belongs to the caller (the alert evaluator), which knows the
// window; the store's job is to not lose the row.
func (s *memStore) ListInstanceHealth() ([]InstanceHealth, error) {
	s.mu.Lock()
	out := make([]InstanceHealth, 0, len(s.health))
	for _, h := range s.health {
		out = append(out, h)
	}
	s.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if !out[i].ReportedAt.Equal(out[j].ReportedAt) {
			return out[i].ReportedAt.After(out[j].ReportedAt)
		}
		return out[i].Instance < out[j].Instance // stable tiebreak
	})
	return out, nil
}
