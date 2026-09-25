package main

import (
	"sort"
	"strings"
	"time"
)

// The flow dataset: pre-aggregated traffic counters shipped from the firewall
// (#32 Phase C / C2, D80/D81/D92). Design: docs/CAPACITY_INSTRUMENTATION.md §4.
//
// WHY THIS IS NOT THE AUDIT LOG — three independent reasons, any one sufficient:
//
//  1. Cardinality. An audit event is one per terminal VERDICT per package. Bytes move
//     on one-per-HTTP-response: metadata plus N artifacts plus registry infrastructure.
//  2. The invariant. One-event-per-verdict is what the #28 compliance export reads as
//     "the record of decisions"; byte rows in that table would corrupt its meaning.
//  3. They do not co-occur. Bytes flow on paths with NO verdict at all (ungated infra
//     relays, /_files/ byte fetches, refused paths), so there is nothing to attach to.
//
// WHY PRE-AGGREGATED, not a row per response: at enterprise pull volume a row per
// relayed response IS a full request log, and storage cost is exactly what makes
// short-staffed teams switch telemetry off — the opposite of the D81 wedge. Bucketing
// in the firewall bounds writes to "distinct keys seen per bucket".

// FlowBucket is one time bucket of traffic for one package, on one firewall instance.
//
// An EMPTY Package is legitimate and load-bearing: registry-infrastructure relays (an
// OCI /v2/ handshake, a token endpoint, a registry ping) carry bytes but no package
// identity. They are recorded under the empty name — like the audit view's
// "(unobserved)" source-IP bucket — so per-package rows still SUM TO THE INSTANCE
// TOTAL. Dropping them would make the dashboard's own arithmetic disagree with itself,
// which is worse than a missing row because it is invisible.
type FlowBucket struct {
	BucketStart time.Time `json:"bucket_start"`
	Instance    string    `json:"instance"`  // which firewall replica produced this
	Ecosystem   string    `json:"ecosystem"` // npm | pypi | oci | maven
	Package     string    `json:"package,omitempty"`
	Kind        string    `json:"kind"` // metadata | artifact | infra

	Requests      int64 `json:"requests"`
	BytesUpstream int64 `json:"bytes_upstream"` // pulled from the internet — the egress number
	BytesClient   int64 `json:"bytes_client"`   // served to developers — the LAN number

	// Failure accounting (D81 Q5). The first six are TRANSPORT-level and stay named
	// honestly for the reason they always were: naming a transport count "corruption"
	// implies an integrity guarantee. The last one IS an integrity count, and it is
	// separate rather than folded in so that honesty survives the addition.
	//
	// The old blanket claim here -- we relay artifact bytes verbatim and never
	// hash-verify -- is now true of npm, and of anything fetched by HEAD, by Range or
	// with a Content-Encoding. It is not true of a whole OCI blob, of a PyPI file whose
	// index the gate relayed, or of a Maven file whose repository sent a checksum header:
	// #64 hashes those against their published digest.
	Truncated       int64 `json:"truncated"`
	RelayErrors     int64 `json:"relay_errors"`
	TransportErrors int64 `json:"transport_errors"`
	UpstreamStatus  int64 `json:"upstream_status"`
	MetaErrors      int64 `json:"meta_errors"`
	Retries         int64 `json:"retries"`
	// #64. No omitempty: a zero is the informative "checked, all matched", and must
	// not read on the wire like a gate too old to check.
	IntegrityMismatches int64 `json:"integrity_mismatches"`
}

// FlowIPBucket is the SECOND, deliberately SEPARATE aggregation: traffic by source IP
// (D92 — the ruling: "the information is valuable for network bandwidth utilization tracking
// and we should include it").
//
// It is its own table rather than a source_ip column on FlowBucket, and that is the
// whole design point. Keying one table by (…, package, kind, source_ip) is a CROSS
// PRODUCT — its row count is distinct-packages × distinct-IPs per bucket, the one
// dimension here that grows multiplicatively. "Which packages are the bulk of traffic"
// and "which hosts are consuming the pipe" are two MARGINAL questions, and answering
// them marginally costs a fraction of the rows. The joint question ("which IP pulled
// which package") is already answered completely by DownloadsByIP over the audit log,
// so this dataset does not need to duplicate it. Whether the cross product ever earns
// its rows is a measurement to make against the mock enterprise env, not a guess.
type FlowIPBucket struct {
	BucketStart time.Time `json:"bucket_start"`
	Instance    string    `json:"instance"`
	Ecosystem   string    `json:"ecosystem"`
	SourceIP    string    `json:"source_ip,omitempty"` // "" = unobserved, same honesty as the audit view

	Requests      int64 `json:"requests"`
	BytesUpstream int64 `json:"bytes_upstream"`
	BytesClient   int64 `json:"bytes_client"`
}

// FlowFilter scopes a read. Times are half-open [From, To) so adjacent windows never
// double-count a bucket that sits exactly on the boundary. A zero time means unbounded
// on that side.
type FlowFilter struct {
	From      time.Time
	To        time.Time
	Ecosystem string // exact match; "" = any
	Instance  string // exact match; "" = any (all replicas summed)
}

func (f FlowFilter) matchesTime(at time.Time) bool {
	if !f.From.IsZero() && at.Before(f.From) {
		return false
	}
	// Half-open: a bucket starting exactly at To belongs to the NEXT window.
	if !f.To.IsZero() && !at.Before(f.To) {
		return false
	}
	return true
}

func (f FlowFilter) matches(b FlowBucket) bool {
	if f.Ecosystem != "" && b.Ecosystem != f.Ecosystem {
		return false
	}
	if f.Instance != "" && b.Instance != f.Instance {
		return false
	}
	return f.matchesTime(b.BucketStart)
}

func (f FlowFilter) matchesIP(b FlowIPBucket) bool {
	if f.Ecosystem != "" && b.Ecosystem != f.Ecosystem {
		return false
	}
	if f.Instance != "" && b.Instance != f.Instance {
		return false
	}
	return f.matchesTime(b.BucketStart)
}

// FlowSummary is the "how much data is flowing through my system" answer (D81 Q2):
// every counter summed across the scoped window.
type FlowSummary struct {
	Requests      int64 `json:"requests"`
	BytesUpstream int64 `json:"bytes_upstream"`
	BytesClient   int64 `json:"bytes_client"`

	Truncated       int64 `json:"truncated"`
	RelayErrors     int64 `json:"relay_errors"`
	TransportErrors int64 `json:"transport_errors"`
	UpstreamStatus  int64 `json:"upstream_status"`
	MetaErrors      int64 `json:"meta_errors"`
	Retries         int64 `json:"retries"`
	// #64. No omitempty: a zero is the informative "checked, all matched", and must
	// not read on the wire like a gate too old to check.
	IntegrityMismatches int64 `json:"integrity_mismatches"`

	// Packages is the number of DISTINCT non-empty package names in the window. It is
	// here so a summary tile can say "4,102 packages moved 812 GB" without a second
	// query, and because it is the natural sanity check against the top-N list.
	Packages int64 `json:"packages"`
}

// FlowPackage is one row of the per-package ranking (D81 Q1: "what packages constitute
// the bulk of the data flowing through my system?"). Kinds are collapsed here — an
// operator asking which packages dominate wants the package total, not one row per
// metadata/artifact split.
type FlowPackage struct {
	Package       string `json:"package,omitempty"` // "" = the unattributed bucket
	Ecosystem     string `json:"ecosystem"`
	Requests      int64  `json:"requests"`
	BytesUpstream int64  `json:"bytes_upstream"`
	BytesClient   int64  `json:"bytes_client"`
}

// FlowSource is one row of the per-source-IP ranking (D81 Q4's "top talkers" half).
type FlowSource struct {
	SourceIP      string `json:"source_ip,omitempty"` // "" = unobserved
	Requests      int64  `json:"requests"`
	BytesUpstream int64  `json:"bytes_upstream"`
	BytesClient   int64  `json:"bytes_client"`
}

// FlowPoint is one step of the time series behind "why is the pipe saturated RIGHT NOW"
// (D81 Q4). Rates are NOT stored — the series carries totals per step and the caller
// divides by the step width, because a stored rate is wrong the moment the window
// changes.
type FlowPoint struct {
	Start         time.Time `json:"start"`
	Requests      int64     `json:"requests"`
	BytesUpstream int64     `json:"bytes_upstream"`
	BytesClient   int64     `json:"bytes_client"`
}

// truncateTo rounds a timestamp down to a step boundary in UTC. Used for both the
// firewall's bucketing and the series re-bucketing so the two can never disagree about
// where a boundary falls.
func truncateTo(t time.Time, step time.Duration) time.Time {
	return t.UTC().Truncate(step)
}

// ---------------------------------------------------------------------------
// memStore implementation
// ---------------------------------------------------------------------------

// flowPkgKey / flowIPKey are the in-memory upsert keys, mirroring the primary keys the
// SQL side uses so both backends aggregate identically.
type flowPkgKey struct {
	BucketStart time.Time
	Instance    string
	Ecosystem   string
	Package     string
	Kind        string
}

type flowIPKey struct {
	BucketStart time.Time
	Instance    string
	Ecosystem   string
	SourceIP    string
}

// AddFlow merges a batch of buckets into the store, ADDING to any existing row with the
// same key rather than replacing it.
//
// Additive-not-replace is required because several firewall replicas report the same
// (bucket, ecosystem, package) independently, and because one replica may flush the same
// bucket more than once as it keeps accruing. The consequence — recorded here because it
// is easy to "fix" wrongly later — is that this operation is NOT idempotent: a
// re-delivered batch double-counts. That is why the firewall side emits fire-and-forget
// with a drop counter and NEVER retries: a dropped batch under-reports, a retried one
// over-reports, and under-reporting is the safe direction for a capacity view because it
// never invents traffic that did not happen.
func (s *memStore) AddFlow(pkgs []FlowBucket, ips []FlowIPBucket) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flowPkgs == nil {
		s.flowPkgs = make(map[flowPkgKey]*FlowBucket)
	}
	if s.flowIPs == nil {
		s.flowIPs = make(map[flowIPKey]*FlowIPBucket)
	}
	for _, b := range pkgs {
		b.BucketStart = b.BucketStart.UTC()
		k := flowPkgKey{b.BucketStart, b.Instance, b.Ecosystem, b.Package, b.Kind}
		cur := s.flowPkgs[k]
		if cur == nil {
			cp := b
			s.flowPkgs[k] = &cp
			continue
		}
		cur.Requests += b.Requests
		cur.BytesUpstream += b.BytesUpstream
		cur.BytesClient += b.BytesClient
		cur.Truncated += b.Truncated
		cur.RelayErrors += b.RelayErrors
		cur.TransportErrors += b.TransportErrors
		cur.UpstreamStatus += b.UpstreamStatus
		cur.MetaErrors += b.MetaErrors
		cur.Retries += b.Retries
		cur.IntegrityMismatches += b.IntegrityMismatches
	}
	for _, b := range ips {
		b.BucketStart = b.BucketStart.UTC()
		k := flowIPKey{b.BucketStart, b.Instance, b.Ecosystem, b.SourceIP}
		cur := s.flowIPs[k]
		if cur == nil {
			cp := b
			s.flowIPs[k] = &cp
			continue
		}
		cur.Requests += b.Requests
		cur.BytesUpstream += b.BytesUpstream
		cur.BytesClient += b.BytesClient
	}
	return nil
}

func (s *memStore) FlowSummary(f FlowFilter) (FlowSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out FlowSummary
	seen := make(map[string]struct{})
	for _, b := range s.flowPkgs {
		if !f.matches(*b) {
			continue
		}
		out.Requests += b.Requests
		out.BytesUpstream += b.BytesUpstream
		out.BytesClient += b.BytesClient
		out.Truncated += b.Truncated
		out.RelayErrors += b.RelayErrors
		out.TransportErrors += b.TransportErrors
		out.UpstreamStatus += b.UpstreamStatus
		out.MetaErrors += b.MetaErrors
		out.IntegrityMismatches += b.IntegrityMismatches
		out.Retries += b.Retries
		if b.Package != "" {
			seen[b.Ecosystem+"\x00"+b.Package] = struct{}{}
		}
	}
	out.Packages = int64(len(seen))
	return out, nil
}

// FlowTopPackages ranks packages by bytes served, biggest first.
//
// limit <= 0 means NO limit: the caller gets every matching package. That matters because
// the summary's byte total and this list must be reconcilable — an operator who sums the
// rows and finds less than the headline figure has been silently misled, so "give me all
// of it" has to be expressible.
func (s *memStore) FlowTopPackages(f FlowFilter, limit int) ([]FlowPackage, error) {
	s.mu.RLock()
	agg := make(map[string]*FlowPackage)
	for _, b := range s.flowPkgs {
		if !f.matches(*b) {
			continue
		}
		// Collapse the metadata/artifact/infra split: the question is which PACKAGE
		// dominates, and one row per kind would push a package down the ranking by
		// splitting its own total across rows.
		k := b.Ecosystem + "\x00" + b.Package
		cur := agg[k]
		if cur == nil {
			cur = &FlowPackage{Package: b.Package, Ecosystem: b.Ecosystem}
			agg[k] = cur
		}
		cur.Requests += b.Requests
		cur.BytesUpstream += b.BytesUpstream
		cur.BytesClient += b.BytesClient
	}
	s.mu.RUnlock()

	out := make([]FlowPackage, 0, len(agg))
	for _, v := range agg {
		out = append(out, *v)
	}
	sortFlowPackages(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// sortFlowPackages orders by bytes served desc, with the UNATTRIBUTED bucket forced last
// and a name tiebreak for a stable order. Unattributed sorts last for the same reason the
// audit view sinks "(unobserved)": real, actionable rows should lead, but the bucket is
// still present so the totals reconcile.
func sortFlowPackages(rows []FlowPackage) {
	sort.Slice(rows, func(i, j int) bool {
		ui, uj := rows[i].Package == "", rows[j].Package == ""
		if ui != uj {
			return uj
		}
		if rows[i].BytesClient != rows[j].BytesClient {
			return rows[i].BytesClient > rows[j].BytesClient
		}
		if rows[i].Ecosystem != rows[j].Ecosystem {
			return rows[i].Ecosystem < rows[j].Ecosystem
		}
		return rows[i].Package < rows[j].Package
	})
}

func (s *memStore) FlowTopSources(f FlowFilter, limit int) ([]FlowSource, error) {
	s.mu.RLock()
	agg := make(map[string]*FlowSource)
	for _, b := range s.flowIPs {
		if !f.matchesIP(*b) {
			continue
		}
		cur := agg[b.SourceIP]
		if cur == nil {
			cur = &FlowSource{SourceIP: b.SourceIP}
			agg[b.SourceIP] = cur
		}
		cur.Requests += b.Requests
		cur.BytesUpstream += b.BytesUpstream
		cur.BytesClient += b.BytesClient
	}
	s.mu.RUnlock()

	out := make([]FlowSource, 0, len(agg))
	for _, v := range agg {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		ui, uj := out[i].SourceIP == "", out[j].SourceIP == ""
		if ui != uj {
			return uj // unobserved last, same rule as the package ranking
		}
		if out[i].BytesClient != out[j].BytesClient {
			return out[i].BytesClient > out[j].BytesClient
		}
		return out[i].SourceIP < out[j].SourceIP
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// FlowSeries re-buckets the stored buckets into coarser steps for the "right now" view.
//
// Empty steps inside the range are emitted as ZERO rows rather than omitted. A chart that
// simply skips quiet minutes draws a continuous line across an outage — which is the
// exact moment the operator is looking at it — so the gap has to be present in the data.
func (s *memStore) FlowSeries(f FlowFilter, step time.Duration) ([]FlowPoint, error) {
	if step <= 0 {
		step = time.Minute
	}
	s.mu.RLock()
	agg := make(map[time.Time]*FlowPoint)
	var min, max time.Time
	for _, b := range s.flowPkgs {
		if !f.matches(*b) {
			continue
		}
		start := truncateTo(b.BucketStart, step)
		cur := agg[start]
		if cur == nil {
			cur = &FlowPoint{Start: start}
			agg[start] = cur
		}
		cur.Requests += b.Requests
		cur.BytesUpstream += b.BytesUpstream
		cur.BytesClient += b.BytesClient
		if min.IsZero() || start.Before(min) {
			min = start
		}
		if max.IsZero() || start.After(max) {
			max = start
		}
	}
	s.mu.RUnlock()

	// Gap-filling goes through the SAME helper the SQL backend uses. It was duplicated
	// inline here at first, which quietly defeated its own negative control: removing the
	// helper's gap-fill left this copy intact, so the test still passed and reported a
	// property that was no longer enforced on either path. One implementation, one place
	// to break.
	return fillFlowSeries(agg, f, step, min, max), nil
}

// PurgeFlowBefore deletes buckets older than cutoff and reports how many rows went.
//
// Retention is UNIFORM for every deployment and operator-configurable, with NO tier check
// anywhere in this path (D88). The ruling: "the only limit to retention is how big your hard
// drive is as the customer, and if I bill you for that also you will be incensed." The
// general rule that produced it — charge for what costs us, never meter the customer's
// own hardware — is why this function takes a cutoff and nothing else.
func (s *memStore) PurgeFlowBefore(cutoff time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for k, b := range s.flowPkgs {
		if b.BucketStart.Before(cutoff) {
			delete(s.flowPkgs, k)
			n++
		}
	}
	for k, b := range s.flowIPs {
		if b.BucketStart.Before(cutoff) {
			delete(s.flowIPs, k)
			n++
		}
	}
	return n, nil
}

// normalizeFlowKind guards the kind dimension at the ingest edge. An unknown kind is
// coerced to "infra" rather than rejected: the counters are best-effort telemetry, and
// losing a batch because a future firewall version invented a new kind would be a worse
// failure than filing it under the catch-all.
func normalizeFlowKind(k string) string {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "metadata":
		return "metadata"
	case "artifact":
		return "artifact"
	default:
		return "infra"
	}
}
