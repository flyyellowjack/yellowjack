package main

import (
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

// Verdict is a human's ruling on a package the automated firewall could not score.
type Verdict string

const (
	VerdictPending  Verdict = "pending"  // seen by the firewall, awaiting a human
	VerdictApproved Verdict = "approved" // a human said: allow this package
	VerdictDenied   Verdict = "denied"   // a human said: block this package
)

// firstSeenSkewTolerance is how far ahead of the write time a caller-supplied enqueue
// time may sit before it is treated as wrong rather than as clock skew.
//
// Generous on purpose: this service and the firewall that posts to it are separate
// processes, possibly on separate hosts, and a minute or two of drift is ordinary. The
// value being guarded against is not a slightly-fast clock but a timestamp months or
// years out, which is either corrupt or deliberate.
const firstSeenSkewTolerance = 5 * time.Minute

// Decision is the persistent answer to "what do we do with this unscorable
// package?" — recorded once so the question isn't re-asked on every pull.
type Decision struct {
	Package   string    `json:"package"`           // npm package name (identity)
	Verdict   Verdict   `json:"verdict"`           // pending / approved / denied
	RepoURL   string    `json:"repoUrl,omitempty"` // optional human-supplied correct repo
	Note      string    `json:"note,omitempty"`    // free-text reason
	DecidedBy string    `json:"decidedBy,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`

	// FirstSeen is when this package ENTERED the queue, and it is never rewritten.
	//
	// AGE is the load-bearing number in #50 — "no timeline, no visibility, and no
	// accountability" is the named failure mode, and the target is a queue measured
	// in hours against the three months one operator reported. UpdatedAt cannot
	// carry it: it means "last edited", so it moves to the decision time the moment
	// a human rules, and it would reset on every pull if anything ever re-Put a
	// pending row. Either way the queue reports a bounded wait while being
	// unbounded — a failure that is invisible precisely because the number it shows
	// still looks plausible. So the enqueue time is stored separately and preserved.
	FirstSeen time.Time `json:"firstSeen"`
}

// ScoreRecord is a durable, remembered OpenSSF Scorecard result for a source repo
// (keyed by "github.com/owner/name"). This is the async-local-mode L2 (D12/D18):
// the firewall's on-demand scan runs in the BACKGROUND and writes its result here,
// so later pulls of the same (or a sibling) package read a verdict instantly
// instead of re-launching a ~20–80s scan. It lives in this stateful service, not
// the firewall, precisely so the firewall stays stateless.
//
// Score is a POINTER on purpose (same idiom as the firewall's depsDevResponse): a
// nil Score is the NEGATIVE marker — "we scanned this repo and could NOT score it"
// — distinct from "no row yet" (never scanned). Without a durable negative, a repo
// the scanner can't score would L2-miss and re-launch a scan on every single pull,
// forever. A present Score is a real numeric result.
type ScoreRecord struct {
	Repo      string    `json:"repo"`
	Score     *float64  `json:"score"` // nil = scanned-but-unscorable (negative marker)
	UpdatedAt time.Time `json:"updatedAt"`

	// Coverage (#133): the score was computed over ScoredChecks of TotalChecks,
	// without the checks named. A score that passed the gate's required-check floor
	// (D271) is a real score, but it is a different measurement from a full one, and
	// storing only the number made the two indistinguishable everywhere downstream.
	// Zero/empty means a full report or a row older than these fields -- "unknown",
	// never "partial".
	ScoredChecks    int      `json:"scoredChecks,omitempty"`
	TotalChecks     int      `json:"totalChecks,omitempty"`
	ComputedWithout []string `json:"computedWithout,omitempty"`
}

// Partial says whether the score was computed over fewer checks than the run emitted;
// the same predicate the gate and the scanner apply, restated here because the three
// are separate binaries. Zero counts are "unknown", not partial.
func (r ScoreRecord) Partial() bool { return r.TotalChecks > 0 && r.ScoredChecks < r.TotalChecks }

// Partial on an audit event: the verdict's score was a partial measurement (#154).
func (e AuditEvent) Partial() bool { return e.TotalChecks > 0 && e.ScoredChecks < e.TotalChecks }

// AuditAction is what the firewall ultimately did with a package request. Only the
// two TERMINAL verdicts are audited — allow and block. A cold scan Pending and an
// Unavailable source are deliberately NOT logged: they are not a ruling on the
// package, and recording them would flood the trail with noise on every cold pull.
//
// Since D102 those two answer with a 403 like a real block does, which makes this
// look like an omission rather than a decision — it is not. The audit trail records
// RULINGS, and "we are still scanning" is the absence of one however it is
// transported. What changed in D102 was the status code, not what we decided.
type AuditAction string

const (
	ActionAllow AuditAction = "allow"
	ActionBlock AuditAction = "block"
)

// Sane bounds for reads of the audit log, so a single HTTP request can never make
// the store return an unbounded result set. The handler applies defaultEventLimit
// when no ?limit is given and clamps anything larger to maxEventLimit.
const (
	defaultEventLimit = 200
	maxEventLimit     = 1000
)

// AuditEvent is one immutable record of "the firewall saw a request for this
// package and allowed / blocked it, for this reason." It is the data source for
// the console's audit view (D10 #3, view "a": everything requested/allowed/blocked
// and why).
//
// The log is APPEND-ONLY by design: the firewall may insert events but can never
// update or delete one — that is why the Store below exposes AppendEvent but no
// PutEvent and no delete. An audit trail the audited party can rewrite is not an
// audit trail. Score is a pointer (same idiom as ScoreRecord): nil means "no score
// was available" (e.g. an unscorable package allowed by policy), distinct from a
// real numeric score.
type AuditEvent struct {
	ID        int64       `json:"id"`                  // assigned by the store on append (0 on the way in)
	Package   string      `json:"package"`             // package name (identity of what was requested)
	Ecosystem string      `json:"ecosystem,omitempty"` // npm / pypi / oci
	Action    AuditAction `json:"action"`              // allow / block
	Score     *float64    `json:"score,omitempty"`     // nil = no score was available
	Reason    string      `json:"reason,omitempty"`    // the same text surfaced to the developer
	SourceIP  string      `json:"source_ip,omitempty"` // observed connecting-peer IP (#41); "" = unobserved. NOT a human identity — a shared NAT/CI/egress address, treated as personal data (D83).
	At        time.Time   `json:"at"`                  // when the decision was made

	// The verdict's INPUTS (#28). Everything above records what we decided; these
	// record what we decided it against, which is what makes an exported record
	// reproducible by someone who was not there. Both are additive and omitempty, so
	// events written before this field existed still parse and still export — an
	// audit schema an auditor depends on may gain fields, never change the meaning of
	// one that is already there.
	// The gate's STRUCTURED attribution of a block (D182, #20): which kind of denial,
	// the rule that fired, and the source it came from ("known-malware feed", "operator
	// deny list", ...). The gate has emitted these on every event since D182 and this
	// type had no field for them, so they were silently dropped here and the export
	// never carried them -- the "attributable without log correlation" claim in the
	// gate's audit.go was true of the wire and false of the record. Found while
	// building #142, which cannot tell an advisory block from an operator one without
	// them. Additive and omitempty, like Threshold above.
	DenyKind string `json:"deny_kind,omitempty"`
	// Override: this verdict went against a finding on an explicit operator instruction
	// (D312). Stored and exported for the reason the gate emits it — an override that
	// leaves no record on the exported log is indistinguishable from a gate that missed
	// something.
	Override string `json:"override,omitempty"`
	Rule     string `json:"rule,omitempty"`
	Source   string `json:"source,omitempty"`
	// The SECOND instance of the same drop, found by the guard written for the first
	// (auditwire_test.go): #114 made a report-mode block machine-distinguishable from a
	// real one on the wire -- action=block, taken=allow, mode=report -- and these two
	// fields were never stored either. So the record, the console and the export showed
	// "block" for packages that were in fact SERVED. Empty on rows written before this.
	Taken string `json:"taken,omitempty"`
	Mode  string `json:"mode,omitempty"`

	// What Score was computed over (#154): ScoredChecks of TotalChecks, without the
	// checks named. The gate sends them only with a score; 0/0/empty on an older row
	// or a full report reads as "unknown", never as partial, so an exported 6.2 over
	// 11 of 18 checks is a different record from a 6.2 over 18 -- the #133
	// denominator, carried to the record that leaves the deployment (#28).
	ScoredChecks    int      `json:"scored_checks,omitempty"`
	TotalChecks     int      `json:"total_checks,omitempty"`
	ComputedWithout []string `json:"computed_without,omitempty"`

	Threshold    *float64 `json:"threshold,omitempty"`     // nil = no threshold was in play (e.g. a known-malware refusal, decided before any scoring)
	PolicyDigest string   `json:"policy_digest,omitempty"` // PolicyView fingerprint of the policy in force; safe to export by construction (carries no upstream URL and no credential)
}

// EventFilter narrows an audit-log read. It is the incident-response query: "show
// me the blocks for npm", "everything about package X". A zero value matches every
// event (so ListEvents(EventFilter{}) is "all events, newest-first"). The filter is
// applied at the STORE, across the whole history, before Limit truncates — so a
// match that is older than Limit events back is still found. Doing this in the
// caller over a pre-fetched window would silently miss such events and read as "it
// never happened", which for an audit trail is a correctness bug, not a UI nicety.
type EventFilter struct {
	Ecosystem string      // exact match; "" = any ecosystem
	Action    AuditAction // exact match (allow/block); "" = any action
	Package   string      // case-insensitive substring; "" = any package
	Limit     int         // cap on events returned; <= 0 means "no explicit cap here"
}

// matches reports whether one event satisfies the filter. An empty field in the
// filter is a wildcard for that dimension. Package is a substring match because an
// operator scoping an incident rarely types the exact normalized name.
func (f EventFilter) matches(e AuditEvent) bool {
	if f.Ecosystem != "" && e.Ecosystem != f.Ecosystem {
		return false
	}
	if f.Action != "" && e.Action != f.Action {
		return false
	}
	if f.Package != "" && !strings.Contains(strings.ToLower(e.Package), strings.ToLower(f.Package)) {
		return false
	}
	return true
}

// IPCount is one row of the "downloads by source IP" aggregation (#41, D83): for a
// scoped set of pulls, how many came from each observed source IP and when the most
// recent one was. It is the incident-response answer to "search a package, see how
// many times it was downloaded and by what IPs". LastAt gives recency ("this host
// last pulled it 3 minutes ago") which is what an incident timeline needs. IP is ""
// for pulls whose source was not observed (pre-#41 events, or a direct pull we could
// not attribute) — surfaced as its own bucket rather than dropped, so the counts
// still sum to the true total.
type IPCount struct {
	IP     string    `json:"ip"`      // observed source IP; "" = unobserved
	Count  int       `json:"count"`   // pulls from this IP matching the filter
	LastAt time.Time `json:"last_at"` // most recent matching pull from this IP
}

// PackageActivity is one row of the "what has gone quiet" aggregation (#32 Phase C,
// D81 Q3): for a scoped set of events, how many matched each package and when the
// most recent one was.
//
// READ THE NAME LITERALLY: this is OBSERVED FLOW, not a repository inventory. It can
// only describe packages this firewall has actually seen requested. It cannot know
// about a package that exists upstream and was never pulled — which is what D81 Q3
// ("published but not pulled") literally asks for, and which needs a durable package
// inventory with publish dates that nothing in this system holds today (the cache
// service is a 5-minute response cache, not an inventory — see
// docs/CAPACITY_INSTRUMENTATION.md §3.3). Anything rendering this MUST say so; calling
// it "packages in your repository" would be a false claim about our own coverage.
//
// Keyed by (package, ecosystem) rather than package alone because one approval store
// serves a firewall instance PER ecosystem, so the same name legitimately exists in
// two of them (e.g. "requests" on pypi and npm) and they are different packages.
type PackageActivity struct {
	Package   string    `json:"package"`
	Ecosystem string    `json:"ecosystem,omitempty"`
	Events    int       `json:"events"`  // matching events for this package
	LastAt    time.Time `json:"last_at"` // most recent matching event
}

// EventSummary is the at-a-glance tally of the audit log since a point in time: the
// console's Overview answers "what did the gate do today" with it.
//
// It is an AGGREGATE rather than a list for the same reason DownloadsByIP is: the
// question is a count, and a count taken over a bounded list page is a wrong count the
// moment a busy day exceeds the page. Complete by construction.
//
// Blocked counts verdicts the gate actually REFUSED. A block verdict relayed anyway under
// report mode (taken=allow, #114) is counted in BlockedServed instead, because a tile
// saying "14 stopped" when those 14 were delivered is the single most misleading number
// this page could show.
type EventSummary struct {
	Since         time.Time `json:"since"`
	Allowed       int       `json:"allowed"`
	Blocked       int       `json:"blocked"`
	BlockedServed int       `json:"blocked_served"`
	// ByDenyKind splits Blocked by the gate's structured attribution (D182). The key ""
	// is "not recorded" -- events from before the control plane kept the field -- and is
	// kept as its own bucket so the parts still sum to Blocked.
	ByDenyKind map[string]int `json:"by_deny_kind"`
	// Sources is the number of distinct OBSERVED source IPs. Unobserved events are not a
	// source, so they are excluded rather than counted as one more host.
	Sources int `json:"sources"`
}

// add folds n events of one shape into the summary. Shared by memStore and the Postgres
// row loop so the two backends cannot disagree on what "blocked" means.
func (s *EventSummary) add(action AuditAction, denyKind, taken string, n int) {
	switch {
	case action == ActionAllow:
		s.Allowed += n
	case action == ActionBlock && taken == string(ActionAllow):
		s.BlockedServed += n
	case action == ActionBlock:
		s.Blocked += n
		s.ByDenyKind[denyKind] += n
	}
}

// Store is the storage abstraction. Defining it as an interface lets us swap
// backends (in-memory for dev, Postgres for real persistence) without touching
// the HTTP handlers — they depend only on this contract. Methods return error
// because a real database can fail; the in-memory implementation simply never
// returns one.
type Store interface {
	Get(pkg string) (Decision, bool, error)
	Put(d Decision) (Decision, error)
	List() ([]Decision, error)

	// The L2 score cache (repo-keyed), separate from the package-keyed human
	// decisions above: a cached fact with its own lifecycle, not a human ruling.
	GetScore(repo string) (ScoreRecord, bool, error)
	PutScore(rec ScoreRecord) (ScoreRecord, error)
	// DeleteScore removes a repo's cached score so the next pull is cold and the
	// firewall re-scans it — the operator-triggered re-scan primitive (issue #12).
	// existed reports whether a row was actually removed, so the handler can 404 a
	// no-op delete. Deleting a fact (unlike an audit event) is legitimate: it is a
	// cache, not a ledger.
	DeleteScore(repo string) (existed bool, err error)

	// The append-only audit log (D10 #3 / D12). AppendEvent inserts one immutable
	// event and returns it with its assigned ID; there is deliberately no update or
	// delete, so whatever is being audited cannot rewrite the trail. ListEvents
	// returns the most recent MATCHING events first, capped at f.Limit — the filter
	// is applied across the whole history, not a pre-truncated window.
	AppendEvent(e AuditEvent) (AuditEvent, error)
	ListEvents(f EventFilter) ([]AuditEvent, error)

	// StreamEvents yields every MATCHING event to fn, oldest-first, for the
	// compliance/decision-log export (#28). It deliberately has NO limit: the export's
	// value is that it is COMPLETE ("every component that entered"), so unlike
	// ListEvents it must not truncate. It calls fn once per event instead of returning
	// a slice so neither the store nor the caller ever holds the whole log in memory —
	// pgStore streams rows, memStore walks its slice, and the handler encodes each
	// event straight to the response. Oldest-first because an audit record reads
	// chronologically. If fn returns an error, iteration stops and that error is
	// returned (e.g. the client disconnected mid-download).
	StreamEvents(f EventFilter, fn func(AuditEvent) error) error

	// DownloadsByIP aggregates the MATCHING events by source IP (#41): the "who pulled
	// this package, and how often" incident-response query. Like StreamEvents and unlike
	// ListEvents it is COMPLETE — it counts over the whole matching history, so f.Limit
	// is IGNORED (a partial count is a wrong count for incident response). Rows come back
	// most-frequent-first (lexical IP tiebreak for a stable order). The unobserved-source
	// bucket (IP "") is included so the counts sum to the real total, but sorts LAST so
	// real attributable IPs lead an incident view.
	DownloadsByIP(f EventFilter) ([]IPCount, error)

	// SummarizeEvents tallies every event at or after since (see EventSummary). Complete,
	// like DownloadsByIP: no limit applies.
	SummarizeEvents(since time.Time) (EventSummary, error)

	// False-positive reports (#142): an operator's statement that a recorded block was
	// wrong. Append-only like events -- a retracted report is a second report, not a
	// deletion, because the value of the record is that it is a ledger. List is
	// newest-first and capped; there is no filter yet because the page shows them all.
	AddFalsePositive(r FalsePositiveReport) (FalsePositiveReport, error)
	ListFalsePositives(limit int) ([]FalsePositiveReport, error)

	// The flow dataset (#32 Phase C / C2): pre-aggregated traffic counters, kept
	// deliberately SEPARATE from the audit log above — see flowstore.go for the three
	// reasons. AddFlow is additive (and therefore not idempotent, on purpose); the
	// reads are the four D81 questions; PurgeFlowBefore is the uniform, untiered
	// retention sweep (D88).
	AddFlow(pkgs []FlowBucket, ips []FlowIPBucket) error
	FlowSummary(f FlowFilter) (FlowSummary, error)
	FlowTopPackages(f FlowFilter, limit int) ([]FlowPackage, error)
	FlowTopSources(f FlowFilter, limit int) ([]FlowSource, error)
	FlowSeries(f FlowFilter, step time.Duration) ([]FlowPoint, error)
	PurgeFlowBefore(cutoff time.Time) (int64, error)

	// Per-replica liveness + self-reported delivery failures (#32 Phase C / C4a).
	// UpsertInstanceHealth REPLACES the row for an instance rather than adding to it —
	// unlike the flow buckets above, these counters are cumulative gauges, not deltas.
	// See InstanceHealth in health.go for why liveness is a heartbeat and not inferred
	// from an absence of traffic.
	UpsertInstanceHealth(h InstanceHealth) error
	ListInstanceHealth() ([]InstanceHealth, error)

	// LastSeenByPackage aggregates the MATCHING events by (package, ecosystem): "what
	// has this firewall seen, and when did each one last come through" (#32 Phase C,
	// D81 Q3). Like DownloadsByIP and unlike ListEvents it is COMPLETE — f.Limit is
	// IGNORED, because the whole point is to find the package that went quiet a long
	// time ago, which is precisely the one a recency window would drop.
	//
	// Rows come back OLDEST-LAST-EVENT FIRST — the opposite of DownloadsByIP's
	// most-frequent-first, and deliberately so: this view answers "what has gone
	// quiet", so the quietest package must lead. Ties break on package then ecosystem
	// for a stable, testable order.
	//
	// The filter decides what "seen" means, and the CALLER owns that choice: pass
	// Action "allow" for last-successfully-pulled (bytes actually moved), or "" to
	// include blocks. Counting a block as a pull would overstate freshness — a package
	// blocked every day looks busy but is not being consumed — so a caller presenting
	// this as "last pulled" must filter to allow. See the console's staleness view.
	LastSeenByPackage(f EventFilter) ([]PackageActivity, error)

	// Alert-notification dedup (#32 Phase C / C4c). The ONLY durable alert state: the
	// alert list itself stays derived on read, so nothing here can make the console
	// show a stale opinion. See alertnotify.go for why the ordering matters.
	//
	// ClaimAlertNotification records "we are notifying about this now" and reports
	// whether THIS caller won the claim. It must be ATOMIC — an insert that either
	// creates the row or reports that it already existed — because a check-then-write
	// would let two sweeps (or two control-plane replicas) both decide to send.
	//
	// ReleaseAlertNotification undoes a claim whose send failed, so the next sweep
	// retries rather than the condition being permanently marked "already told them".
	//
	// ForgetResolvedAlerts deletes every claim NOT in active, which is what lets a
	// condition that clears and later recurs be notified again. Passing an empty slice
	// legitimately clears everything, so the caller must only ever call it with a
	// successfully-evaluated active set.
	ClaimAlertNotification(key string, at time.Time) (claimed bool, err error)
	ReleaseAlertNotification(key string) error
	ForgetResolvedAlerts(active []string) (int64, error)
}

// memStore keeps decisions in memory. Useful for local dev, but state is lost on
// restart — which is exactly why Layer 3.3 adds the Postgres-backed Store. Its
// map is mutated by concurrent requests, so every access is guarded by a mutex
// (unlike the firewall, whose shared state is read-only after startup).
type memStore struct {
	mu        sync.RWMutex
	decisions map[string]Decision
	scores    map[string]ScoreRecord
	events    []AuditEvent // append-only, kept in insertion (chronological) order
	nextID    int64        // monotonic id source for events (the in-memory BIGSERIAL)
	fps       []FalsePositiveReport
	nextFPID  int64

	// The flow dataset (#32 Phase C). Two SEPARATE maps, not one keyed by both
	// package and IP — see FlowIPBucket for why the cross product is avoided.
	// Lazily created by AddFlow so an untouched store costs nothing.
	flowPkgs map[flowPkgKey]*FlowBucket
	flowIPs  map[flowIPKey]*FlowIPBucket

	// Per-replica heartbeats, keyed by instance. Lazily created like the flow maps.
	health map[string]InstanceHealth

	// "We have already emailed about this condition", keyed by alertKey (#32 C4c).
	// The ONLY durable alert state there is: the alert list itself stays derived.
	alertNotified map[string]time.Time
}

func newMemStore() *memStore {
	return &memStore{
		decisions: make(map[string]Decision),
		scores:    make(map[string]ScoreRecord),
	}
}

func (s *memStore) Get(pkg string) (Decision, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.decisions[pkg]
	return d, ok, nil
}

func (s *memStore) Put(d Decision) (Decision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d.UpdatedAt = time.Now().UTC()
	// Preserve the enqueue time across updates. The caller cannot be trusted to send
	// it — the firewall's recordPending posts package/verdict/note only — so taking
	// FirstSeen from the incoming value would zero it on every write and make every
	// entry read as brand new, which is the exact way an unbounded queue hides.
	if prev, ok := s.decisions[d.Package]; ok && !prev.FirstSeen.IsZero() {
		d.FirstSeen = prev.FirstSeen
	} else if d.FirstSeen.IsZero() {
		d.FirstSeen = d.UpdatedAt
	} else if d.FirstSeen.After(d.UpdatedAt.Add(firstSeenSkewTolerance)) {
		// A caller-supplied enqueue time in the future is refused at the BOUNDARY, not
		// just where it is displayed. PUT /v1/decisions decodes firstSeen straight from
		// its body, so this value is chosen by whoever reaches this service.
		//
		// Why it matters: age is computed as now - FirstSeen, so a future timestamp is
		// negative, and anything that clamps it renders the row as newly arrived --
		// permanently, because the value never ages. A package parked this way sits in
		// the queue forever while looking like the freshest entry, which defeats the one
		// thing the queue exists to show.
		//
		// The console renders such a row as unmeasurable, but fixing it only there would
		// leave every OTHER consumer lying: the CLI dry-run (D137) and the compliance
		// export (#28) read the same records. So the stored value is corrected here and
		// the console keeps its own defence, because a store is not the only thing that
		// can write to a database.
		log.Printf("decision %q: refusing a firstSeen %v in the future (now %v); recording the write time instead",
			d.Package, d.FirstSeen.UTC(), d.UpdatedAt)
		d.FirstSeen = d.UpdatedAt
	}
	s.decisions[d.Package] = d
	return d, nil
}

func (s *memStore) List() ([]Decision, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Decision, 0, len(s.decisions))
	for _, d := range s.decisions {
		out = append(out, d)
	}
	return out, nil
}

func (s *memStore) GetScore(repo string) (ScoreRecord, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.scores[repo]
	return rec, ok, nil
}

func (s *memStore) PutScore(rec ScoreRecord) (ScoreRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec.UpdatedAt = time.Now().UTC()
	s.scores[rec.Repo] = rec
	return rec, nil
}

func (s *memStore) DeleteScore(repo string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, existed := s.scores[repo]
	delete(s.scores, repo)
	return existed, nil
}

// AppendEvent assigns the next id, stamps the time if the caller left it zero, and
// appends. It only ever grows the slice — no path here updates or removes an
// existing event, which is the whole point of an audit log.
func (s *memStore) AppendEvent(e AuditEvent) (AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	e.ID = s.nextID
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	s.events = append(s.events, e)
	return e, nil
}

// ListEvents returns the most recent MATCHING events first, capped at f.Limit.
// Because the slice is stored oldest-first, we walk it from the tail and keep only
// events the filter matches, stopping once we have Limit of them. Crucially the
// match test runs against the full history as we walk — not against a slice already
// truncated to the newest Limit — so an event that matches but sits further back
// than Limit is still surfaced (see TestListEventsFilterAcrossWindow). f.Limit <= 0
// means "no cap" here; the HTTP handler applies a sane default before calling, so an
// unbounded read is never triggered by an outside request.
func (s *memStore) ListEvents(f EventFilter) ([]AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEvent, 0)
	for i := len(s.events) - 1; i >= 0 && (f.Limit <= 0 || len(out) < f.Limit); i-- {
		if f.matches(s.events[i]) {
			out = append(out, s.events[i])
		}
	}
	return out, nil
}

// StreamEvents walks the whole log oldest-first (natural insertion order) and hands
// each matching event to fn. No limit — the export is complete by design. The read
// lock is held for the duration; fn only encodes to a response, so it is fast and
// non-blocking on the store.
func (s *memStore) StreamEvents(f EventFilter, fn func(AuditEvent) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.events {
		if !f.matches(e) {
			continue
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

// DownloadsByIP walks the whole matching history (no limit — completeness is the
// point, see the interface) and tallies a count + most-recent time per source IP,
// then returns the rows most-frequent-first. Ties break on IP so the order is stable
// and testable. The unobserved bucket (IP "") is counted like any other so the totals
// are honest.
func (s *memStore) DownloadsByIP(f EventFilter) ([]IPCount, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	agg := make(map[string]*IPCount)
	for _, e := range s.events {
		if !f.matches(e) {
			continue
		}
		row := agg[e.SourceIP]
		if row == nil {
			row = &IPCount{IP: e.SourceIP}
			agg[e.SourceIP] = row
		}
		row.Count++
		if e.At.After(row.LastAt) {
			row.LastAt = e.At
		}
	}
	out := make([]IPCount, 0, len(agg))
	for _, row := range agg {
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count // most-frequent first
		}
		// The unobserved bucket ("") always sorts LAST, so real, attributable IPs
		// surface first in an incident view rather than being pushed down by the
		// remainder. Among real IPs, a lexical tiebreak keeps the order stable/testable.
		if (out[i].IP == "") != (out[j].IP == "") {
			return out[j].IP == ""
		}
		return out[i].IP < out[j].IP
	})
	return out, nil
}

// SummarizeEvents walks the log newest-first and stops at the first event older than
// since. Events are appended in time order, so everything before that point is older
// too; an out-of-order clock could only UNDER-count here, never invent events.
func (s *memStore) SummarizeEvents(since time.Time) (EventSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := EventSummary{Since: since, ByDenyKind: map[string]int{}}
	ips := map[string]bool{}
	for i := len(s.events) - 1; i >= 0; i-- {
		e := s.events[i]
		if e.At.Before(since) {
			break
		}
		out.add(e.Action, e.DenyKind, e.Taken, 1)
		if e.SourceIP != "" {
			ips[e.SourceIP] = true
		}
	}
	out.Sources = len(ips)
	return out, nil
}

// LastSeenByPackage walks the whole matching history (no limit — see the interface;
// a recency window would drop exactly the quiet packages this exists to find) and
// tallies a count + most-recent time per (package, ecosystem), oldest-last-event
// first.
func (s *memStore) LastSeenByPackage(f EventFilter) ([]PackageActivity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// The composite map key must not be a plain concatenation: "a" + "b|c" and
	// "a|b" + "c" would collide into one row and silently merge two packages. A
	// struct key keeps the two fields separate, and Go compares it field-wise.
	type key struct{ pkg, eco string }
	agg := make(map[key]*PackageActivity)
	for _, e := range s.events {
		if !f.matches(e) {
			continue
		}
		k := key{e.Package, e.Ecosystem}
		row := agg[k]
		if row == nil {
			row = &PackageActivity{Package: e.Package, Ecosystem: e.Ecosystem}
			agg[k] = row
		}
		row.Events++
		if e.At.After(row.LastAt) {
			row.LastAt = e.At
		}
	}
	out := make([]PackageActivity, 0, len(agg))
	for _, row := range agg {
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastAt.Equal(out[j].LastAt) {
			return out[i].LastAt.Before(out[j].LastAt) // quietest (oldest) first
		}
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return out[i].Ecosystem < out[j].Ecosystem
	})
	return out, nil
}
