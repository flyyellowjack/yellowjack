package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

// flowEmitter ships the recorder's counters to the approval service's durable sink
// (#32 Phase C / C2b). It is the last link in the chain the capacity dashboard reads:
//
//	relay -> flowRecorder (in memory) -> flowEmitter (this file) -> POST /v1/flow -> flow_buckets
//
// FIRE-AND-FORGET, AND NEVER RETRY. The sink's upsert is additive by necessity —
// replicas report the same key independently — which makes it NOT idempotent: a
// re-delivered batch double-counts. So the two failure directions are:
//
//	dropped batch  -> the dashboard UNDER-reports; no traffic is invented
//	retried batch  -> the dashboard OVER-reports; traffic that never happened appears
//
// Under-reporting is the safe direction for a capacity view, so a failed flush is
// logged and counted, never retried. The drop counter is itself surfaced, so an
// operator can tell "quiet" from "we lost the numbers" — the distinction that makes
// under-reporting honest rather than merely convenient.
type flowEmitter struct {
	endpoint string // approval POST URL; empty => disabled
	instance string // which replica these rows came from
	client   *http.Client
	recorder *flowRecorder
	interval time.Duration

	dropped atomic.Int64 // batches lost (transport error, or a non-2xx answer)
	// shedLogged and lastBeatStatus exist so the two heartbeat diagnostics (#139) are said
	// ONCE per change rather than every interval: a refusal repeats on every beat.
	shedLogged  atomic.Bool
	beatOutcome outcomeLog

	// healthEndpoint is where the heartbeat goes (#32 Phase C / C4a); empty disables it.
	healthEndpoint string
	// audit is consulted for ITS drop counter, so the two "we lost data" signals travel
	// together in one heartbeat rather than needing a second reporting path. nil is fine
	// (auditing disabled) and reports zero.
	audit *auditEmitter
	// startedAt makes a restart visible to the operator: when the drop counters reset to
	// zero, this is what says why.
	startedAt time.Time

	// policy is what this replica is ENFORCING (#32 Phase D / D4), reported on every beat
	// so the control plane can render it and spot replicas that disagree. A nil source
	// omits the field entirely, so a firewall without one sends exactly the bytes it
	// always did.
	//
	// Re-sent every beat rather than announced once at startup: the control plane's view
	// has to survive ITS OWN restart without requiring every firewall to restart too.
	//
	// ⚠️ A FUNCTION, NOT A SNAPSHOT, SINCE D195 — and proxy.go's own comment called this
	// shot before it happened: "a snapshot is correct today and wrong the moment refresh
	// exists". Refresh now exists: the operator allow/deny lists re-read from disk while
	// the process runs, so a *PolicyView captured at construction reports the policy this
	// replica had AT BOOT, forever. The e2e leg caught exactly that — the gate enforced an
	// edited deny list while the console kept rendering the old one, which is worse than
	// showing nothing because the page is confidently wrong.
	policy func() *PolicyView
}

// flowBucketDTO / flowIPBucketDTO are this service's OWN wire types, declared here
// rather than imported from the approval package — the same REST-boundary independence
// discipline as approval_client.go and audit.go. The JSON tags must match the approval
// service's FlowBucket/FlowIPBucket exactly.
type flowBucketDTO struct {
	BucketStart time.Time `json:"bucket_start"`
	Ecosystem   string    `json:"ecosystem"`
	Package     string    `json:"package,omitempty"`
	Kind        string    `json:"kind"`

	Requests      int64 `json:"requests"`
	BytesUpstream int64 `json:"bytes_upstream"`
	BytesClient   int64 `json:"bytes_client"`

	Truncated       int64 `json:"truncated"`
	RelayErrors     int64 `json:"relay_errors"`
	TransportErrors int64 `json:"transport_errors"`
	UpstreamStatus  int64 `json:"upstream_status"`
	MetaErrors      int64 `json:"meta_errors"`
	Retries         int64 `json:"retries"`
	// #64. omitempty is deliberately ABSENT: a zero here means "checked, all matched",
	// which is the reassuring reading an operator wants, and omitempty would make it
	// indistinguishable on the wire from a gate too old to check at all.
	IntegrityMismatches int64 `json:"integrity_mismatches"`
}

type flowIPBucketDTO struct {
	BucketStart time.Time `json:"bucket_start"`
	Ecosystem   string    `json:"ecosystem"`
	SourceIP    string    `json:"source_ip,omitempty"`

	Requests      int64 `json:"requests"`
	BytesUpstream int64 `json:"bytes_upstream"`
	BytesClient   int64 `json:"bytes_client"`
}

type flowBatchDTO struct {
	Instance string            `json:"instance"`
	Packages []flowBucketDTO   `json:"packages"`
	Sources  []flowIPBucketDTO `json:"sources"`
}

// newFlowEmitter builds an emitter and starts its flush loop. An empty approvalURL or a
// non-positive interval DISABLES emission (the recorder keeps counting locally, which is
// still useful for the live gauges), so a deployment with no control plane runs exactly
// as it did before.
func newFlowEmitter(approvalURL, instance string, client *http.Client, rec *flowRecorder, interval time.Duration, audit *auditEmitter) *flowEmitter {
	e := &flowEmitter{instance: instance, client: client, recorder: rec, interval: interval,
		audit: audit, startedAt: time.Now().UTC()}
	if approvalURL == "" || interval <= 0 || rec == nil {
		return e
	}
	e.endpoint = trimRightSlash(approvalURL) + "/v1/flow"
	e.healthEndpoint = trimRightSlash(approvalURL) + "/v1/health"
	go e.run()
	return e
}

func trimRightSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// run flushes on the interval, aligned to the wall clock.
//
// ALIGNMENT MATTERS: the bucket a batch is stamped with is the interval it covers, so
// flushing at :00, :01, :02 makes each batch line up with the minute it describes. An
// unaligned ticker (started whenever the process happened to boot) would smear each
// replica's traffic across bucket boundaries differently, and several replicas would
// disagree about where a minute begins — which shows up on the dashboard as phantom
// sawtooth in the series with no cause in the traffic.
func (e *flowEmitter) run() {
	for {
		now := time.Now()
		next := now.Truncate(e.interval).Add(e.interval)
		time.Sleep(time.Until(next))
		// The batch covers the interval that just ENDED, so stamp it with that bucket's
		// start, not with "now" (which is the start of the next one).
		e.flush(next.Add(-e.interval))
	}
}

// flush drains the recorder and posts one batch.
//
// The drain happens even when emission is disabled or the POST fails: counters that are
// never drained grow forever, and the memory they occupy is per distinct package, which
// on a busy instance is unbounded. Losing a batch is the accepted failure mode; leaking
// memory because the control plane is down is not.
func (e *flowEmitter) flush(bucketStart time.Time) {
	pkgs, ips := e.recorder.Drain()

	// The heartbeat goes FIRST and UNCONDITIONALLY — before the early return below, and
	// whether or not any traffic moved. That is the entire point of it: an idle interval
	// is exactly when a dead firewall and a quiet one look identical in the flow data,
	// so the one moment the heartbeat matters most is the moment there is nothing else
	// to send. Putting it after the "nothing moved" return would make liveness reporting
	// stop precisely when liveness became the question.
	e.heartbeat()

	if len(pkgs) == 0 && len(ips) == 0 {
		return // nothing moved this interval; no empty batches
	}
	if e.endpoint == "" {
		return
	}

	batch := flowBatchDTO{Instance: e.instance}
	for _, r := range pkgs {
		batch.Packages = append(batch.Packages, flowBucketDTO{
			BucketStart: bucketStart, Ecosystem: r.Ecosystem, Package: r.Package, Kind: string(r.Kind),
			Requests: r.Requests, BytesUpstream: r.BytesUpstream, BytesClient: r.BytesClient,
			Truncated: r.Truncated, RelayErrors: r.RelayErrors, TransportErrors: r.TransportErrors,
			UpstreamStatus: r.UpstreamStatus, MetaErrors: r.MetaErrors, Retries: r.Retries,
			IntegrityMismatches: r.IntegrityMismatches,
		})
	}
	for _, r := range ips {
		batch.Sources = append(batch.Sources, flowIPBucketDTO{
			BucketStart: bucketStart, Ecosystem: r.Ecosystem, SourceIP: r.SourceIP,
			Requests: r.Requests, BytesUpstream: r.BytesUpstream, BytesClient: r.BytesClient,
		})
	}

	if err := e.post(batch); err != nil {
		n := e.dropped.Add(1)
		// Logged at full volume rather than sampled: this line is how an operator
		// distinguishes "the graph is flat because nothing happened" from "the graph is
		// flat because we could not deliver". Those look identical on the dashboard.
		log.Printf("flow emit: DROPPED a batch of %d package rows / %d source rows (%d dropped so far): %v — capacity numbers will under-report this interval",
			len(batch.Packages), len(batch.Sources), n, err)
	}
}

func (e *flowEmitter) post(batch flowBatchDTO) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer closeDrained(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &flowPostError{status: resp.StatusCode}
	}
	return nil
}

type flowPostError struct{ status int }

func (e *flowPostError) Error() string {
	return "approval answered HTTP " + http.StatusText(e.status)
}

// Dropped reports how many batches were lost. Surfaced so the dashboard can say its own
// numbers are incomplete rather than presenting a short total as fact.
func (e *flowEmitter) Dropped() int64 {
	if e == nil {
		return 0
	}
	return e.dropped.Load()
}

// heartbeat reports this replica's liveness and its cumulative delivery failures.
//
// Failures here are logged at low volume and NOT counted into e.dropped: that counter
// means "capacity numbers are short", and a missed heartbeat does not make the numbers
// short — conflating them would have a control-plane blip inflate a data-loss metric.
// A heartbeat that does not arrive is already visible as the absence it is: the row's
// reported_at simply stops advancing, which is what the staleness check reads.
// policyNow reads the policy currently in force, tolerating a nil source.
//
// Nil is the ordinary case for a firewall constructed without one (every test that
// builds an emitter directly), so this is not defensive habit: without the guard the
// heartbeat would panic on those, and the heartbeat is the one thing that must keep
// working when everything else is degraded.
func (e *flowEmitter) policyNow() *PolicyView {
	if e.policy == nil {
		return nil
	}
	return e.policy()
}

// heartbeatBudget is the most this replica will put in one beat.
//
// The control plane refuses a beat over its own cap (approval/healthhttp.go,
// maxHealthBytes = 64 KiB), and a refused beat reads as a DEAD replica -- liveness lost
// to a reporting feature, which that file calls the worst possible trade. The policy view
// is the only part of the beat that grows with operator input, and it can outgrow the cap:
// measured 2026-09-20, two 200-name lists of ~160-character entries make it 62.5 KB, and
// digest-pinned OCI references run 110-150 characters.
//
// So the beat is made to fit BY CONSTRUCTION rather than by hoping lists stay short: over
// budget, it is re-marshalled with the list NAMES shed (see heartbeatBody). The two
// binaries share no constant, so TestTheHeartbeatBudgetIsBelowTheControlPlanesCap derives
// the other side's number from its source and holds this one under it.
const heartbeatBudget = 48 << 10

// heartbeatBody marshals one beat, shedding operator-list names if that is what it takes
// to fit heartbeatBudget.
//
// What is shed is chosen so nothing the control plane DECIDES on changes: each list keeps
// its path and content digest, the policy digest is untouched (it was computed over the
// full lists), so divergence detection is exactly as sharp. Only the human-readable names
// go, and Omitted says how many.
//
// ⚠️ This comment used to end "the page already renders 'N more not shown', so a shed list
// reads as truncated rather than as empty". That was written from the template's existence,
// not from reading it: the note sat INSIDE `{{ if .Names }}`, so a shed list fell through
// to "loaded ZERO entries -- check the file this replica mounted". The console now has a
// branch for names-shed-but-entries-loaded, and e2e/async_local.sh leg 28 is what holds the
// two binaries to it.
func (e *flowEmitter) heartbeatBody() ([]byte, error) {
	type beat struct {
		Instance     string    `json:"instance"`
		Ecosystem    string    `json:"ecosystem,omitempty"`
		StartedAt    time.Time `json:"started_at,omitempty"`
		AuditDropped int64     `json:"audit_dropped"`
		FlowDropped  int64     `json:"flow_dropped"`
		// omitempty, so a firewall with no policy view sends the bytes it always did.
		Policy *PolicyView `json:"policy,omitempty"`
	}
	b := beat{
		Instance:  e.instance,
		Ecosystem: e.recorder.ecosystemName(),
		StartedAt: e.startedAt,
		// Both counters are process-lifetime cumulative, re-sent unchanged every beat.
		// The sink REPLACES rather than adds for exactly this reason.
		AuditDropped: e.audit.Dropped(),
		FlowDropped:  e.dropped.Load(),
		Policy:       e.policyNow(),
	}
	body, err := json.Marshal(b)
	if err != nil || len(body) <= heartbeatBudget || b.Policy == nil || len(b.Policy.Lists) == 0 {
		return body, err
	}

	shed := *b.Policy // a copy: the source's view must not be mutated under a concurrent reader
	shed.Lists = make([]ListView, len(b.Policy.Lists))
	for i, l := range b.Policy.Lists {
		l.Omitted += len(l.Names)
		l.Names = nil
		shed.Lists[i] = l
	}
	b.Policy = &shed
	if !e.shedLogged.Swap(true) {
		log.Printf("flow heartbeat: the reported policy is %d bytes, over the %d-byte heartbeat budget, so operator-list "+
			"NAMES are omitted from the report (digests and counts are kept; enforcement is unaffected). The console "+
			"will show those lists as truncated", len(body), heartbeatBudget)
	}
	return json.Marshal(b)
}

func (e *flowEmitter) heartbeat() {
	if e.healthEndpoint == "" {
		return // emission disabled; the recorder still drains
	}
	body, err := e.heartbeatBody()
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, e.healthEndpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		log.Printf("flow heartbeat: %v (liveness reporting only; capacity counters unaffected)", err)
		return
	}
	closeDrained(resp.Body)
	// The status used to be IGNORED, so a refused beat was silent on this side too: the
	// control plane answered 400 to nobody, this process logged nothing, and the console
	// showed a healthy firewall as stale with no line anywhere saying why (#139). Logged
	// once per change of outcome, not per beat -- a refusal repeats every interval.
	if last, changed := e.beatOutcome.changed(resp.StatusCode); changed {
		switch {
		case accepted(resp.StatusCode):
			if last != 0 {
				log.Printf("flow heartbeat: accepted again (HTTP %d)", resp.StatusCode)
			}
		case resp.StatusCode == http.StatusRequestEntityTooLarge:
			log.Printf("flow heartbeat: REFUSED as too large (HTTP 413, %d bytes sent). This replica will read as "+
				"STALE in the console until the report shrinks; enforcement is unaffected", len(body))
		default:
			log.Printf("flow heartbeat: REFUSED by the control plane (HTTP %d). This replica will read as STALE "+
				"in the console; enforcement is unaffected", resp.StatusCode)
		}
	}
}
