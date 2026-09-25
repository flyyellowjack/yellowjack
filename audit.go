package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
)

// The two terminal verdicts we audit, as the approval service's /v1/events expects
// them. Declared here (not imported from the approval package) so the firewall and
// approval services stay independent across the REST boundary — the same discipline
// as approval_client.go's own DTOs.
const (
	auditActionAllow = "allow"
	auditActionBlock = "block"
)

// auditBufferSize bounds how many un-delivered events may queue before Emit starts
// dropping. Sized generously so only a sustained approval-service outage — not a
// brief blip — ever drops an event; a full buffer is a signal the trail is lagging,
// never a reason to stall a pull.
const auditBufferSize = 1024

// auditEvent is the firewall's own DTO for one record posted to the approval
// service's append-only audit log (POST /v1/events). Its JSON tags match the
// approval service's AuditEvent exactly; Score is a pointer so nil marshals to an
// omitted field, carrying "no score was available".
type auditEvent struct {
	Package   string `json:"package"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Action    string `json:"action"` // the VERDICT: "allow" | "block"
	// Taken is what the gate actually did with that verdict, and Mode is why the two
	// can differ (#114): under FW_MODE=report a "block" verdict is relayed anyway, so
	// the record reads action=block, taken=allow, mode=report -- machine-distinguishable
	// from a real block without reading a log line. Under enforce, taken == action.
	Taken  string   `json:"taken"`
	Mode   string   `json:"mode"`
	Score  *float64 `json:"score,omitempty"`
	Reason string   `json:"reason,omitempty"`
	// What Score was computed over (#154, the #133 denominator carried to the record):
	// ScoredChecks of TotalChecks, without the checks named. Zero/empty when no score
	// was in play, on a full report, or from a scanner that predates the counts -- so
	// an exported 6.2 over 11 of 18 checks is no longer the same record as a 6.2 over
	// 18. Absent (omitempty) rather than 0 so an older record is "unknown", not "full".
	ScoredChecks    int      `json:"scored_checks,omitempty"`
	TotalChecks     int      `json:"total_checks,omitempty"`
	ComputedWithout []string `json:"computed_without,omitempty"`
	// The structured half of the reason (D182, #20): which kind of denial, the
	// identifier of the rule that fired, and the policy or feed it came from. Empty on
	// an allow, so an exported decision log is attributable without log correlation.
	DenyKind string `json:"deny_kind,omitempty"`
	Rule     string `json:"rule,omitempty"`
	Source   string `json:"source,omitempty"`
	// Override says this verdict went AGAINST a finding on an explicit operator
	// instruction (D312): an allow-list entry naming a release that a known-malware
	// advisory also names. Empty on every ordinary record, including an ordinary allow.
	//
	// It is on the EXPORTED record, not only in a log, because that is the whole of
	// D312's second condition: the administrator gets their way and the organisation
	// still gets told. A compliance reader comparing two allows must be able to see that
	// one of them was made over a standing advisory — which is exactly the question the
	// structured fields beside it exist to answer.
	Override string `json:"override,omitempty"`
	// SourceIP is the observed connecting-peer address (see clientIP): the "which
	// host pulled this" incident-response signal, never a claimed human identity.
	// omitempty so an unobserved source marshals to an absent field, matching the
	// approval AuditEvent's own omitempty.
	SourceIP string `json:"source_ip,omitempty"`

	// The two fields below are the DECISION'S INPUTS, not more description of it
	// (#28: "the reason and the inputs that produced it"). Score and Reason say what
	// we concluded; these say what we concluded it AGAINST, which is the difference
	// between a log line and evidence.
	//
	// Concretely: a record reading score 4.2, blocked is not reproducible. An auditor
	// months later cannot tell whether 4.2 failed a threshold of 5.0 or whether the
	// block came from somewhere else entirely and the score is incidental. With the
	// threshold present the arithmetic is checkable from the record alone.
	//
	// Threshold is a pointer for the same reason Score is: a nil threshold marshals
	// to an absent field and means "no threshold was in play", which is honest for a
	// verdict that never consulted a score (a known-malware refusal, say). Writing 0
	// there would read as "the threshold was zero, so everything passes" — the most
	// misleading possible value.
	Threshold *float64 `json:"threshold,omitempty"`
	// PolicyDigest names the policy in force when this verdict was rendered — #28's
	// "policy in force, config version". It is the PolicyView fingerprint, which is
	// already built to be safe to hand out: it deliberately excludes upstream URLs
	// and never includes FW_UPSTREAM_AUTH, so stamping it on an exported record
	// cannot leak a credential or let a reader retarget the gate.
	PolicyDigest string `json:"policy_digest,omitempty"`
}

// auditEmitter ships terminal allow/block verdicts to the approval service's
// append-only audit log WITHOUT ever blocking a package pull. This is the
// non-blocking-emission requirement made concrete:
//
//   - Emit does a NON-BLOCKING send onto a buffered channel and returns at once,
//     so the request goroutine never waits on the audit network hop.
//   - A single background goroutine drains the channel and POSTs each event.
//   - If the buffer is full (approval slow or down) the event is DROPPED and
//     counted, never backpressured onto the request. The audit trail is
//     best-effort; the gate must never fail or stall because logging is slow.
//
// The firewall side has only Emit — no update, no delete — mirroring the
// append-only shape of the store on the other end.
type auditEmitter struct {
	endpoint string // approval POST URL; empty => disabled, Emit is a no-op
	client   *http.Client
	ch       chan auditEvent
	// dropped counts every event that did not reach the store: a full local buffer, AND
	// (#153) an event the control plane answered with anything but 2xx. It is reported in
	// each heartbeat as audit_dropped so the console can say "this record is incomplete",
	// which is only true if it counts the losses that actually happen.
	dropped atomic.Int64
	outcome outcomeLog
}

// newAuditEmitter builds an emitter. An empty approvalURL DISABLES auditing (Emit
// becomes a no-op and no goroutine starts), which keeps deployments and tests with
// no approval service running exactly as before. bufSize bounds how many events
// may queue before Emit starts dropping.
func newAuditEmitter(approvalURL string, client *http.Client, bufSize int) *auditEmitter {
	a := &auditEmitter{}
	if approvalURL == "" {
		return a // disabled: Emit is a no-op
	}
	a.endpoint = strings.TrimRight(approvalURL, "/") + "/v1/events"
	a.client = client
	a.ch = make(chan auditEvent, bufSize)
	go a.run()
	return a
}

// Emit queues one event without blocking. A full buffer means the background drain
// can't keep up (approval slow/down); we drop and count rather than stall a
// developer's pull.
func (a *auditEmitter) Emit(e auditEvent) {
	if a == nil || a.ch == nil {
		return // auditing disabled
	}
	select {
	case a.ch <- e:
	default:
		a.dropped.Add(1)
	}
}

// run is the single background consumer: drain the channel, POST each event
// best-effort. It exits when the channel is closed (process shutdown).
func (a *auditEmitter) run() {
	for e := range a.ch {
		a.post(e)
	}
}

// post delivers one event. Every failure is logged and swallowed — a broken audit
// hop must never crash or wedge the firewall.
func (a *auditEmitter) post(e auditEvent) {
	body, err := json.Marshal(e)
	if err != nil {
		log.Printf("audit emit %q: marshal: %v", e.Package, err)
		return
	}
	req, err := http.NewRequest(http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		log.Printf("audit emit %q: build request: %v", e.Package, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		// An event that could not be DELIVERED is as lost as one that was refused, and it
		// used to be logged (once per event) but never counted. That made the commonest
		// outage -- the approval service simply down, connection refused -- the one where
		// docs/FAILURE_MODES.md's "lost events are counted, not silently absent" was false:
		// a fast failure drains the queue, so the buffer-full path never fires either.
		a.dropped.Add(1)
		if _, changed := a.outcome.changed(undeliverable); changed {
			log.Printf("audit emit: decision records cannot be DELIVERED (first for %q): %v. Every event lost this way "+
				"is counted as dropped (%d so far): the AUDIT TRAIL IS INCOMPLETE until this clears. Enforcement "+
				"is unaffected", e.Package, err, a.dropped.Load())
		}
		return
	}
	status := resp.StatusCode
	closeDrained(resp.Body)

	// #153. The status used to be discarded, so a refusal was invisible end to end: with
	// the approval service UP and its database DOWN, /v1/events answers 500 for every
	// event, this logged nothing, and `dropped` stayed at 0 -- the heartbeat told the
	// console the record was complete during exactly the outage that was losing all of it.
	if !accepted(status) {
		a.dropped.Add(1)
	}
	if prev, changed := a.outcome.changed(status); changed {
		switch {
		case !accepted(status):
			log.Printf("audit emit: the control plane REFUSED a decision record (HTTP %d, first for %q). Every event "+
				"refused this way is counted as dropped (%d so far): the AUDIT TRAIL IS INCOMPLETE until this clears. "+
				"Enforcement is unaffected", status, e.Package, a.dropped.Load())
		case prev != 0:
			log.Printf("audit emit: decision records are being accepted again (HTTP %d); %d were lost in total",
				status, a.dropped.Load())
		}
	}
}

// Dropped reports how many audit events were discarded because the buffer was full.
// Surfaced (via the flow heartbeat) so "the trail is lagging" becomes an operator-visible
// alert rather than a counter nobody reads. A nil emitter means auditing is disabled,
// which is zero drops, not an error.
func (a *auditEmitter) Dropped() int64 {
	if a == nil {
		return 0
	}
	return a.dropped.Load()
}
