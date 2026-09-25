package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// False-positive reports (#142): the one quantity a request log cannot supply.
//
// A block that was correct and a block that was wrong are indistinguishable in the audit
// trail -- the distinguishing fact lives with the person who got the 403. This is the
// channel for that person's operator to record it. It is designed LOCAL FIRST: an
// operator's own false-positive history is useful with no egress at all (they act on it
// with the allow list), and that has to be the whole value proposition, because the
// invariants D244 was decided to preserve (zero egress, no phone-home) forbid collecting
// these automatically. Forwarding exists, is generic, and is empty by default.
//
// # What a report carries
//
// The identity of the block as the developer saw it, plus the STRUCTURED attribution the
// gate emits with every event (D182): which kind of denial, the rule that fired, and the
// source it came from. The source is the field this feature cannot do without -- a false
// positive against a published advisory and one against the operator's own deny-list
// entry are different facts with different remedies (D193 requires they stay
// distinguishable). Until this change those three fields were DROPPED at this service's
// door: the gate sent them, AuditEvent had no field for them, and the export never
// carried them. They are now stored with the event and copied onto the report.

// FalsePositiveReport is one operator statement that a recorded block was wrong.
type FalsePositiveReport struct {
	ID        int64  `json:"id"`
	EventID   int64  `json:"event_id,omitempty"` // the audit event it disputes, when known
	Package   string `json:"package"`
	Ecosystem string `json:"ecosystem,omitempty"`
	// Reason is the text the developer was shown; Source, DenyKind and Rule are the
	// gate's structured attribution of the same block, copied from the event.
	Reason   string `json:"reason,omitempty"`
	Source   string `json:"source,omitempty"`
	DenyKind string `json:"deny_kind,omitempty"`
	Rule     string `json:"rule,omitempty"`
	// Note is the operator's own words. ReportedBy is the console's identity for them
	// (a real person under OIDC, the shared label under basic auth) -- #41.
	Note       string    `json:"note,omitempty"`
	ReportedBy string    `json:"reported_by,omitempty"`
	At         time.Time `json:"at"`
}

// SourceKind classifies the block's origin for the operator and for a forwarded report.
// Anything the gate can emit as a Source maps onto one of three words; a value this
// function does not recognise is reported verbatim rather than guessed at.
func (r FalsePositiveReport) SourceKind() string {
	switch strings.TrimSpace(r.Source) {
	case "known-malware feed":
		return "advisory"
	case "operator deny list", "approval service":
		return "operator"
	case "":
		return "unattributed"
	}
	return r.Source
}

// ── forwarding ─────────────────────────────────────────────────────────────────────

// fpForwarder posts each accepted report to an operator-configured destination.
//
// Nil is the shipped default and means: no destination, no client, no outbound call.
// That is asserted rather than assumed (TestAnUnconfiguredInstallForwardsNothing), to the
// same bar as the never-meters invariant: the negative control is the load-bearing half.
// There is no built-in destination and no vendor host; the operator names one URL, so an
// air-gapped site points it at something inside their own boundary or leaves it empty.
type fpForwarder struct {
	url     string
	client  *http.Client
	outcome outcomeLog
	dropped atomic.Int64
	mu      sync.Mutex
}

// newFPForwarder reads APPROVAL_FP_WEBHOOK. Empty -> nil.
func newFPForwarder() *fpForwarder {
	return newFPForwarderTo(strings.TrimSpace(os.Getenv("APPROVAL_FP_WEBHOOK")), &http.Client{Timeout: 10 * time.Second})
}

func newFPForwarderTo(raw string, client *http.Client) *fpForwarder {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		// Refuse to boot rather than silently forward nowhere: an operator who set
		// this wants the reports to go somewhere, and "nothing arrived" is the failure
		// they would notice last.
		log.Fatalf("APPROVAL_FP_WEBHOOK=%q is not an http(s) URL", raw)
	}
	return &fpForwarder{url: raw, client: client}
}

// forward posts one report. Best-effort and out of the request path: a destination that
// is down must not stop the operator's own record being kept, which is why the store is
// written first and this is called after. Failures are counted and logged once per change
// of outcome (#153's rule), never per report.
func (f *fpForwarder) forward(r FalsePositiveReport) {
	if f == nil {
		return
	}
	body, err := json.Marshal(struct {
		FalsePositiveReport
		SourceKind string `json:"source_kind"`
	}{r, r.SourceKind()})
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, f.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "yellowjack-approval/false-positive-report")

	f.mu.Lock()
	defer f.mu.Unlock()
	resp, err := f.client.Do(req)
	status := undeliverable
	if err == nil {
		status = resp.StatusCode
		resp.Body.Close()
	}
	if !accepted(status) {
		f.dropped.Add(1)
	}
	if prev, changed := f.outcome.changed(status); changed {
		switch {
		case err != nil:
			log.Printf("false-positive forwarding: the destination cannot be reached: %v. Reports are still recorded locally; %d not forwarded so far", err, f.dropped.Load())
		case !accepted(status):
			log.Printf("false-positive forwarding: the destination answered HTTP %d. Reports are still recorded locally; %d not forwarded so far", status, f.dropped.Load())
		case prev != 0:
			log.Printf("false-positive forwarding: accepted again (HTTP %d); %d were not forwarded in total", status, f.dropped.Load())
		}
	}
}

// ── outcome bookkeeping, copied from the gate (separate binary) ─────────────────────

type outcomeLog struct{ last atomic.Int32 }

func (o *outcomeLog) changed(status int) (prev int, changed bool) {
	prev = int(o.last.Swap(int32(status)))
	return prev, prev != status
}

const undeliverable = -1

func accepted(status int) bool { return status >= 200 && status <= 299 }

// ── HTTP ───────────────────────────────────────────────────────────────────────────

var errFPInvalid = errors.New("invalid false-positive report")

// handleFalsePositives serves GET (list, newest first) and POST (record one).
func (srv *server) handleFalsePositives(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		reports, err := srv.store.ListFalsePositives(200)
		if err != nil {
			log.Printf("list false positives: %v", err)
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
		if reports == nil {
			reports = []FalsePositiveReport{}
		}
		writeJSON(w, http.StatusOK, reports)
	case http.MethodPost:
		var in FalsePositiveReport
		if err := decodeCapped(r.Body, smallBodyMaxBytes, &in); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if err := validateFalsePositive(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		in.At = time.Now().UTC()
		saved, err := srv.store.AddFalsePositive(in)
		if err != nil {
			log.Printf("record false positive %q: %v", in.Package, err)
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
		log.Printf("false positive recorded: %s (%s) by %q, source %s", saved.Package, saved.Ecosystem, saved.ReportedBy, saved.SourceKind())
		srv.fpForwarder.forward(saved)
		writeJSON(w, http.StatusCreated, saved)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// smallBodyMaxBytes bounds a report: a package name, a reason and a note.
const smallBodyMaxBytes = 64 << 10

func validateFalsePositive(r *FalsePositiveReport) error {
	r.Package = strings.TrimSpace(r.Package)
	if r.Package == "" {
		return fmt.Errorf("%w: package is required", errFPInvalid)
	}
	for name, v := range map[string]*string{"note": &r.Note, "reason": &r.Reason} {
		if len(*v) > 4096 {
			return fmt.Errorf("%w: %s is longer than 4096 bytes", errFPInvalid, name)
		}
	}
	return nil
}
