package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestGetScoreFromScanner exercises "local" scoring mode against a fake scanner
// service, so we test the firewall's wiring without running the real scanner or
// Scorecard.
func TestGetScoreFromScanner(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/scan" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"repo":"github.com/x/y","score":6.4,"checks":[]}`))
	}))
	defer ts.Close()

	f := &Firewall{
		cfg:           Config{ScorecardMode: "local", ScannerURL: ts.URL},
		scannerClient: &http.Client{Timeout: 5 * time.Second},
	}
	score, err := f.getScore("github.com/x/y")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if score != 6.4 {
		t.Errorf("score = %v, want 6.4", score)
	}
}

func TestGetScoreFromScannerErrors(t *testing.T) {
	// "local" mode without a configured URL is a config error, surfaced clearly.
	f := &Firewall{cfg: Config{ScorecardMode: "local"}}
	if _, err := f.getScore("github.com/x/y"); err == nil {
		t.Error("expected error when FW_SCANNER_URL unset in local mode")
	}

	// A failed scan (non-200) becomes "no score", so the unscorable path takes over.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"error":"scan failed"}`))
	}))
	defer ts.Close()
	f2 := &Firewall{
		cfg:           Config{ScorecardMode: "local", ScannerURL: ts.URL},
		scannerClient: &http.Client{Timeout: 5 * time.Second},
	}
	if _, err := f2.getScore("github.com/x/y"); err == nil {
		t.Error("expected error on scanner 502")
	} else if errors.Is(err, errUpstreamUnavailable) {
		// A 502 means the SCAN failed (repo not found, no token) — a statement about
		// the repo, so it must keep feeding the unscorable policy, not become a
		// retryable 503.
		t.Error("a scanner 502 must not be classified transient")
	}
}

// The scheduler answers 503 when it is at its scan-concurrency cap (issue #13,
// item 3). That is about OUR capacity, not the package, so it must be classified
// TRANSIENT — otherwise a burst of cold packages would hit the unscorable policy and,
// under the fail-closed default, block good packages for being unlucky.
func TestGetScoreSchedulerAtCapacityIsTransient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"scheduler at scan capacity, retry"}`))
	}))
	defer ts.Close()

	f := &Firewall{
		cfg:           Config{ScorecardMode: "local", ScannerURL: ts.URL},
		scannerClient: &http.Client{Timeout: 5 * time.Second},
	}
	_, err := f.getScore("github.com/x/y")
	if err == nil {
		t.Fatal("expected an error when the scheduler sheds the scan")
	}
	if !errors.Is(err, errUpstreamUnavailable) {
		t.Errorf("error = %v, want it to wrap errUpstreamUnavailable so the client gets a retryable 503", err)
	}
}

// TestGetScoreSchedulerPrepareFailureIsTransient pins the 500 case, which was falling
// through to "unscorable" — a verdict about the package — when nothing had been asked
// about the repo at all.
//
// The scheduler answers 500 "failed to prepare scan" when it cannot mint a waiter or a
// capability token. That is our own infrastructure failing, exactly like the 503
// capacity shed above, and under the DEFAULT byte gate a soft deny serves the artifact.
// This is the same shape as the OCI lookup bug (!93): a misclassification one layer
// above the gate makes the gate's own guard inapplicable, because the decision never
// becomes Unavailable in the first place.
func TestGetScoreSchedulerPrepareFailureIsTransient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"failed to prepare scan"}`))
	}))
	defer ts.Close()

	f := &Firewall{
		cfg:           Config{ScorecardMode: "local", ScannerURL: ts.URL},
		scannerClient: &http.Client{Timeout: 5 * time.Second},
	}
	_, err := f.getScore("github.com/x/y")
	if err == nil {
		t.Fatal("expected an error when the scheduler cannot prepare a scan")
	}
	if !errors.Is(err, errUpstreamUnavailable) {
		t.Errorf("error = %v, want it to wrap errUpstreamUnavailable — nothing was asked about the repo, "+
			"so this must be a retryable 503 and never an unscorable verdict", err)
	}
}

// TestGetScoreScannerBadGatewayStaysUnscorable is the guard on the OTHER side, and the
// reason the fix above is narrow rather than "5xx is transient".
//
// The scheduler answers 502 for two OPPOSITE things: "failed to launch scanner" (ours)
// and "scan failed: <reason>" — the scan ran and the repo could not be scored. The
// status alone cannot separate them, so reclassifying 502 would make a genuinely
// unscorable package retry forever instead of ever reaching the approval path.
//
// Pinned explicitly so a future "just make all 5xx transient" tidy-up fails here and
// has to confront the overloading rather than silently trading one bug for another.
// Fixing it properly means giving the scheduler distinct statuses (see the follow-up
// issue); until then this asymmetry is deliberate.
func TestGetScoreScannerBadGatewayStaysUnscorable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"error":"scan failed: repo not found"}`))
	}))
	defer ts.Close()

	f := &Firewall{
		cfg:           Config{ScorecardMode: "local", ScannerURL: ts.URL},
		scannerClient: &http.Client{Timeout: 5 * time.Second},
	}
	_, err := f.getScore("github.com/x/y")
	if err == nil {
		t.Fatal("expected an error when the scan itself failed")
	}
	if errors.Is(err, errUpstreamUnavailable) {
		t.Error("a 502 'scan failed' must stay unscorable — retrying cannot help, and the " +
			"approval path is where an unscorable package belongs")
	}
}

// TestSchedulerStatusTaxonomy pins the whole 502-vs-503 split end to end (issue #69).
//
// The scheduler used to answer 502 for two OPPOSITE things — "we failed to launch"
// (ours) and "the scan ran and the repo could not be scored" (the package) — so the
// firewall could not classify them apart and had to pick one bug or the other. 502 is
// now reserved for the second meaning alone.
//
// This is a table rather than three separate tests because the VALUE is in the
// contrast: each row is only correct relative to the others, and a future change that
// collapses two statuses back together should fail here with the pairing visible.
func TestSchedulerStatusTaxonomy(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantTransi bool
		why        string
	}{
		{"at scan capacity", http.StatusServiceUnavailable, `{"error":"scheduler at scan capacity, retry"}`, true,
			"our capacity (#13) — a burst must not block good packages"},
		{"failed to launch scanner", http.StatusServiceUnavailable, `{"error":"failed to launch scanner: image not found"}`, true,
			"#69: the container never started, so we never reached the repo"},
		{"scan returned no result", http.StatusServiceUnavailable, `{"error":"scan returned no result"}`, true,
			"#69: our container broke its own contract; not a finding about the repo"},
		{"failed to prepare scan", http.StatusInternalServerError, `{"error":"failed to prepare scan"}`, true,
			"!94: nothing was ever asked about the repo"},

		{"scan failed", http.StatusBadGateway, `{"error":"scan failed: repo not found"}`, false,
			"the scan RAN and could not score the repo — retrying cannot help, the approval queue is where it belongs"},
		{"scan timed out", http.StatusGatewayTimeout, `{"error":"scan timed out"}`, false,
			"#69: deliberately non-transient — a repo that always exceeds the deadline must reach approval, not 503 forever"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(c.status)
				w.Write([]byte(c.body))
			}))
			defer ts.Close()

			f := &Firewall{
				cfg:           Config{ScorecardMode: "local", ScannerURL: ts.URL},
				scannerClient: &http.Client{Timeout: 5 * time.Second},
			}
			_, err := f.getScore("github.com/x/y")
			if err == nil {
				t.Fatalf("status %d: expected an error", c.status)
			}
			if got := errors.Is(err, errUpstreamUnavailable); got != c.wantTransi {
				t.Errorf("status %d: transient=%v, want %v\n  %s\n  err: %v",
					c.status, got, c.wantTransi, c.why, err)
			}
		})
	}
}

// TestSchedulerReasonIsCarried pins that a transient failure names WHICH of the three
// 503 causes it was. This used to hard-code "at scan capacity", which silently
// mislabelled the other two once #69 gave them the same status — an operator debugging
// a stuck pull would have been sent looking at concurrency limits that were fine.
func TestSchedulerReasonIsCarried(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"failed to launch scanner: image not found"}`))
	}))
	defer ts.Close()

	f := &Firewall{
		cfg:           Config{ScorecardMode: "local", ScannerURL: ts.URL},
		scannerClient: &http.Client{Timeout: 5 * time.Second},
	}
	_, err := f.getScore("github.com/x/y")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "failed to launch scanner") {
		t.Errorf("error = %v, want it to carry the scheduler's own reason, not a hard-coded one", err)
	}
	if strings.Contains(err.Error(), "at scan capacity") {
		t.Errorf("error = %v, still reports the hard-coded capacity reason for a LAUNCH failure", err)
	}
}
