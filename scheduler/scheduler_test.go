package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeLauncher stands in for a real container launch. Instead of starting a
// container, it (optionally, after a delay) POSTs a canned scanReport to the sink
// URL the scheduler handed it — exactly what a real run-once container does — so
// the whole /scan -> launch -> /results -> /scan-response flow is exercised
// without Docker.
type fakeLauncher struct {
	report    scanReport
	delay     time.Duration
	launchErr error
	silent    bool // if true, never POST back (to exercise the timeout path)
}

func (f *fakeLauncher) Launch(ctx context.Context, repo, sinkURL string) error {
	if f.launchErr != nil {
		return f.launchErr
	}
	if f.silent {
		return nil
	}
	go func() {
		if f.delay > 0 {
			time.Sleep(f.delay)
		}
		body, _ := json.Marshal(f.report)
		http.Post(sinkURL, "application/json", bytes.NewReader(body))
	}()
	return nil
}

// newTestScheduler starts the scheduler behind an httptest server and points its
// selfURL at that server, so a launched "container" can POST results back to it.
// Uncapped (0) by default so these tests exercise the request path only; the
// concurrency cap has its own tests in capacity_test.go.
func newTestScheduler(t *testing.T, l launcher, timeout time.Duration) (*scheduler, *httptest.Server) {
	t.Helper()
	return newTestSchedulerCapped(t, l, timeout, 0)
}

func newTestSchedulerCapped(t *testing.T, l launcher, timeout time.Duration, maxConcurrent int) (*scheduler, *httptest.Server) {
	t.Helper()
	s := newScheduler(l, "http://placeholder", timeout, maxConcurrent)
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	s.selfURL = ts.URL // now containers report to the real test server
	return s, ts
}

func postScan(t *testing.T, ts *httptest.Server, repo string) *http.Response {
	t.Helper()
	resp, err := http.Post(ts.URL+"/scan", "application/json", strings.NewReader(`{"repo":"`+repo+`"}`))
	if err != nil {
		t.Fatalf("POST /scan: %v", err)
	}
	return resp
}

func TestScanReturnsResult(t *testing.T) {
	report := scanReport{
		Repo:   "github.com/example/pkg",
		Result: &scanResult{Repo: "github.com/example/pkg", Score: 6.7},
	}
	_, ts := newTestScheduler(t, &fakeLauncher{report: report}, 5*time.Second)

	resp := postScan(t, ts, "github.com/example/pkg")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got scanResult
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Score != 6.7 || got.Repo != "github.com/example/pkg" {
		t.Errorf("result = %+v", got)
	}
}

// A delayed report (a slow scan) still gets correlated and returned.
func TestScanWaitsForDelayedResult(t *testing.T) {
	report := scanReport{Repo: "r", Result: &scanResult{Repo: "r", Score: 9.1}}
	_, ts := newTestScheduler(t, &fakeLauncher{report: report, delay: 150 * time.Millisecond}, 5*time.Second)

	resp := postScan(t, ts, "r")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// A reported scan failure comes back as non-2xx, so the firewall treats it as
// unscorable (same contract as the old scanner's non-200).
func TestScanFailureIsNon2xx(t *testing.T) {
	report := scanReport{Repo: "r", Error: "repo not found"}
	_, ts := newTestScheduler(t, &fakeLauncher{report: report}, 5*time.Second)

	resp := postScan(t, ts, "r")
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("expected non-200 for a failed scan, got 200")
	}
}

// A report carrying NEITHER a result nor an error violates the container's
// contract (buggy or truncated POST). It must be treated as a failed scan
// (non-2xx), not nil-panic on report.Result when reading the score.
func TestScanMalformedReportIsNon2xx(t *testing.T) {
	report := scanReport{Repo: "r"} // no Result, no Error
	_, ts := newTestScheduler(t, &fakeLauncher{report: report}, 5*time.Second)

	resp := postScan(t, ts, "r")
	defer resp.Body.Close()
	// 503, not 502 (issue #69). The point of this test is "non-2xx rather than a
	// nil-panic", and the STATUS now also carries a meaning: a report with neither a
	// result nor an error violates our container's contract, so it is our plumbing
	// failing, not a finding about the repo. 502 is reserved for "the scan ran and the
	// repo could not be scored", which is the only case here the firewall may treat as
	// unscorable.
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 for a malformed report", resp.StatusCode)
	}
}

// A launch that never starts is surfaced immediately, not after a timeout.
func TestScanLaunchErrorIsSurfaced(t *testing.T) {
	_, ts := newTestScheduler(t, &fakeLauncher{launchErr: errors.New("image not found")}, 5*time.Second)

	start := time.Now()
	resp := postScan(t, ts, "r")
	defer resp.Body.Close()
	// 503, not 502 (issue #69). This test's subject is the IMMEDIACY below; the status
	// was incidental until 502 acquired a specific meaning. A container that never
	// started means we never reached the repo — our infrastructure, so the firewall
	// must see it as transient and retry, not record an unscorable verdict and (under
	// the default byte gate) serve the artifact anyway.
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if time.Since(start) > time.Second {
		t.Errorf("launch error took %s — should be immediate", time.Since(start))
	}
}

// If no result ever arrives, /scan times out rather than hanging forever.
func TestScanTimesOut(t *testing.T) {
	_, ts := newTestScheduler(t, &fakeLauncher{silent: true}, 100*time.Millisecond)

	resp := postScan(t, ts, "r")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", resp.StatusCode)
	}
}

// A result POSTed for an unknown/expired id is accepted and dropped (no panic,
// no error to the container) — a late report from a container whose scan already
// timed out must not make that container exit non-zero. The token is well-formed
// here; there is simply no waiter left to hand the report to.
func TestResultForUnknownIDIsAccepted(t *testing.T) {
	_, ts := newTestScheduler(t, &fakeLauncher{silent: true}, time.Second)

	resp, err := http.Post(ts.URL+"/results/does-not-exist/some-token", "application/json", strings.NewReader(`{"repo":"r","result":{"score":5}}`))
	if err != nil {
		t.Fatalf("POST /results: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestScanRejectsBadInput(t *testing.T) {
	_, ts := newTestScheduler(t, &fakeLauncher{silent: true}, time.Second)

	cases := []struct {
		method, path, body string
		want               int
	}{
		{http.MethodGet, "/scan", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "/scan", "not json", http.StatusBadRequest},
		{http.MethodPost, "/scan", `{"repo":""}`, http.StatusBadRequest},
		{http.MethodGet, "/nope", "", http.StatusNotFound},
	}
	for _, c := range cases {
		req, _ := http.NewRequest(c.method, ts.URL+c.path, strings.NewReader(c.body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", c.method, c.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s %s -> %d, want %d", c.method, c.path, resp.StatusCode, c.want)
		}
	}
}

func TestHealthz(t *testing.T) {
	_, ts := newTestScheduler(t, &fakeLauncher{silent: true}, time.Second)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz = %d", resp.StatusCode)
	}
}
