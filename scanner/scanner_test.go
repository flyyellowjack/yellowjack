package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeRunner returns canned output so the scan flow can be tested without the real
// scorecard binary, a network connection, or a GitHub token.
type fakeRunner struct {
	out []byte
	err error
}

func (f *fakeRunner) run(ctx context.Context, repo string) ([]byte, error) {
	return f.out, f.err
}

// A trimmed but realistic Scorecard JSON report, including a check that could not
// be evaluated (score -1) to make sure we pass that through rather than choke.
const sampleScorecardJSON = `{
  "date": "2026-07-12T00:00:00Z",
  "repo": {"name": "github.com/example/pkg", "commit": "abc123"},
  "score": 6.7,
  "checks": [
    {"name": "Maintained", "score": 10, "reason": "30 out of 30 commits maintained"},
    {"name": "Branch-Protection", "score": -1, "reason": "internal error"}
  ]
}`

func TestScanParsesScorecardOutput(t *testing.T) {
	got, err := scan(context.Background(), &fakeRunner{out: []byte(sampleScorecardJSON)}, "github.com/example/pkg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Score != 6.7 {
		t.Errorf("score = %v, want 6.7", got.Score)
	}
	if got.Repo != "github.com/example/pkg" || got.Commit != "abc123" {
		t.Errorf("repo/commit = %q/%q", got.Repo, got.Commit)
	}
	if len(got.Checks) != 2 {
		t.Fatalf("checks = %d, want 2", len(got.Checks))
	}
	if got.Checks[0].Name != "Maintained" || got.Checks[0].Score != 10 {
		t.Errorf("check[0] = %+v", got.Checks[0])
	}
	if got.Checks[1].Score != -1 {
		t.Errorf("unevaluated check score = %d, want -1", got.Checks[1].Score)
	}
}

func TestScanPropagatesRunnerError(t *testing.T) {
	_, err := scan(context.Background(), &fakeRunner{err: errors.New("scorecard: repo not found")}, "github.com/nope/nope")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected runner error to propagate, got %v", err)
	}
}

// runScan wraps a successful scan in a report with Result set and no Error.
func TestRunScanSuccess(t *testing.T) {
	rep := runScan(context.Background(), &fakeRunner{out: []byte(sampleScorecardJSON)}, "github.com/example/pkg")
	if rep.Error != "" {
		t.Fatalf("unexpected error in report: %s", rep.Error)
	}
	if rep.Result == nil || rep.Result.Score != 6.7 {
		t.Fatalf("result = %+v, want score 6.7", rep.Result)
	}
	if rep.Repo != "github.com/example/pkg" {
		t.Errorf("repo = %q", rep.Repo)
	}
}

// runScan turns a scan failure into a report with Error set (not a thrown error),
// so the caller can still deliver it to the sink.
func TestRunScanFailureIsReported(t *testing.T) {
	rep := runScan(context.Background(), &fakeRunner{err: errors.New("scorecard: repo not found")}, "github.com/nope/nope")
	if rep.Result != nil {
		t.Fatalf("expected no result on failure, got %+v", rep.Result)
	}
	if !strings.Contains(rep.Error, "not found") {
		t.Errorf("error = %q, want it to mention 'not found'", rep.Error)
	}
	if rep.Repo != "github.com/nope/nope" {
		t.Errorf("repo = %q", rep.Repo)
	}
}

// postReport delivers the JSON envelope to the sink; the sink receives exactly the
// report the container produced.
func TestPostReportDeliversToSink(t *testing.T) {
	var got scanReport
	var gotContentType string
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	sent := runScan(context.Background(), &fakeRunner{out: []byte(sampleScorecardJSON)}, "github.com/example/pkg")
	if err := postReport(context.Background(), sink.Client(), sink.URL, sent); err != nil {
		t.Fatalf("postReport failed: %v", err)
	}
	if gotContentType != "application/json" {
		t.Errorf("content-type = %q, want application/json", gotContentType)
	}
	if got.Repo != "github.com/example/pkg" || got.Result == nil || got.Result.Score != 6.7 {
		t.Errorf("sink received %+v", got)
	}
}

// A non-2xx sink response is surfaced as a delivery error.
func TestPostReportSurfacesSinkError(t *testing.T) {
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer sink.Close()

	err := postReport(context.Background(), sink.Client(), sink.URL, scanReport{Repo: "x"})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected a 500 delivery error, got %v", err)
	}
}

// A short deadline makes delivery fail rather than hang forever.
func TestPostReportRespectsContext(t *testing.T) {
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := postReport(ctx, sink.Client(), sink.URL, scanReport{Repo: "x"}); err == nil {
		t.Fatal("expected a context-deadline error, got nil")
	}
}
