package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConcurrentEvaluateStress fans out many concurrent Evaluate() calls across
// the SAME and DIFFERENT packages in local (async) mode, so the race detector has
// real overlap to inspect on every piece of shared, mutable firewall state:
//   - the L1 score cache (scoreCache) get/put,
//   - the repoCache reads,
//   - the inflightScans begin/done dedup set,
//   - and the background-scan goroutines writing L1 + the durable L2 concurrently.
//
// It is deterministic: a scheduler fake returns a fixed score, an approval fake is
// the in-memory L2, no network. The assertions are light on purpose — the point is
// to give `go test -race` the fan-out; the detector is the real oracle here. We do
// still assert the two invariants the concurrency is meant to guarantee: at most
// ONE scan per repo (dedup held under load) and every repo ending up allowed.
func TestConcurrentEvaluateStress(t *testing.T) {
	const (
		numRepos   = 6
		goroutines = 240 // 40 pulls per repo, all overlapping
	)

	// scans[repo] counts how many times the scheduler was actually asked to scan
	// that repo. Under the in-flight dedup it must never exceed 1, even though many
	// goroutines pull each repo cold at the same instant.
	var (
		scansMu sync.Mutex
		scans   = map[string]int{}
	)
	sched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Repo string `json:"repo"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		scansMu.Lock()
		scans[req.Repo]++
		scansMu.Unlock()
		_ = json.NewEncoder(w).Encode(scannerResponse{Score: 8.0})
	}))
	defer sched.Close()

	appr := newFakeApproval()
	apprSrv := httptest.NewServer(appr)
	defer apprSrv.Close()

	f, err := NewFirewall(Config{
		Ecosystem:                "npm",
		UpstreamRegistry:         "http://unused.invalid",
		ScorecardMode:            "local",
		ScannerURL:               sched.URL,
		ApprovalURL:              apprSrv.URL,
		ScoreThreshold:           5.0,
		UnscorablePolicy:         "block",
		ScoreCacheTTL:            time.Minute,
		PendingRetryAfterSeconds: 60,
	})
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}

	pkgs := make([]string, numRepos)
	repos := make([]string, numRepos)
	for i := 0; i < numRepos; i++ {
		pkgs[i] = fmt.Sprintf("pkg%d", i)
		repos[i] = fmt.Sprintf("github.com/org/pkg%d", i)
		f.repos.put(pkgs[i], repos[i]) // skip the (unwired) npm registry lookup
	}

	// pendings counts how many pulls were quarantined as Pending — expected to be
	// high on the cold burst, but we only need it to prove the pulls really ran.
	var pendings int32
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := f.Evaluate(pkgs[i%numRepos])
			if d.Pending {
				atomic.AddInt32(&pendings, 1)
			}
		}(i)
	}
	wg.Wait()

	// Let every background scan finish so L1/L2 are fully written before we assert.
	for _, repo := range repos {
		waitScanDone(t, f, repo)
	}

	// Invariant 1: the in-flight guard held under load — at most one scan per repo.
	scansMu.Lock()
	for _, repo := range repos {
		if scans[repo] > 1 {
			t.Errorf("repo %s scanned %d times, want at most 1 (dedup broke under load)", repo, scans[repo])
		}
	}
	scansMu.Unlock()

	// Invariant 2: after the scans land, every package resolves to a real allow
	// verdict from the cached score (8.0 >= 5.0) — no lingering pending/blocked.
	for i := 0; i < numRepos; i++ {
		if d := f.Evaluate(pkgs[i]); !d.Allowed {
			t.Errorf("post-scan pull of %s: Allowed=false, want true (%s)", pkgs[i], d.Reason)
		}
	}
}

// TestConcurrentEvaluateUnscorableStress is the negative-marker twin of the test
// above. The scanner FAILS to score every repo, so each scan records a durable L2
// negative marker instead of an L1 score. That marker lives only in L2, so the
// dedup double-check must re-read L2 (not just L1) after winning the in-flight
// slot — otherwise a pull whose cache check raced ahead of the marker write would
// re-scan an already-decided unscorable repo. We assert the same at-most-one-scan
// invariant holds on this path under the same 240-goroutine burst.
func TestConcurrentEvaluateUnscorableStress(t *testing.T) {
	const (
		numRepos   = 6
		goroutines = 240
	)

	var (
		scansMu sync.Mutex
		scans   = map[string]int{}
	)
	// A non-transient scanner failure (502) -> the firewall records the negative
	// marker, exactly like TestAsyncUnscorableRecordsNegative.
	sched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Repo string `json:"repo"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		scansMu.Lock()
		scans[req.Repo]++
		scansMu.Unlock()
		http.Error(w, "scan failed: repo not found", http.StatusBadGateway)
	}))
	defer sched.Close()

	appr := newFakeApproval()
	apprSrv := httptest.NewServer(appr)
	defer apprSrv.Close()

	f, err := NewFirewall(Config{
		Ecosystem:                "npm",
		UpstreamRegistry:         "http://unused.invalid",
		ScorecardMode:            "local",
		ScannerURL:               sched.URL,
		ApprovalURL:              apprSrv.URL,
		ScoreThreshold:           5.0,
		UnscorablePolicy:         "block",
		ScoreCacheTTL:            time.Minute,
		PendingRetryAfterSeconds: 60,
	})
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}

	pkgs := make([]string, numRepos)
	repos := make([]string, numRepos)
	for i := 0; i < numRepos; i++ {
		pkgs[i] = fmt.Sprintf("pkg%d", i)
		repos[i] = fmt.Sprintf("github.com/org/pkg%d", i)
		f.repos.put(pkgs[i], repos[i])
	}

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f.Evaluate(pkgs[i%numRepos])
		}(i)
	}
	wg.Wait()

	for _, repo := range repos {
		waitScanDone(t, f, repo)
	}

	// Invariant 1: even though the result is a durable L2 marker (never an L1
	// score), the in-flight guard + L2 double-check held each repo to one scan.
	scansMu.Lock()
	for _, repo := range repos {
		if scans[repo] > 1 {
			t.Errorf("repo %s scanned %d times, want at most 1 (negative-marker dedup broke under load)", repo, scans[repo])
		}
	}
	scansMu.Unlock()

	// Invariant 2: every package now resolves to the unscorable verdict from the
	// cached marker (fail-closed => blocked), with no lingering pending.
	for i := 0; i < numRepos; i++ {
		if d := f.Evaluate(pkgs[i]); d.Allowed || d.Pending {
			t.Errorf("post-scan pull of %s: Allowed=%v Pending=%v, want blocked-unscorable (%s)", pkgs[i], d.Allowed, d.Pending, d.Reason)
		}
	}
}
