package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This file is the end-to-end half of issue #16's verification: the unit tests in
// singleflight_test.go prove flightGroup coalesces; these prove the FIREWALL is
// actually wired to it on the npm/deps.dev hot path, which is where the
// thundering herd was.
//
// The scenario is a cold `npm install`: N requests for the same package land
// together (the metadata request plus every tarball request), all miss the L1
// caches because nothing is warm yet, and — before this fix — each made its own
// registry, verification, and score call. That is the burst that earns a 429.

// depsDevMock serves the three deps.dev endpoints the firewall uses, counting each
// separately so a test can tell "one score lookup" from "one verification".
type depsDevMock struct {
	scoreHits     atomic.Int32 // GET /v3/projects/{repo}                       (Scorecard score)
	verifyPkgHits atomic.Int32 // GET /v3/systems/npm/packages/{pkg}            (default version)
	verifyVerHits atomic.Int32 // GET /v3/systems/npm/packages/{pkg}/versions/… (source repo)

	// scoreFor returns the score to serve for a repo; nil means "8.0 for all".
	scoreFor func(repo string) float64
	// beforeScore runs before serving a score, so a test can hold the first score
	// lookup open while the rest of the herd arrives.
	beforeScore func(repo string)
}

func (m *depsDevMock) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		// Verification, step 2: the version's related projects (the source repo).
		if i := strings.Index(path, "/versions/"); i >= 0 {
			m.verifyVerHits.Add(1)
			pkg := strings.TrimPrefix(path[:i], "/v3/systems/npm/packages/")
			json.NewEncoder(w).Encode(map[string]any{
				"relatedProjects": []map[string]any{{
					"projectKey":   map[string]string{"id": "github.com/org/" + pkg},
					"relationType": "SOURCE_REPO",
				}},
			})
			return
		}
		// Verification, step 1: the package's default version.
		if strings.HasPrefix(path, "/v3/systems/") {
			m.verifyPkgHits.Add(1)
			json.NewEncoder(w).Encode(map[string]any{
				"versions": []map[string]any{
					{"versionKey": map[string]string{"version": "1.0.0"}, "isDefault": true},
				},
			})
			return
		}
		// Scoring.
		repo := strings.TrimPrefix(path, "/v3/projects/")
		if m.beforeScore != nil {
			m.beforeScore(repo)
		}
		m.scoreHits.Add(1)
		score := 8.0
		if m.scoreFor != nil {
			score = m.scoreFor(repo)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"scorecard": map[string]any{"overallScore": score},
		})
	})
}

// npmRegistryMock serves the npm "latest" manifest, declaring github.com/org/{pkg}
// as the package's source repo.
type npmRegistryMock struct {
	metaHits   atomic.Int32
	beforeMeta func(pkg string)
}

func (m *npmRegistryMock) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pkg := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/latest")
		if m.beforeMeta != nil {
			m.beforeMeta(pkg)
		}
		m.metaHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"repository": map[string]string{"url": "git+https://github.com/org/" + pkg + ".git"},
		})
	})
}

func newCoalesceFirewall(t *testing.T, registryURL, depsDevURL string) *Firewall {
	t.Helper()
	f, err := NewFirewall(Config{
		Ecosystem:        "npm",
		UpstreamRegistry: registryURL,
		ScorecardMode:    "api",
		VerifyRepo:       true, // exercise the deps.dev cross-check inside the repo flight
		ScoreThreshold:   5.0,
		UnscorablePolicy: "block",
		ScoreCacheTTL:    time.Minute,
	})
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	f.depsDevBase = depsDevURL
	return f
}

// TestEvaluateCoalescesColdLookups is the issue's acceptance test: N simultaneous
// evaluations of the SAME cold package must produce exactly one registry metadata
// call, one deps.dev verification pair, and one deps.dev score call — not N of each.
//
// It is deterministic rather than timing-based: each upstream handler holds the
// first (leader) call open until the other N-1 callers have provably attached to
// that flight (awaitWaiters reads the group's own waiter count). If the guard were
// broken, the extra callers would sail past into their own upstream calls and the
// counters would exceed 1 — the assertions fail loudly instead of hanging.
func TestEvaluateCoalescesColdLookups(t *testing.T) {
	const (
		pkg      = "left-pad"
		repo     = "github.com/org/left-pad"
		requests = 24
	)

	var f *Firewall // set below; the handlers close over it to read its flight groups

	registry := &npmRegistryMock{beforeMeta: func(string) {
		// Hold the repo lookup open until the whole herd is waiting on this flight.
		if !awaitWaiters(f.repoFlights, pkg, requests-1) {
			t.Errorf("repo flight: %d followers attached, want %d", f.repoFlights.waiters(pkg), requests-1)
		}
	}}
	regSrv := httptest.NewServer(registry.handler())
	defer regSrv.Close()

	dd := &depsDevMock{beforeScore: func(repo string) {
		// Same, one layer down: hold the score lookup open until the herd arrives.
		if !awaitWaiters(f.scoreFlights, repo, requests-1) {
			t.Errorf("score flight: %d followers attached, want %d", f.scoreFlights.waiters(repo), requests-1)
		}
	}}
	ddSrv := httptest.NewServer(dd.handler())
	defer ddSrv.Close()

	f = newCoalesceFirewall(t, regSrv.URL, ddSrv.URL)

	decisions := make([]Decision, requests)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			decisions[i] = f.Evaluate(pkg)
		}(i)
	}
	wg.Wait()

	// One call per upstream, for all 24 requests.
	if got := registry.metaHits.Load(); got != 1 {
		t.Errorf("registry metadata called %d times for %d concurrent requests, want 1", got, requests)
	}
	if got := dd.verifyPkgHits.Load(); got != 1 {
		t.Errorf("deps.dev GetPackage (verification) called %d times, want 1", got)
	}
	if got := dd.verifyVerHits.Load(); got != 1 {
		t.Errorf("deps.dev GetVersion (verification) called %d times, want 1", got)
	}
	if got := dd.scoreHits.Load(); got != 1 {
		t.Errorf("deps.dev score called %d times for %d concurrent requests, want 1", got, requests)
	}

	// Coalescing must not change the verdict any single request would have gotten.
	for i, d := range decisions {
		if !d.Allowed || !d.HasScore || d.Score != 8.0 {
			t.Errorf("request %d: got %+v, want allowed with score 8.0", i, d)
		}
	}

	// And the caches are warm afterwards, so a later request adds no upstream calls.
	if d := f.Evaluate(pkg); !d.Allowed {
		t.Errorf("post-herd request: got %+v, want allowed", d)
	}
	if got := dd.scoreHits.Load(); got != 1 {
		t.Errorf("score called %d times after a warm-cache request, want still 1", got)
	}
	if _, ok := f.repos.get(pkg); !ok {
		t.Error("repo cache was not populated by the coalesced lookup")
	}
	if _, ok := f.cache.get(repo); !ok {
		t.Error("score cache was not populated by the coalesced lookup")
	}
}

// TestEvaluateDoesNotCoalesceDistinctPackages is the negative control for the test
// above. A guard that collapsed everything into ONE flight regardless of key would
// pass "exactly 1 upstream call" while serving every package the first package's
// score — a catastrophic gate failure (one allowed package would allow the whole
// tree). Here 8 distinct packages resolve concurrently and must each get their own
// lookup AND their own verdict: even-numbered ones score 9.0 (allowed), odd ones
// 1.0 (blocked below the 5.0 threshold).
func TestEvaluateDoesNotCoalesceDistinctPackages(t *testing.T) {
	const packages = 8

	scoreForRepo := func(repo string) float64 {
		if strings.HasSuffix(repo, "0") || strings.HasSuffix(repo, "2") ||
			strings.HasSuffix(repo, "4") || strings.HasSuffix(repo, "6") {
			return 9.0
		}
		return 1.0
	}

	registry := &npmRegistryMock{}
	regSrv := httptest.NewServer(registry.handler())
	defer regSrv.Close()

	// Every score lookup blocks until all 8 are in flight together, so the calls
	// genuinely overlap — the condition under which a same-key guard coalesces.
	var inFlight sync.WaitGroup
	inFlight.Add(packages)
	release := make(chan struct{})
	dd := &depsDevMock{
		scoreFor: scoreForRepo,
		beforeScore: func(string) {
			inFlight.Done()
			<-release
		},
	}
	ddSrv := httptest.NewServer(dd.handler())
	defer ddSrv.Close()

	f := newCoalesceFirewall(t, regSrv.URL, ddSrv.URL)

	go func() { inFlight.Wait(); close(release) }()

	decisions := make([]Decision, packages)
	var wg sync.WaitGroup
	for i := 0; i < packages; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			decisions[i] = f.Evaluate(fmt.Sprintf("pkg%d", i))
		}(i)
	}
	wg.Wait()

	if got := registry.metaHits.Load(); got != packages {
		t.Errorf("registry metadata called %d times for %d distinct packages, want %d", got, packages, packages)
	}
	if got := dd.scoreHits.Load(); got != packages {
		t.Errorf("deps.dev score called %d times for %d distinct repos, want %d", got, packages, packages)
	}
	for i, d := range decisions {
		wantAllowed := scoreForRepo(fmt.Sprintf("github.com/org/pkg%d", i)) >= 5.0
		if d.Allowed != wantAllowed {
			t.Errorf("pkg%d: allowed = %v, want %v (%+v) — verdicts crossed between packages",
				i, d.Allowed, wantAllowed, d)
		}
	}
}
