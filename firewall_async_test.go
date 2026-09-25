package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeApproval is an in-memory stand-in for the approval service's L2 score cache
// (/v1/scores) plus the decisions endpoint the unscorable path consults. A repo
// present in the map is a "row"; a nil score is the negative marker (score:null);
// absence is a 404 (cold, never scanned). Each row also carries an updatedAt so the
// L2 freshness window (issue #12) can be exercised: a real PUT stamps "now", and
// tests can plant an aged row with seed().
type fakeScoreRow struct {
	score     *float64
	updatedAt time.Time
}

type fakeApproval struct {
	mu     sync.Mutex
	scores map[string]fakeScoreRow
}

func newFakeApproval() *fakeApproval {
	return &fakeApproval{scores: map[string]fakeScoreRow{}}
}

func (a *fakeApproval) get(repo string) (*float64, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	row, ok := a.scores[repo]
	return row.score, ok
}

// seed plants an L2 row with an explicit write time, so a test can make a score
// arbitrarily old (older than FW_SCORE_L2_TTL) to trigger the stale path.
func (a *fakeApproval) seed(repo string, score *float64, updatedAt time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.scores[repo] = fakeScoreRow{score: score, updatedAt: updatedAt}
}

func (a *fakeApproval) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/scores":
		switch r.Method {
		case http.MethodGet:
			repo := r.URL.Query().Get("repo")
			a.mu.Lock()
			row, ok := a.scores[repo]
			a.mu.Unlock()
			if !ok {
				http.Error(w, "cold", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(scoreRecord{Repo: repo, Score: row.score, UpdatedAt: row.updatedAt})
		case http.MethodPut:
			var rec scoreRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			a.mu.Lock()
			// Mimic the real store: a write stamps the row's time to "now".
			a.scores[rec.Repo] = fakeScoreRow{score: rec.Score, updatedAt: time.Now().UTC()}
			a.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}
	case "/v1/decisions":
		// No human rulings in these tests: GET is always "not found", PUT (record
		// pending) is accepted. This keeps the unscorable path exercising the real
		// applyHumanRuling -> policy fallback.
		if r.Method == http.MethodGet {
			http.Error(w, "no decision", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}

// newAsyncFirewall builds a local-mode firewall wired to a scheduler fake and an
// approval fake, with the package's repo pre-seeded so the test doesn't need a fake
// npm registry (LookupRepo is skipped on a repoCache hit).
func newAsyncFirewall(t *testing.T, scannerURL, approvalURL, pkg, repo string) *Firewall {
	t.Helper()
	f, err := NewFirewall(Config{
		Ecosystem:                "npm",
		UpstreamRegistry:         "http://unused.invalid",
		ScorecardMode:            "local",
		ScannerURL:               scannerURL,
		ApprovalURL:              approvalURL,
		ScoreThreshold:           5.0,
		UnscorablePolicy:         "block",
		ScoreCacheTTL:            time.Minute,
		PendingRetryAfterSeconds: 60,
	})
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	f.repos.put(pkg, repo)
	return f
}

// waitScanDone blocks until the background scan for repo has finished (the inflight
// slot is released), or fails the test. Works even for the transient case, which
// writes nothing durable to poll on.
func waitScanDone(t *testing.T, f *Firewall, repo string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !f.inflight.isRunning(repo) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("background scan did not finish in time")
}

// TestAsyncColdThenCached is the core async flow: the first (cold) pull returns
// verdict-pending WITHOUT blocking on the scan, a single background scan runs, its
// result lands in L2, and the next pull decides for real.
func TestAsyncColdThenCached(t *testing.T) {
	var scans int32
	sched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&scans, 1)
		_ = json.NewEncoder(w).Encode(scannerResponse{Score: 8.0})
	}))
	defer sched.Close()
	appr := newFakeApproval()
	apprSrv := httptest.NewServer(appr)
	defer apprSrv.Close()

	repo := "github.com/lodash/lodash"
	f := newAsyncFirewall(t, sched.URL, apprSrv.URL, "lodash", repo)

	// Cold pull: quarantined as pending, not blocked.
	if d := f.Evaluate("lodash"); !d.Pending {
		t.Fatalf("cold pull: Pending=%v, want true (%s)", d.Pending, d.Reason)
	}
	waitScanDone(t, f, repo)

	// The background scan ran once and wrote the score to L2.
	if got := atomic.LoadInt32(&scans); got != 1 {
		t.Fatalf("scans = %d, want 1", got)
	}
	if s, ok := appr.get(repo); !ok || s == nil || *s != 8.0 {
		t.Fatalf("L2 score = (%v, ok=%v), want 8.0", s, ok)
	}

	// Next pull: score is cached (score 8.0 >= 5.0) -> allowed, no new scan.
	if d := f.Evaluate("lodash"); !d.Allowed {
		t.Fatalf("warm pull: Allowed=%v, want true (%s)", d.Allowed, d.Reason)
	}
	if got := atomic.LoadInt32(&scans); got != 1 {
		t.Fatalf("scans after warm pull = %d, want still 1", got)
	}
}

// TestAsyncDedup: many concurrent cold pulls of the same repo trigger exactly ONE
// background scan (D12's 9x fan-out killed by the in-flight guard).
func TestAsyncDedup(t *testing.T) {
	var scans int32
	release := make(chan struct{})
	sched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&scans, 1)
		<-release // hold the scan open so all concurrent pulls overlap it
		_ = json.NewEncoder(w).Encode(scannerResponse{Score: 8.0})
	}))
	defer sched.Close()
	apprSrv := httptest.NewServer(newFakeApproval())
	defer apprSrv.Close()

	repo := "github.com/lodash/lodash"
	f := newAsyncFirewall(t, sched.URL, apprSrv.URL, "lodash", repo)

	var wg sync.WaitGroup
	for i := 0; i < 9; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d := f.Evaluate("lodash"); !d.Pending {
				t.Errorf("concurrent cold pull: want Pending, got %s", d.Reason)
			}
		}()
	}
	wg.Wait()
	close(release)
	waitScanDone(t, f, repo)

	if got := atomic.LoadInt32(&scans); got != 1 {
		t.Fatalf("scans = %d, want exactly 1 despite 9 concurrent pulls", got)
	}
}

// TestAsyncL2CrossReplica: a SECOND firewall (fresh, empty L1 — a different replica)
// reads the durable L2 score written by the first and decides instantly, never
// scanning. Proves the result lives in the durable store, not just in-memory.
func TestAsyncL2CrossReplica(t *testing.T) {
	var scans int32
	sched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&scans, 1)
		_ = json.NewEncoder(w).Encode(scannerResponse{Score: 8.0})
	}))
	defer sched.Close()
	apprSrv := httptest.NewServer(newFakeApproval())
	defer apprSrv.Close()

	repo := "github.com/lodash/lodash"
	f1 := newAsyncFirewall(t, sched.URL, apprSrv.URL, "lodash", repo)
	f1.Evaluate("lodash") // cold -> scan -> L2
	waitScanDone(t, f1, repo)

	// Replica 2: empty L1, same approval service.
	f2 := newAsyncFirewall(t, sched.URL, apprSrv.URL, "lodash", repo)
	if d := f2.Evaluate("lodash"); !d.Allowed {
		t.Fatalf("replica 2: Allowed=%v, want true from L2 (%s)", d.Allowed, d.Reason)
	}
	if got := atomic.LoadInt32(&scans); got != 1 {
		t.Fatalf("scans = %d, want 1 — replica 2 must use L2, not re-scan", got)
	}
}

// TestAsyncUnscorableRecordsNegative: when the scanner cannot score the repo, the
// firewall persists the negative marker and the NEXT pull routes to the unscorable
// policy (block, fail-closed) WITHOUT launching another scan.
func TestAsyncUnscorableRecordsNegative(t *testing.T) {
	var scans int32
	sched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&scans, 1)
		http.Error(w, "scan failed: repo not found", http.StatusBadGateway)
	}))
	defer sched.Close()
	appr := newFakeApproval()
	apprSrv := httptest.NewServer(appr)
	defer apprSrv.Close()

	repo := "github.com/ghost/ghost"
	f := newAsyncFirewall(t, sched.URL, apprSrv.URL, "ghost", repo)

	if d := f.Evaluate("ghost"); !d.Pending {
		t.Fatalf("cold pull: want Pending, got %s", d.Reason)
	}
	waitScanDone(t, f, repo)

	// Negative marker recorded (row present, score nil).
	if s, ok := appr.get(repo); !ok || s != nil {
		t.Fatalf("L2 = (%v, ok=%v), want present negative marker (nil)", s, ok)
	}

	// Next pull: reads the marker -> unscorable -> blocked (fail-closed), no re-scan.
	d := f.Evaluate("ghost")
	if d.Allowed {
		t.Fatalf("warm pull of unscorable: Allowed=true, want blocked under fail-closed (%s)", d.Reason)
	}
	if got := atomic.LoadInt32(&scans); got != 1 {
		t.Fatalf("scans = %d, want 1 — negative marker must prevent re-scanning", got)
	}
}

// TestAsyncTransientDoesNotPin: a transient scanner outage records NOTHING durable,
// so the repo stays cold and a later pull re-triggers a scan (rather than pinning a
// failure forever).
func TestAsyncTransientDoesNotPin(t *testing.T) {
	// A scanner that abruptly closes the connection -> the HTTP client sees a
	// transport error -> errUpstreamUnavailable (transient), not a non-200.
	sched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.(net.Conn).Close()
			}
		}
	}))
	defer sched.Close()
	appr := newFakeApproval()
	apprSrv := httptest.NewServer(appr)
	defer apprSrv.Close()

	repo := "github.com/lodash/lodash"
	f := newAsyncFirewall(t, sched.URL, apprSrv.URL, "lodash", repo)

	if d := f.Evaluate("lodash"); !d.Pending {
		t.Fatalf("cold pull: want Pending, got %s", d.Reason)
	}
	waitScanDone(t, f, repo)

	// Nothing durable written: still cold, and the in-flight slot is free so a
	// later pull can retry.
	if _, ok := appr.get(repo); ok {
		t.Fatal("transient failure must not write a durable marker")
	}
	if f.inflight.begin(repo) != true {
		t.Fatal("in-flight slot should be free after a transient failure (re-scannable)")
	}
}

// TestAsyncProxyPendingIsForbidden asserts the proxy maps a Pending decision to a
// 403 whose explanation says a scan is still running, and that the configurable wait
// survives in the reason text (D102).
//
// It previously asserted a 503 carrying the longer Retry-After. That header was the
// mechanism that made D18's async model self-healing: npm re-requested after the
// scan finished, and the cold pull succeeded on its own. Under a 403 nothing retries,
// so this is the exact spot where D18's client contract is given up — the project accepted
// that cost and named the replacement (a real way to request a scan) as the follow-up.
func TestAsyncProxyPendingIsForbidden(t *testing.T) {
	sched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond) // keep the scan in flight during the request
		_ = json.NewEncoder(w).Encode(scannerResponse{Score: 8.0})
	}))
	defer sched.Close()
	apprSrv := httptest.NewServer(newFakeApproval())
	defer apprSrv.Close()

	repo := "github.com/lodash/lodash"
	f := newAsyncFirewall(t, sched.URL, apprSrv.URL, "lodash", repo)
	p := newProxyServer(f.cfg, f)

	req := httptest.NewRequest(http.MethodGet, "http://firewall.local/lodash", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, pendingErrMsg) {
		t.Fatalf("body = %s, want the PENDING explanation %q — a cold pull must not be "+
			"reported as a verdict about the package", body, pendingErrMsg)
	}
	// The configured wait used to ride on Retry-After. With that gone, the reason text
	// is the only channel left to it, so a developer can still tell how long to wait.
	if !strings.Contains(body, "60") {
		t.Fatalf("body = %s, want the configured pending wait (60s) in the reason text", body)
	}
	waitScanDone(t, f, repo)
}

func f64p(v float64) *float64 { return &v }

// TestL2Stale checks the freshness predicate in isolation: it depends only on
// cfg.ScoreL2TTL and the row's write time, so a bare Firewall value exercises every
// branch without any HTTP wiring.
func TestL2Stale(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name      string
		ttl       time.Duration
		updatedAt time.Time
		want      bool
	}{
		{"ttl disabled ignores age", 0, now.Add(-100 * time.Hour), false},
		{"zero timestamp is never stale", time.Hour, time.Time{}, false},
		{"older than ttl is stale", time.Hour, now.Add(-2 * time.Hour), true},
		{"younger than ttl is fresh", time.Hour, now.Add(-30 * time.Minute), false},
		{"just written is fresh", time.Hour, now, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &Firewall{cfg: Config{ScoreL2TTL: tc.ttl}}
			if got := f.l2Stale(tc.updatedAt); got != tc.want {
				t.Fatalf("l2Stale(ttl=%s, age from %v) = %v, want %v", tc.ttl, tc.updatedAt, got, tc.want)
			}
		})
	}
}

// TestAsyncL2FreshNoReScan: with a freshness window set, a recently-written L2 score
// is served straight from L2 — allowed, no scan launched (the common case must not
// regress into needless re-scanning).
func TestAsyncL2FreshNoReScan(t *testing.T) {
	var scans int32
	sched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&scans, 1)
		_ = json.NewEncoder(w).Encode(scannerResponse{Score: 8.0})
	}))
	defer sched.Close()
	appr := newFakeApproval()
	apprSrv := httptest.NewServer(appr)
	defer apprSrv.Close()

	repo := "github.com/lodash/lodash"
	appr.seed(repo, f64p(8.0), time.Now()) // fresh, passing score
	f := newAsyncFirewall(t, sched.URL, apprSrv.URL, "lodash", repo)
	f.cfg.ScoreL2TTL = time.Hour

	if d := f.Evaluate("lodash"); !d.Allowed {
		t.Fatalf("fresh L2: Allowed=%v, want true (%s)", d.Allowed, d.Reason)
	}
	if got := atomic.LoadInt32(&scans); got != 0 {
		t.Fatalf("scans = %d, want 0 — a fresh L2 score must not re-scan", got)
	}
}

// TestAsyncL2StaleReScans is the core of issue #12: an L2 score older than the
// freshness window is NOT served. The pull is quarantined as pending, a single
// background re-scan runs and refreshes L2, and only then does the fresh score
// decide. The stale row here would PASS if served — proving stale trust is refused.
func TestAsyncL2StaleReScans(t *testing.T) {
	var scans int32
	sched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&scans, 1)
		_ = json.NewEncoder(w).Encode(scannerResponse{Score: 8.0})
	}))
	defer sched.Close()
	appr := newFakeApproval()
	apprSrv := httptest.NewServer(appr)
	defer apprSrv.Close()

	repo := "github.com/lodash/lodash"
	appr.seed(repo, f64p(8.0), time.Now().Add(-2*time.Hour)) // stale, would-pass score
	f := newAsyncFirewall(t, sched.URL, apprSrv.URL, "lodash", repo)
	f.cfg.ScoreL2TTL = time.Hour

	// Stale L2 => treated as cold => pending, NOT allowed off the old score.
	if d := f.Evaluate("lodash"); !d.Pending {
		t.Fatalf("stale L2: Pending=%v Allowed=%v, want pending re-scan (%s)", d.Pending, d.Allowed, d.Reason)
	}
	waitScanDone(t, f, repo)

	if got := atomic.LoadInt32(&scans); got != 1 {
		t.Fatalf("scans = %d, want 1 — a stale score must trigger exactly one re-scan", got)
	}
	// The re-scan refreshed L2, so the next pull decides on the fresh score.
	if d := f.Evaluate("lodash"); !d.Allowed {
		t.Fatalf("after re-scan: Allowed=%v, want true off the fresh score (%s)", d.Allowed, d.Reason)
	}
	if got := atomic.LoadInt32(&scans); got != 1 {
		t.Fatalf("scans after warm pull = %d, want still 1", got)
	}
}

// TestAsyncL2TTLZeroNeverStale: the default TTL of 0 preserves the pre-#12 behavior —
// even an ancient score is served without a re-scan (freshness is an explicit opt-in).
func TestAsyncL2TTLZeroNeverStale(t *testing.T) {
	var scans int32
	sched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&scans, 1)
		_ = json.NewEncoder(w).Encode(scannerResponse{Score: 8.0})
	}))
	defer sched.Close()
	appr := newFakeApproval()
	apprSrv := httptest.NewServer(appr)
	defer apprSrv.Close()

	repo := "github.com/lodash/lodash"
	appr.seed(repo, f64p(8.0), time.Now().Add(-100*24*time.Hour)) // 100 days old
	f := newAsyncFirewall(t, sched.URL, apprSrv.URL, "lodash", repo)
	// ScoreL2TTL left at its zero default: freshness disabled.

	if d := f.Evaluate("lodash"); !d.Allowed {
		t.Fatalf("ancient L2 with TTL=0: Allowed=%v, want true (%s)", d.Allowed, d.Reason)
	}
	if got := atomic.LoadInt32(&scans); got != 0 {
		t.Fatalf("scans = %d, want 0 — TTL=0 must never treat a score as stale", got)
	}
}

// TestAsyncL2StaleNegativeMarkerReScans: the freshness window applies to the negative
// (scanned-but-unscorable) marker too. A repo we once couldn't score may have become
// scorable, so an aged marker earns a re-scan rather than blocking forever.
func TestAsyncL2StaleNegativeMarkerReScans(t *testing.T) {
	var scans int32
	sched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&scans, 1)
		_ = json.NewEncoder(w).Encode(scannerResponse{Score: 8.0}) // now scorable
	}))
	defer sched.Close()
	appr := newFakeApproval()
	apprSrv := httptest.NewServer(appr)
	defer apprSrv.Close()

	repo := "github.com/ghost/ghost"
	appr.seed(repo, nil, time.Now().Add(-2*time.Hour)) // stale negative marker
	f := newAsyncFirewall(t, sched.URL, apprSrv.URL, "ghost", repo)
	f.cfg.ScoreL2TTL = time.Hour

	// Stale marker => cold => pending re-scan, NOT an immediate unscorable block.
	if d := f.Evaluate("ghost"); !d.Pending {
		t.Fatalf("stale negative marker: Pending=%v, want pending re-scan (%s)", d.Pending, d.Reason)
	}
	waitScanDone(t, f, repo)

	if got := atomic.LoadInt32(&scans); got != 1 {
		t.Fatalf("scans = %d, want 1", got)
	}
	if d := f.Evaluate("ghost"); !d.Allowed {
		t.Fatalf("after re-scan: Allowed=%v, want true (%s)", d.Allowed, d.Reason)
	}
}
