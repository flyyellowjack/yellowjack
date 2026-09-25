package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// D39: the borrow-a-score cross-check (D33) extended to LOCAL/async mode.
//
// These tests deliberately assert SIDE EFFECTS, not just the Decision. In local mode
// the Decision alone cannot tell the two failure shapes apart: "refused to score the
// borrowed repo" and "launched a scan on the borrowed repo and blocked for some other
// reason" can both surface as a block. What actually closes the hole is that NO scan
// is launched against a borrowed repo — so every test here checks the scanner call
// log, the in-flight slot, and the durable L2 store.

// recordingScanner stands in for the scheduler+scanner stack, recording the repo of
// every /scan request so a test can assert WHICH repo was scanned.
type recordingScanner struct {
	mu     sync.Mutex
	repos  []string
	score  float64
	status int // non-200 to simulate a failed scan (0 = 200 OK)
	// hold, when non-nil, blocks each scan until the test closes it. Set it to keep a
	// scan in flight for the whole duration of a concurrency test; without it a mock
	// scan can finish DURING the burst, which legitimately lets a late pull read the
	// warm cache and be allowed. Read-only once the server is started.
	hold chan struct{}
}

func (s *recordingScanner) start(t *testing.T) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Repo string `json:"repo"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.mu.Lock()
		s.repos = append(s.repos, req.Repo)
		s.mu.Unlock()
		if s.hold != nil {
			<-s.hold // keep this scan in flight until the test releases it
		}
		if s.status != 0 {
			w.WriteHeader(s.status)
			return
		}
		_ = json.NewEncoder(w).Encode(scannerResponse{Score: s.score})
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

// scanned returns a copy of the repos the scanner was asked to scan, in order.
func (s *recordingScanner) scanned() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.repos...)
}

func startDepsDev(t *testing.T, m *mockDepsDev) string {
	t.Helper()
	ts := m.server()
	t.Cleanup(ts.Close)
	return ts.URL
}

func startApproval(t *testing.T) (*fakeApproval, string) {
	t.Helper()
	appr := newFakeApproval()
	ts := httptest.NewServer(appr)
	t.Cleanup(ts.Close)
	return appr, ts.URL
}

// newLocalVerifyFirewall builds a LOCAL-mode firewall wired to a real npm registry
// mock (so LookupRepo actually reads the publisher-controlled `repository` field —
// the input the attack abuses), a deps.dev mock, the recording scanner, and the
// approval fake (the durable L2 store).
//
// It deliberately does NOT pre-seed repoCache the way newAsyncFirewall does: the
// cross-check runs only on a repoCache MISS, so pre-seeding would skip the very code
// under test.
func newLocalVerifyFirewall(t *testing.T, registryURL, depsDevURL, scannerURL, approvalURL string, verify bool) *Firewall {
	t.Helper()
	f, err := NewFirewall(Config{
		Ecosystem:                "npm",
		UpstreamRegistry:         registryURL,
		ScorecardMode:            "local",
		ScannerURL:               scannerURL,
		ApprovalURL:              approvalURL,
		ScoreThreshold:           5.0,
		UnscorablePolicy:         "block",
		VerifyRepo:               verify,
		ScoreCacheTTL:            time.Minute,
		PendingRetryAfterSeconds: 60,
		// A REAL backoff TTL, so the D25 breaker assertions below are not vacuous: with
		// the default 0 the cache's mark() is a no-op and "backoff is not armed" would
		// pass no matter what the code did.
		RateLimitBackoffTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	f.depsDevBase = depsDevURL // NewFirewall points at the public API; a test must not
	return f
}

// TestLocalBorrowedRepoLaunchesNoScan is the core D39 assertion: in local mode a
// package claiming someone else's repo is refused BEFORE a scan is launched.
func TestLocalBorrowedRepoLaunchesNoScan(t *testing.T) {
	const borrowed = "github.com/lodash/lodash"
	registry := npmRegistry(t, "git+https://github.com/lodash/lodash.git") // the borrowed claim
	dd := &mockDepsDev{sourceRepoID: "github.com/evil/evil-pkg"}           // deps.dev's own record
	scanner := &recordingScanner{score: 9.0}                               // would score HIGH if ever asked
	appr, apprURL := startApproval(t)
	f := newLocalVerifyFirewall(t, registry, startDepsDev(t, dd), scanner.start(t), apprURL, true)

	d := f.Evaluate("evil-pkg")

	if d.Allowed {
		t.Fatalf("borrowed-score package was ALLOWED in local mode — the hole is open (reason: %s)", d.Reason)
	}
	// A mismatch is a durable verdict, not a "not computed yet" quarantine: it must
	// NOT come back as the retryable Pending 503, or the client would just retry into
	// the same wall forever.
	if d.Pending {
		t.Errorf("a mismatch must be terminal, not Pending: %s", d.Reason)
	}
	if d.HasScore {
		t.Errorf("a mismatch must not carry the borrowed score; got %v", d.Score)
	}
	if !strings.Contains(d.Reason, "does not match") {
		t.Errorf("reason should explain the mismatch, got %q", d.Reason)
	}

	// The side effect that actually closes the hole. inflight is the DETERMINISTIC
	// check: begin() is called synchronously inside scoreFor before the goroutine is
	// spawned, so if a scan had been launched the slot would already be claimed by the
	// time Evaluate returned.
	if f.inflight.isRunning(borrowed) {
		t.Error("in-flight scan slot was claimed for the borrowed repo — a scan was launched")
	}
	if got := scanner.scanned(); len(got) != 0 {
		t.Fatalf("NO scan may be launched on a borrowed repo; scanner was asked for %v", got)
	}
	if _, ok := appr.get(borrowed); ok {
		t.Error("an L2 row was written for the borrowed repo")
	}
	// Not cached, so a later human correction/approval takes effect immediately.
	if repo, cached := f.repos.get("evil-pkg"); cached {
		t.Errorf("a mismatch must not be cached in repoCache, got %q", repo)
	}
}

// TestLocalVerifiedRepoIsScannedThenAllowed: the honest case still works end to end —
// cold pull quarantines as Pending, the background scan runs against the verified
// repo, and the next pull allows on the real score.
func TestLocalVerifiedRepoIsScannedThenAllowed(t *testing.T) {
	const repo = "github.com/lodash/lodash"
	registry := npmRegistry(t, "git+https://github.com/lodash/lodash.git")
	dd := &mockDepsDev{sourceRepoID: repo} // deps.dev agrees
	scanner := &recordingScanner{score: 8.0}
	appr, apprURL := startApproval(t)
	f := newLocalVerifyFirewall(t, registry, startDepsDev(t, dd), scanner.start(t), apprURL, true)

	if d := f.Evaluate("lodash"); !d.Pending {
		t.Fatalf("cold pull of a verified package should be Pending, got %+v", d)
	}
	waitScanDone(t, f, repo)

	if got := scanner.scanned(); len(got) != 1 || got[0] != repo {
		t.Fatalf("scanned %v, want exactly [%s]", got, repo)
	}
	if s, ok := appr.get(repo); !ok || s == nil || *s != 8.0 {
		t.Fatalf("L2 score = (%v, ok=%v), want 8.0", s, ok)
	}
	if d := f.Evaluate("lodash"); !d.Allowed {
		t.Fatalf("warm pull of a verified, high-scoring package should be allowed (reason: %s)", d.Reason)
	}
}

// TestLocalAdoptsDepsDevRepoForScan: the package declares NO repo but deps.dev knows
// one. Local mode must scan deps.dev's repo — proving adoption reaches the scanner,
// not just the Decision. Pre-D39 this package was simply unscorable in local mode.
func TestLocalAdoptsDepsDevRepoForScan(t *testing.T) {
	const adopted = "github.com/adopted/pkg"
	registry := npmRegistry(t, "") // declares no repository URL
	dd := &mockDepsDev{sourceRepoID: adopted}
	scanner := &recordingScanner{score: 7.5}
	appr, apprURL := startApproval(t)
	f := newLocalVerifyFirewall(t, registry, startDepsDev(t, dd), scanner.start(t), apprURL, true)

	if d := f.Evaluate("quiet-pkg"); !d.Pending {
		t.Fatalf("adopted repo should be scanned (Pending on the cold pull), got %+v", d)
	}
	waitScanDone(t, f, adopted)

	if got := scanner.scanned(); len(got) != 1 || got[0] != adopted {
		t.Fatalf("scanned %v, want exactly [%s] (deps.dev's repo, adopted)", got, adopted)
	}
	if s, ok := appr.get(adopted); !ok || s == nil || *s != 7.5 {
		t.Fatalf("L2 score for the adopted repo = (%v, ok=%v), want 7.5", s, ok)
	}
	if d := f.Evaluate("quiet-pkg"); !d.Allowed {
		t.Fatalf("adopted repo scored 7.5 >= 5.0, should be allowed (reason: %s)", d.Reason)
	}
}

// TestLocalDepsDevDownQuarantinesWithoutScanning is the LOCAL-mode half of D36's
// transient rule. Our own dependency being down is not a verdict, so the pull comes
// back as a retryable 503 — but under the fail-closed default it is Unavailable
// ("can't verify right now"), NOT Pending, and NO scan is launched: we will not scan,
// cache, or later serve a score for a repo we couldn't tie to the package.
//
// This is a deliberate D36 tightening of D39's original degrade-open behaviour (which
// fell back to the self-declared repo and scanned it). The cost is that cold pulls
// stall behind 503s while deps.dev is down; the operator's lever is the policy below.
func TestLocalDepsDevDownQuarantinesWithoutScanning(t *testing.T) {
	const repo = "github.com/lodash/lodash"
	registry := npmRegistry(t, "git+https://github.com/lodash/lodash.git")
	dd := &mockDepsDev{sourceRepoID: repo, status: http.StatusServiceUnavailable}
	scanner := &recordingScanner{score: 8.0}
	_, apprURL := startApproval(t)
	f := newLocalVerifyFirewall(t, registry, startDepsDev(t, dd), scanner.start(t), apprURL, true)

	d := f.Evaluate("lodash")
	if !d.Unavailable {
		t.Fatalf("a deps.dev outage must be the retryable Unavailable 503, got %+v", d)
	}
	if d.Allowed {
		t.Error("must not allow on an unverified repo")
	}
	if d.Pending {
		t.Error("Pending means 'a scan is running'; no scan was launched, so this must not be Pending")
	}
	if got := scanner.scanned(); len(got) != 0 {
		t.Errorf("scanned %v, want nothing — verification gates the scan (D36)", got)
	}
}

// TestLocalDepsDevDownOpenWithVisibilityStillScans is the negative control, and keeps
// D39's original contract available: with the policy chosen explicitly, a deps.dev
// outage falls back to the self-declared repo, the background scan runs, and the async
// taxonomy is Pending ("answer not computed yet") — not Unavailable.
func TestLocalDepsDevDownOpenWithVisibilityStillScans(t *testing.T) {
	const repo = "github.com/lodash/lodash"
	registry := npmRegistry(t, "git+https://github.com/lodash/lodash.git")
	dd := &mockDepsDev{sourceRepoID: repo, status: http.StatusServiceUnavailable}
	scanner := &recordingScanner{score: 8.0}
	appr, apprURL := startApproval(t)
	f := newLocalVerifyFirewall(t, registry, startDepsDev(t, dd), scanner.start(t), apprURL, true)
	f.cfg.UnverifiedPolicy = unverifiedPolicyOpen

	d := f.Evaluate("lodash")
	if !d.Pending {
		t.Fatalf("open-with-visibility: a deps.dev outage must not break local scanning; want Pending, got %+v", d)
	}
	if d.Unavailable {
		t.Error("a degraded-open verification must not be reported as Unavailable (D17/D18 taxonomy)")
	}
	waitScanDone(t, f, repo)

	if got := scanner.scanned(); len(got) != 1 || got[0] != repo {
		t.Fatalf("scanned %v, want exactly [%s] (self-declared fallback)", got, repo)
	}
	if s, ok := appr.get(repo); !ok || s == nil || *s != 8.0 {
		t.Fatalf("L2 score = (%v, ok=%v), want 8.0", s, ok)
	}
}

// TestLocalDepsDev429BackoffInteraction pins the D25 interaction under both policies —
// the reason it differs is worth stating, because D39 originally forbade arming the
// backoff here outright:
//   - closed: the pull is already a 503 and no scan is launched, so arming the breaker
//     costs nothing and stops the next pull re-probing a source that is throttling us.
//   - open-with-visibility: verification degrades open and the scan DOES run, so arming
//     the breaker would short-circuit the next pull to a 503 and stall local scanning on
//     a throttle from a source that isn't even scoring the package. Still forbidden.
func TestLocalDepsDev429BackoffInteraction(t *testing.T) {
	const repo = "github.com/lodash/lodash"

	t.Run("closed_arms_backoff", func(t *testing.T) {
		registry := npmRegistry(t, "git+https://github.com/lodash/lodash.git")
		dd := &mockDepsDev{sourceRepoID: repo, status: http.StatusTooManyRequests}
		scanner := &recordingScanner{score: 8.0}
		_, apprURL := startApproval(t)
		f := newLocalVerifyFirewall(t, registry, startDepsDev(t, dd), scanner.start(t), apprURL, true)

		if d := f.Evaluate("lodash"); !d.Unavailable {
			t.Fatalf("a deps.dev 429 must be a retryable 503, got %+v", d)
		}
		if !f.backoff.active("lodash") {
			t.Error("want the D25 breaker armed so retries don't amplify the 429")
		}
		if got := scanner.scanned(); len(got) != 0 {
			t.Errorf("scanned %v, want nothing", got)
		}
	})

	t.Run("open_with_visibility_does_not_arm_backoff", func(t *testing.T) {
		registry := npmRegistry(t, "git+https://github.com/lodash/lodash.git")
		dd := &mockDepsDev{sourceRepoID: repo, status: http.StatusTooManyRequests}
		scanner := &recordingScanner{score: 8.0}
		_, apprURL := startApproval(t)
		f := newLocalVerifyFirewall(t, registry, startDepsDev(t, dd), scanner.start(t), apprURL, true)
		f.cfg.UnverifiedPolicy = unverifiedPolicyOpen

		d := f.Evaluate("lodash")
		if !d.Pending {
			t.Fatalf("a deps.dev 429 during verification must still scan; want Pending, got %+v", d)
		}
		if f.backoff.active("lodash") {
			t.Error("verification 429 must NOT arm the D25 package backoff — that would stall local scanning")
		}
		waitScanDone(t, f, repo)
		if got := scanner.scanned(); len(got) != 1 || got[0] != repo {
			t.Fatalf("scanned %v, want exactly [%s]", got, repo)
		}
	})
}

// TestLocalVerifiesOncePerRepoCacheTTL is the fan-out guard: the cross-check hangs off
// the repoCache MISS branch, so repeated pulls of the same package inside the TTL must
// not re-probe deps.dev. Without this, every package in a cold npm install tree would
// add deps.dev round-trips to the hot path on EVERY pull, not just the first.
func TestLocalVerifiesOncePerRepoCacheTTL(t *testing.T) {
	const repo = "github.com/lodash/lodash"
	registry := npmRegistry(t, "git+https://github.com/lodash/lodash.git")
	dd := &mockDepsDev{sourceRepoID: repo}
	scanner := &recordingScanner{score: 8.0}
	_, apprURL := startApproval(t)
	f := newLocalVerifyFirewall(t, registry, startDepsDev(t, dd), scanner.start(t), apprURL, true)

	f.Evaluate("lodash") // cold: verifies (GetPackage + GetVersion), launches the scan
	waitScanDone(t, f, repo)
	afterFirst := dd.hits.Load()
	if afterFirst != 2 {
		t.Fatalf("deps.dev hits after the first pull = %d, want 2 (GetPackage + GetVersion)", afterFirst)
	}

	for i := 0; i < 5; i++ {
		if d := f.Evaluate("lodash"); !d.Allowed {
			t.Fatalf("pull %d should be allowed from cache (reason: %s)", i, d.Reason)
		}
	}
	if got := dd.hits.Load(); got != afterFirst {
		t.Errorf("deps.dev hits = %d after 5 more pulls, want still %d (verify once per repoCache TTL)", got, afterFirst)
	}
}

// TestLocalConcurrentColdPullsStillScanOnce: the cross-check sits upstream of the
// check-then-begin window and must not disturb it. Concurrent cold pulls may each run
// the (idempotent) verification, but exactly ONE background scan may result — D18's
// dedup guarantee is untouched by the added deps.dev round-trips.
//
// The scan is held open for the whole burst (like TestAsyncDedup). That is not just
// tidiness: verification adds two deps.dev round-trips to each pull, so with a fast
// mock scan the FIRST pull's scan can complete while later pulls are still verifying —
// and those late pulls then read the warm cache and are legitimately ALLOWED with a
// real score. Correct behavior (a late sibling in one install gets a verdict instead of
// a 503), but it makes "every pull is quarantined" a timing coin-flip rather than an
// invariant. Holding the scan makes the overlap real and the assertion honest.
func TestLocalConcurrentColdPullsStillScanOnce(t *testing.T) {
	const repo = "github.com/lodash/lodash"
	registry := npmRegistry(t, "git+https://github.com/lodash/lodash.git")
	dd := &mockDepsDev{sourceRepoID: repo}
	scanner := &recordingScanner{score: 8.0, hold: make(chan struct{})}
	_, apprURL := startApproval(t)
	f := newLocalVerifyFirewall(t, registry, startDepsDev(t, dd), scanner.start(t), apprURL, true)

	var wg sync.WaitGroup
	for i := 0; i < 9; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d := f.Evaluate("lodash"); !d.Pending {
				t.Errorf("cold pull overlapping an in-flight scan must be Pending, got: %+v", d)
			}
		}()
	}
	wg.Wait()
	close(scanner.hold) // let the single scan finish
	waitScanDone(t, f, repo)

	if got := scanner.scanned(); len(got) != 1 {
		t.Fatalf("scanned %v, want exactly 1 scan despite 9 concurrent cold pulls", got)
	}
}

// TestLocalVerifyDisabledScansBorrowedRepo is the escape hatch AND the control for
// this whole file: with FW_VERIFY_REPO=false the SAME borrowed package is scanned on
// the borrowed repo and allowed on its score — proving the check is what closes the
// hole, and that the flag really gates local mode too.
func TestLocalVerifyDisabledScansBorrowedRepo(t *testing.T) {
	const borrowed = "github.com/lodash/lodash"
	registry := npmRegistry(t, "git+https://github.com/lodash/lodash.git")
	dd := &mockDepsDev{sourceRepoID: "github.com/evil/evil-pkg"}
	scanner := &recordingScanner{score: 9.0}
	_, apprURL := startApproval(t)
	f := newLocalVerifyFirewall(t, registry, startDepsDev(t, dd), scanner.start(t), apprURL, false)

	if d := f.Evaluate("evil-pkg"); !d.Pending {
		t.Fatalf("with verification off, the cold pull should just be Pending, got %+v", d)
	}
	waitScanDone(t, f, borrowed)

	if got := scanner.scanned(); len(got) != 1 || got[0] != borrowed {
		t.Fatalf("scanned %v, want [%s] — with the flag off we score whatever is claimed", got, borrowed)
	}
	if got := dd.hits.Load(); got != 0 {
		t.Errorf("FW_VERIFY_REPO=false must not call deps.dev at all, got %d hits", got)
	}
	if d := f.Evaluate("evil-pkg"); !d.Allowed {
		t.Fatalf("pre-D39 behavior: the borrowed score should allow it (reason: %s)", d.Reason)
	}
}

// TestRepoVerificationEnabled pins the gate matrix, including that stub mode stays
// offline (a deps.dev call there would defeat its purpose and hang offline tests).
func TestRepoVerificationEnabled(t *testing.T) {
	cases := []struct {
		mode   string
		verify bool
		want   bool
	}{
		{"api", true, true},
		{"local", true, true}, // D39: the change this file exists for
		{"stub", true, false}, // offline by design
		{"api", false, false},
		{"local", false, false},
		{"stub", false, false},
		{"future-mode", true, false}, // allowlist: a new mode must opt in explicitly
	}
	for _, c := range cases {
		f := &Firewall{cfg: Config{ScorecardMode: c.mode, VerifyRepo: c.verify}}
		if got := f.repoVerificationEnabled(); got != c.want {
			t.Errorf("mode=%q verify=%v: enabled = %v, want %v", c.mode, c.verify, got, c.want)
		}
	}
}

// TestOCIUnverifiedFailsClosedWithoutCallingDepsDev: deps.dev has no package index for
// OCI/Docker images, so an image's self-declared repo can never be cross-checked. Under
// the closed default that is a TERMINAL fail-closed refusal (D48, #33) -- the inverse of
// the degrade-open this test used to pin -- and under open-with-visibility it is the old
// fallback: keep the self-declared repo, logged unverified. Either way, no round-trip is
// spent discovering the gap. An image that declares NO repo is not a claim and falls
// through to the unscorable path unchanged.
func TestOCIUnverifiedFailsClosedWithoutCallingDepsDev(t *testing.T) {
	const self = "github.com/acme/app"
	for _, tc := range []struct {
		name, policy, selfRepo string
		wantDone               bool
	}{
		{"closed (default): the claim is refused", "", self, true},
		{"open-with-visibility: the claim is kept, logged", unverifiedPolicyOpen, self, false},
		{"no claim: nothing to refuse", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dd := &mockDepsDev{sourceRepoID: "github.com/someone/else"}
			f := &Firewall{
				cfg:         Config{Ecosystem: "oci", ScorecardMode: "local", VerifyRepo: true, UnscorablePolicy: "block", UnverifiedPolicy: tc.policy},
				client:      &http.Client{Timeout: 5 * time.Second},
				depsDevBase: startDepsDev(t, dd),
			}
			if !f.repoVerificationEnabled() {
				t.Fatal("local mode + VerifyRepo should enable verification regardless of ecosystem")
			}
			repo, d, done := f.verifyRepo("ghcr.io/acme/app", tc.selfRepo)
			if done != tc.wantDone {
				t.Fatalf("done = %v, want %v (decision %+v)", done, tc.wantDone, d)
			}
			if done {
				if d.Allowed || d.Deny != denyUnverified {
					t.Errorf("decision = %+v, want a denyUnverified refusal", d)
				}
				for _, want := range []string{"cannot be verified", "no oci index", self} {
					if !strings.Contains(d.Reason, want) {
						t.Errorf("reason %q lacks %q", d.Reason, want)
					}
				}
				if d.Rule == "" || d.Source == "" {
					t.Errorf("the refusal names no rule/source: %+v", d)
				}
			} else if repo != tc.selfRepo {
				t.Errorf("repo = %q, want the self-declared %q", repo, tc.selfRepo)
			}
			if got := dd.hits.Load(); got != 0 {
				t.Errorf("OCI must not call deps.dev at all, got %d hits", got)
			}
		})
	}
}
