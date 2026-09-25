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

// mockDepsDev stands in for the deps.dev API. It serves the two endpoints
// verifyRepo uses — GetPackage (version list) and GetVersion (relatedProjects) —
// for a single package, returning the given SOURCE_REPO project id. status lets a
// test simulate deps.dev being unreachable (5xx) or not knowing the package (404).
type mockDepsDev struct {
	sourceRepoID string // projectKey.id served as the SOURCE_REPO relation ("" = none)
	extra        []relatedProject
	status       int // non-200 to return for BOTH endpoints (0 means 200/normal)
	// hits counts requests received (to assert caching/short-circuit). Atomic because
	// the local-mode tests (D39) run a background scan concurrently with the assertion.
	hits atomic.Int64
}

type relatedProject struct {
	ProjectKey struct {
		ID string `json:"id"`
	} `json:"projectKey"`
	RelationType       string `json:"relationType"`
	RelationProvenance string `json:"relationProvenance"`
}

func rel(id, relType string) relatedProject {
	var rp relatedProject
	rp.ProjectKey.ID = id
	rp.RelationType = relType
	rp.RelationProvenance = "UNVERIFIED_METADATA"
	return rp
}

func (m *mockDepsDev) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.hits.Add(1)
		if m.status != 0 {
			w.WriteHeader(m.status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/versions/") {
			var projects []relatedProject
			projects = append(projects, rel("github.com/example/issues", "ISSUE_TRACKER"))
			if m.sourceRepoID != "" {
				projects = append(projects, rel(m.sourceRepoID, "SOURCE_REPO"))
			}
			projects = append(projects, m.extra...)
			json.NewEncoder(w).Encode(map[string]any{"relatedProjects": projects})
			return
		}
		// GetPackage: a two-version list with the second marked default.
		json.NewEncoder(w).Encode(map[string]any{
			"versions": []map[string]any{
				{"versionKey": map[string]string{"version": "0.9.0"}, "isDefault": false},
				{"versionKey": map[string]string{"version": "1.0.0"}, "isDefault": true},
			},
		})
	}))
}

// newVerifyFirewall builds a minimal api-mode Firewall pointed at the mock, with
// UnscorablePolicy=block so a mismatch's unscorable routing yields Allowed=false
// (no approval service wired, so applyHumanRuling is a no-op and policy decides).
func newVerifyFirewall(base string) *Firewall {
	return &Firewall{
		cfg:         Config{Ecosystem: "npm", ScorecardMode: "api", UnscorablePolicy: "block"},
		client:      &http.Client{Timeout: 5 * time.Second},
		depsDevBase: base,
	}
}

func TestVerifyRepoMatch(t *testing.T) {
	m := &mockDepsDev{sourceRepoID: "github.com/lodash/lodash"}
	ts := m.server()
	defer ts.Close()
	f := newVerifyFirewall(ts.URL)

	repo, _, done := f.verifyRepo("lodash", "github.com/lodash/lodash")
	if done {
		t.Fatal("match should not be terminal (done=true)")
	}
	if repo != "github.com/lodash/lodash" {
		t.Errorf("repo = %q, want the verified self-declared repo", repo)
	}
}

func TestVerifyRepoMatchCaseInsensitive(t *testing.T) {
	// deps.dev lower-cases; the package's metadata may not. A capitalization-only
	// difference must NOT be treated as a mismatch.
	m := &mockDepsDev{sourceRepoID: "github.com/lodash/lodash"}
	ts := m.server()
	defer ts.Close()
	f := newVerifyFirewall(ts.URL)

	_, _, done := f.verifyRepo("lodash", "github.com/Lodash/Lodash")
	if done {
		t.Error("case-only difference should verify as a match, not a mismatch")
	}
}

func TestVerifyRepoMismatchBlocks(t *testing.T) {
	// The attack: package claims lodash's repo, but deps.dev's record for it points
	// elsewhere. Must be terminal (done) and NOT allowed on the borrowed score.
	m := &mockDepsDev{sourceRepoID: "github.com/realauthor/realpkg"}
	ts := m.server()
	defer ts.Close()
	f := newVerifyFirewall(ts.URL)

	repo, dec, done := f.verifyRepo("evil-pkg", "github.com/lodash/lodash")
	if !done {
		t.Fatal("mismatch must be terminal (done=true) — must not fall through to scoring")
	}
	if repo != "" {
		t.Errorf("mismatch must not yield a repo to score, got %q", repo)
	}
	if dec.Allowed {
		t.Error("mismatch must not be allowed on the borrowed score")
	}
	if dec.HasScore {
		t.Error("mismatch decision should carry no score")
	}
}

// ─── D36: durable-unverified fails CLOSED, transient stays a retryable 503 ───
//
// The pair of behaviours these tests pin apart is the one thing D36 says must not be
// confused. Each has its own negative control under FW_UNVERIFIED_POLICY=
// open-with-visibility, which is also the regression test for D33's old behaviour.

func TestVerifyRepoUnverifiedIgnoresPermissiveUnscorablePolicy(t *testing.T) {
	// The gap Ruling A actually closes. Pre-D36 an unverified/mismatched repo was routed
	// to unscorable(), which defers to FW_UNSCORABLE_POLICY — so a deployment running
	// "allow" (fail-open / monitoring mode) got NO protection from the cross-check: the
	// borrowed repo was waved through with a log. The unverified posture is now its own
	// knob, so "I tolerate unscorable packages" no longer means "I tolerate forged
	// provenance claims".
	for _, tc := range []struct {
		name         string
		sourceRepoID string
		status       int
	}{
		{"mismatch", "github.com/realauthor/realpkg", 0},
		{"no_mapping", "", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &mockDepsDev{sourceRepoID: tc.sourceRepoID, status: tc.status}
			ts := m.server()
			defer ts.Close()
			f := newVerifyFirewall(ts.URL)
			f.cfg.UnscorablePolicy = "allow" // the permissive deployment

			_, dec, done := f.verifyRepo("evil-pkg", "github.com/lodash/lodash")
			if !done {
				t.Fatal("must still be terminal with a permissive unscorable policy")
			}
			if dec.Allowed {
				t.Errorf("FW_UNSCORABLE_POLICY=allow must NOT open the unverified path: %s", dec.Reason)
			}
		})
	}
}

func TestVerifyRepoMismatchOpenWithVisibilityStillRefusesToScoreClaim(t *testing.T) {
	// open-with-visibility restores D33's degrade-open for MISSING records only. A
	// definitive contradiction was never a degrade case — there is nothing absent to
	// degrade over — so it stays terminal, routed to the pre-D36 unscorable posture.
	m := &mockDepsDev{sourceRepoID: "github.com/realauthor/realpkg"}
	ts := m.server()
	defer ts.Close()
	f := newVerifyFirewall(ts.URL) // UnscorablePolicy=block
	f.cfg.UnverifiedPolicy = unverifiedPolicyOpen

	repo, dec, done := f.verifyRepo("evil-pkg", "github.com/lodash/lodash")
	if !done {
		t.Fatal("a mismatch must be terminal under BOTH policies — never scored on the borrowed repo")
	}
	if repo != "" || dec.Allowed {
		t.Errorf("mismatch must not yield a scorable repo or an allow, got repo=%q %+v", repo, dec)
	}
}

func TestVerifyRepoNoMappingFailsClosedByDefault(t *testing.T) {
	// deps.dev doesn't know the package (404) — DURABLE. This is the fresh-typosquat
	// profile (published minutes ago, no deps.dev record), and pre-D36 it inherited the
	// claimed repo's score for free. Default posture: refuse, don't score the claim.
	m := &mockDepsDev{status: http.StatusNotFound}
	ts := m.server()
	defer ts.Close()
	f := newVerifyFirewall(ts.URL)

	repo, dec, done := f.verifyRepo("brand-new-pkg", "github.com/some/repo")
	if !done {
		t.Fatal("a durably unverified repo must be terminal under the fail-closed default")
	}
	if repo != "" {
		t.Errorf("repo = %q, want no repo to score", repo)
	}
	if dec.Allowed {
		t.Error("durably unverified must not be allowed by default (D36 Ruling A)")
	}
	if dec.Unavailable || dec.Pending {
		t.Errorf("a DURABLE negative must be a verdict, not a retryable 503: %+v", dec)
	}
	if dec.HasScore {
		t.Error("an unverified decision must carry no score")
	}
}

func TestVerifyRepoNoMappingOpenWithVisibilityFallsBack(t *testing.T) {
	// Negative control + the operator escape hatch: with the policy set explicitly, the
	// pre-D36 degrade-open returns (proceed on the self-declared repo, logged).
	m := &mockDepsDev{status: http.StatusNotFound}
	ts := m.server()
	defer ts.Close()
	f := newVerifyFirewall(ts.URL)
	f.cfg.UnverifiedPolicy = unverifiedPolicyOpen

	repo, _, done := f.verifyRepo("brand-new-pkg", "github.com/some/repo")
	if done {
		t.Fatal("open-with-visibility should fall back, not be terminal")
	}
	if repo != "github.com/some/repo" {
		t.Errorf("repo = %q, want the self-declared repo on fallback", repo)
	}
}

func TestVerifyRepoOutageIsRetryableNotBlocked(t *testing.T) {
	// deps.dev is down (500) — TRANSIENT. Failing CLOSED here does NOT mean blocking:
	// we know nothing about this package, so the answer is "ask again shortly" (503),
	// never a verdict. Getting this wrong turns a deps.dev hiccup into a wall of 403s.
	m := &mockDepsDev{status: http.StatusInternalServerError}
	ts := m.server()
	defer ts.Close()
	f := newVerifyFirewall(ts.URL)

	_, dec, done := f.verifyRepo("lodash", "github.com/lodash/lodash")
	if !done {
		t.Fatal("under the fail-closed default we must not proceed on an unverified repo")
	}
	if !dec.Unavailable {
		t.Errorf("a deps.dev outage must be the retryable Unavailable 503, got %+v", dec)
	}
	if dec.Allowed {
		t.Error("must not allow on an unverified repo")
	}
	if !strings.Contains(dec.Reason, "verification") {
		// The client sees this string; it must not read as "the scanner is down".
		t.Errorf("reason should name repo verification as the thing unavailable, got %q", dec.Reason)
	}
}

func TestVerifyRepoOutageOpenWithVisibilityFallsBack(t *testing.T) {
	// Negative control: availability chosen deliberately — an outage disables the check
	// instead of quarantining the pull.
	m := &mockDepsDev{status: http.StatusInternalServerError}
	ts := m.server()
	defer ts.Close()
	f := newVerifyFirewall(ts.URL)
	f.cfg.UnverifiedPolicy = unverifiedPolicyOpen

	repo, _, done := f.verifyRepo("lodash", "github.com/lodash/lodash")
	if done {
		t.Fatal("open-with-visibility: a deps.dev outage must not stop the pull")
	}
	if repo != "github.com/lodash/lodash" {
		t.Errorf("repo = %q, want self-declared repo on deps.dev outage", repo)
	}
}

func TestVerifyRepo429IsRetryableAndArmsBackoff(t *testing.T) {
	// A 429 is transient like a 5xx, but additionally arms the D25 circuit breaker: the
	// verdict is already a 503, so the only effect is that the next pull of this package
	// doesn't re-probe a source that is actively throttling us.
	m := &mockDepsDev{status: http.StatusTooManyRequests}
	ts := m.server()
	defer ts.Close()
	f := newVerifyFirewall(ts.URL)
	f.backoff = newBackoffCache(time.Minute)

	_, dec, done := f.verifyRepo("lodash", "github.com/lodash/lodash")
	if !done || !dec.Unavailable {
		t.Fatalf("a deps.dev 429 must be a retryable 503, got done=%v %+v", done, dec)
	}
	if !strings.Contains(dec.Reason, "429") {
		t.Errorf("reason should name the rate limit distinctly (D25), got %q", dec.Reason)
	}
	if !f.backoff.active("lodash") {
		t.Error("a verification 429 should arm the D25 backoff so retries don't amplify it")
	}
}

func TestVerifyRepoNoRepoDeclaredAndNoMappingStaysUnscorable(t *testing.T) {
	// Neither side has a repo: nothing was claimed, so there is no borrowed score to
	// refuse. That is the ordinary messy-metadata UNSCORABLE case and must keep flowing
	// to FW_UNSCORABLE_POLICY (Evaluate's "no usable source repository" path) rather
	// than being escalated by the unverified posture.
	m := &mockDepsDev{status: http.StatusNotFound}
	ts := m.server()
	defer ts.Close()
	f := newVerifyFirewall(ts.URL)

	repo, _, done := f.verifyRepo("no-repo-pkg", "")
	if done {
		t.Fatal("a package with no declared repo should fall through to the unscorable path")
	}
	if repo != "" {
		t.Errorf("repo = %q, want empty", repo)
	}
}

func TestVerifyRepoAdoptsWhenSelfDeclaresNone(t *testing.T) {
	// Package declares no repo, but deps.dev knows one — adopt it so we can score a
	// package we'd otherwise treat as unscorable.
	m := &mockDepsDev{sourceRepoID: "github.com/known/repo"}
	ts := m.server()
	defer ts.Close()
	f := newVerifyFirewall(ts.URL)

	repo, _, done := f.verifyRepo("somepkg", "")
	if done {
		t.Fatal("adopting deps.dev's repo should not be terminal")
	}
	if repo != "github.com/known/repo" {
		t.Errorf("repo = %q, want deps.dev's source repo", repo)
	}
}

func TestVerifyRepoNonGitHubIsDurablyUnverified(t *testing.T) {
	// deps.dev's source repo is on GitLab, which our scorer can't use — so we end up
	// with NO usable record to check the GitHub claim against. Durable (retrying won't
	// grow GitLab support), so it fails closed with everything else in that branch.
	// Note this is strictly a tightening: deps.dev's record here arguably CONTRADICTS
	// the self-declared github.com claim, which pre-D36 was silently degraded open.
	m := &mockDepsDev{sourceRepoID: "gitlab.com/group/proj"}
	ts := m.server()
	defer ts.Close()
	f := newVerifyFirewall(ts.URL)

	_, dec, done := f.verifyRepo("pkg", "github.com/self/declared")
	if !done || dec.Allowed {
		t.Fatalf("an unusable deps.dev record leaves the claim unverified; want a refusal, got done=%v %+v", done, dec)
	}

	// Negative control: the operator can still take the old behaviour.
	f.cfg.UnverifiedPolicy = unverifiedPolicyOpen
	repo, _, done := f.verifyRepo("pkg", "github.com/self/declared")
	if done {
		t.Fatal("open-with-visibility: non-GitHub deps.dev repo should fall back, not block")
	}
	if repo != "github.com/self/declared" {
		t.Errorf("repo = %q, want self-declared repo when deps.dev repo is non-GitHub", repo)
	}
}

func TestVerifyRepoUnsupportedEcosystemFailsClosedThenFallsBackOnOverride(t *testing.T) {
	// OCI isn't indexed by deps.dev by package, so there is nothing to cross-check --
	// which D48 (#33) reads as "durably unverifiable", refused under the closed default
	// and kept (logged) only under the operator's override. No deps.dev call either way.
	m := &mockDepsDev{sourceRepoID: "github.com/x/y"}
	ts := m.server()
	defer ts.Close()
	f := newVerifyFirewall(ts.URL)
	f.cfg.Ecosystem = "oci"
	_, dec, done := f.verifyRepo("someimage", "github.com/self/declared")
	if !done || dec.Allowed || dec.Deny != denyUnverified {
		t.Fatalf("closed: an unindexed ecosystem must fail closed on a self-declared repo (D48), got done=%v %+v", done, dec)
	}
	if !strings.Contains(dec.Reason, "no oci index") {
		t.Errorf("the refusal does not say WHY it cannot verify: %q", dec.Reason)
	}
	f.cfg.UnverifiedPolicy = unverifiedPolicyOpen
	repo, _, done := f.verifyRepo("someimage", "github.com/self/declared")
	if done {
		t.Fatal("open-with-visibility: unsupported ecosystem should fall back, not block")
	}
	if repo != "github.com/self/declared" {
		t.Errorf("repo = %q, want self-declared repo", repo)
	}
	if got := m.hits.Load(); got != 0 {
		t.Errorf("OCI must not call deps.dev at all, got %d hits", got)
	}
}

func TestDepsDevSourceReposDedupes(t *testing.T) {
	// A version can list the same repo under multiple relations, or twice. We should
	// return each distinct source repo once.
	m := &mockDepsDev{sourceRepoID: "github.com/a/b"}
	m.extra = []relatedProject{rel("github.com/a/b", "SOURCE_REPO")}
	ts := m.server()
	defer ts.Close()
	f := newVerifyFirewall(ts.URL)

	repos, found, err := f.depsDevSourceRepos("npm", "pkg")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v, want found with no error", found, err)
	}
	if len(repos) != 1 || repos[0] != "github.com/a/b" {
		t.Errorf("repos = %v, want exactly [github.com/a/b]", repos)
	}
}

// ─── end-to-end Evaluate tests: the borrow-a-score hole is actually closed ───

// npmRegistry mocks registry.npmjs.org's /{pkg}/latest, returning the given
// self-declared repository URL — the publisher-controlled input the attack abuses.
func npmRegistry(t *testing.T, selfRepoURL string) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"repository": map[string]string{"type": "git", "url": selfRepoURL},
		})
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

// depsDevWithScore mocks deps.dev serving BOTH the package->version->SOURCE_REPO
// mapping (sourceRepoID) and the /v3/projects/{repo} scorecard endpoint, so a full
// api-mode Evaluate runs end to end. Any repo it's asked to score returns
// scoreForRepo — high enough to prove that a mismatch is refused on principle, not
// because the borrowed repo happened to score low.
func depsDevWithScore(t *testing.T, sourceRepoID string, scoreForRepo float64) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/v3/projects/"):
			json.NewEncoder(w).Encode(map[string]any{
				"scorecard": map[string]any{"overallScore": scoreForRepo},
			})
		case strings.Contains(r.URL.Path, "/versions/"):
			json.NewEncoder(w).Encode(map[string]any{
				"relatedProjects": []relatedProject{rel(sourceRepoID, "SOURCE_REPO")},
			})
		default: // GetPackage
			json.NewEncoder(w).Encode(map[string]any{
				"versions": []map[string]any{{"versionKey": map[string]string{"version": "1.0.0"}, "isDefault": true}},
			})
		}
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

// evalFirewall hand-builds an api-mode npm Firewall pointed at the two mocks (the
// public-base NewFirewall can't be redirected to a test deps.dev).
func evalFirewall(registryURL, depsDevURL string, verify bool) *Firewall {
	cfg := Config{
		Ecosystem:        "npm",
		UpstreamRegistry: registryURL,
		ScorecardMode:    "api",
		ScoreThreshold:   5.0,
		UnscorablePolicy: "block",
		VerifyRepo:       verify,
		ScoreCacheTTL:    time.Minute,
		// Must be set: a zero cap DISABLES the L1 caches (#61), which would
		// quietly turn every hit in this test into a miss.
		ScoreCacheMaxEntries: 1000,
	}
	return &Firewall{
		cfg:         cfg,
		client:      &http.Client{Timeout: 5 * time.Second},
		depsDevBase: depsDevURL,
		eco:         npmEcosystem{base: registryURL},
		cache:       newScoreCache(cfg.ScoreCacheTTL, cfg.ScoreCacheMaxEntries),
		repos:       newRepoCache(cfg.ScoreCacheTTL, cfg.ScoreCacheMaxEntries),
		backoff:     newBackoffCache(0),
	}
}

func TestEvaluateBorrowedScoreIsBlocked(t *testing.T) {
	// The attack: "evil-pkg" declares lodash's repo. deps.dev's record for evil-pkg
	// points at its REAL (different) repo. Even though lodash's repo would score 9.0,
	// the mismatch must block the borrow.
	registry := npmRegistry(t, "git+https://github.com/lodash/lodash.git")
	depsDev := depsDevWithScore(t, "github.com/evil/evil-pkg", 9.0)
	f := evalFirewall(registry, depsDev, true)

	d := f.Evaluate("evil-pkg")
	if d.Allowed {
		t.Fatalf("borrowed-score package was ALLOWED — the hole is open (reason: %s)", d.Reason)
	}
	if d.HasScore {
		t.Errorf("a mismatch must not carry the borrowed score; got score=%v", d.Score)
	}
	if !strings.Contains(d.Reason, "does not match") {
		t.Errorf("reason should explain the mismatch, got %q", d.Reason)
	}
}

func TestEvaluateVerifiedRepoIsAllowed(t *testing.T) {
	// The honest case: the self-declared repo agrees with deps.dev's record and scores
	// above threshold — allowed, unchanged from before D31.
	registry := npmRegistry(t, "git+https://github.com/lodash/lodash.git")
	depsDev := depsDevWithScore(t, "github.com/lodash/lodash", 9.0)
	f := evalFirewall(registry, depsDev, true)

	d := f.Evaluate("lodash")
	if !d.Allowed {
		t.Fatalf("verified, high-scoring package should be allowed (reason: %s)", d.Reason)
	}
	if d.Score != 9.0 {
		t.Errorf("score = %v, want 9.0", d.Score)
	}
}

func TestEvaluateVerifyDisabledRestoresOldBehavior(t *testing.T) {
	// Escape hatch: FW_VERIFY_REPO=false. The SAME borrowed-score package is now
	// allowed on lodash's score — proving both that the flag disables the check and
	// that the check is what closes the hole.
	registry := npmRegistry(t, "git+https://github.com/lodash/lodash.git")
	depsDev := depsDevWithScore(t, "github.com/evil/evil-pkg", 9.0)
	f := evalFirewall(registry, depsDev, false)

	d := f.Evaluate("evil-pkg")
	if !d.Allowed {
		t.Fatalf("with verification off, the pre-D31 behavior (score the claimed repo) should allow it (reason: %s)", d.Reason)
	}
}

// depsDevUnknownPackageWithScore mocks the D36 scenario end to end: deps.dev has NO
// record of the package (404 on the package/version endpoints — a package published
// minutes ago) but WILL happily serve a high score for the healthy repo the package
// claims. That combination is precisely what made the brand-new-package borrow free.
func depsDevUnknownPackageWithScore(t *testing.T, scoreForRepo float64) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v3/projects/") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"scorecard": map[string]any{"overallScore": scoreForRepo},
			})
			return
		}
		http.NotFound(w, r) // no package -> project mapping at all
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

func TestEvaluateBrandNewPackageBorrowIsBlocked(t *testing.T) {
	// The D36 attack, through the full Evaluate path: a package nobody has ingested yet
	// declares lodash's repo, and lodash's repo scores 9.0. Must NOT be allowed, and must
	// NOT be a retryable 503 (nothing here is transient — deps.dev answered).
	registry := npmRegistry(t, "git+https://github.com/lodash/lodash.git")
	depsDev := depsDevUnknownPackageWithScore(t, 9.0)
	f := evalFirewall(registry, depsDev, true)

	d := f.Evaluate("brand-new-evil")
	if d.Allowed {
		t.Fatalf("a brand-new package borrowing lodash's repo was ALLOWED (reason: %s)", d.Reason)
	}
	if d.Unavailable || d.Pending {
		t.Errorf("deps.dev answered — this is a verdict, not a retry: %+v", d)
	}
	if d.HasScore {
		t.Errorf("must not carry the borrowed 9.0; got score=%v", d.Score)
	}
	if !strings.Contains(d.Reason, "could not be verified") {
		t.Errorf("reason should explain the unverified linkage, got %q", d.Reason)
	}
}

func TestEvaluateBrandNewPackageOpenWithVisibilityAllowsIt(t *testing.T) {
	// The negative control that proves the hole was real AND that the escape hatch
	// works: the SAME package under open-with-visibility is allowed on the borrowed 9.0,
	// which is exactly what shipped before D36.
	registry := npmRegistry(t, "git+https://github.com/lodash/lodash.git")
	depsDev := depsDevUnknownPackageWithScore(t, 9.0)
	f := evalFirewall(registry, depsDev, true)
	f.cfg.UnverifiedPolicy = unverifiedPolicyOpen

	d := f.Evaluate("brand-new-evil")
	if !d.Allowed {
		t.Fatalf("open-with-visibility should restore the pre-D36 allow (reason: %s)", d.Reason)
	}
	if d.Score != 9.0 {
		t.Errorf("score = %v, want the (borrowed) 9.0 the old behaviour used", d.Score)
	}
}

// TestConcurrentUnverifiedBlocksEveryFollower covers the seam between D36 and issue
// #16's request coalescing, which landed on main while this branch was open. The
// verify step now runs INSIDE a repoFlights flight, so one leader's outcome is handed
// to every follower as a shared `repoResolution`. A durable refusal travels as
// `{repo: "", done: true, decision: <block>}` — and the failure mode worth a test is a
// follower that takes the empty repo but MISSES the done flag, falls through to
// scoring, and gets a verdict on the very repo we refused to trust. One leaked allow
// out of N is a security hole, so assert on all N.
//
// Deterministic, not timing-based: the registry handler holds the leader open until
// the whole herd has provably attached to the flight (awaitWaiters), so a broken guard
// fails loudly instead of racing.
func TestConcurrentUnverifiedBlocksEveryFollower(t *testing.T) {
	const (
		pkg      = "brand-new-evil"
		requests = 24
	)

	// runHerd fires `requests` simultaneous evaluations of one cold, durably
	// unverified package and returns every decision plus the registry hit count.
	runHerd := func(t *testing.T, policy string) ([]Decision, int32) {
		t.Helper()
		var f *Firewall // the handler closes over it to read the flight group
		var metaHits atomic.Int32

		regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Hold the leader open until the whole herd has provably attached, so a
			// broken guard fails loudly instead of racing.
			if !awaitWaiters(f.repoFlights, pkg, requests-1) {
				t.Errorf("repo flight: %d followers attached, want %d", f.repoFlights.waiters(pkg), requests-1)
			}
			metaHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"repository": map[string]string{"url": "git+https://github.com/lodash/lodash.git"},
			})
		}))
		defer regSrv.Close()

		// deps.dev knows nothing of the package (durably unverified) but would gladly
		// score the repo it claims — so a follower that fell through comes back ALLOWED
		// on 9.0, making a leak unmistakable rather than subtle.
		var err error
		f, err = NewFirewall(Config{
			Ecosystem:        "npm",
			UpstreamRegistry: regSrv.URL,
			ScorecardMode:    "api",
			VerifyRepo:       true,
			UnverifiedPolicy: policy,
			ScoreThreshold:   5.0,
			UnscorablePolicy: "block",
			ScoreCacheTTL:    time.Minute,
		})
		if err != nil {
			t.Fatalf("NewFirewall: %v", err)
		}
		f.depsDevBase = depsDevUnknownPackageWithScore(t, 9.0)

		decisions := make([]Decision, requests)
		var wg sync.WaitGroup
		for i := range decisions {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				decisions[i] = f.Evaluate(pkg)
			}(i)
		}
		wg.Wait()
		return decisions, metaHits.Load()
	}

	t.Run("closed_blocks_all_of_them", func(t *testing.T) {
		decisions, metaHits := runHerd(t, unverifiedPolicyClosed)
		for i, d := range decisions {
			if d.Allowed {
				t.Fatalf("request %d was ALLOWED on the unverified repo — coalescing leaked a verdict: %s", i, d.Reason)
			}
			if d.HasScore {
				t.Errorf("request %d carries a score (%v); a refused repo must never be scored", i, d.Score)
			}
			if d.Unavailable || d.Pending {
				t.Errorf("request %d is a retryable 503 (%+v); deps.dev answered, so this is durable", i, d)
			}
		}
		if metaHits != 1 {
			t.Errorf("registry metadata fetched %d times, want 1 (the herd should share one flight)", metaHits)
		}
	})

	t.Run("open_with_visibility_allows_all_of_them", func(t *testing.T) {
		// The negative control that keeps the assertions above honest: the identical
		// herd under the opt-out is allowed on the borrowed 9.0. So "all blocked" above
		// is genuinely the policy at work, not a mock that could never allow anything.
		decisions, metaHits := runHerd(t, unverifiedPolicyOpen)
		for i, d := range decisions {
			if !d.Allowed {
				t.Fatalf("request %d was blocked under %s: %s", i, unverifiedPolicyOpen, d.Reason)
			}
		}
		if metaHits != 1 {
			t.Errorf("registry metadata fetched %d times, want 1", metaHits)
		}
	})
}

// sanity: the mock's URL scheme matches what depsDevGet builds, so a bad path is a
// real 404 from the httptest mux, not a wrong-base artifact.
func TestDepsDevGetPathShape(t *testing.T) {
	var gotPaths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.EscapedPath()) // preserves %2F; r.URL.Path would decode it
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/versions/") {
			json.NewEncoder(w).Encode(map[string]any{"relatedProjects": []relatedProject{rel("github.com/o/n", "SOURCE_REPO")}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"versions": []map[string]any{{"versionKey": map[string]string{"version": "2.3.4"}, "isDefault": true}}})
	}))
	defer ts.Close()
	f := newVerifyFirewall(ts.URL)

	if _, _, err := f.depsDevSourceRepos("npm", "@scope/name"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantPkg := "/v3/systems/npm/packages/@scope%2Fname"
	wantVer := fmt.Sprintf("%s/versions/2.3.4", wantPkg)
	if len(gotPaths) != 2 || gotPaths[0] != wantPkg || gotPaths[1] != wantVer {
		t.Errorf("request paths = %v, want [%q %q]", gotPaths, wantPkg, wantVer)
	}
}
