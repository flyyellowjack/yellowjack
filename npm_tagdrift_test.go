package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Does the #93 tag-drift class stop at OCI?
//
// `!309` measured it for OCI and diagnosed the root property as: the repo cache is keyed
// by PACKAGE, and for npm/PyPI/Maven that identity carries an immutable version while
// OCI's `image:ref` is mutable. That diagnosis makes a prediction about npm, and the
// prediction is worth checking rather than believing, because `malware.go` says
// something that cuts against it:
//
//	"npm: ... Scoring still uses /latest -- the `/latest` decision in ecosystem.go was
//	 about what to FETCH to score a package"
//
// npm's identity carries NO version at all (`PackageNameFromPath` returns a bare name),
// and the thing fetched to score it is `/latest`, which is a MUTABLE dist-tag. So the
// cache key is stable while the thing it describes moves — the same shape as OCI, by a
// different route. If that holds, #93's framing as an OCI problem is too narrow.
//
// Predicted before running: npm drifts too. Recorded here so the result cannot be read
// back as whatever happened.

// npmDriftUpstream serves one package whose `latest` MOVES. Before the flip it declares
// a source repo (stub-scored 7.5 -> allowed at 5.0); after, it declares none
// (unscorable -> blocked under policy=block). Same discriminator as the OCI rig, so the
// two results are comparable.
type npmDriftUpstream struct {
	*httptest.Server
	mu       sync.Mutex
	flipped  bool
	metadata int
}

const npmDriftPkg = "driftpkg"

func newNpmDriftUpstream() *npmDriftUpstream {
	u := &npmDriftUpstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == "/"+npmDriftPkg+"/latest", p == "/"+npmDriftPkg:
			u.mu.Lock()
			u.metadata++
			flipped := u.flipped
			u.mu.Unlock()
			if flipped {
				// No usable source repo -> unscorable -> blocked.
				w.Write([]byte(`{"name":"` + npmDriftPkg + `","version":"2.0.0"}`))
				return
			}
			w.Write([]byte(`{"name":"` + npmDriftPkg + `","version":"1.0.0","repository":"github.com/acme/` + npmDriftPkg + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	return u
}

func (u *npmDriftUpstream) flip() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.flipped = true
}

func newNpmDriftProxy(t *testing.T, up *httptest.Server, ttl time.Duration) *proxyServer {
	t.Helper()
	return newTestProxy(t, up, func(c *Config) {
		c.Ecosystem = "npm"
		c.ScoreThreshold = 5.0
		c.UnscorablePolicy = "block"
		c.ScoreCacheTTL = ttl
	})
}

func npmDriftGet(t *testing.T, p *proxyServer, path string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code
}

// TestNpmLatestDriftsTheSameWayOCIDoes checks whether the #93 class spans ecosystems.
//
// Same three-arm structure as the OCI rig: anti-vacuity (the pre-drift state is really
// allowed), a COLD control on the identical upstream state (so a warm 200 is
// attributable to the cache and not the content), then the measurement.
func TestNpmLatestDriftsTheSameWayOCIDoes(t *testing.T) {
	up := newNpmDriftUpstream()
	defer up.Close()

	warm := newNpmDriftProxy(t, up.Server, time.Hour) // shipped default

	if code := npmDriftGet(t, warm, "/"+npmDriftPkg); code != http.StatusOK {
		t.Fatalf("pre-drift %s = %d, want 200 — the allowed state must be real or this measures nothing", npmDriftPkg, code)
	}

	up.flip() // `latest` now resolves to a release declaring no source repo

	cold := newNpmDriftProxy(t, up.Server, time.Hour)
	if code := npmDriftGet(t, cold, "/"+npmDriftPkg); code != http.StatusForbidden {
		t.Fatalf("COLD proxy on the flipped upstream = %d, want 403 — the flip did not produce a blockable package, so the warm result proves nothing", code)
	}

	code := npmDriftGet(t, warm, "/"+npmDriftPkg)
	t.Logf("npm drift probe: warm gate answered %d after `latest` moved (cold gate on the same state: 403)", code)

	// Pinned as the measured behaviour, exactly as the OCI siblings are: the fix is
	// #93's unowned selection policy, not this test's business. When this goes red the
	// class has been closed for npm — re-arm it and say so on #93.
	if code != http.StatusOK {
		t.Errorf("npm drift appears CLOSED: warm gate answered %d (not 200) after `latest` moved. "+
			"If deliberate, re-arm this test to assert the refusal and update #93; if not, something "+
			"changed npm's caching by accident.", code)
	}
}

// TestNpmDriftIsTheSameCacheAsOCIs isolates the mechanism, so "npm drifts too" is a
// statement about the SAME defect rather than a coincidence with the same symptom.
func TestNpmDriftIsTheSameCacheAsOCIs(t *testing.T) {
	up := newNpmDriftUpstream()
	defer up.Close()

	p := newNpmDriftProxy(t, up.Server, 0) // score/repo caching off

	if code := npmDriftGet(t, p, "/"+npmDriftPkg); code != http.StatusOK {
		t.Fatalf("pre-drift = %d, want 200", code)
	}
	up.flip()

	code := npmDriftGet(t, p, "/"+npmDriftPkg)
	t.Logf("with FW_SCORE_CACHE_TTL=0 the post-drift answer is %d", code)

	if code != http.StatusForbidden {
		t.Errorf("with caching OFF npm still answered %d after the drift; want 403. If this fails, "+
			"npm's drift is NOT the score/repo cache and it is a different defect from the OCI one.", code)
	}
}

// TestTheDriftClassIsNotOCIOnly states the cross-ecosystem conclusion in one place, so a
// reader of #93 does not have to infer it from two files.
//
// It asserts the PROPERTY that makes both ecosystems vulnerable: the identity the cache
// is keyed on does not name the bytes. For npm the identity is a bare package name and
// what gets scored is `/latest`; for OCI it is `image:ref` where ref may be a tag.
func TestTheDriftClassIsNotOCIOnly(t *testing.T) {
	// npm: the identity carries no version at all.
	if got := (npmEcosystem{}).PackageNameFromPath("/" + npmDriftPkg + "/latest"); strings.Contains(got, "latest") ||
		strings.Contains(got, "@") || got != npmDriftPkg {
		t.Errorf("npm identity for a /latest request = %q, expected the bare name %q. If npm's identity "+
			"has started carrying a version, the drift analysis on #93 needs redoing.", got, npmDriftPkg)
	}
	// OCI: the identity carries a ref, and a tag ref is mutable.
	if _, ref := ociSplitRef("library/app"); ref != "latest" {
		t.Errorf("ociSplitRef defaulted to %q, not \"latest\" — #93's analysis assumed this default", ref)
	}
	t.Log("both npm and OCI key the cache on an identity that does not name the bytes; #93 is not OCI-only")
}
