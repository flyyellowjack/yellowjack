package main

// PRE-REGISTERED 2026-09-21, before the cache exists: the follow-on D320 named. On a
// bearer-challenged registry (Docker Hub's shape) a warm tag pull costs THREE requests --
// the HEAD refused 401, a token fetch, the HEAD repeated -- because ociToken caches nothing.
// A per-image token cache should return it to ONE. Predictions:
//
//	T1  Challenged registry, tokens cached: the SECOND and later warm pulls of a tag cost
//	    exactly one request each (the authenticated HEAD): no 401, no token fetch.
//	    Measured today (R3): three.
//	T2  Anonymous registry: unchanged at one request per warm pull. The cache must not add
//	    a probe where none was needed.
//	T3  A cached token the registry no longer accepts (expired, revoked): that ONE pull costs
//	    three (the 401, a fresh token, the HEAD), the pull still SUCCEEDS, and the next pull
//	    is back to one. Recovery is a cost, never a client-visible failure.
//	T4  The COLD resolve on a challenged registry, with a token already cached from an
//	    earlier HEAD: the anonymous probe GET is skipped, so the resolve costs two requests
//	    (manifest, config) instead of three. Today's cold path is probe + manifest + config.
//	T5  Tokens are per IMAGE: a cached token for image A is never presented for image B
//	    (a token's scope is repository:<image>:pull, and presenting A's for B is at best a
//	    401 and at worst a registry that accepts it and audits the wrong principal).
//
// What would change the design: T3 failing the client (then a stale token must be
// detected before use, i.e. expires_in must be honoured rather than a fixed TTL), or T1
// measuring two (then the challenge is being re-issued per request and the cache is not
// consulted on the first HEAD).

// RESULTS (2026-09-21, ocitoken.go). FIVE OF FIVE HELD.
//
//	T1  held: one authenticated HEAD per warm pull, no token fetch, on a challenged registry.
//	T2  held: an anonymous registry stays at one request per warm pull.
//	T3  held: a revoked token costs that one pull a 401, a token fetch and a retry; the pull
//	    succeeds; the next pull is back to one. Expiry is ALSO honoured from expires_in
//	    (T5's margin case), so this is the recovery path, not the normal one.
//	T4  held: a cold re-resolve with a cached token skips the anonymous probe (one manifest
//	    GET, no token fetch).
//	T5  held: per image; a lifetime inside the safety margin is never reused; "" (no auth
//	    needed) is remembered as an answer, not a miss.
//
// R3 in oci_tagdrift_test.go, which measured THREE per warm pull before this cache, is
// re-armed to one and keeps the history in its comment.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// pullDrift is the challenged-registry pull: the client presents its own bearer, the
// gate's revalidation is challenged on its own account.
func pullDrift(p *proxyServer) int {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v2/"+ociDriftImage+"/manifests/latest", nil)
	req.Header.Set("Authorization", "Bearer client-held-token")
	p.ServeHTTP(rec, req)
	return rec.Code
}

func TestACachedTokenMakesAChallengedWarmPullCostOne(t *testing.T) {
	up := newOCIDriftUpstream()
	defer up.Close()
	up.challenge = true
	up.tokenExpiresIn = 300 // Docker Hub's figure
	warm := newDriftProxy(t, up.Server, time.Hour)

	if code := pullDrift(warm); code != http.StatusOK {
		t.Fatalf("cold pull = %d, want 200", code)
	}
	// The first warm pull may still pay for a token if the cold resolve's token was
	// scoped differently; what T1 pins is the steady state, so measure pulls 2-4.
	pullDrift(warm)
	g0, h0, t0 := up.counts()
	for i := 0; i < 3; i++ {
		if code := pullDrift(warm); code != http.StatusOK {
			t.Fatalf("warm pull %d = %d, want 200", i, code)
		}
	}
	g1, h1, t1 := up.counts()
	t.Logf("T1: three warm pulls on a challenged registry cost manifest GETs +%d, HEADs +%d, tokens +%d", g1-g0, h1-h0, t1-t0)
	if h1-h0 != 3 || t1-t0 != 0 {
		t.Errorf("T1: want exactly one authenticated HEAD per warm pull and NO token fetches; got HEADs +%d tokens +%d "+
			"(before the cache this was 3 requests per pull)", h1-h0, t1-t0)
	}
	if g1-g0 > 3 {
		t.Errorf("T1: %d manifest GETs for 3 relays: the tag was re-resolved, not revalidated", g1-g0)
	}
}

func TestTheTokenCacheAddsNothingOnAnAnonymousRegistry(t *testing.T) {
	up := newOCIDriftUpstream()
	defer up.Close()
	warm := newDriftProxy(t, up.Server, time.Hour)
	if code := ociGet(t, warm, "/v2/"+ociDriftImage+"/manifests/latest"); code != http.StatusOK {
		t.Fatalf("cold pull = %d, want 200", code)
	}
	g0, h0, t0 := up.counts()
	for i := 0; i < 3; i++ {
		ociGet(t, warm, "/v2/"+ociDriftImage+"/manifests/latest")
	}
	g1, h1, t1 := up.counts()
	if h1-h0 != 3 || t1-t0 != 0 || g1-g0 > 3 {
		t.Errorf("T2: anonymous registry: HEADs +%d tokens +%d GETs +%d for three warm pulls; want 3, 0, <=3", h1-h0, t1-t0, g1-g0)
	}
}

func TestARevokedTokenIsReplacedOnceAndThePullSucceeds(t *testing.T) {
	up := newOCIDriftUpstream()
	defer up.Close()
	up.challenge = true
	up.tokenExpiresIn = 300
	warm := newDriftProxy(t, up.Server, time.Hour)
	if code := pullDrift(warm); code != http.StatusOK {
		t.Fatalf("cold pull = %d, want 200", code)
	}
	pullDrift(warm)

	up.revokeTokens() // everything the gate holds is now stale
	g0, h0, t0 := up.counts()
	if code := pullDrift(warm); code != http.StatusOK {
		t.Fatalf("T3: the pull after a revocation answered %d, want 200: recovery must be a cost, never a client-visible failure", code)
	}
	g1, h1, t1 := up.counts()
	t.Logf("T3: the pull after revocation cost manifest GETs +%d, HEADs +%d (the 401 is not counted), tokens +%d", g1-g0, h1-h0, t1-t0)
	if t1-t0 != 1 {
		t.Errorf("T3: want exactly one fresh token fetched after a revocation; got %d", t1-t0)
	}
	// The recovery is a REVALIDATION retry, not a full re-resolve: the only manifest GET
	// is the relay to the client. Without the retry in cacheIdentity the pull would
	// still succeed -- the resolve path has its own -- but at the cost of re-reading the
	// manifest and the config blob, which is the difference this line pins.
	if g1-g0 != 1 {
		t.Errorf("T3: the recovery pull issued %d manifest GETs; want 1 (the relay only): the stale token fell through to a full re-resolve instead of a HEAD retry", g1-g0)
	}
	// And the NEXT pull is back to one request.
	_, h2, t2 := up.counts()
	if code := pullDrift(warm); code != http.StatusOK {
		t.Fatalf("T3: pull after recovery = %d", code)
	}
	_, h3, t3 := up.counts()
	if h3-h2 != 1 || t3-t2 != 0 {
		t.Errorf("T3: the pull after recovery cost HEADs +%d tokens +%d; want 1 and 0", h3-h2, t3-t2)
	}
}

func TestACachedTokenSkipsTheColdProbe(t *testing.T) {
	// T4: a cold RESOLVE for a tag whose image already has a cached token skips the
	// anonymous probe. Arrange it by pulling once (caches the token), then moving the tag
	// so the next pull must re-resolve.
	up := newOCIDriftUpstream()
	defer up.Close()
	up.challenge = true
	up.tokenExpiresIn = 300
	warm := newDriftProxy(t, up.Server, time.Hour)
	if code := pullDrift(warm); code != http.StatusOK {
		t.Fatalf("cold pull = %d, want 200", code)
	}
	up.flip()
	g0, _, t0 := up.counts()
	if code := pullDrift(warm); code != http.StatusForbidden {
		t.Fatalf("post-flip pull = %d, want 403 (the moved tag resolves to an unscorable image)", code)
	}
	g1, _, t1 := up.counts()
	t.Logf("T4: the re-resolve after the flip cost manifest GETs +%d, tokens +%d", g1-g0, t1-t0)
	if t1-t0 != 0 {
		t.Errorf("T4: the re-resolve fetched %d token(s) although one was cached", t1-t0)
	}
	// Probe + manifest would be 2 GETs before the config blob; with the probe skipped
	// the manifest is read once. (The client relay is refused, so it adds no GET.)
	if g1-g0 != 1 {
		t.Errorf("T4: the re-resolve issued %d manifest GETs; want 1 (the probe is skipped when a token is cached)", g1-g0)
	}
}

func TestTokensAreNeverPresentedForAnotherImage(t *testing.T) {
	// T5, at the cache's own seam: what is remembered for one image is not returned for
	// another, whatever the scope text says. Driven directly because the fixture serves
	// one image.
	e := ociEcosystem{tokens: newTTLLRU[ociTokenEntry](ociTokenCacheBound, 0)}
	e.rememberToken("library/a", "tok-a", 300)
	if tok, ok := e.cachedToken("library/a"); !ok || tok != "tok-a" {
		t.Fatalf("the token was not remembered for its own image: %q %v", tok, ok)
	}
	if tok, ok := e.cachedToken("library/b"); ok {
		t.Fatalf("T5: image b was handed image a's token %q", tok)
	}
	// Expiry is honoured from expires_in, with the margin: a 5 s token is never reused.
	e.rememberToken("library/c", "tok-c", 5)
	if _, ok := e.cachedToken("library/c"); ok {
		t.Error("a token whose lifetime is within the safety margin was offered for reuse")
	}
	// And "" is a real answer (anonymous registry), distinct from a miss.
	e.rememberToken("library/d", "", 0)
	if tok, ok := e.cachedToken("library/d"); !ok || tok != "" {
		t.Errorf("an anonymous answer was not remembered as one: %q %v", tok, ok)
	}
	_ = fmt.Sprint // keep the import list identical to the other test files' shape
}
