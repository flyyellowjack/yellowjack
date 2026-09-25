package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// #93 asks for the re-scan SELECTION policy, and names as its own first example
// "detecting that a cached `latest` has drifted from the registry's current `latest`".
// It has no design. Before anyone designs one, this measures the exposure it is about:
// WHEN a tag moves under us, for how long does the old verdict keep answering?
//
// WHY A TAG IS DIFFERENT FROM EVERY OTHER PACKAGE IDENTITY WE CACHE. The repo cache is
// keyed by PACKAGE, and for npm/PyPI/Maven a package identity carries an immutable
// version, so a cache hit describes the same bytes it described when it was written.
// For OCI the identity is `image:ref` (ociSplitRef), and a REF IS MUTABLE. The same key
// can describe different bytes an hour apart, and nothing in the cache lookup knows it.
//
// #93 names the ociBlobBindingTTL (10 minutes) as the "deliberate stopgap". These tests
// exist to check whether that is the TTL that actually governs the exposure, because the
// repo/score caches are on FW_SCORE_CACHE_TTL, which defaults to an HOUR.

// PRE-REGISTERED 2026-09-21, before the fix exists (#93 question 1: restore what D164 ruled).
// The repair is REVALIDATION on an OCI tag: a HEAD on the manifest for Docker-Content-Digest,
// and the repo cache keyed on image@digest instead of image:tag. Predictions:
//
//	R1  TestACachedTagKeepsAnsweringAfterTheTagHasMoved goes RED as written and is re-armed
//	    to want 403; the warm proxy refuses the moved tag on the FIRST request after the flip.
//	R2  Cost on an ANONYMOUS registry: a warm tag pull costs exactly ONE upstream request (the
//	    HEAD), where today it costs ZERO (the cold path's three requests are cached for an
//	    hour). #93 quoted "~2.15 per pull" as 1.15 + one request; that derivation stands.
//	R3  Cost on a BEARER-CHALLENGED registry (Docker Hub's shape): THREE requests per warm pull
//	    -- the HEAD is refused 401, a token is fetched, the HEAD is repeated -- because ociToken
//	    caches nothing. #93's "+1" is therefore optimistic for Hub, and this is the number the
//	    issue needs. A token cache would bring it back to one and is out of scope here.
//	R4  A digest ref (image@sha256:...) is already immutable and gains NO request.
//	R5  A registry that omits Docker-Content-Digest on HEAD cannot be revalidated; the name
//	    cache is then bypassed and every pull re-resolves (the blunt repair), never a stale
//	    verdict. Fail toward cost, not toward trust.
//
// What would change the docs the other way: R3 measuring 2 (Hub answers HEAD anonymously for
// public images), or R1 needing a second request to refuse (a cache read site missed -- the
// #93 note warns resolveRepo re-checks the cache under the singleflight).

// RESULTS (2026-09-21, ocirevalidate.go). FIVE OF FIVE HELD.
//
//	R1  held: the warm gate refused the moved tag on the first request. The re-armed test
//	    below and the real-client leg (e2e/oci_tagdrift_test.go, crane against registry:2)
//	    both pin it; reverting the fix reddens both.
//	R2  held: +1 HEAD per warm pull, no token, no manifest body, on an anonymous registry.
//	R3  held: the 401, one token fetch, one authenticated HEAD -- three per warm pull on a
//	    bearer-challenged registry. #93's "+1" was optimistic for Hub; this is the number.
//	R4  held: a pull by digest issues no HEAD.
//	R5  held: no Docker-Content-Digest on HEAD -> the name cache is bypassed, every pull
//	    re-resolves, the moved tag is still refused. The FIRST run of R1 went through this
//	    path, because the fixture did not send the header; the fixture was then made honest
//	    (every registry measured on #93 sends it) so R2/R3 could be measured at all.
//
// One sabotage a test cannot reach: resolveRepo's re-check of the cache under the
// singleflight reading by NAME stays green on its own, because once the put is keyed by
// identity nothing ever writes under the name. It is defence in depth against that put
// regressing, and the put's own sabotage is what the cost tests catch.

// ociDriftUpstream is a registry whose `latest` tag MOVES. Before the flip it resolves
// to a config declaring a source repo (stub-scored 7.5 -> allowed at a 5.0 threshold);
// after the flip it resolves to a config with no source label at all (unscorable ->
// blocked under policy=block).
//
// The two states are chosen so the verdict FLIPS on the same tag with no change to the
// request: that is what "drift" means here, and it is the only way to tell a cached
// answer from a re-resolved one without reading the cache's internals.
type ociDriftUpstream struct {
	*httptest.Server
	mu        sync.Mutex
	flipped   bool
	manifests int // manifest GETs served (a body left the registry)
	heads     int // manifest HEADs served (revalidation: zero body bytes)
	tokens    int // token-endpoint hits
	// challenge makes the registry demand a bearer token (Docker Hub's shape) so the
	// revalidation's cost can be measured on both registry kinds.
	challenge bool
	// noDigestHeader withholds Docker-Content-Digest on HEAD: a registry that cannot be
	// revalidated cheaply. The gate must then fail toward COST (re-resolve), never trust.
	noDigestHeader bool
	// Token lifetime the endpoint states (0 = say nothing, so the spec's 60 s applies)
	// and the serial of the token currently accepted; bump it to revoke what was issued.
	tokenExpiresIn int
	tokenSerial    int
}

const ociDriftImage = "library/drifter"

func newOCIDriftUpstream() *ociDriftUpstream {
	u := &ociDriftUpstream{}

	good := `{"config":{"Labels":{"org.opencontainers.image.source":"https://github.com/acme/drifter"}}}`
	bad := `{"config":{"Labels":{}}}`
	goodD, badD := ociDigest(good), ociDigest(bad)

	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == "/token":
			u.mu.Lock()
			u.tokens++
			tok := fmt.Sprintf("drift-token-%d", u.tokenSerial)
			exp := u.tokenExpiresIn
			u.mu.Unlock()
			if exp > 0 {
				fmt.Fprintf(w, `{"token":%q,"expires_in":%d}`, tok, exp)
			} else {
				fmt.Fprintf(w, `{"token":%q}`, tok)
			}

		case strings.Contains(p, "/manifests/"):
			u.mu.Lock()
			auth := r.Header.Get("Authorization")
			// Any bearer is accepted from the CLIENT side of a relay (it did its own
			// dance); the gate's own requests carry a drift-token-N, and only the
			// current serial is honoured.
			stale := strings.HasPrefix(auth, "Bearer drift-token-") && auth != fmt.Sprintf("Bearer drift-token-%d", u.tokenSerial)
			if u.challenge && (auth == "" || stale) {
				u.mu.Unlock()
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+u.URL+`/token",service="drift",scope="repository:`+ociDriftImage+`:pull"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Method == http.MethodHead {
				u.heads++
			} else {
				u.manifests++
			}
			flipped := u.flipped
			noDigest := u.noDigestHeader
			u.mu.Unlock()

			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			cfg := goodD
			if flipped {
				cfg = badD
			}
			// One layer digest, shared: the point here is the CONFIG the tag resolves
			// to, not the layer set.
			body := fmt.Sprintf(`{"config":{"digest":%q},"layers":[{"digest":%q}]}`, cfg, ociDigest("LAYER"))
			if !noDigest {
				w.Header().Set("Docker-Content-Digest", ociDigest(body))
			}
			if r.Method == http.MethodHead {
				return
			}
			fmt.Fprint(w, body)

		case strings.HasSuffix(p, "/blobs/"+goodD):
			fmt.Fprint(w, good)
		case strings.HasSuffix(p, "/blobs/"+badD):
			fmt.Fprint(w, bad)
		default:
			fmt.Fprint(w, "{}")
		}
	}))
	return u
}

func (u *ociDriftUpstream) flip() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.flipped = true
}

func (u *ociDriftUpstream) manifestCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.manifests
}

// revokeTokens makes every token issued so far stale: the next gate request carrying
// one is answered 401, and the token endpoint issues the new serial.
func (u *ociDriftUpstream) revokeTokens() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.tokenSerial++
}

// counts returns (manifest GETs, manifest HEADs, token hits): the whole upstream cost.
func (u *ociDriftUpstream) counts() (int, int, int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.manifests, u.heads, u.tokens
}

func newDriftProxy(t *testing.T, up *httptest.Server, ttl time.Duration) *proxyServer {
	t.Helper()
	return newTestProxy(t, up, func(c *Config) {
		c.Ecosystem = "oci"
		c.ScoreThreshold = 5.0
		c.UnscorablePolicy = "block"
		c.ScoreCacheTTL = ttl
	})
}

// TestACachedTagKeepsAnsweringAfterTheTagHasMoved measures the drift window.
//
// It is written to be informative whichever way it comes out: the ANTI-VACUITY leg and
// the COLD CONTROL together mean a pass cannot be explained by "the flip did nothing"
// or by "everything is blocked anyway".
func TestACachedTagKeepsAnsweringAfterTheTagHasMoved(t *testing.T) {
	up := newOCIDriftUpstream()
	defer up.Close()

	warm := newDriftProxy(t, up.Server, time.Hour) // the shipped default

	// 1. ANTI-VACUITY: before any drift, the tag is ALLOWED. Without this a 403 later
	//    would be indistinguishable from a gate that refuses everything.
	if code := ociGet(t, warm, "/v2/"+ociDriftImage+"/manifests/latest"); code != http.StatusOK {
		t.Fatalf("pre-drift latest = %d, want 200 — the allowed state must be real or this test measures nothing", code)
	}
	before := up.manifestCount()

	// 2. The tag moves. Same name, different bytes, and the new bytes are unscorable.
	up.flip()

	// 3. COLD CONTROL, same registry state: a proxy with no cache history must refuse.
	//    This is what proves the post-flip content is genuinely blockable, so whatever
	//    the warm proxy does next is attributable to its CACHE and not to the content.
	cold := newDriftProxy(t, up.Server, time.Hour)
	if code := ociGet(t, cold, "/v2/"+ociDriftImage+"/manifests/latest"); code != http.StatusForbidden {
		t.Fatalf("COLD proxy on the flipped registry = %d, want 403 — the flip did not produce a blockable image, so the warm result below would prove nothing", code)
	}

	// 4. THE MEASUREMENT. Same request, same warm proxy, tag has moved.
	code := ociGet(t, warm, "/v2/"+ociDriftImage+"/manifests/latest")
	after := up.manifestCount()

	t.Logf("drift probe: warm proxy answered %d after the tag moved; manifest requests %d -> %d", code, before, after)

	// RE-ARMED 2026-09-21 (R1 held). Until ocirevalidate.go this asserted the GAP -- a
	// 200 for a moved tag, for the whole FW_SCORE_CACHE_TTL -- and said "when this goes
	// red, the gap is closed: re-arm it to want 403". It went red on the fix's first run.
	// The warm gate now revalidates the tag with one HEAD (measured below) and refuses
	// the moved tag on the FIRST request after the flip.
	if code != http.StatusForbidden {
		t.Errorf("the warm gate answered %d (want 403) for a tag that moved under it: a cached verdict "+
			"is answering for an image it never judged, the #93 gap D164 ruled against", code)
	}
	if after == before {
		t.Errorf("the warm gate refused WITHOUT going back to the registry (manifest GETs %d -> %d), so the "+
			"refusal is not a re-resolution of the moved tag", before, after)
	}
}

// TestTagRevalidationCostsOneRequestOnAnAnonymousRegistry is R2: a warm pull of an UNMOVED
// tag costs exactly one upstream request, the HEAD, and no manifest body. Before the fix
// it cost zero, and #93 priced the repair as "1.15 + one request"; this is that request.
func TestTagRevalidationCostsOneRequestOnAnAnonymousRegistry(t *testing.T) {
	up := newOCIDriftUpstream()
	defer up.Close()
	warm := newDriftProxy(t, up.Server, time.Hour)

	if code := ociGet(t, warm, "/v2/"+ociDriftImage+"/manifests/latest"); code != http.StatusOK {
		t.Fatalf("cold pull = %d, want 200", code)
	}
	g0, h0, t0 := up.counts()
	if h0 == 0 {
		t.Fatal("the cold pull issued no HEAD, so revalidation is not on this path at all")
	}
	for i := 0; i < 3; i++ {
		if code := ociGet(t, warm, "/v2/"+ociDriftImage+"/manifests/latest"); code != http.StatusOK {
			t.Fatalf("warm pull %d = %d, want 200", i, code)
		}
	}
	g1, h1, t1 := up.counts()
	t.Logf("R2: three warm pulls cost manifest GETs +%d, HEADs +%d, tokens +%d", g1-g0, h1-h0, t1-t0)
	// The relay of the manifest to the client is itself one GET per pull (that is the
	// pull); what must NOT grow is the RESOLVE: config blob, token, extra manifest reads.
	if h1-h0 != 3 {
		t.Errorf("R2: three warm pulls issued %d HEADs, want exactly 3 (one revalidation per pull)", h1-h0)
	}
	if t1-t0 != 0 {
		t.Errorf("R2: an anonymous registry was asked for %d tokens on warm pulls, want 0", t1-t0)
	}
	if g1-g0 > 3 {
		t.Errorf("R2: three warm pulls issued %d manifest GETs; more than the 3 relays means the tag was re-resolved, not revalidated", g1-g0)
	}
}

// TestTagRevalidationOnAChallengedRegistryCostsOneWithTheTokenCache is R3, Docker Hub's
// shape. As first measured (D320) it cost THREE requests per warm pull -- the HEAD refused
// 401, a token fetch, the HEAD repeated -- because ociToken cached nothing. With the token
// cache (ocitoken.go, T1) the steady state is ONE: the cached token rides the first HEAD.
// The first warm pull after the cold resolve is measured separately below, because the
// cold resolve is what fills the cache.
func TestTagRevalidationOnAChallengedRegistryCostsOneWithTheTokenCache(t *testing.T) {
	up := newOCIDriftUpstream()
	defer up.Close()
	up.challenge = true
	warm := newDriftProxy(t, up.Server, time.Hour)

	// The CLIENT does its own token dance and presents a bearer on the pull; the gate
	// relays it. What this leg measures is the GATE's revalidation, which carries no
	// client credential and is challenged on its own account.
	pull := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v2/"+ociDriftImage+"/manifests/latest", nil)
		req.Header.Set("Authorization", "Bearer client-held-token")
		warm.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := pull(); code != http.StatusOK {
		t.Fatalf("cold pull = %d, want 200", code)
	}
	g0, h0, t0 := up.counts()
	if code := pull(); code != http.StatusOK {
		t.Fatalf("warm pull = %d, want 200", code)
	}
	g1, h1, t1 := up.counts()
	t.Logf("R3: one warm pull on a bearer-challenged registry cost manifest GETs +%d, HEADs +%d, tokens +%d (the 401 is not counted as a HEAD)", g1-g0, h1-h0, t1-t0)
	if h1-h0 != 1 || t1-t0 != 0 {
		t.Errorf("R3 (with the token cache): want one authenticated HEAD and NO token fetch per warm pull; got HEADs +%d tokens +%d", h1-h0, t1-t0)
	}
	// And the revalidation still WORKS through the challenge: the moved tag is refused.
	up.flip()
	if code := pull(); code != http.StatusForbidden {
		t.Errorf("R3: after the flip the challenged registry's moved tag was answered %d, want 403", code)
	}
}

// TestADigestRefIsNotRevalidated is R4: image@sha256:... names immutable content, so a
// warm pull by digest issues NO HEAD.
func TestADigestRefIsNotRevalidated(t *testing.T) {
	up := newOCIDriftUpstream()
	defer up.Close()
	warm := newDriftProxy(t, up.Server, time.Hour)
	good := fmt.Sprintf(`{"config":{"digest":%q},"layers":[{"digest":%q}]}`, ociDigest(`{"config":{"Labels":{"org.opencontainers.image.source":"https://github.com/acme/drifter"}}}`), ociDigest("LAYER"))
	ref := "/v2/" + ociDriftImage + "/manifests/" + ociDigest(good)

	if code := ociGet(t, warm, ref); code != http.StatusOK {
		t.Fatalf("cold pull by digest = %d, want 200", code)
	}
	_, h0, _ := up.counts()
	if code := ociGet(t, warm, ref); code != http.StatusOK {
		t.Fatalf("warm pull by digest = %d, want 200", code)
	}
	_, h1, _ := up.counts()
	if h1 != h0 {
		t.Errorf("R4: a warm pull BY DIGEST issued %d HEAD(s); a digest is immutable and must cost nothing to revalidate", h1-h0)
	}
}

// TestARegistryWithoutTheDigestHeaderFailsTowardCost is R5: no Docker-Content-Digest on
// HEAD means the tag cannot be revalidated cheaply. The gate must then bypass the name
// cache and re-resolve every pull -- the blunt repair -- and STILL refuse the moved tag.
// The one outcome that is never acceptable is the stale approval.
func TestARegistryWithoutTheDigestHeaderFailsTowardCost(t *testing.T) {
	up := newOCIDriftUpstream()
	defer up.Close()
	up.noDigestHeader = true
	warm := newDriftProxy(t, up.Server, time.Hour)

	if code := ociGet(t, warm, "/v2/"+ociDriftImage+"/manifests/latest"); code != http.StatusOK {
		t.Fatalf("cold pull = %d, want 200", code)
	}
	g0, _, _ := up.counts()
	if code := ociGet(t, warm, "/v2/"+ociDriftImage+"/manifests/latest"); code != http.StatusOK {
		t.Fatalf("warm pull = %d, want 200", code)
	}
	g1, _, _ := up.counts()
	if g1-g0 < 2 {
		t.Errorf("R5: with no digest header a warm pull issued only %d manifest GET(s); the resolve was served from the name cache, which is the stale-approval path", g1-g0)
	}
	up.flip()
	if code := ociGet(t, warm, "/v2/"+ociDriftImage+"/manifests/latest"); code != http.StatusForbidden {
		t.Errorf("R5: the moved tag was answered %d on a registry that cannot be revalidated, want 403", code)
	}
}

// TestTheDriftWindowIsTheScoreCacheTTLNotTheBindingTTL isolates WHICH knob governs it,
// because #93 reasons about the 10-minute binding TTL and a fix aimed at the wrong knob
// would leave the exposure exactly where it is.
//
// Run with the score cache DISABLED (0 = off, the same convention ScoreCacheTTL uses):
// if the drift is governed by the score/repo cache, this leg re-resolves and refuses.
func TestTheDriftWindowIsTheScoreCacheTTLNotTheBindingTTL(t *testing.T) {
	up := newOCIDriftUpstream()
	defer up.Close()

	p := newDriftProxy(t, up.Server, 0) // caching off

	if code := ociGet(t, p, "/v2/"+ociDriftImage+"/manifests/latest"); code != http.StatusOK {
		t.Fatalf("pre-drift latest = %d, want 200", code)
	}
	up.flip()

	code := ociGet(t, p, "/v2/"+ociDriftImage+"/manifests/latest")
	t.Logf("with FW_SCORE_CACHE_TTL=0 the post-drift answer is %d", code)

	if code != http.StatusForbidden {
		t.Errorf("with caching OFF the gate still answered %d for a tag that now points at an unscorable image; "+
			"want 403. If this fails, the drift is NOT the score cache and the diagnosis in the sibling test is wrong.", code)
	}
}

// TestTheClientReceivesTheNEWImageUnderTheOLDApproval is the sharp end of the finding,
// and the reason this is not merely "a stale answer".
//
// A stale CACHE that served stale BYTES would be a freshness problem: the client gets an
// old image, which is at worst inconvenient. What happens here is the other thing. The
// verdict comes from cache, but the relay goes to the registry and returns whatever the
// tag points at NOW -- so the client receives the DRIFTED image carrying an approval that
// was formed by inspecting the previous one.
//
// The assertion is on the config digest in the relayed body, because that is the field
// the verdict was derived from: `good` declares a source repo, `bad` declares none.
// Seeing `bad`'s digest in a 200 response is the whole defect in one value.
func TestTheClientReceivesTheNEWImageUnderTheOLDApproval(t *testing.T) {
	up := newOCIDriftUpstream()
	defer up.Close()

	badCfgDigest := ociDigest(`{"config":{"Labels":{}}}`)

	warm := newDriftProxy(t, up.Server, time.Hour)
	body, code := ociGetBody(t, warm, "/v2/"+ociDriftImage+"/manifests/latest")
	if code != http.StatusOK {
		t.Fatalf("pre-drift latest = %d, want 200", code)
	}
	if strings.Contains(body, badCfgDigest) {
		t.Fatalf("the PRE-drift manifest already names the unscorable config — the fixture is not set up as described, so nothing below is attributable to drift")
	}

	up.flip()

	body, code = ociGetBody(t, warm, "/v2/"+ociDriftImage+"/manifests/latest")
	drifted := strings.Contains(body, badCfgDigest)
	t.Logf("post-drift relay: status %d, names the unscorable config: %v", code, drifted)

	// RE-ARMED 2026-09-21. This pinned the gap's worst reading -- not a stale cache
	// handing back stale content (a freshness issue) but a stale VERDICT applied to
	// CURRENT bytes, an approval for an image it never saw. With revalidation the moved
	// tag is refused, and the drifted manifest is never relayed under the old approval.
	if code != http.StatusForbidden || drifted {
		t.Errorf("post-drift: status %d, relayed the drifted manifest: %v; want 403 and no relay -- "+
			"otherwise the old approval is being applied to bytes it never judged", code, drifted)
	}
}
