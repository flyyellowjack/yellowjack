package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Issue #109: a digest spelled in tag position names the image with that digest.
//
// A request for manifests/sha256-<hex> is the OCI 1.1 referrers-tag fallback (and
// cosign's signature-tag convention): a lookup ABOUT the image whose manifest digest is
// <hex>. One arrived through a registry:2 pull-through cache in the #98 run:
//
//	GET /v2/library/alpine/manifests/sha256-ea72def7a47260a6b8cea592a2d0e07b36131d7e0694cfa3417615f87b3ae30d
//
// The firewall read "sha256-ea72def…" as an ordinary tag, fetched a manifest by that
// tag to find the source label, got a 404, and filed an image it had scored seconds
// earlier as UNSCORABLE -- waved through under the fail-open policy, refused under the
// fail-closed one. The client was handing us exactly the immutable identity D164 says
// we want, and we threw it away.
//
// Two things must therefore be true, and they are pinned separately: the VERDICT
// follows the image the digest names (reusing the answer already resolved for it), and
// the RELAY forwards the client's path verbatim, because the tag's content -- a
// referrers index, a signature, or the upstream's 404 for "none" -- is what was asked
// for. A fix that rewrote the relay to the digest form would hand back the image
// manifest where the client expected its referrers.

const (
	digestTagImage = "library/goodimage"
	digestTagLayer = "GOODIMAGE-LAYER-BYTES"
	referrersIndex = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[],"referrers-of":"the digest named in tag position"}`
)

// ociDigestUpstream is a registry that knows one image under one tag, under that
// manifest's own digest, and under the referrers TAG named after the digest -- whose
// content is deliberately different from the image, the way a real referrers index is.
// Any other manifest reference is a 404, the way a real registry answers.
type ociDigestUpstream struct {
	*ociSpyUpstream
	manifest     string // the exact bytes served for the tag and for the digest
	digest       string // "sha256:<hex of manifest>"
	configDigest string
}

func newOciDigestUpstream() *ociDigestUpstream {
	u := &ociDigestUpstream{ociSpyUpstream: &ociSpyUpstream{}}
	configBody := `{"config":{"Labels":{"org.opencontainers.image.source":"https://github.com/good/goodimage"}}}`
	u.configDigest = ociDigest(configBody)
	layerDigest := ociDigest(digestTagLayer)
	u.manifest = fmt.Sprintf(`{"schemaVersion":2,"config":{"digest":%q},"layers":[{"digest":%q}]}`, u.configDigest, layerDigest)
	u.digest = ociDigest(u.manifest)

	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hit = append(u.hit, r.Method+" "+r.URL.Path)
		u.mu.Unlock()
		p := r.URL.Path
		switch {
		case p == "/v2/"+digestTagImage+"/manifests/3.19", p == "/v2/"+digestTagImage+"/manifests/"+u.digest:
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Header().Set("Docker-Content-Digest", u.digest)
			fmt.Fprint(w, u.manifest)
		case p == "/v2/"+digestTagImage+"/manifests/"+strings.Replace(u.digest, ":", "-", 1):
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			fmt.Fprint(w, referrersIndex)
		case strings.Contains(p, "/manifests/"):
			http.NotFound(w, r)
		case strings.HasSuffix(p, "/blobs/"+u.configDigest):
			fmt.Fprint(w, configBody)
		case strings.HasSuffix(p, "/blobs/"+layerDigest):
			fmt.Fprint(w, digestTagLayer)
		default:
			fmt.Fprint(w, "{}")
		}
	}))
	return u
}

// count returns how many upstream requests matched sub.
func (u *ociDigestUpstream) count(sub string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, h := range u.hit {
		if strings.Contains(h, sub) {
			n++
		}
	}
	return n
}

// TestOciDigestInTagPositionFollowsTheImageUnderFailClosed is the assertion that
// would have caught #109: after the image has been scored by tag, the referrers-tag
// lookup for its digest must be served under the fail-closed policy -- and served for
// the RIGHT reasons, each pinned separately.
func TestOciDigestInTagPositionFollowsTheImageUnderFailClosed(t *testing.T) {
	up := newOciDigestUpstream()
	defer up.Close()
	p := newTestProxy(t, up.Server, func(cfg *Config) {
		cfg.Ecosystem = "oci"
		cfg.ScoreThreshold = 1.0 // stub 7.5: a healthy lookup ALLOWS; the only route to a refusal is unscorable
		cfg.UnscorablePolicy = "block"
	})
	tagPath := "/v2/" + digestTagImage + "/manifests/3.19"
	hexOnly := strings.TrimPrefix(up.digest, "sha256:")
	referrers := "/v2/" + digestTagImage + "/manifests/sha256-" + hexOnly

	// Cold pull by tag: scored, allowed, the real manifest relayed.
	if code, body := get(t, p, tagPath); code != http.StatusOK || body != up.manifest {
		t.Fatalf("cold pull by tag: status %d body %q; want 200 with the real manifest", code, body)
	}
	configFetches := up.count("/blobs/" + up.configDigest)
	if configFetches != 1 {
		t.Fatalf("cold pull resolved the repo through %d config-blob fetches, want exactly 1 (the control for the reuse check below)", configFetches)
	}

	// The referrers-tag lookup for that image's digest.
	code, body := get(t, p, referrers)
	if code != http.StatusOK {
		t.Fatalf("manifests/sha256-<hex> under FW_UNSCORABLE_POLICY=block: status %d, body %q\n"+
			"  the image was scored seconds ago; refusing a lookup about its own digest is #109", code, body)
	}
	// (1) The bytes relayed are what the client asked for: the TAG's content, verbatim.
	if body != referrersIndex {
		t.Fatalf("the referrers-tag lookup relayed something other than the tag's content:\n  %s\n"+
			"  a client asking for manifests/sha256-<hex> wants that tag -- a referrers index -- not the image manifest", body)
	}
	// (2) The upstream was asked for the tag exactly as the client spelled it.
	if up.count("GET "+referrers) == 0 {
		t.Errorf("the relay never asked upstream for %s verbatim; it saw %v", referrers, up.paths())
	}
	// (3) The repo was REUSED, not re-resolved: no second config-blob fetch, and no
	// lookup of the digest by tag.
	if again := up.count("/blobs/" + up.configDigest); again != configFetches {
		t.Errorf("the lookup re-resolved the repo (config-blob fetches %d -> %d); a digest we have already read must reuse its answer", configFetches, again)
	}

	// registry:2 HEADs before it GETs (#108); the tag-position HEAD answers the same way.
	req := httptest.NewRequest(http.MethodHead, "http://fw.local"+referrers, nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("HEAD of the digest in tag position: status %d, want 200", rec.Code)
	}

	// NEGATIVE CONTROL: a digest the registry has never seen must still land on the
	// unscorable path (a 403 under block) -- recognising the spelling must not turn
	// "unknown" into "allowed" -- and it must be looked up by DIGEST, never by tag.
	unknownHex := strings.Repeat("0", 64)
	unknown := "/v2/" + digestTagImage + "/manifests/sha256-" + unknownHex
	if code, body := get(t, p, unknown); code != http.StatusForbidden || !strings.Contains(body, blockErrMsg) {
		t.Errorf("an unknown digest in tag position: status %d body %q; want 403 with %q (the unscorable path)", code, body, blockErrMsg)
	}
	if up.count("GET /v2/"+digestTagImage+"/manifests/sha256:"+unknownHex) == 0 {
		t.Errorf("the unknown digest was not looked up in digest form; upstream saw %v", up.paths())
	}
	if up.count("GET /v2/"+digestTagImage+"/manifests/sha256-"+unknownHex) != 0 {
		t.Errorf("the unknown digest was looked up AS A TAG -- the #109 defect; upstream saw %v", up.paths())
	}
}

// TestOciDigestInTagPositionIsRefusedWithTheImage pins the other direction of "the
// verdict follows the image": the referrers of a BLOCKED image are withheld too.
// Recognising the digest must never become a way to reach a refused image's artifacts.
func TestOciDigestInTagPositionIsRefusedWithTheImage(t *testing.T) {
	up := newOciDigestUpstream()
	defer up.Close()
	p := newTestProxy(t, up.Server, func(cfg *Config) {
		cfg.Ecosystem = "oci"
		cfg.ScoreThreshold = 9.9 // stub 7.5 -> below threshold -> hard deny
	})
	hexOnly := strings.TrimPrefix(up.digest, "sha256:")
	if code, _ := get(t, p, "/v2/"+digestTagImage+"/manifests/3.19"); code != http.StatusForbidden {
		t.Fatalf("the image itself: status %d, want 403 (the control: this image is denied on its merits)", code)
	}
	code, body := get(t, p, "/v2/"+digestTagImage+"/manifests/sha256-"+hexOnly)
	if code != http.StatusForbidden || strings.Contains(body, "referrers-of") {
		t.Fatalf("the referrers tag of a DENIED image: status %d body %q; want 403 -- the digest names the same image", code, body)
	}
}

// TestOciDigestByDigestReferenceReusesTheTagsAnswer pins the same reuse for the
// canonical "@sha256:" spelling a client uses when it pulls by digest, so the two
// spellings cannot drift apart.
func TestOciDigestByDigestReferenceReusesTheTagsAnswer(t *testing.T) {
	up := newOciDigestUpstream()
	defer up.Close()
	p := newTestProxy(t, up.Server, func(cfg *Config) {
		cfg.Ecosystem = "oci"
		cfg.ScoreThreshold = 1.0
		cfg.UnscorablePolicy = "block"
	})
	if code, _ := get(t, p, "/v2/"+digestTagImage+"/manifests/3.19"); code != http.StatusOK {
		t.Fatalf("cold pull by tag: status %d", code)
	}
	before := up.count("/blobs/")
	if code, _ := get(t, p, "/v2/"+digestTagImage+"/manifests/"+up.digest); code != http.StatusOK {
		t.Fatalf("pull by digest after the tag was scored: status %d, want 200", code)
	}
	if after := up.count("/blobs/"); after != before {
		t.Errorf("pull by digest re-resolved the repo (blob fetches %d -> %d)", before, after)
	}
}
