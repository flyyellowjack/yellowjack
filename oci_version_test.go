package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// These are the regression assertions for D164 — "we verify package VERSIONS, not
// packages in perpetuity" — and for the hole that closing it would otherwise open.
//
// THE DEFECT. oci.go pinned `const ref = "latest"`, so every container verdict was
// formed by inspecting whatever the "latest" tag pointed at, regardless of which
// version the client was actually pulling. Anyone who controlled ONE tag on an image
// could therefore choose which version we judged.
//
// WHY A PARSING TEST IS NOT ENOUGH. Asserting that PackageNameFromPath returns
// "nginx:1.25" proves the reference was extracted, not that it reached the registry.
// TestLookupRepoResolvesTheRequestedVersion watches the WIRE instead: it fails if any
// manifest request carries a reference the caller did not ask for.
//
// THE HOLE THE FIX WOULD OPEN ON ITS OWN. Once verdicts are version-keyed, the two
// halves of the OCI gate stop speaking the same language — a manifest request carries
// a reference, a blob request carries only a digest. Judging a blob by its bare image
// name would then mean "judge it as latest", so a BLOCKED version's layers would be
// served whenever a different version of the same name is allowed. That is what
// TestBlobVerdictFollowsTheVersionThatEnumeratedIt pins, and it is why the version fix
// and the blob binding are one change rather than two.

// ociVersionUpstream is a fake registry serving ONE image at two tags that differ in
// the only way stub scoring can express: v1 declares a source repo (scored 7.5 ->
// allowed at a 5.0 threshold), v2 declares none (unscorable -> blocked). Their layers
// are different blobs, so a digest identifies a version unambiguously.
type ociVersionUpstream struct {
	*httptest.Server
	mu   sync.Mutex
	refs []string // every manifest reference asked for, in order
}

const (
	ociVerImage  = "library/app"
	ociVerLayer1 = "LAYER-BYTES-OF-V1"
	ociVerLayer2 = "LAYER-BYTES-OF-V2-BLOCKED"
)

func newOCIVersionUpstream() *ociVersionUpstream {
	u := &ociVersionUpstream{}

	// v1 is scoreable: its config declares a source repo.
	cfg1 := `{"config":{"Labels":{"org.opencontainers.image.source":"https://github.com/acme/app"}}}`
	// v2 is NOT: no source label at all -> unscorable -> blocked under policy=block.
	cfg2 := `{"config":{"Labels":{}}}`

	cfg1D, cfg2D := ociDigest(cfg1), ociDigest(cfg2)
	lay1D, lay2D := ociDigest(ociVerLayer1), ociDigest(ociVerLayer2)

	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.Contains(p, "/manifests/"):
			ref := p[strings.LastIndex(p, "/manifests/")+len("/manifests/"):]
			u.mu.Lock()
			u.refs = append(u.refs, ref)
			u.mu.Unlock()

			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			// "latest" deliberately aliases v1, the ALLOWED version. That is the
			// attacker's setup: a benign latest standing in front of a blocked v2.
			if ref == "v2" {
				fmt.Fprintf(w, `{"config":{"digest":%q},"layers":[{"digest":%q}]}`, cfg2D, lay2D)
				return
			}
			fmt.Fprintf(w, `{"config":{"digest":%q},"layers":[{"digest":%q}]}`, cfg1D, lay1D)

		case strings.HasSuffix(p, "/blobs/"+cfg1D):
			fmt.Fprint(w, cfg1)
		case strings.HasSuffix(p, "/blobs/"+cfg2D):
			fmt.Fprint(w, cfg2)
		case strings.HasSuffix(p, "/blobs/"+lay1D):
			fmt.Fprint(w, ociVerLayer1)
		case strings.HasSuffix(p, "/blobs/"+lay2D):
			// The blocked version's payload. Delivering this is the failure.
			fmt.Fprint(w, ociVerLayer2)
		default:
			fmt.Fprint(w, "{}")
		}
	}))
	return u
}

func (u *ociVersionUpstream) manifestRefs() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.refs...)
}

// TestLookupRepoResolvesTheRequestedVersion watches the wire: every manifest request
// the firewall makes must carry the reference the caller asked for.
//
// NEGATIVE CONTROL (run by hand, per the rule that an assertion never seen to fail is
// not evidence): restore `const ref = "latest"` in oci.go's LookupRepo and both
// subtests go red — "by tag" sees "latest" where it wants "1.25", "by digest" sees
// "latest" where it wants the digest. Verified 2026-08-19.
func TestLookupRepoResolvesTheRequestedVersion(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pkg     string
		wantRef string
	}{
		{"by tag", ociVerImage + ":1.25", "1.25"},
		{"by digest", ociVerImage + "@sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("a", 64)},
		{"bare name means latest", ociVerImage, "latest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := newOCIVersionUpstream()
			defer up.Close()

			eco := ociEcosystem{base: up.URL, bindings: newOCIBlobBindings()}
			if _, err := eco.LookupRepo(up.Client(), tc.pkg); err != nil {
				t.Fatalf("LookupRepo(%q): %v", tc.pkg, err)
			}

			refs := up.manifestRefs()
			if len(refs) == 0 {
				t.Fatalf("no manifest request reached the registry for %q — the test proves nothing", tc.pkg)
			}
			for _, got := range refs {
				if got != tc.wantRef {
					t.Errorf("manifest requested ref %q, want %q (D164: the verdict must describe the version being pulled, not whatever %q points at)",
						got, tc.wantRef, "latest")
				}
			}
		})
	}
}

// TestBlobVerdictFollowsTheVersionThatEnumeratedIt is the bypass assertion.
//
// Setup: "latest" and "v1" are ALLOWED (scored 7.5 >= 5.0); "v2" is BLOCKED
// (unscorable, policy=block). A client pulls v2's manifest — refused — and then asks
// for v2's LAYER directly, which is the shape every real bypass takes (`crane blob`,
// a cached manifest, a resumed layer). The layer must not be served.
//
// Without the (image, digest) -> version binding this test fails: the blob URL carries
// no tag, so the byte gate would fall back to the bare image name, resolve it as
// "latest", find it allowed, and hand over the blocked version's bytes.
func TestBlobVerdictFollowsTheVersionThatEnumeratedIt(t *testing.T) {
	up := newOCIVersionUpstream()
	defer up.Close()

	p := newTestProxy(t, up.Server, func(c *Config) {
		c.Ecosystem = "oci"
		c.ScoreThreshold = 5.0 // stub 7.5 clears it, so v1/latest are allowed
		c.UnscorablePolicy = "block"
		c.ByteGate = byteGateEnforce
	})

	// 1. The allowed version really is allowed — otherwise step 3 proves nothing,
	//    because a blanket refusal would also "pass".
	if code := ociGet(t, p, "/v2/"+ociVerImage+"/manifests/v1"); code != http.StatusOK {
		t.Fatalf("v1 manifest = %d, want 200 — the ANTI-VACUITY leg: if the allowed version is refused too, this test cannot tell a working gate from a broken one", code)
	}

	// 2. The blocked version is blocked at the manifest, as it was before this change.
	if code := ociGet(t, p, "/v2/"+ociVerImage+"/manifests/v2"); code != http.StatusForbidden {
		t.Fatalf("v2 manifest = %d, want 403 (unscorable + policy=block)", code)
	}

	// 3. THE BYPASS. v2's layer, fetched directly with no manifest request of its own.
	body, code := ociGetBody(t, p, "/v2/"+ociVerImage+"/blobs/"+ociDigest(ociVerLayer2))
	if strings.Contains(body, ociVerLayer2) {
		t.Errorf("BYPASS: the BLOCKED version's layer was delivered byte-for-byte (status %d).\n"+
			"  The blob URL carries a digest but no tag, so the byte gate judged the bare\n"+
			"  image name — i.e. 'latest', which is allowed — instead of the version that\n"+
			"  manifest enumerated. See D164 and ociBlobBindings.", code)
	}
	if code == http.StatusOK {
		t.Errorf("v2 layer returned 200; want a refusal (got body %q)", body)
	}
}

// TestUnknownBlobDigestFallsBackToTheImageName pins the ADDITIVE property, which is
// the reason this change cannot break a working deployment.
//
// A digest we have no binding for — a cold `crane blob`, a client whose manifest is
// cached elsewhere, a blob upload path — must be judged exactly as it was before the
// binding existed: on the bare image name. If this ever becomes a refusal it is a
// deliberate, ruled posture change, not a side effect; see the note on ociBlobBindings.
func TestUnknownBlobDigestFallsBackToTheImageName(t *testing.T) {
	up := newOCIVersionUpstream()
	defer up.Close()

	p := newTestProxy(t, up.Server, func(c *Config) {
		c.Ecosystem = "oci"
		c.ScoreThreshold = 5.0
		c.UnscorablePolicy = "block"
		c.ByteGate = byteGateEnforce
	})

	// No manifest request first, so nothing is bound. v1's layer belongs to an image
	// whose "latest" is allowed, so it must be served — the pre-binding behaviour.
	body, code := ociGetBody(t, p, "/v2/"+ociVerImage+"/blobs/"+ociDigest(ociVerLayer1))
	if code != http.StatusOK || !strings.Contains(body, ociVerLayer1) {
		t.Errorf("unbound blob of an ALLOWED image = %d %q, want 200 with the layer bytes.\n"+
			"  A digest with no recorded binding must fall back to the bare image name.\n"+
			"  Refusing it here would break every client that reaches bytes without a\n"+
			"  manifest request — which is most of them.", code, body)
	}
}

// ociGet issues a request through the proxy and returns the status.
func ociGet(t *testing.T, p *proxyServer, path string) int {
	t.Helper()
	_, code := ociGetBody(t, p, path)
	return code
}

func ociGetBody(t *testing.T, p *proxyServer, path string) (string, int) {
	t.Helper()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Body.String(), rec.Code
}
