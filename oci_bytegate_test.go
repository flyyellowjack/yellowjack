package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Issue #11 / D70 deferred an OCI byte gate on REASONING, not evidence. The
// argument was:
//
//	"no ordinary OCI client fetches a blob without first fetching the manifest,
//	 which IS gated."
//
// That argument has two separable claims, and they need separate evidence:
//
//	CLAIM 1 (structural): the blob path is ungated. If a blob request arrives, the
//	  firewall does not evaluate it. This is decidable in-process, here.
//	CLAIM 2 (behavioural): no real client ever sends one without a gated manifest
//	  request first. That needs REAL CLIENTS — see e2e/oci_blob_test.go.
//
// Claim 1 is the load-bearing one: if the blob path is ungated, then the whole
// deferral rests entirely on client behaviour being universally well-mannered —
// including for a client whose manifest is already cached, one pulling by digest,
// one resuming a partial layer, and any tool that fetches blobs directly. These
// tests established exactly what claim 1 was worth: nothing.
//
// BOTH CLAIMS FAILED, and issue #57 fixed the gate: OCI blob fetches now run through
// proxyServer.proxyArtifactBytes on the same FW_BYTE_GATE knob as npm tarballs,
// evaluating the <name> the distribution spec puts in the blob URL itself.
//
// The tests below were written as CHARACTERIZATION tests asserting the defect, and
// are kept in place INVERTED rather than deleted — each now fails if the bypass
// returns, and the assertion messages name issue #57 so a future regression arrives
// with its own history attached.

// ociSpyUpstream is a fake OCI registry that serves one image and records every
// path it is asked for. As with the Maven spy, the recorder is the bypass
// detector: bytes leaving the upstream is the failure, not the status the client saw.
type ociSpyUpstream struct {
	*httptest.Server
	mu  sync.Mutex
	hit []string
}

// The image under test. Its config blob declares a source repo so the image is
// SCORED (stub 7.5) rather than unscorable — a positive-finding denial under a
// 9.9 threshold, exactly like the Maven case.
const (
	spyImage     = "library/badimage"
	spyLayerBody = "LAYER-PAYLOAD-DELIVERED"
)

// ociDigest returns the "sha256:..." digest of s, the way a registry addresses a blob.
func ociDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func newOciSpyUpstream() *ociSpyUpstream { return newOciSpyUpstreamOpts(false) }

// newOciSpyUpstreamOpts builds the spy registry. failMeta makes the manifest and
// config-blob reads — everything the firewall needs to EVALUATE the image — fail
// transiently with a 503, while the LAYER blob keeps serving normally.
//
// That asymmetry is the whole point, and it is the shape #60 was reachable through:
// the bytes are one relay away while evaluation is impossible. A spy that failed
// everything would prove nothing, because the layer would be unavailable anyway and
// a "nothing was delivered" pass could not distinguish the gate working from the
// upstream simply being down.
//
// failMeta is fixed at construction rather than toggled on the struct so the handler
// goroutine never races the test goroutine reading it (-race runs in CI).
func newOciSpyUpstreamOpts(failMeta bool) *ociSpyUpstream {
	u := &ociSpyUpstream{}
	configBody := `{"config":{"Labels":{"org.opencontainers.image.source":"https://github.com/evil/badimage"}}}`
	configDigest := ociDigest(configBody)
	layerDigest := ociDigest(spyLayerBody)

	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hit = append(u.hit, r.URL.Path)
		u.mu.Unlock()

		switch {
		case strings.Contains(r.URL.Path, "/manifests/"):
			if failMeta {
				http.Error(w, "registry is briefly unreachable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			fmt.Fprintf(w, `{"config":{"digest":%q},"layers":[{"digest":%q}]}`, configDigest, layerDigest)
		case strings.HasSuffix(r.URL.Path, "/blobs/"+configDigest):
			if failMeta {
				http.Error(w, "registry is briefly unreachable", http.StatusServiceUnavailable)
				return
			}
			fmt.Fprint(w, configBody)
		case strings.HasSuffix(r.URL.Path, "/blobs/"+layerDigest):
			// The actual layer bytes — what an attacker wants delivered.
			fmt.Fprint(w, spyLayerBody)
		default:
			fmt.Fprint(w, "{}")
		}
	}))
	return u
}

func (u *ociSpyUpstream) contacted(sub string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, p := range u.hit {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

// paths returns every path the upstream was asked for, for diagnostics.
func (u *ociSpyUpstream) paths() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.hit...)
}

func newOciTestProxy(t *testing.T, upstream *httptest.Server) *proxyServer {
	t.Helper()
	return newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "oci"
		c.ScoreThreshold = 9.9 // stub 7.5 -> below threshold -> hard deny
		c.ByteGate = byteGateEnforce
	})
}

// TestOciManifestIsGated is the NEGATIVE CONTROL: it proves this rig detects a
// working gate. The manifest IS the documented OCI control point, so a
// below-threshold image must be denied there.
func TestOciManifestIsGated(t *testing.T) {
	up := newOciSpyUpstream()
	defer up.Close()
	p := newOciTestProxy(t, up.Server)

	code, body := get(t, p, "/v2/"+spyImage+"/manifests/latest")
	if code == http.StatusOK {
		t.Fatalf("manifest of a below-threshold image returned 200 — the OCI control "+
			"point is not gating at all; body=%q", body)
	}
	t.Logf("control: manifest correctly denied with status %d", code)
}

// TestOciBlobPathIsGated settles CLAIM 1: for an image the firewall has DECIDED to
// block, a blob request is refused and the layer is never fetched from upstream.
//
// This test was, until issue #57 was fixed, a CHARACTERIZATION test asserting the
// exact opposite — that the blob sailed through. It is kept in place, inverted,
// rather than deleted: the assertion that a blocked image's layer cannot be reached
// by its blob URL is now a permanent invariant, and the file's history is the record
// of what the D70 deferral was actually worth. TestOciManifestIsGated below/above is
// the negative control proving this rig can tell a gate from no gate.
//
// The upstream-contact check is the load-bearing half. A 403 with the layer already
// pulled from upstream is still a bypass — the bytes left the registry, we just
// declined to forward them — so "did the upstream get asked for the layer" is the
// real assertion and the status is the secondary one.
func TestOciBlobPathIsGated(t *testing.T) {
	up := newOciSpyUpstream()
	defer up.Close()
	p := newOciTestProxy(t, up.Server)

	// Establish the image really is blocked, so a refusal below can't be mistaken for
	// some unrelated failure on an image that was never blockable.
	if code, _ := get(t, p, "/v2/"+spyImage+"/manifests/latest"); code == http.StatusOK {
		t.Fatalf("precondition failed: manifest returned 200, image is not blocked")
	}

	layerDigest := ociDigest(spyLayerBody)
	blobPath := "/v2/" + spyImage + "/blobs/" + layerDigest

	code, body := get(t, p, blobPath)
	delivered := code == http.StatusOK && strings.Contains(body, spyLayerBody)
	fetched := up.contacted("/blobs/" + layerDigest)

	if delivered || fetched {
		t.Errorf("issue #57 REGRESSED: a blocked image's layer escaped via the blob path "+
			"(status=%d bytesDelivered=%v upstreamContactedForLayer=%v).\n"+
			"  The blob path must be evaluated exactly like the manifest path — see\n"+
			"  ociBlobPath and proxyServer.proxyArtifactBytes.\n"+
			"  upstream saw: %v", code, delivered, fetched, up.paths())
	}
	if code != http.StatusForbidden {
		t.Errorf("blob of a below-threshold image returned %d, want 403 — a hard deny "+
			"(score below threshold) must refuse bytes in every FW_BYTE_GATE mode (D72)", code)
	}
}

// TestOciBlobGatedEvenWithoutPriorManifest is the case the D70 deferral quietly
// assumed away: a client that never sends a manifest request at all — because its
// manifest is already cached locally, because it is pulling by digest from a stored
// reference, because it is resuming a partial layer, or because it is a tool that
// reads blobs directly (`crane blob`, `oras blob fetch`).
//
// The CLIENT sends only the blob request here. That is the whole point: before the
// fix the gate had no opportunity to act, because its only control point was a
// request this client never makes.
//
// NOTE on the upstream's view of "/manifests/", which changed meaning with the fix
// and will mislead anyone who greps for it: the spy now DOES record manifest hits in
// this test. They are the FIREWALL's own — evaluating the blob calls LookupRepo,
// which reads the manifest and config blob to resolve the source repo. That is the
// gate working, not the client walking the manifest path. So the assertion below is
// on the LAYER specifically, never on "/manifests/" or a bare "/blobs/".
func TestOciBlobGatedEvenWithoutPriorManifest(t *testing.T) {
	up := newOciSpyUpstream()
	defer up.Close()
	p := newOciTestProxy(t, up.Server)

	layerDigest := ociDigest(spyLayerBody)
	code, body := get(t, p, "/v2/"+spyImage+"/blobs/"+layerDigest)
	delivered := code == http.StatusOK && strings.Contains(body, spyLayerBody)

	if delivered {
		t.Errorf("issue #57 REGRESSED: layer bytes delivered on the no-manifest path "+
			"(status=%d). This is the crane-blob shape — the client never asks for the "+
			"manifest, so the manifest gate can never fire and the blob gate is the only "+
			"thing standing between a blocked image and its bytes.", code)
	}
	if up.contacted("/blobs/" + layerDigest) {
		t.Errorf("issue #57 REGRESSED: the upstream was asked for the LAYER (%s). Even if "+
			"the client is then refused, the bytes already left the registry.\n"+
			"  upstream saw: %v", layerDigest, up.paths())
	}
	if code != http.StatusForbidden {
		t.Errorf("blob returned %d, want 403", code)
	}
}

// TestOciBlobPathParsing pins the parser itself, separately from the proxy, because
// the parser is where a silent bypass would live: any path shape it fails to
// recognise as a blob fetch goes back to being relayed ungated, and no status code
// anywhere would look wrong.
func TestOciBlobPathParsing(t *testing.T) {
	const digest = "sha256:abc123"
	cases := []struct {
		path, want, why string
	}{
		{"/v2/library/alpine/blobs/" + digest, "library/alpine",
			"the ordinary shape: <name> has a slash in it, as most real images do"},
		{"/v2/alpine/blobs/" + digest, "alpine",
			"single-segment name (a registry root namespace)"},
		{"/v2/a/b/c/d/blobs/" + digest, "a/b/c/d",
			"deeply nested name — Harbor/GitLab registries nest several levels"},

		// The reason ociNameBefore splits on the LAST separator. "blobs" is a legal
		// component of a repository name, so a first-match split would evaluate the
		// image "evil" — a DIFFERENT package, with a different verdict, while serving
		// this one's bytes. Cheap to get wrong, invisible when wrong.
		{"/v2/evil/blobs/x/blobs/" + digest, "evil/blobs/x",
			"a repository literally named \".../blobs/...\" must not be truncated"},

		// Not blob fetches: these must return "" so they keep flowing to the paths
		// that do handle them, rather than being evaluated as a package.
		{"/v2/library/alpine/manifests/latest", "", "a manifest is the metadata gate's job"},
		{"/v2/", "", "the version handshake"},
		{"/v2/library/alpine/tags/list", "", "a tag listing carries no artifact bytes"},
		{"/blobs/" + digest, "", "not under /v2/ at all"},
		{"/v2/blobs/" + digest, "", "no <name> before the separator — empty identity, never gate on it"},
	}
	for _, c := range cases {
		got, ok := ociBlobPath(c.path)
		if got != c.want {
			t.Errorf("ociBlobPath(%q) = %q, want %q — %s", c.path, got, c.want, c.why)
		}
		if ok != (c.want != "") {
			t.Errorf("ociBlobPath(%q) ok = %v, want %v", c.path, ok, c.want != "")
		}
	}
}

// TestOciBlobGateFollowsByteGateMode proves OCI honours the SAME FW_BYTE_GATE
// semantics npm got in D72, rather than having grown a parallel knob that happens to
// look similar. The distinction D72 draws is between two unlike denials:
//
//   - a HARD deny (scored below threshold / a human said no) is a POSITIVE FINDING.
//     Serving those bytes was never the intent, so it is refused in every mode.
//   - a SOFT deny (we could not score or verify it) is an ABSENCE OF TRUST. It fires
//     on plenty of legitimate packages, so allow-but-log keeps serving them — that is
//     the whole reason the default is visibility-first.
//
// Getting this backwards for OCI would be the quiet kind of wrong: enforce-only
// gating would leave the default deployment exactly as exposed as before the fix.
func TestOciBlobGateFollowsByteGateMode(t *testing.T) {
	layerDigest := ociDigest(spyLayerBody)
	blobPath := "/v2/" + spyImage + "/blobs/" + layerDigest

	// spyImage declares a source repo, so stub scores it 7.5. Threshold decides which
	// kind of denial we get; unscorable=block turns "no repo" into a SOFT deny.
	cases := []struct {
		name          string
		byteGate      string
		threshold     float64
		failMeta      bool
		wantDelivered bool
		why           string
	}{
		{"off/hard-deny", byteGateOff, 9.9, false, true,
			"off is the documented escape hatch — it disables the gate entirely, by design"},
		{"allow-but-log/hard-deny", byteGateAllowButLog, 9.9, false, false,
			"D72: a positive finding refuses bytes even in visibility mode"},
		{"enforce/hard-deny", byteGateEnforce, 9.9, false, false,
			"enforce refuses everything not allowed"},
		{"allow-but-log/allowed", byteGateAllowButLog, 1.0, false, true,
			"an image above threshold is simply allowed; the gate must not block on merit it has"},
		{"enforce/allowed", byteGateEnforce, 1.0, false, true,
			"same, under enforce"},

		// #60 — the rows this table was MISSING, and the reason the npm twin of this
		// bug survived: every case above supplies a completed verdict, so none of them
		// exercised "we could not evaluate at all".
		//
		// An Unavailable verdict carries an EMPTY deny kind, because evaluation never
		// got far enough to establish one — so it is not a hardDeny and the D72 row
		// above does not cover it. A threshold of 1.0 is used deliberately: on a
		// healthy registry this image is ALLOWED, so nothing here is a disguised
		// hard-deny test. The only reason to withhold the bytes is that we could not look.
		{"allow-but-log/unavailable", byteGateAllowButLog, 1.0, true, false,
			"#60: evaluation failed, so the verdict kind is unknown — bytes are withheld even in visibility mode, " +
				"or degrading our path to the registry becomes a policy bypass"},
		{"enforce/unavailable", byteGateEnforce, 1.0, true, false,
			"#60: same under enforce, which already refused here"},
		{"off/unavailable", byteGateOff, 1.0, true, true,
			"off still disables the gate entirely — no evaluation is attempted at all, so there is no verdict to withhold on. " +
				"Pinned so the escape hatch's meaning stays explicit rather than accidental"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			up := newOciSpyUpstreamOpts(c.failMeta)
			defer up.Close()
			p := newTestProxy(t, up.Server, func(cfg *Config) {
				cfg.Ecosystem = "oci"
				cfg.ScoreThreshold = c.threshold
				cfg.ByteGate = c.byteGate
			})

			code, body := get(t, p, blobPath)
			delivered := code == http.StatusOK && strings.Contains(body, spyLayerBody)
			if delivered != c.wantDelivered {
				t.Errorf("FW_BYTE_GATE=%s threshold=%v failMeta=%v: layer delivered=%v, want %v (status=%d)\n"+
					"  %s\n  upstream saw: %v",
					c.byteGate, c.threshold, c.failMeta, delivered, c.wantDelivered, code, c.why, up.paths())
			}
			// A withheld-on-unavailable case must say WHY it was withheld: the image is
			// not being judged, we simply could not look. Asserting this separately keeps
			// "withheld correctly" distinct from "withheld by breaking the product",
			// which a delivered=false check alone cannot tell apart.
			//
			// Under D102 that distinction moved from the status code (503 vs 403) into
			// the explanation, since both outcomes are now 403. So the explanation is
			// what gets asserted — and it must reach the client through OCI's
			// distribution-spec error shape, not just our own header.
			if c.failMeta && !c.wantDelivered {
				if code != http.StatusForbidden {
					t.Errorf("FW_BYTE_GATE=%s: status = %d, want 403 (D102)", c.byteGate, code)
				}
				if !strings.Contains(body, unavailableErrMsg) {
					t.Errorf("FW_BYTE_GATE=%s: body = %s\n  want the UNAVAILABLE explanation %q — "+
						"an unevaluable image must not be reported as a verdict about the image",
						c.byteGate, body, unavailableErrMsg)
				}
			}
		})
	}
}

// ociBlobEvasions are request-path spellings for a blob that a real OCI client never
// emits and an attacker does. Each aims at the same bytes by a route the gate might
// not recognise as a blob fetch — and anything the gate does not RECOGNISE is relayed
// ungated, which is a 200 with the payload and no decision line anywhere.
//
// "/V2/" is not hypothetical padding: it MEASURABLY leaked the layer when this fix was
// first written, because both OCI parsers required a lowercase "v2/" and anything else
// fell through to the infrastructure relay. See ociNameBefore.
var ociBlobEvasions = []struct{ name, path, why string }{
	{"uppercase API prefix", "/V2/" + spyImage + "/blobs/%s",
		"measured leaking the layer before ociNameBefore folded the structural tokens"},
	{"uppercase separator", "/v2/" + spyImage + "/Blobs/%s",
		"same class as /V2/ — the separator is structural too"},
	{"mixed-case separator", "/v2/" + spyImage + "/bLoBs/%s",
		"case folding must be total, not a two-spelling special case"},
	{"trailing slash", "/v2/" + spyImage + "/blobs/%s/",
		"a trailing slash must not turn a blob into an unrecognised path"},
	{"query string", "/v2/" + spyImage + "/blobs/%s?ignored=1",
		"the query is not part of the path identity and must not shift it"},
	{"blob under a name containing \"blobs\"", "/v2/" + spyImage + "/blobs/x/blobs/%s",
		"a first-match split would evaluate a DIFFERENT, possibly allowed, image"},
	{"manifest-shaped prefix", "/v2/" + spyImage + "/manifests/latest/blobs/%s",
		"must not be mistaken for a manifest request and pass the byte gate untested"},
	{"upload session path", "/v2/" + spyImage + "/blobs/uploads/xyz",
		"the push endpoint shares the /blobs/ prefix; it must not become an ungated hole"},
}

// TestOciBlobGateResistsPathEvasion is the TIER-3 (adversarial) leg for issue #57 —
// the firewall under attack rather than under use. Tier 2 structurally cannot find
// this class: an honest OCI client never spells a blob URL any of these ways.
//
// It asserts on CONTENT, not status. The bypass class being guarded returns a
// perfectly ordinary 200; a test that accepted "not 200" would have passed against the
// very defect that motivated this file.
//
// The DISCRIMINATOR is the second half: "nothing came back" is also what a broken
// firewall produces, so every evasion is replayed against a deliberately PERMISSIVE
// config in which the honest path demonstrably serves the layer. A refusal in the
// strict run only means something because the same request succeeds in the permissive
// one — that is what separates "the gate stopped it" from "we broke the proxy".
func TestOciBlobGateResistsPathEvasion(t *testing.T) {
	digest := ociDigest(spyLayerBody)

	// ---- strict: everything is blocked; no spelling may return the layer ----
	up := newOciSpyUpstream()
	defer up.Close()
	strict := newOciTestProxy(t, up.Server) // threshold 9.9 -> hard deny, enforce

	// Anti-vacuity: the rig must be able to serve these bytes at all, or every
	// assertion below passes for free.
	if code, body := get(t, strict, "/v2/"+spyImage+"/manifests/latest"); code == http.StatusOK {
		t.Fatalf("precondition: image is not blocked (manifest 200, body=%q)", body)
	}

	for _, ev := range ociBlobEvasions {
		path := ev.path
		if strings.Contains(path, "%s") {
			path = fmt.Sprintf(path, digest)
		}
		code, body := get(t, strict, path)
		if strings.Contains(body, spyLayerBody) {
			t.Errorf("BYPASS via %s: %s\n  returned status %d WITH the layer payload.\n  %s",
				ev.name, path, code, ev.why)
		}
		if up.contacted("/blobs/" + digest) {
			t.Errorf("BYPASS via %s: %s\n  the upstream was asked for the layer; the bytes "+
				"left the registry even if the client was refused.\n  %s", ev.name, path, ev.why)
			up = newOciSpyUpstream() // reset so one failure doesn't cascade
		}
	}

	// ---- discriminator: the same spellings against a permissive firewall ----
	// Here the image is ALLOWED, so any refusal is the path handling, not the verdict.
	// This is what proves the strict run's refusals were decisions rather than damage.
	up2 := newOciSpyUpstream()
	defer up2.Close()
	permissive := newTestProxy(t, up2.Server, func(c *Config) {
		c.Ecosystem = "oci"
		c.ScoreThreshold = 1.0 // stub 7.5 clears it -> allowed
		c.ByteGate = byteGateEnforce
	})
	if code, body := get(t, permissive, "/v2/"+spyImage+"/blobs/"+digest); !strings.Contains(body, spyLayerBody) {
		t.Fatalf("DISCRIMINATOR BROKEN: the honest blob path does not serve the layer even "+
			"when the image is ALLOWED (status=%d). Every refusal above is then "+
			"meaningless — it could just be a broken proxy.\n  body=%q", code, body)
	}
	t.Log("discriminator: the honest blob path serves the layer when allowed, so the " +
		"refusals above are the gate acting, not the proxy failing")
}

// TestOciBlobGateAppliesToHeadAndRange covers the two request shapes the D70 deferral
// named as its own counter-examples and which therefore must not be exempt.
//
// HEAD is how docker checks whether it already has a blob, and Range is how a client
// RESUMES a partial layer — the case where, by construction, no manifest request is
// coming. Both were gated correctly on the first run; they are pinned here because an
// optimization that skipped the gate for "cheap" methods would be an easy and
// invisible thing for a later change to add.
func TestOciBlobGateAppliesToHeadAndRange(t *testing.T) {
	up := newOciSpyUpstream()
	defer up.Close()
	p := newOciTestProxy(t, up.Server)
	blobPath := "/v2/" + spyImage + "/blobs/" + ociDigest(spyLayerBody)

	for _, tc := range []struct{ name, method, rangeHdr string }{
		{"HEAD", http.MethodHead, ""},
		{"ranged GET (resumed layer)", http.MethodGet, "bytes=0-1023"},
	} {
		req := httptest.NewRequest(tc.method, "http://firewall.local"+blobPath, nil)
		if tc.rangeHdr != "" {
			req.Header.Set("Range", tc.rangeHdr)
		}
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("%s on a blocked image's blob returned %d, want 403", tc.name, rec.Code)
		}
		if strings.Contains(rec.Body.String(), spyLayerBody) {
			t.Errorf("%s on a blocked image's blob returned layer payload", tc.name)
		}
		// A HEAD carries no body, so the reason has to survive on a header or the
		// developer sees an unexplained failure. That is why writeBlock sets it.
		if rec.Header().Get("X-Yellowjack-Reason") == "" {
			t.Errorf("%s: no X-Yellowjack-Reason header — a body-less client gets no "+
				"explanation for the refusal", tc.name)
		}
	}
}

// TestOciConfigBlobLookupDoesNotRecurse guards the one genuinely circular-looking
// piece of this fix. Evaluating a blob calls LookupRepo, which itself READS A BLOB —
// the image config, for its org.opencontainers.image.source label. If that internal
// read ever went back through the proxy it would be gated, calling LookupRepo again,
// forever.
//
// It does not, because the ecosystem talks to cfg.UpstreamRegistry directly rather
// than to ourselves. That is a property of wiring, which is exactly the kind of thing
// a later refactor can quietly break, so it gets a test rather than a comment: an
// infinite recursion here would hang or blow the stack, and this test would catch it
// as a timeout instead of a mystery in production.
func TestOciConfigBlobLookupDoesNotRecurse(t *testing.T) {
	up := newOciSpyUpstream()
	defer up.Close()
	p := newOciTestProxy(t, up.Server)

	done := make(chan struct{})
	go func() {
		defer close(done)
		get(t, p, "/v2/"+spyImage+"/blobs/"+ociDigest(spyLayerBody))
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("gating a blob did not terminate — LookupRepo's own config-blob read is " +
			"most likely routing back through the proxy and re-entering the gate")
	}

	// A bounded number of upstream reads, not an unbounded retry storm: manifest(s)
	// plus the config blob for one evaluation.
	if n := len(up.paths()); n > 8 {
		t.Errorf("evaluating one blob made %d upstream requests: %v", n, up.paths())
	}
}
