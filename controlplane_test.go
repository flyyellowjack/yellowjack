package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// npm's control plane must stay ungated WITHOUT us recognising it (issue #30).
//
// # The failure this guards against
//
// Another tool gated npm's control plane with an ALLOWLIST of known endpoints. On
// 2026-05-22 npm shipped staged publishing, and every `npm stage list|view|approve`
// started returning 403 Forbidden through their proxy, because their allowlist had never
// heard of "/-/stage". Their users' documented workaround was to invoke npm directly —
// i.e. to stop using the firewall. A gate that breaks the client on an upstream feature
// release gets uninstalled, and no amount of correct blocking compensates.
//
// We are immune to that class by design: npmEcosystem.ControlPlanePath is a PREFIX test
// ("/-/…"), not an enumeration, so an endpoint that does not exist yet passes for the same
// reason /-/ping does. But immune-by-design is worth nothing unasserted — someone
// tightening path handling later gets no failing test, and the first symptom is a
// customer's CI breaking on an npm feature we have never heard of.
//
// # If you came here from the Ecosystem interface doc, read this first
//
// That doc says "MATCH STRICTLY — no case folding, no prefix tests where an exact one will
// do", and it is right for OCI, PyPI and Maven. npm is the deliberate exception, because an
// exact match will NOT do: the set of control-plane endpoints is open and npm adds to it
// without telling us. Tightening npm's ControlPlanePath to exact matching is precisely the
// other product's bug, and it is what the negative control for this test reproduces — with the
// allowlist in place, the pre-existing TestNpmControlPlaneNotGatedUnderEnforce still PASSES
// while the tests below fail with 403 on /-/stage. That is why these exist.
//
// The strictness the interface doc is protecting is preserved elsewhere for npm: the byte
// gate claims "/<pkg>/-/<file>.tgz" BEFORE this method sees it, so widening here cannot
// wave an artifact through as infrastructure. The split test below pins that.
//
// bytegate_test.go already asserts /-/ping, /-/whoami and the advisories-bulk endpoint
// pass under enforce. Every one of those is an endpoint WE ALREADY KNOW ABOUT — which is
// precisely the shape of that bug, since their allowlist also handled every
// endpoint they knew about. So the assertion that actually guards it is the one below:
// endpoints chosen specifically because nothing in this repo mentions them.
//
// # The split, and why it is asserted in BOTH directions
//
// The code distinguishes on the prefix BEFORE "/-/":
//
//	empty prefix     — "/-/ping", "/-/stage", "/-/npm/v2/anything"   → ungated passthrough
//	non-empty prefix — "/lodash/-/lodash-4.17.21.tgz"                → GATED at the byte level
//
// Collapsing that distinction one way reproduces that outage. Collapsing it
// the other way reopens issue #11 — `npm ci` fetches tarballs straight from lockfile URLs
// without ever requesting metadata, so artifact bytes must stay gated on the byte path.
//
// This is worth stating loudly because this issue's ORIGINAL acceptance criteria listed
// "/lodash/-/lodash-4.17.21.tgz" among the paths that must pass ungated. That was true
// when it was filed and is now deliberately false (#11, D70/D72). Implementing it
// literally would produce a red test whose obvious fix is to loosen the byte gate — i.e.
// to silently reopen the lockfile side-door. Both directions are asserted here so neither
// mistake can be made quietly.

// spyUpstream records every path the firewall actually forwarded, so "ungated" can be
// checked as REACHED UPSTREAM rather than merely "returned 200". A 200 the firewall
// synthesised itself is not passthrough, and a test that only read the status could not
// tell the two apart.
type spyUpstream struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string
}

func newSpyUpstream() *spyUpstream {
	s := &spyUpstream{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.seen = append(s.seen, r.URL.Path)
		s.mu.Unlock()
		w.Write([]byte(`{"ok":true}`))
	}))
	return s
}

func (s *spyUpstream) sawPath(p string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, got := range s.seen {
		if got == p {
			return true
		}
	}
	return false
}

// unknownControlPlaneEndpoints are chosen because NOTHING in this repo handles them by
// name. "/-/stage" is the real endpoint that broke that product; the others stand in for
// whatever npm ships next. If any of these ever acquires special handling, replace it here
// with one that has none — the value of this list is entirely in its unfamiliarity.
var unknownControlPlaneEndpoints = []string{
	"/-/stage",                        // npm staged publishing, shipped 2026-05-22
	"/-/some-future-npm-feature",      // does not exist; that is the point
	"/-/npm/v2/whatever",              // a version bump of a namespace we do handle
	"/-/npm/v1/security/audits/quick", // a sibling of an endpoint we DO know
}

// TestNpmUnknownControlPlaneEndpointStaysUngated is the assertion issue #30 exists for.
//
// Run at the STRICTEST posture we ship — a threshold nothing can pass, the byte gate
// enforcing, and the unknown-path policy at its default block — so a passthrough here
// cannot be an artefact of a permissive configuration.
func TestNpmUnknownControlPlaneEndpointStaysUngated(t *testing.T) {
	upstream := newSpyUpstream()
	defer upstream.Close()

	p := newTestProxy(t, upstream.Server, func(c *Config) {
		c.ScoreThreshold = 10.0      // nothing could pass the gate on its merits
		c.ByteGate = byteGateEnforce // the strictest byte posture
		// Left empty on purpose: unknownPathPolicy("") reads as "block", so this is the
		// SHIPPED default rather than a value chosen to make the test pass.
		c.UnknownPathPolicy = ""
	})

	// Anti-vacuity: prove the gate is genuinely ON in this configuration before reading
	// anything into a request that got through. Without this, every passthrough below is
	// equally explained by a firewall that gates nothing at all.
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/lodash", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("control: an ordinary package request returned 200 at threshold 10.0 — the gate is "+
			"not enforcing, so 'the control plane passed through' proves nothing (body: %s)",
			rec.Body.String())
	}

	for _, path := range unknownControlPlaneEndpoints {
		t.Run("ungated: "+path, func(t *testing.T) {
			// POST, because npm's control plane mixes verbs: `npm audit` is a POST that is
			// semantically a read, and `npm login` is a PUT. Using POST keeps this honest
			// about the surface rather than testing the easy GET case.
			req := httptest.NewRequest(http.MethodPost, "http://fw.local"+path, strings.NewReader(`{}`))
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("CONTROL PLANE BROKEN: POST %s returned %d, want 200.\n"+
					"An endpoint we do not recognise must still pass through — recognising it is exactly "+
					"the allowlist design that broke another tool when npm shipped /-/stage. "+
					"(body: %s)", path, rec.Code, rec.Body.String())
				return
			}
			// A 200 is not enough: it has to have REACHED the registry.
			if !upstream.sawPath(path) {
				t.Errorf("POST %s returned 200 but the request never reached upstream — it was answered "+
					"locally, so the client did not actually get its control-plane call", path)
			}
		})
	}

	// The other direction of the split. This must stay GATED, or issue #11's lockfile
	// side-door reopens: `npm ci` fetches this exact URL shape with no metadata request.
	t.Run("still gated: a package artifact under the same /-/ marker", func(t *testing.T) {
		const tarball = "/lodash/-/lodash-4.17.21.tgz"
		req := httptest.NewRequest(http.MethodGet, "http://fw.local"+tarball, nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)

		if rec.Code == http.StatusOK {
			t.Errorf("GATE REGRESSION (#11): GET %s returned 200. A NON-EMPTY prefix before /-/ is a "+
				"package artifact and must be gated at the byte level — `npm ci` fetches exactly this "+
				"URL from a lockfile without ever requesting metadata. Treating it as control plane "+
				"reopens the side-door #11 closed.", tarball)
		}
		if upstream.sawPath(tarball) {
			t.Errorf("GET %s was forwarded upstream — a blocked package's bytes must not be fetched at all",
				tarball)
		}
	})
}

// TestNpmControlPlaneIdentityIsEmptyForBothShapes pins the parser-level property the
// passthrough rests on: neither shape yields a package name, so the METADATA control point
// cannot misparse either one as a package to score.
//
// Separate from the behavioural test because it fails at a different layer and with a
// different meaning: this going red means the parser changed, whereas the test above going
// red means routing changed. Told apart, the two localise a regression immediately.
func TestNpmControlPlaneIdentityIsEmptyForBothShapes(t *testing.T) {
	e := npmEcosystem{}

	for _, path := range append([]string{"/-/ping", "/"}, unknownControlPlaneEndpoints...) {
		if name := e.PackageNameFromPath(path); name != "" {
			t.Errorf("PackageNameFromPath(%q) = %q, want \"\" — a control-plane path names no package, "+
				"and scoring one would both break the endpoint and record a meaningless verdict", path, name)
		}
		if !e.ControlPlanePath(path) {
			t.Errorf("ControlPlanePath(%q) = false, want true. This is the prefix test that makes us "+
				"immune to that allowlist bug; an endpoint we have never heard of must "+
				"match it.", path)
		}
	}

	// The artifact shape: explicitly NOT control plane, or the byte gate is bypassed for
	// every lockfile fetch (#11).
	const tarball = "/lodash/-/lodash-4.17.21.tgz"
	if e.ControlPlanePath(tarball) {
		t.Errorf("ControlPlanePath(%q) = true — a package artifact must never be classified as "+
			"infrastructure, or the byte gate is bypassed for every lockfile fetch (#11)", tarball)
	}
}
