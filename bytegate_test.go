package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestNpmArtifactPath pins the URL parsing that the whole byte gate rests on. The
// dangerous failure here is silent: a path we fail to recognize as an artifact is
// passed through UNGATED (the pre-#11 hole), and a name we mis-parse evaluates some
// other package — which, being unknown, resolves toward allow. So both directions
// are asserted, including the control-plane endpoints that must stay ungated.
func TestNpmArtifactPath(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		wantPkg string
		wantObj string
		wantOK  bool
	}{
		// Shape 2 — the registry's own convention, which is what a lockfile's
		// "resolved" URL contains and what `npm ci` therefore requests.
		{"native tarball", "/lodash/-/lodash-4.17.21.tgz", "lodash", "/lodash/-/lodash-4.17.21.tgz", true},
		{"native scoped tarball", "/@babel/core/-/core-7.0.0.tgz", "@babel/core", "/@babel/core/-/core-7.0.0.tgz", true},
		{"native scoped encoded", "/@babel%2fcore/-/core-7.0.0.tgz", "@babel/core", "/@babel%2fcore/-/core-7.0.0.tgz", true},
		// The name comes from the path prefix, NEVER the filename: a hyphenated
		// name+version is not separable, and guessing would evaluate the wrong thing.
		{"hyphenated name not split", "/left-pad/-/left-pad-1.3.0.tgz", "left-pad", "/left-pad/-/left-pad-1.3.0.tgz", true},

		// Shape 1 — what relayRewritten mints, carrying the authoritative name.
		{"rewritten", "/_tarball/lodash/lodash/-/lodash-4.17.21.tgz", "lodash", "/lodash/-/lodash-4.17.21.tgz", true},
		{"rewritten scoped", "/_tarball/@babel%2Fcore/@babel/core/-/core-7.0.0.tgz", "@babel/core", "/@babel/core/-/core-7.0.0.tgz", true},
		// A registry whose artifact URLs do not follow the "/-/" convention still
		// re-gates, because the identity rides in the prefix rather than the shape.
		{"rewritten odd upstream shape", "/_tarball/lodash/files/abc123.tgz", "lodash", "/files/abc123.tgz", true},

		// npm's control plane: "/-/" with an EMPTY prefix. Gating these would
		// evaluate a package named after the endpoint and break audit/search/login.
		{"control plane audit", "/-/npm/v1/security/advisories/bulk", "", "", false},
		{"control plane ping", "/-/ping", "", "", false},
		{"control plane whoami", "/-/whoami", "", "", false},

		// Not artifacts: metadata paths keep flowing to the metadata control point.
		{"metadata", "/lodash", "", "", false},
		{"metadata scoped", "/@babel%2fcore", "", "", false},
		{"metadata version", "/lodash/latest", "", "", false},
		{"root", "/", "", "", false},
		// Malformed rewritten paths carry no object path to forward.
		{"rewritten no object path", "/_tarball/lodash", "", "", false},
		{"rewritten empty pkg", "/_tarball//lodash/-/lodash-1.0.0.tgz", "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg, obj, ok := npmArtifactPath(tc.path)
			if ok != tc.wantOK || pkg != tc.wantPkg || obj != tc.wantObj {
				t.Errorf("npmArtifactPath(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.path, pkg, obj, ok, tc.wantPkg, tc.wantObj, tc.wantOK)
			}
		})
	}
}

// npmTarballUpstream is a fake registry that serves metadata for `pkg` and tarball
// bytes for any "/-/" path. onTarball fires whenever the bytes are actually fetched,
// which is how the tests below detect a BYPASS (a gate that should have stopped the
// fetch but didn't) rather than only checking the status the client saw.
func npmTarballUpstream(t *testing.T, pkg, body string, onTarball func()) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := url.PathUnescape(r.URL.EscapedPath())
		switch {
		case strings.Contains(p, "/-/"):
			if onTarball != nil {
				onTarball()
			}
			w.Write([]byte(body))
		case p == "/"+pkg+"/latest", p == "/"+pkg:
			w.Write([]byte(`{"repository":"github.com/acme/` + pkg + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

// TestNpmTarballGateEnforceBlocks is the acceptance criterion for issue #11: an
// `npm ci` fetching a BLOCKED package's tarball straight from its lockfile
// "resolved" URL must be refused, not proxied. Both URL shapes are asserted,
// because both really arrive: the native one from lockfiles already in the wild
// (and from npm's own origin-swap), the "/_tarball/" one from metadata we rewrote.
func TestNpmTarballGateEnforceBlocks(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
	}{
		{"native lockfile URL", "http://fw.local/lodash/-/lodash-1.0.0.tgz"},
		{"rewritten URL", "http://fw.local/_tarball/lodash/lodash/-/lodash-1.0.0.tgz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			served := false
			upstream := npmTarballUpstream(t, "lodash", "raw-tarball-bytes", func() { served = true })
			defer upstream.Close()

			p := newTestProxy(t, upstream, func(c *Config) {
				c.ScoreThreshold = 9.0 // stub scores 7.5 -> below threshold -> BLOCK
				c.ByteGate = byteGateEnforce
			})
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 — a blocked package's bytes must not be served (body: %s)",
					rec.Code, rec.Body.String())
			}
			if served {
				t.Error("BYPASS: the tarball was fetched from upstream despite the block")
			}
			if rec.Header().Get("X-Yellowjack-Reason") == "" {
				t.Error("blocked byte fetch missing X-Yellowjack-Reason header")
			}
			assertReasonSurfaced(t, rec, blockErrMsg)
		})
	}
}

// TestNpmTarballGateEnforceAllows is the other half of the same gate: enforcement
// must not break ordinary installs. An allowed package's bytes stream through
// VERBATIM — rewriting an artifact would corrupt it and fail npm's dist.integrity
// check, so this doubles as the guard on that.
func TestNpmTarballGateEnforceAllows(t *testing.T) {
	payload := "raw-tarball-bytes"
	upstream := npmTarballUpstream(t, "lodash", payload, nil)
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) { c.ByteGate = byteGateEnforce }) // stub 7.5 >= 5.0
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/lodash/-/lodash-1.0.0.tgz", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != payload {
		t.Errorf("tarball bytes altered by the gate: %q", rec.Body.String())
	}
}

// TestNpmTarballGateDefaultBlocksHardDeny is the D72 change, and it is the assertion
// that actually closes the lockfile side-door for the case that matters. Out of the
// box — no FW_BYTE_GATE set at all — a package the firewall denied on a POSITIVE
// FINDING (here, a score below the threshold) must not have its bytes served. Before
// D72 this returned 200: the same package installed or failed depending only on
// whether the developer ran `npm install` or `npm ci`.
func TestNpmTarballGateDefaultBlocksHardDeny(t *testing.T) {
	served := false
	upstream := npmTarballUpstream(t, "lodash", "raw-tarball-bytes", func() { served = true })
	defer upstream.Close()

	// No ByteGate set: exactly what a deployment gets with no FW_BYTE_GATE.
	p := newTestProxy(t, upstream, func(c *Config) { c.ScoreThreshold = 9.0 }) // stub 7.5 -> hard deny
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/lodash/-/lodash-1.0.0.tgz", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — a hard deny must block bytes even in the default mode (body: %s)",
			rec.Code, rec.Body.String())
	}
	if served {
		t.Error("BYPASS: the tarball was fetched from upstream despite a hard deny")
	}
}

// TestNpmTarballGateDefaultServesUnscorable is the other half of D72, and the reason
// the change is a scalpel rather than "make the default enforce": a package denied
// merely because we could not SCORE it still has its bytes served-and-logged under the
// default. That case fires on plenty of legitimate packages whose metadata is thin, and
// silently breaking those CI builds is exactly what the visibility-first default
// exists to avoid. So the noisy case keeps the old behaviour; only an affirmative
// refusal changed.
func TestNpmTarballGateDefaultServesUnscorable(t *testing.T) {
	payload := "raw-tarball-bytes"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/-/") {
			w.Write([]byte(payload))
			return
		}
		// Metadata with NO repository field -> nothing to score -> unscorable, which
		// under the default block policy is still a denial, but a soft one.
		w.Write([]byte(`{"name":"mystery"}`))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil) // UnscorablePolicy "block", no ByteGate set
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/mystery/-/mystery-1.0.0.tgz", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — an unscorable package keeps the allow-but-log default (body: %s)",
			rec.Code, rec.Body.String())
	}
	if rec.Body.String() != payload {
		t.Errorf("tarball bytes altered: %q", rec.Body.String())
	}
}

// TestDenyKindClassification pins which denials are HARD, because the byte gate's whole
// behaviour hangs off that one predicate. A denial reason added later must default to
// the SOFT side — someone has to opt it in deliberately — so this also guards the
// "unknown kind" case.
func TestDenyKindClassification(t *testing.T) {
	cases := []struct {
		name string
		d    Decision
		hard bool
	}{
		{"below threshold", Decision{Allowed: false, Deny: denyScore}, true},
		{"human denied", Decision{Allowed: false, Deny: denyHuman}, true},
		{"unscorable", Decision{Allowed: false, Deny: denyUnscorable}, false},
		{"unverified", Decision{Allowed: false, Deny: denyUnverified}, false},
		{"unknown future kind", Decision{Allowed: false, Deny: denyKind("something-new")}, false},
		{"allowed", Decision{Allowed: true}, false},
		{"allowed with a stray kind", Decision{Allowed: true, Deny: denyScore}, false},
		{"pending", Decision{Allowed: false, Pending: true}, false},
		{"unavailable", Decision{Allowed: false, Unavailable: true}, false},
	}
	for _, tc := range cases {
		if got := tc.d.hardDeny(); got != tc.hard {
			t.Errorf("%s: hardDeny() = %v, want %v", tc.name, got, tc.hard)
		}
	}
}

// TestNpmTarballGateOff verifies the escape hatch is a true escape hatch: no
// evaluation on the byte path, and metadata artifact URLs rewritten the pre-#11 way
// (plain host swap, no "/_tarball/" prefix).
func TestNpmTarballGateOff(t *testing.T) {
	payload := "raw-tarball-bytes"
	upstream := npmTarballUpstream(t, "lodash", payload, nil)
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.ScoreThreshold = 9.0 // would BLOCK if the byte path evaluated at all
		c.ByteGate = byteGateOff
	})

	req := httptest.NewRequest(http.MethodGet, "http://fw.local/lodash/-/lodash-1.0.0.tgz", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != payload {
		t.Fatalf("off mode did not pass the tarball through: status %d body %q", rec.Code, rec.Body.String())
	}
}

// TestNpmTarballGateOffKeepsPlainRewrite is the metadata half of "off": the
// packument's tarball URLs must come back on the plain proxy host, not through
// "/_tarball/", so the mode really is the pre-#11 behavior.
func TestNpmTarballGateOffKeepsPlainRewrite(t *testing.T) {
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lodash/latest":
			w.Write([]byte(`{"repository":"github.com/lodash/lodash"}`))
		case "/lodash":
			w.Write([]byte(`{"versions":{"1.0.0":{"dist":{"tarball":"` + upstream.URL + `/lodash/-/lodash-1.0.0.tgz"}}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) { c.ByteGate = byteGateOff })
	req := httptest.NewRequest(http.MethodGet, "http://fw.local:8080/lodash", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, npmTarballPrefix) {
		t.Errorf("off mode still rewrote artifact URLs through %s: %s", npmTarballPrefix, body)
	}
	if !strings.Contains(body, "http://fw.local:8080/lodash/-/lodash-1.0.0.tgz") {
		t.Errorf("off mode lost the plain host rewrite: %s", body)
	}
}

// TestNpmControlPlaneNotGatedUnderEnforce is the negative control on the parser:
// under the strictest mode, with a threshold that blocks everything, npm's registry
// API ("/-/npm/v1/…", ping, whoami) must still pass through. If npmArtifactPath ever
// starts matching an empty prefix, this goes red instead of npm silently losing
// audit and login.
func TestNpmControlPlaneNotGatedUnderEnforce(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.ScoreThreshold = 10.0 // nothing could pass the gate
		c.ByteGate = byteGateEnforce
	})
	for _, path := range []string{"/-/npm/v1/security/advisories/bulk", "/-/ping", "/-/whoami"} {
		req := httptest.NewRequest(http.MethodPost, "http://fw.local"+path, strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s gated: status = %d, want 200 (body: %s)", path, rec.Code, rec.Body.String())
		}
	}
}

// TestNpmTarballGateUnavailableIsForbidden keeps the byte path inside the CURRENT
// status taxonomy (D102): when we cannot reach metadata to decide, npm gets a 403
// whose explanation says we could not verify — not a 503, and not a bare block.
//
// The D17 rule this replaces said the opposite (a retryable 503, never a 403,
// because npm retries 5xx and treats 403 as final). That was a statement about what
// makes builds survive a hiccup, and it was correct on those terms. D102 overrides
// it on taxonomy: our inability to reach an upstream is not the client's server
// failing. The build-survival property is genuinely given up, not engineered around.
//
// The residual risk the old comment named — "teach developers that the firewall
// blocks at random" — is now carried entirely by the explanation string, which is
// why this asserts on it rather than on the status alone.
func TestNpmTarballGateUnavailableIsForbidden(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/-/") {
			w.Write([]byte("raw-tarball-bytes"))
			return
		}
		http.Error(w, "upstream down", http.StatusServiceUnavailable)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) { c.ByteGate = byteGateEnforce })
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/ghost/-/ghost-1.0.0.tgz", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an undecidable byte fetch (body: %s)", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, unavailableErrMsg) {
		t.Errorf("body = %s, want the UNAVAILABLE explanation %q — the refusal has to say we "+
			"could not evaluate, not that we judged the package (D102)", body, unavailableErrMsg)
	}
}

// TestNpmTarballGateDefaultWithholdsBytesWhenEvaluationFailed is the regression test for
// #60, and it is the DEFAULT-config twin of the enforce-mode test above — which is
// precisely the gap the bug lived in. Enforce was covered; the mode almost everyone
// actually runs was not.
//
// The defect: an Unavailable verdict carries an EMPTY deny kind, because evaluation never
// got far enough to establish one. Empty is not a hard deny, so allow-but-log served the
// bytes — including for a package that is hard-denied whenever the registry is healthy.
// A failed lookup silently rewrote the verdict into a weaker one.
//
// This matters because the trigger is attacker-influenceable rather than merely unlucky:
// anything that degrades our path to the registry converts "blocked" into "here are the
// bytes". The e2e suite saw this as an intermittent failure and it was initially written
// off as host contention; it was a real bypass.
func TestNpmTarballGateDefaultWithholdsBytesWhenEvaluationFailed(t *testing.T) {
	served := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The tarball path stays perfectly healthy — this is the shape that makes the
		// bug reachable. Only the METADATA fetch fails, so evaluation cannot complete
		// while the bytes remain one relay away.
		if strings.Contains(r.URL.Path, "/-/") {
			served = true
			w.Write([]byte("raw-tarball-bytes"))
			return
		}
		http.Error(w, "registry is briefly unreachable", http.StatusServiceUnavailable)
	}))
	defer upstream.Close()

	// A threshold that hard-denies on a good day: if evaluation had completed, this
	// package is refused outright. The bug is that failing to evaluate served it.
	p := newTestProxy(t, upstream, func(c *Config) { c.ScoreThreshold = 9.0 }) // no ByteGate => default
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/lodash/-/lodash-1.0.0.tgz", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	// Assert on the BYTES, not just the status: a bypass here returns an ordinary 200
	// with a real payload, so status alone would not have caught it.
	if served {
		t.Error("BYPASS (#60): the tarball was fetched from upstream after evaluation FAILED — " +
			"an unavailable verdict must not serve bytes, or degrading our path to the registry becomes a policy bypass")
	}
	if rec.Body.String() == "raw-tarball-bytes" {
		t.Error("BYPASS (#60): tarball bytes were served to the client despite an undecidable verdict")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — we could not evaluate, so we decline to answer rather than deliver (body: %s)",
			rec.Code, rec.Body.String())
	}
	// Not a verdict, and the response must not read like one. Under the old contract
	// this was carried by the 503 status plus Retry-After; under D102 the explanation
	// is what carries it, so without this assertion the fix would be
	// indistinguishable from declaring the package bad.
	body := rec.Body.String()
	if !strings.Contains(body, unavailableErrMsg) {
		t.Errorf("body = %s, want the UNAVAILABLE explanation %q", body, unavailableErrMsg)
	}
	if strings.Contains(body, blockErrMsg) {
		t.Errorf("body = %s, must NOT read as a verdict — nothing was evaluated", body)
	}
}

// TestNpmScopedTarballRoundTrip walks the whole loop for a scoped package, which is
// where the encoding is easy to get wrong: metadata is rewritten to "/_tarball/
// @scope%2Fname/…", and fetching exactly that URL re-evaluates the SCOPED name (not
// "@scope", not the filename) and blocks it.
func TestNpmScopedTarballRoundTrip(t *testing.T) {
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := url.PathUnescape(r.URL.EscapedPath())
		switch p {
		case "/@babel/core/latest", "/@babel/core":
			w.Write([]byte(`{"repository":"github.com/babel/babel","versions":{"7.0.0":{"dist":{"tarball":"` +
				upstream.URL + `/@babel/core/-/core-7.0.0.tgz"}}}}`))
		default:
			t.Errorf("BYPASS: upstream received %s", r.URL.EscapedPath())
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.ScoreThreshold = 9.0 // stub 7.5 -> BLOCK
		c.ByteGate = byteGateEnforce
	})

	// The blocked package's metadata never gets relayed, so drive the rewrite from an
	// ALLOWED read first: raise nothing, just fetch with a permissive proxy.
	permissive := newTestProxy(t, upstream, func(c *Config) { c.ByteGate = byteGateEnforce })
	u, _ := url.Parse("http://fw.local/@babel%2fcore")
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/", nil)
	req.URL = u
	rec := httptest.NewRecorder()
	permissive.ServeHTTP(rec, req)

	// No FW_PUBLIC_URL is set, so the rewrite uses the Host the client reached us on.
	want := "http://fw.local" + npmTarballPrefix + "@babel%2Fcore/"
	if !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("scoped tarball URL not rewritten through %q: %s", want, rec.Body.String())
	}

	// Now fetch that exact rewritten URL against the blocking proxy.
	u2, _ := url.Parse("http://fw.local" + npmTarballPrefix + "@babel%2Fcore/@babel/core/-/core-7.0.0.tgz")
	req2 := httptest.NewRequest(http.MethodGet, "http://fw.local/", nil)
	req2.URL = u2
	rec2 := httptest.NewRecorder()
	p.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusForbidden {
		t.Fatalf("scoped byte fetch status = %d, want 403 (body: %s)", rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), `"package":"@babel/core"`) {
		t.Errorf("byte fetch evaluated the wrong identity: %s", rec2.Body.String())
	}
}

// TestByteGateMode pins the "unrecognized value" rule: a typo must land on the
// DEFAULT, never on "off" (which would silently restore the blind passthrough) and
// never on "enforce" (which would start blocking installs nobody asked to block).
func TestByteGateMode(t *testing.T) {
	cases := map[string]string{
		byteGateOff:         byteGateOff,
		byteGateAllowButLog: byteGateAllowButLog,
		byteGateEnforce:     byteGateEnforce,
		"":                  byteGateAllowButLog,
		"ENFORCE":           byteGateAllowButLog, // case-sensitive on purpose
		"allow_but_log":     byteGateAllowButLog,
		"nonsense":          byteGateAllowButLog,
	}
	for in, want := range cases {
		if got := byteGateMode(in); got != want {
			t.Errorf("byteGateMode(%q) = %q, want %q", in, got, want)
		}
	}
}
