package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// Tier 1 for the npm half of issue #67, ruled by D159.
//
// The relay minted "/_tarball/<pkg>/<object path>" and then treated the two halves as if
// they belonged together. They did not: the prefix decided WHICH PACKAGE WAS EVALUATED,
// the object path decided WHICH BYTES CAME BACK, and any client could choose them
// independently. Pair an allowed package's prefix with a blocked package's object path
// and the gate judged the decoy while the target streamed — measured at 318 KB.
//
// The fix is exact rather than heuristic, which is why it does not re-open what D101
// closed: npm addresses a tarball as "/<name>/-/<file>.tgz", so the name is a path
// segment we can READ, not a filename we would have to SPLIT.

// TestNpmObjectPathBinding is the table. The honest rows matter as much as the attacks:
// a binding that refused real tarball paths would be found by a developer whose
// `npm ci` broke, which is a far worse way to learn it than a test.
func TestNpmObjectPathBinding(t *testing.T) {
	honest := []struct{ pkg, objectPath, why string }{
		{"lodash", "/lodash/-/lodash-4.17.21.tgz", "the ordinary case"},
		{"@babel/core", "/@babel/core/-/core-7.0.0.tgz", "scoped, unescaped slash"},
		{"@babel/core", "/@babel%2Fcore/-/core-7.0.0.tgz", "scoped, escaped slash — the same package, second spelling"},
		{"a-b-c", "/a-b-c/-/a-b-c-1.0.0.tgz", "hyphens in the name — what makes PyPI's grammar ambiguous and npm's not"},
		{"express", "/express/-/express-4.18.2.tgz", "the decoy of the attack below, on its OWN path"},
	}
	for _, c := range honest {
		if !npmObjectPathBindsToPackage(c.pkg, c.objectPath) {
			t.Errorf("npmObjectPathBindsToPackage(%q, %q) = false, want true — %s", c.pkg, c.objectPath, c.why)
		}
	}

	attacks := []struct{ pkg, objectPath, why string }{
		{"express", "/lodash/-/lodash-4.17.21.tgz",
			"THE confused deputy: allowed prefix, blocked package's object path"},
		{"express", "/files/abc123.tgz",
			`no "/-/" at all — refused rather than waved through, or the attacker simply avoids the shape`},
		{"express", "/-/express/-/express-1.0.0.tgz",
			`a leading "/-/" addresses npm's control plane, not a package`},
		{"lodash", "/lodash-evil/-/lodash-evil-1.0.0.tgz",
			"name EXTENSION: an attacker publishes a name starting with an allowed one. This is the attack that " +
				"defeated prefix-only matching on the PyPI side, and no corpus of real packages can show it"},
		{"lodash", "/@scope/lodash/-/lodash-1.0.0.tgz",
			"a different package whose name merely ENDS with the allowed one"},
		{"Lodash", "/lodash/-/lodash-1.0.0.tgz",
			"npm names are case-sensitive, so a second spelling is a second identity"},
		{"lodash", "", "empty object path"},
	}
	for _, c := range attacks {
		if npmObjectPathBindsToPackage(c.pkg, c.objectPath) {
			t.Errorf("npmObjectPathBindsToPackage(%q, %q) = true, want false — %s", c.pkg, c.objectPath, c.why)
		}
	}
}

// TestNpmBindingNegativeControl proves the table above CAN fail.
//
// Mandated by D159 and warranted by history: during the #77 work PyPI's always-on
// grammar check masked a signature failure, so a leg went green while testing nothing.
// A binding rule is exactly the kind of check that passes for the wrong reason — a rule
// that accepted everything would leave every honest row green, and one that refused
// everything would leave every attack row green. This runs both directions against
// stand-ins whose answers are known, so a table that had quietly gone vacuous shows up
// here rather than in production.
func TestNpmBindingNegativeControl(t *testing.T) {
	alwaysTrue := func(string, string) bool { return true }
	alwaysFalse := func(string, string) bool { return false }

	attack := [][2]string{
		{"express", "/lodash/-/lodash-4.17.21.tgz"},
		{"lodash", "/lodash-evil/-/lodash-evil-1.0.0.tgz"},
	}
	honest := [][2]string{
		{"lodash", "/lodash/-/lodash-4.17.21.tgz"},
		{"@babel/core", "/@babel%2Fcore/-/core-7.0.0.tgz"},
	}

	for _, c := range attack {
		if !alwaysTrue(c[0], c[1]) {
			t.Fatal("control broken: alwaysTrue should accept")
		}
		if npmObjectPathBindsToPackage(c[0], c[1]) {
			t.Errorf("real rule accepted an attack the control shows is detectable: %v", c)
		}
	}
	for _, c := range honest {
		if alwaysFalse(c[0], c[1]) {
			t.Fatal("control broken: alwaysFalse should reject")
		}
		if !npmObjectPathBindsToPackage(c[0], c[1]) {
			t.Errorf("real rule rejected honest traffic: %v", c)
		}
	}
}

// TestNpmConfusedDeputyIsRefusedWithoutASigningKey is the claim D159 actually makes:
// the DEFAULT install — no signing key, nothing configured — is safe.
//
// Deliberately built so the binding is the ONLY thing that can refuse. The threshold is
// 0 and unscorables are allowed, so every package passes on merit and an unbound request
// WOULD be relayed; signing is off, so artifactURLAuthentic waves everything through. If
// the binding is removed this does not merely weaken — it goes red, because the upstream
// counter fires.
func TestNpmConfusedDeputyIsRefusedWithoutASigningKey(t *testing.T) {
	var reached atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("TARBALL-BYTES"))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.ScoreThreshold = 0         // nothing is refused on merit
		c.UnscorablePolicy = "allow" // nor for want of a score
		c.ByteGate = byteGateEnforce
		c.URLSigningKey = "" // the default: no key, so signing cannot be what saves us
	})

	req := httptest.NewRequest(http.MethodGet, "http://fw.local/_tarball/express/lodash/-/lodash-4.17.21.tgz", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("GATE BYPASS: the confused-deputy URL returned 200 (%d bytes). The prefix named "+
			"'express' while the object path fetched lodash's tarball.", rec.Body.Len())
	}
	if n := reached.Load(); n != 0 {
		t.Errorf("the confused-deputy URL reached upstream %d time(s) — it must be refused BEFORE the "+
			"relay, or the bytes are already gone by the time we decide", n)
	}
}

// TestNpmOwnPathShapeStillWorks is the anti-vacuity twin: the fix must not close the door
// on npm's native "/<pkg>/-/<file>.tgz", which every lockfile in the wild records and
// which modern npm/pnpm rebuild themselves by swapping only the origin. That shape is not
// one we mint, so the binding must not apply to it — which is also what proves the
// refusal above is specific, rather than a blanket 4xx on anything tarball-shaped.
func TestNpmOwnPathShapeStillWorks(t *testing.T) {
	var reached atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("TARBALL-BYTES"))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.ScoreThreshold = 0
		c.UnscorablePolicy = "allow"
		c.ByteGate = byteGateEnforce
	})

	req := httptest.NewRequest(http.MethodGet, "http://fw.local/lodash/-/lodash-4.17.21.tgz", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if reached.Load() == 0 {
		t.Errorf("npm's own tarball path was refused (%d) — every existing lockfile fetches this shape, "+
			"so breaking it breaks `npm ci` for traffic that was never confusable", rec.Code)
	}
}
