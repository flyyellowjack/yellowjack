package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Tier 1 for issue #66: Yellow Jack is a pull-through gate, so a request that would
// WRITE to the upstream registry is refused rather than relayed.
//
// The defect this pins was not a bypass of the gate — it was a capability nobody chose.
// `POST /v2/<name>/blobs/uploads/` parses as a perfectly good blob path, so an upload was
// handed to the byte gate, judged on the image's PULL score, and forwarded upstream if
// that score passed. A product sold as a pull-through firewall was acting as a
// push-through proxy for any image good enough to install.

// TestWriteMethodClassification pins the allowlist. Reads are enumerated; everything
// else is a write.
//
// The direction matters more than the contents. Enumerating WRITES would have to stay
// complete forever — OCI alone reaches upstream via POST to start an upload, PATCH per
// chunk and PUT to finalise — and one unlisted verb, from a registry extension or a spec
// revision, would be relayed. Listing reads makes an unknown method fail closed by
// construction.
func TestWriteMethodClassification(t *testing.T) {
	for _, tc := range []struct {
		method  string
		isWrite bool
	}{
		{http.MethodGet, false},
		{http.MethodHead, false},
		{http.MethodPut, true},    // npm publish, mvn deploy, OCI manifest push
		{http.MethodPost, true},   // OCI upload start, PyPI upload
		{http.MethodPatch, true},  // OCI chunked upload
		{http.MethodDelete, true}, // registry delete
		{http.MethodOptions, true},
		{http.MethodTrace, true},
		{http.MethodConnect, true},
		{"PROPFIND", true},   // WebDAV; some artifact stores speak it
		{"FROBNICATE", true}, // the point of the allowlist: unknown verbs fail closed
		{"get", true},        // HTTP methods are case-SENSITIVE; "get" is not a read
	} {
		if got := isWriteRequest(tc.method); got != tc.isWrite {
			t.Errorf("isWriteRequest(%q) = %v, want %v", tc.method, got, tc.isWrite)
		}
	}
}

// TestWritePolicyNormalization pins that a typo fails CLOSED. Same direction as
// FW_UNKNOWN_PATH_POLICY and the opposite of FW_UNSCORABLE_POLICY, deliberately: an
// unscorable package is a legitimate package with thin metadata, whereas a write is a
// capability this product does not have.
func TestWritePolicyNormalization(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"block", writePolicyBlock},
		{"allow-but-log", writePolicyAllowButLog},
		{"allow", writePolicyAllow},
		{"", writePolicyBlock},      // unset
		{"Allow", writePolicyBlock}, // wrong case must NOT relay writes
		{"ALLOW", writePolicyBlock}, // ditto
		{"alow", writePolicyBlock},  // typo
		{"relay", writePolicyBlock}, // plausible-but-wrong guess
		{"disabled", writePolicyBlock},
	} {
		if got := writePolicy(tc.in); got != tc.want {
			t.Errorf("writePolicy(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// countingUpstream is an upstream that records every request that reaches it. "The
// upstream saw nothing" is the assertion that actually matters here: a 405 returned to
// the client while the push was ALSO forwarded would satisfy any status-code check and
// still be the bug.
func countingUpstream(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// writeRequests are the OCI push shapes — the ones #66 was filed against, and the only
// ecosystem where the method is a complete signal (every read in the distribution spec
// is GET or HEAD). See notYetGuarded below for why the others are not here.
var writeRequests = []struct {
	name      string
	ecosystem string
	method    string
	path      string
}{
	{"oci: start blob upload", "oci", http.MethodPost, "/v2/library/alpine/blobs/uploads/"},
	{"oci: chunked blob upload", "oci", http.MethodPatch, "/v2/library/alpine/blobs/uploads/abc-123"},
	{"oci: finalise blob upload", "oci", http.MethodPut, "/v2/library/alpine/blobs/uploads/abc-123"},
	{"oci: push manifest", "oci", http.MethodPut, "/v2/library/alpine/manifests/latest"},
	{"oci: delete manifest", "oci", http.MethodDelete, "/v2/library/alpine/manifests/latest"},
}

// notYetGuarded are the publish shapes in the OTHER ecosystems. They are deliberately
// NOT refused today, and this table exists so that is a recorded decision rather than an
// oversight someone has to rediscover.
//
// The first draft of #66 refused writes everywhere. Two existing tests went red and were
// right: npm's control plane mixes reads and writes on one surface — `npm audit` is a
// POST that reads, `npm login` is a PUT that private-registry users need — so the method
// is not a sound signal there, and choosing which registry operations we support is a
// product decision (see #30, where another tool broke npm's control plane this way).
// OCI has no such ambiguity: every spec read is GET or HEAD.
var notYetGuarded = []struct {
	name      string
	ecosystem string
	method    string
	path      string
}{
	{"npm publish", "npm", http.MethodPut, "/lodash"},
	{"pypi upload", "pypi", http.MethodPost, "/legacy/"},
	{"maven deploy", "maven", http.MethodPut, "/com/example/lib/1.0/lib-1.0.jar"},
}

// TestNonOciWritesAreStillRelayed pins the CURRENT, deliberately-unfinished state, so
// that whoever extends #66 to the other ecosystems sees this go red and has to decide
// rather than discovering the gap in production. It asserts the limitation, not the
// desired end state.
func TestNonOciWritesAreStillRelayed(t *testing.T) {
	for _, tc := range notYetGuarded {
		t.Run(tc.name, func(t *testing.T) {
			upstream, hits := countingUpstream(t)
			p := newTestProxy(t, upstream, func(c *Config) {
				c.Ecosystem = tc.ecosystem
				c.ScoreThreshold = 0
			})
			req := httptest.NewRequest(tc.method, "http://fw.local"+tc.path, strings.NewReader("payload"))
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)

			if rec.Code == http.StatusMethodNotAllowed {
				t.Errorf("%s is now refused. That may well be an improvement — but it is a PRODUCT "+
					"decision (npm audit is a POST that reads; npm login is a PUT that is needed), "+
					"so update #66 and this test deliberately rather than letting it change silently",
					tc.name)
			}
			if hits.Load() == 0 {
				t.Errorf("%s never reached upstream, so this test is not measuring what it claims", tc.name)
			}
		})
	}
}

func TestWritesAreRefusedAndNeverReachUpstream(t *testing.T) {
	for _, tc := range writeRequests {
		t.Run(tc.name, func(t *testing.T) {
			upstream, hits := countingUpstream(t)
			// FW_WRITE_POLICY deliberately left unset: this tests the SHIPPED default,
			// which is what an operator who configures nothing actually gets.
			p := newTestProxy(t, upstream, func(c *Config) { c.Ecosystem = tc.ecosystem })

			req := httptest.NewRequest(tc.method, "http://fw.local"+tc.path, strings.NewReader("payload"))
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want 405 (body: %s)", rec.Code, rec.Body.String())
			}
			// 405 rather than 403 on purpose: this is not a verdict about a package, and
			// "403 from Yellow Jack" must keep meaning "the firewall blocked this
			// package" for operators and clients that key on it.
			if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
				t.Errorf("Allow header = %q, want %q", got, "GET, HEAD")
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("UPSTREAM WAS CONTACTED %d time(s) for a refused %s — the client got a 405 "+
					"but the write was forwarded anyway, which is the whole defect (#66)", n, tc.method)
			}
		})
	}
}

// TestWritesAreRelayedWhenPolicyAllows is the discriminator, and the reason the test
// above can be believed.
//
// Every assertion there is also satisfied by a proxy that refuses EVERYTHING, or by a
// harness that cannot reach its upstream at all. This leg sends the identical requests
// with FW_WRITE_POLICY=allow and requires the upstream to receive each one, so "the
// upstream saw nothing" above is attributable to the policy rather than to a broken pipe.
func TestWritesAreRelayedWhenPolicyAllows(t *testing.T) {
	for _, tc := range writeRequests {
		t.Run(tc.name, func(t *testing.T) {
			upstream, hits := countingUpstream(t)
			p := newTestProxy(t, upstream, func(c *Config) {
				c.Ecosystem = tc.ecosystem
				c.WritePolicy = writePolicyAllow
				c.ScoreThreshold = 0 // nothing is blocked on score, so only the write policy is in play
			})

			req := httptest.NewRequest(tc.method, "http://fw.local"+tc.path, strings.NewReader("payload"))
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)

			if rec.Code == http.StatusMethodNotAllowed {
				t.Errorf("FW_WRITE_POLICY=allow still refused the write with 405 — the escape hatch does not work")
			}
			if n := hits.Load(); n == 0 {
				t.Errorf("DISCRIMINATOR FAILED: with FW_WRITE_POLICY=allow the upstream saw NOTHING, so "+
					"the refusal test above cannot tell a working policy from a harness that never "+
					"reaches upstream — treat it as unproven (status was %d, body %s)",
					rec.Code, rec.Body.String())
			}
		})
	}
}

// TestReadsAreUnaffected is the compatibility half. The refusal sits above every
// ecosystem branch, so a mistake there breaks every pull in the product — the one
// failure mode of this change that would matter to a customer immediately.
func TestReadsAreUnaffected(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		upstream, hits := countingUpstream(t)
		p := newTestProxy(t, upstream, func(c *Config) {
			c.Ecosystem = "npm"
			c.ScoreThreshold = 0 // allow, so the request is expected to reach upstream
		})

		req := httptest.NewRequest(method, "http://fw.local/lodash", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)

		if rec.Code == http.StatusMethodNotAllowed {
			t.Errorf("%s was refused as a write — reads must be unaffected", method)
		}
		if hits.Load() == 0 {
			t.Errorf("%s never reached upstream; the write guard is refusing reads", method)
		}
	}
}

// TestHealthzSurvivesTheWriteGuard pins an ordering detail that would be invisible until
// an orchestrator marked every replica unhealthy: /healthz is answered ABOVE the guard,
// so a probe configured with any method still gets its answer rather than a 405.
func TestHealthzSurvivesTheWriteGuard(t *testing.T) {
	upstream, _ := countingUpstream(t)
	p := newTestProxy(t, upstream, nil)

	req := httptest.NewRequest(http.MethodHead, "http://fw.local/healthz", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("HEAD /healthz = %d, want 200 — liveness must not depend on the write policy", rec.Code)
	}
}
