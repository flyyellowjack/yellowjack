package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// FW_MODE=report: every POLICY verdict is computed and logged, and nothing is refused.
//
// WHY THE FEATURE EXISTS. The single biggest objection to adopting a package firewall is
// that nobody switches a blocking gate on in front of their build system cold — a false
// positive is a stopped deploy, and no operator takes that risk on a vendor's say-so.
// Report mode answers it by making our false-positive rate MEASURABLE rather than
// asserted: run it against real traffic for a week and read what it WOULD have done.
//
// WHY THE TESTS ARE SHAPED LIKE THIS. "Nothing was refused" is also what a firewall that
// is not running produces, so every leg below is paired with an enforce-mode control on
// the SAME package and the SAME upstream. The pair is the evidence; either half alone is
// satisfied by a broken gate.

// blockingProxy builds a proxy whose stub score (7.5) sits below the threshold, so every
// package is refused on a positive finding. mutate can push it into report mode.
func blockingProxy(t *testing.T, upstream *httptest.Server, mode string) *proxyServer {
	t.Helper()
	return newTestProxy(t, upstream, func(c *Config) {
		c.ScoreThreshold = 9.0 // stub scores 7.5 -> below threshold -> BLOCK
		c.Mode = mode
	})
}

func TestReportModeRelaysWhatEnforceWouldRefuse(t *testing.T) {
	var served int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lodash/latest":
			w.Write([]byte(`{"repository":{"url":"git+https://github.com/lodash/lodash.git"}}`))
		default:
			served++
			w.Write([]byte(`{"name":"lodash","dist-tags":{"latest":"1.0.0"}}`))
		}
	}))
	defer upstream.Close()

	get := func(p *proxyServer) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://fw.local/lodash", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		return rec
	}

	// CONTROL FIRST. Without this, "report mode returned 200" is equally consistent with
	// a threshold that never blocked anything, and the test would prove nothing.
	if rec := get(blockingProxy(t, upstream, modeEnforce)); rec.Code != http.StatusForbidden {
		t.Fatalf("control: enforce mode returned %d, want 403. This package is not actually being "+
			"blocked, so the report-mode leg below cannot demonstrate suppression.\nbody: %s",
			rec.Code, rec.Body.String())
	}

	before := served
	rec := get(blockingProxy(t, upstream, modeReport))
	if rec.Code != http.StatusOK {
		t.Fatalf("report mode returned %d, want 200 — a verdict must not be enforced in report mode\nbody: %s",
			rec.Code, rec.Body.String())
	}
	// Status alone is not enough: a 200 with an empty body would also satisfy it while the
	// developer's install still failed. The point of report mode is that the request is
	// SERVED, so assert the upstream was actually reached and its bytes came back.
	if served == before {
		t.Error("report mode returned 200 but never reached upstream — the client got a hollow " +
			"response, which is a broken install wearing a success code")
	}
	if body, _ := io.ReadAll(rec.Body); !strings.Contains(string(body), "dist-tags") {
		t.Errorf("report mode did not relay the real packument; body = %q", body)
	}
	// The refusal must still be VISIBLE. A suppressed verdict that is not recorded is
	// indistinguishable from no verdict, and counting these is the entire feature.
	if rec.Header().Get("X-Yellowjack-Reason") != "" {
		t.Error("report mode set X-Yellowjack-Reason on a relayed response — the client must see " +
			"an ordinary success, or report mode changes client behaviour it was meant to leave alone")
	}
}

// TestReportModeStillRefusesAnIntegrityMismatch is the exception, and it is the reason
// report mode is safe to hand an operator.
//
// An artifact whose object path does not address the package being judged is not a
// verdict about that package — it is a request whose two halves disagree, the
// confused-deputy shape of issue #67. Relaying it "because nothing is enforced in report
// mode" would mean report mode INTRODUCES a bypass that enforce mode does not have, so an
// operator evaluating us would be less safe than one enforcing. That must never be true.
func TestReportModeStillRefusesAnIntegrityMismatch(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("an integrity-mismatched artifact reached upstream (%s) — report mode turned a "+
			"confused-deputy guard off, which is a BYPASS, not observability", r.URL.Path)
		http.Error(w, "should not be reached", http.StatusInternalServerError)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.Mode = modeReport
		c.ScoreThreshold = 0 // allow everything on score, so only the guard can refuse
	})
	// A minted tarball URL whose package prefix and object path name different packages.
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/_tarball/lodash/express/-/express-4.0.0.tgz", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("report mode SERVED an artifact whose path addresses a different package than the "+
			"one judged (status %d). Report mode must suppress verdicts, never integrity guards.", rec.Code)
	}
}

// reportModeSinks are the functions allowed to emit a client-facing refusal directly.
var reportModeSinks = map[string]bool{
	"writeForbidden": true, "writeBlock": true, "writeBlockDecision": true, "refuse": true,
}

// integrityRefusals are the ONLY production call sites permitted to bypass the mode-aware
// sink, identified by a distinctive fragment of the call. Each is a request-integrity
// check, not a policy verdict — see TestReportModeStillRefusesAnIntegrityMismatch.
//
// This list is the entire exception surface. Anything else calling a raw refusal writer
// is a policy refusal that report mode would silently fail to suppress, which makes the
// mode a lie for that path.
var integrityRefusals = []string{
	"artifact path does not belong to the requested package",
	"artifact filename does not belong to the requested package",
	"artifact URL signature is missing or invalid",
	// Increment 8 (docs/TLS_INTERCEPTION.md): an intercepted files-host URL that no relayed
	// index listed has NO package identity to judge, so relaying it would be an ungated
	// byte fetch -- see TestInterceptedUnboundArtifactIsRefusedEvenInReportMode.
	"artifact-not-in-relayed-index",
	// Issue #136: a wheel served under a version naming a different RELEASE than its own
	// PEP 658 metadata declared is misrepresenting itself -- the same class as the two
	// bindings above, not a verdict about the package. Suppressing it under report mode
	// would let a mismatched artifact through in a mode that is supposed to change what is
	// REPORTED, never what is DELIVERED; that is a bypass enforce does not have, which is
	// the exact rule that kept the npm tarball-version check out of the sink too.
	"wheel-version",
}

// TestEveryPolicyRefusalGoesThroughTheModeSink is the guard that keeps report mode
// honest as the code grows.
//
// The compiler already forces most of it: writeDeferred and refuse take a relay closure,
// so a new caller cannot compile without saying what the allow path would have been. But
// the raw writers are still package-level functions, and a future refusal that calls one
// of them directly would compile fine and be silently un-suppressable. That is precisely
// the "half-true posture" failure the mode's contract rules out, so it is asserted rather
// than trusted.
func TestEveryPolicyRefusalGoesThroughTheModeSink(t *testing.T) {
	src, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatalf("read proxy.go: %v", err)
	}
	// The interception handlers live in their own file, present only where the mode is
	// built in (intercept_proxy.go). Its refusal is scanned with the rest when the file
	// exists, and its exemption is expected only then -- so the count stays exact in a
	// tree without the mode rather than pardoning a fragment that cannot occur.
	declared := integrityRefusals
	if isrc, err := os.ReadFile("intercept_proxy.go"); err == nil {
		src = append(append(src, '\n'), isrc...)
	} else {
		declared = nil
		for _, frag := range integrityRefusals {
			if frag != "artifact-not-in-relayed-index" {
				declared = append(declared, frag)
			}
		}
	}
	call := regexp.MustCompile(`\b(writeForbidden|writeBlock|writeBlockDecision)\(`)
	funcStart := regexp.MustCompile(`^func (?:\([^)]*\) )?(\w+)`)

	var enclosing string
	var offenders, allowed int
	for i, line := range strings.Split(string(src), "\n") {
		line = strings.TrimRight(line, "\r")
		if m := funcStart.FindStringSubmatch(line); m != nil {
			enclosing = m[1]
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || !call.MatchString(line) {
			continue
		}
		if reportModeSinks[enclosing] {
			continue // the sink and the writers themselves
		}
		exempt := false
		for _, frag := range declared {
			if strings.Contains(line, frag) {
				exempt = true
				allowed++
			}
		}
		if exempt {
			continue
		}
		offenders++
		t.Errorf("proxy.go:%d refuses a request without going through the mode-aware sink, so "+
			"FW_MODE=report would NOT suppress it:\n    %s\nUse p.refuse / p.refuseDecision / "+
			"p.writeDeferred and pass what the allow path would have done. If this really is a "+
			"request-INTEGRITY refusal rather than a policy verdict, add its message to "+
			"integrityRefusals with the reason.", i+1, trimmed)
	}

	// ANTI-VACUITY, both directions. A regex that matched nothing would report a clean
	// file, and an exemption list that has stopped matching is a pardon waiting to cover
	// something else — the same reasoning e2e/hardening.sh applies to its mount exception.
	if allowed != len(declared) {
		t.Errorf("matched %d of %d declared integrity refusals in proxy.go. Either they moved (so "+
			"they are now UNCHECKED) or they are gone and the exemption should be deleted.",
			allowed, len(declared))
	}
	if offenders == 0 && allowed == 0 {
		t.Error("the scan matched no refusal call at all; this check is not reading proxy.go")
	}
}
