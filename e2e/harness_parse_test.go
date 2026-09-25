//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// The firewall's decision log line has TWO independent parsers: decisionRe here, and
// classifyLog in modematrix_test.go. #76 inserted an outcome token ("[verdict-blocked]")
// into two of the emitting call sites and updated only the mode-matrix one. The matrix
// stayed green — it was reading the new token correctly — while every parse in this
// harness silently returned no match, so `decisionsFor` reported that the gate had never
// judged the package under test. The e2e legs did catch it, but ten minutes and a docker
// runner later, and the failure text ("no verdict was rendered for `express`") describes
// a firewall bug rather than the parser bug it actually was.
//
// This test is the cheap copy of that check: it runs in milliseconds with no container,
// against literal lines in the shapes proxy.go emits. If a log line's shape changes
// again, this reddens first and says so in those terms.
//
// It is deliberately assertion-per-field rather than a match/no-match boolean: a regexp
// that matches while capturing the token as the package name is the dangerous failure,
// because `decisionsFor("express")` would then return nothing while `decisions()` looked
// healthy — the same silence, one layer up.
func TestHarnessParsesEveryDecisionLogShape(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		method  string
		pkg     string
		allowed bool
		bytes   bool
		reason  string
	}{{
		name:   "metadata verdict, blocked, with score",
		line:   `2026/08/06 01:33:24 GET [verdict-blocked] express -> allowed=false score=2.6 hasScore=true (BLOCKED: "express" scored 2.6, below required 5.0)`,
		method: "GET", pkg: "express", allowed: false, bytes: false,
		reason: `BLOCKED: "express" scored 2.6, below required 5.0`,
	}, {
		name:   "metadata verdict, allowed",
		line:   `2026/08/06 01:33:24 GET [verdict-allowed] lodash -> allowed=true score=7.4 hasScore=true (allowed)`,
		method: "GET", pkg: "lodash", allowed: true, bytes: false,
		reason: "allowed",
	}, {
		name:   "upstream outage, withheld",
		line:   `2026/08/06 01:33:24 GET [withheld-unavailable] six -> allowed=false score=0.0 hasScore=false (registry metadata temporarily unavailable)`,
		method: "GET", pkg: "six", allowed: false, bytes: false,
		reason: "registry metadata temporarily unavailable",
	}, {
		name:   "byte relay verdict carries no score",
		line:   `2026/08/06 01:34:06 GET _files [verdict-blocked] six -> allowed=false (BLOCKED: "six" scored 3.7, below required 9.9)`,
		method: "GET", pkg: "six", allowed: false, bytes: true,
		reason: `BLOCKED: "six" scored 3.7, below required 9.9`,
	}, {
		// The pre-#76 shape. Kept because old traces and any not-yet-tokenised call
		// site must still parse -- the token group is optional, and this is what
		// proves the optionality is real rather than assumed.
		name:   "untokenised metadata line still parses",
		line:   `2026/08/06 01:33:24 GET express -> allowed=false score=2.6 hasScore=true (below threshold)`,
		method: "GET", pkg: "express", allowed: false, bytes: false,
		reason: "below threshold",
	}, {
		name:   "untokenised byte relay line still parses",
		line:   `2026/08/06 01:34:06 GET _files six -> allowed=false (below threshold)`,
		method: "GET", pkg: "six", allowed: false, bytes: true,
		reason: "below threshold",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDecisions(tc.line)
			if len(got) != 1 {
				t.Fatalf("parsed %d decisions, want 1 — decisionRe no longer matches this shape:\n  %s",
					len(got), tc.line)
			}
			d := got[0]
			// The package name is the field that fails SILENTLY: a wrong value here
			// makes decisionsFor(pkg) empty, which reads as "the gate never judged it".
			if strings.HasPrefix(d.pkg, "[") {
				t.Fatalf("captured the outcome token %q as the package name; decisionsFor "+
					"would report that the gate never judged this package\n  %s", d.pkg, tc.line)
			}
			if d.pkg != tc.pkg {
				t.Errorf("pkg = %q, want %q\n  %s", d.pkg, tc.pkg, tc.line)
			}
			if d.method != tc.method {
				t.Errorf("method = %q, want %q", d.method, tc.method)
			}
			if d.allowed != tc.allowed {
				t.Errorf("allowed = %v, want %v", d.allowed, tc.allowed)
			}
			if d.bytes != tc.bytes {
				t.Errorf("bytes = %v, want %v — a metadata verdict and an artifact-byte "+
					"verdict are different claims about WHERE the package was refused",
					d.bytes, tc.bytes)
			}
			if d.reason != tc.reason {
				t.Errorf("reason = %q, want %q", d.reason, tc.reason)
			}
		})
	}
}

// blockedCount counts "allowed=false" substrings; decisions() parses. The two agreeing is
// what makes either trustworthy: if decisionRe stops matching a shape, the count keeps
// rising while the parse goes empty, and a test asserting only on the count still passes.
// That divergence is precisely the #76 failure, so it gets its own assertion.
func TestDecisionParserAgreesWithTheRawCount(t *testing.T) {
	lines := []string{
		`2026/08/06 01:33:24 GET [verdict-blocked] express -> allowed=false score=2.6 hasScore=true (below threshold)`,
		`2026/08/06 01:34:06 GET _files [verdict-blocked] six -> allowed=false (below threshold)`,
		`2026/08/06 01:33:24 GET [verdict-allowed] lodash -> allowed=true score=7.4 hasScore=true (allowed)`,
	}
	logText := strings.Join(lines, "\n") + "\n"
	raw := strings.Count(logText, "allowed=true") + strings.Count(logText, "allowed=false")

	if got, want := len(parseDecisions(logText)), raw; got != want {
		t.Fatalf("parsed %d decisions but the log contains %d allowed=… lines; decisionRe "+
			"is silently skipping a shape, so decisionsFor()/blocked() under-report while "+
			"blockedCount() looks healthy\n%s", got, want, logText)
	}
}
