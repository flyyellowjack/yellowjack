package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TIER 3 (adversarial): what can a MALICIOUS PACKAGE put into our response?
//
// Tier 2 asks "does a real client see the block?" and structurally cannot find this: the
// client behaves, so nothing hostile ever reaches the formatting code. These tests assume
// the attacker controls the one thing they demonstrably do control — the name they
// publish, and the repository URL in their own package metadata — and ask what those
// strings can do on the way back out.
//
// The reason string reaches TWO sinks: a JSON body npm parses, and an HTTP response
// header. Reason text is built with fmt.Sprintf; most call sites use %q (which escapes
// control characters) but at least one uses %s on a repo URL taken from package metadata,
// so control characters can reach both sinks.

var attackStrings = []struct {
	name  string
	value string
}{
	{"CRLF header split", "evil\r\nX-Injected: yes"},
	{"bare LF", "evil\nX-Injected: yes"},
	{"bare CR", "evil\rX-Injected: yes"},
	{"NUL byte", "evil\x00truncated"},
	{"response splitting into a body", "evil\r\n\r\n<html>gotcha</html>"},
}

// TestReasonCannotForgeAResponseHeader reads the ACTUAL BYTES off a socket.
//
// This has to be a wire-level test. httptest.ResponseRecorder never serializes, so it
// reports the raw value sitting in a map — and a substring check against that map reports
// an injection that does not exist. The first version of this test did exactly that and
// "found" a header-splitting bug in code that is not vulnerable.
//
// What actually protects us is Go's net/http, which replaces CR and LF with spaces when
// writing a header value. That is a property of the standard library, not of our code,
// which is exactly why it deserves an assertion: nothing here would notice if this reason
// were ever written to a socket by hand, or by a different server.
func TestReasonCannotForgeAResponseHeader(t *testing.T) {
	for _, a := range attackStrings {
		t.Run(a.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// The payload goes through BOTH sinks. The next step is a second
				// attacker-reachable header (#50) and would be untested if only our own
				// constant were ever passed here.
				writeForbidden(w, "npm", "pkg", blockErrMsg, "score too low for "+a.value, "do this: "+a.value,
					verdictMeta{Kind: "score-below-threshold", Rule: "rule " + a.value, Source: "policy " + a.value})
			}))
			defer srv.Close()

			hostport := strings.TrimPrefix(srv.URL, "http://")
			conn, err := net.Dial("tcp", hostport)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			fmt.Fprintf(conn, "GET /x HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostport)

			// Parse the response the way a client does, rather than grepping the bytes.
			// Substring checks against serialized output are the wrong tool here and got this
			// wrong twice: attacker text appears INSIDE the reason header's value (Go replaces
			// CR/LF with spaces), and inside the JSON body, and neither is a forged header.
			// The structural question is the only one that matters -- did a header we never
			// set come into existence?
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("the response is not parseable HTTP at all: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("status %d, want 403 -- a crafted reason changed the verdict", resp.StatusCode)
			}
			if v := resp.Header.Get("X-Injected"); v != "" {
				t.Errorf("RESPONSE SPLITTING: a crafted reason created header X-Injected: %q", v)
			}
			allowed := map[string]bool{
				"Content-Type": true, "X-Yellowjack-Reason": true, "X-Yellowjack-Next-Step": true,
				"X-Yellowjack-Kind": true, "X-Yellowjack-Rule": true, "X-Yellowjack-Source": true,
				"Date": true, "Content-Length": true, "Connection": true, "Cache-Control": true,
			}
			for k := range resp.Header {
				if !allowed[k] {
					t.Errorf("unexpected header %q appeared under attack -- a crafted reason is "+
						"creating headers we never set", k)
				}
			}
			// And the value itself must be a single line on the wire.
			for _, h := range []string{"X-Yellowjack-Reason", "X-Yellowjack-Next-Step", "X-Yellowjack-Kind", "X-Yellowjack-Rule", "X-Yellowjack-Source"} {
				if got := resp.Header.Get(h); strings.ContainsAny(got, "\r\n") {
					t.Errorf("%s survived serialization with a raw newline: %q", h, got)
				}
			}
		})
	}
}

// TestBlockBodyStaysValidJSONUnderAttack.
//
// npm PARSES this body. If a crafted package name can break out of the JSON string, we
// hand the client malformed JSON at best, and control of the fields it reads at worst.
func TestBlockBodyStaysValidJSONUnderAttack(t *testing.T) {
	nasty := []string{
		`","injected":"yes`,
		`\"`,
		"tab\there",
		"quote\"inside",
		`{"nested":"json"}`,
		"unicode\u2028line\u2029sep",
		"crlf\r\ninside",
		// %q is GO quoting, not JSON quoting. They agree on most characters and
		// disagree on these: Go writes a NUL as \x00, which JSON does not accept
		// (JSON requires \u0000). Any character where the two grammars differ
		// turns the body npm parses into a parse error.
		"nul\x00byte",
		"del\x7fchar",
		"bell\x07char",
	}
	for _, pkg := range nasty {
		rec := httptest.NewRecorder()
		writeForbidden(rec, "npm", pkg, blockErrMsg, "reason for "+pkg, nextStepFor(denyScore), verdictMeta{Kind: string(denyScore), Rule: "terminal", Source: "policy test"})

		body := rec.Body.String()
		if strings.Contains(body, `"injected"`) {
			t.Errorf("JSON INJECTION via package %q: attacker created a field:\n%s", pkg, body)
		}
		var probe map[string]any
		if err := decodeJSON(body, &probe); err != nil {
			t.Errorf("package %q produced INVALID JSON that npm cannot parse: %v\n%s", pkg, err, body)
		}
	}
}

// TestOciErrorBodyStaysValidJSONUnderAttack — the OCI branch builds its body separately
// and has drifted from the npm branch before (only the npm branch was dropping the
// reason), so it is attacked separately rather than assumed to match.
func TestOciErrorBodyStaysValidJSONUnderAttack(t *testing.T) {
	for _, pkg := range []string{`","code":"OK`, "img\r\nX-Injected: yes", `esc\"ape`} {
		rec := httptest.NewRecorder()
		writeForbidden(rec, "oci", pkg, blockErrMsg, "reason", nextStepFor(denyScore), verdictMeta{Kind: string(denyScore), Rule: "terminal", Source: "policy test"})

		body := rec.Body.String()
		var probe map[string]any
		if err := decodeJSON(body, &probe); err != nil {
			t.Errorf("OCI body for %q is invalid JSON: %v\n%s", pkg, err, body)
		}
		if strings.Contains(body, `"code":"OK"`) {
			t.Errorf("OCI code field was forged by the package name %q:\n%s", pkg, body)
		}
	}
}

// TestBlockedStatusIsAlways403UnderAttack: no crafted input may downgrade the refusal.
// The status code is the only part of this response some clients look at.
func TestBlockedStatusIsAlways403UnderAttack(t *testing.T) {
	for _, a := range attackStrings {
		rec := httptest.NewRecorder()
		// The hostile string is fed through the next-step field too: it reaches its own
		// header and its own JSON field, so it is a third sink for attacker text, not a
		// place where our constants happen to sit today.
		writeForbidden(rec, "npm", a.value, blockErrMsg, a.value, a.value, verdictMeta{Kind: a.value, Rule: a.value, Source: a.value})
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403 — a crafted name changed the verdict", a.name, rec.Code)
		}
	}
}

// TestNoHandRolledJSONEncodersRemain is a SOURCE-LEVEL guard against the whole class.
//
// The invalid-JSON defect was not a typo — it was a pattern: building a JSON body with a
// format verb. %q is Go quoting, and it silently diverges from JSON quoting on exactly
// the inputs an attacker chooses. Fixing the three occurrences does not stop a fourth
// being written next week, and the failure is invisible until a hostile package name
// reaches it.
//
// So the pattern itself is banned, and the ban is enforced rather than documented. This
// is deliberately a source check: no runtime test can cover an encoder that has not been
// written yet.
func TestNoHandRolledJSONEncodersRemain(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	// ANTI-VACUITY: if the glob stops matching, this test passes while checking nothing.
	if len(files) < 10 {
		t.Fatalf("only %d Go files found in the package root — the scan is broken, so this "+
			"test is not checking anything", len(files))
	}

	// A Fprintf/Sprintf whose format string starts a JSON object is the shape being banned.
	pattern := regexp.MustCompile(`(?:Fprintf|Sprintf)\(.*` + "`" + `\{"`)
	var found []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if pattern.MatchString(line) {
				found = append(found, fmt.Sprintf("%s:%d: %s", f, i+1, strings.TrimSpace(line)))
			}
		}
	}
	for _, hit := range found {
		t.Errorf("hand-rolled JSON encoder — use encoding/json, which is the only thing that "+
			"knows JSON's escaping rules:\n  %s", hit)
	}
}
