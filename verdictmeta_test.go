package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Tier 1 for D182 (#20): a refusal carries the KIND of denial, the identifier of the
// RULE that fired and the SOURCE it came from as machine-readable fields -- three
// headers and three body fields beside the prose -- so "why was this blocked, under
// which rule, from which policy" is a lookup, not a sentence to parse.

type wireVerdict struct {
	status  int
	headers http.Header
	body    map[string]any
}

func fetchVerdict(t *testing.T, p *proxyServer, path string) wireVerdict {
	t.Helper()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://fw.local"+path, nil))
	var body map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
	}
	return wireVerdict{status: rec.Code, headers: rec.Header(), body: body}
}

// assertStructured checks the three fields are present, agree between header and
// body, and match what the caller expects. `want` values are substrings; "" means
// "must be non-empty".
func assertStructured(t *testing.T, name string, v wireVerdict, wantKind, wantRule, wantSource string) {
	t.Helper()
	if v.status != http.StatusForbidden {
		t.Fatalf("%s: status %d, want 403; body %v", name, v.status, v.body)
	}
	fields := v.body
	if errs, ok := v.body["errors"].([]any); ok && len(errs) > 0 { // OCI shape
		fields, _ = errs[0].(map[string]any)["detail"].(map[string]any)
	}
	for _, f := range []struct{ header, field, want string }{
		{"X-Yellowjack-Kind", "kind", wantKind},
		{"X-Yellowjack-Rule", "rule", wantRule},
		{"X-Yellowjack-Source", "source", wantSource},
	} {
		h := v.headers.Get(f.header)
		b, _ := fields[f.field].(string)
		if h == "" || b == "" {
			t.Errorf("%s: %s header %q / body %q -- the structured field is missing on one side", name, f.field, h, b)
			continue
		}
		if h != b {
			t.Errorf("%s: %s header %q != body %q", name, f.field, h, b)
		}
		if f.want != "" && !strings.Contains(h, f.want) {
			t.Errorf("%s: %s = %q, want it to contain %q", name, f.field, h, f.want)
		}
	}
	// The tier-3 disclosure rule (adversarial_test.go), held at tier 1: nothing that
	// reaches the client may name a knob or quote a policy rule. The wire numbers the
	// rule; the log names it.
	for _, internal := range []string{"FW_", "block everything", "allow-but-log:", "terminal:", "reject:"} {
		for h, vals := range v.headers {
			if strings.Contains(strings.Join(vals, " "), internal) {
				t.Errorf("%s: POLICY DISCLOSURE in header %s: %q", name, h, vals)
			}
		}
		if b, _ := json.Marshal(v.body); strings.Contains(string(b), internal) {
			t.Errorf("%s: POLICY DISCLOSURE in the body: contains %q", name, internal)
		}
	}
}

func writeLines(t *testing.T, name string, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRefusalCarriesKindRuleAndSource(t *testing.T) {
	t.Run("known-malware feed, package-wide", func(t *testing.T) {
		up := npmTarballUpstream(t, "evil", "bytes", nil)
		defer up.Close()
		feed := writeFeed(t, `{"id":"MAL-2026-1","ecosystem":"npm","name":"evil"}`)
		p := newTestProxy(t, up, func(c *Config) { c.MalwareListPath = feed })
		assertStructured(t, "feed", fetchVerdict(t, p, "/evil"), "known-malware", "MAL-2026-1", "known-malware feed")
	})
	t.Run("version-pinned advisory on the tarball path", func(t *testing.T) {
		up, _ := npmVersionedUpstream(t, "pkg", "1.0.0", "2.0.0")
		defer up.Close()
		p := pinnedProxy(t, up, pinTwo)
		assertStructured(t, "pinned", fetchVerdict(t, p, "/pkg/-/pkg-2.0.0.tgz"), "known-malware", "MAL-NPM-PIN", "known-malware feed")
	})
	t.Run("operator deny list", func(t *testing.T) {
		up := npmTarballUpstream(t, "lodash", "bytes", nil)
		defer up.Close()
		deny := writeLines(t, "deny.txt", "lodash")
		p := newTestProxy(t, up, func(c *Config) { c.DenyListPath = deny })
		assertStructured(t, "deny list", fetchVerdict(t, p, "/lodash"), "operator-denied", "deny-list:lodash", "operator deny list")
	})
	t.Run("score below threshold names the policy rule and the policy digest", func(t *testing.T) {
		up := npmTarballUpstream(t, "lodash", "bytes", nil)
		defer up.Close()
		p := newTestProxy(t, up, func(c *Config) { c.ScoreThreshold = 9.0 }) // stub 7.5 -> below
		v := fetchVerdict(t, p, "/lodash")
		assertStructured(t, "score", v, "score-below-threshold", "verdict#", "policy ")
		if got, want := v.headers.Get("X-Yellowjack-Source"), "policy "+p.firewall.policyDigestNow(); got != want {
			t.Errorf("source %q != the policy in force %q -- the wire and the audit record must name the same policy", got, want)
		}
	})
	t.Run("unscorable under a blocking policy", func(t *testing.T) {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"name":"mystery"}`)) // no repository anywhere: unscorable
		}))
		defer up.Close()
		p := newTestProxy(t, up, nil) // UnscorablePolicy "block"
		assertStructured(t, "unscorable", fetchVerdict(t, p, "/mystery"), "unscorable", "verdict#", "policy ")
	})
	t.Run("release window with nothing compliant left", func(t *testing.T) {
		up, _ := npmTimedUpstream(t, "pkg", twoVersionsTimed(time.Now()), false)
		defer up.Close()
		p := newTestProxy(t, up, func(c *Config) {
			c.MinReleaseAgeDays = 7
			c.UnscorablePolicy = "allow"
		})
		assertStructured(t, "window", fetchVerdict(t, p, "/pkg"), "release-window", "release-window", "release window")
	})
	t.Run("byte-integrity refusal names the check", func(t *testing.T) {
		up := npmTarballUpstream(t, "lodash", "bytes", nil)
		defer up.Close()
		p := newTestProxy(t, up, nil)
		assertStructured(t, "binding", fetchVerdict(t, p, "/_tarball/lodash/other/-/other-1.0.0.tgz"), "integrity", "artifact-binding", "byte integrity")
	})
	t.Run("OCI carries the fields inside the distribution-spec detail", func(t *testing.T) {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
		defer up.Close()
		feed := writeFeed(t, `{"id":"MAL-OCI-1","ecosystem":"oci","name":"library/evil"}`)
		p := newTestProxy(t, up, func(c *Config) {
			c.Ecosystem = "oci"
			c.MalwareListPath = feed
		})
		v := fetchVerdict(t, p, "/v2/library/evil/manifests/latest")
		assertStructured(t, "oci", v, "known-malware", "MAL-OCI-1", "known-malware feed")
		if _, top := v.body["kind"]; top {
			t.Error("OCI put the fields at the top level; the distribution-spec shape keeps them in errors[0].detail")
		}
	})
	t.Run("an allow carries no structured verdict", func(t *testing.T) {
		up := npmTarballUpstream(t, "lodash", "bytes", nil)
		defer up.Close()
		p := newTestProxy(t, up, nil)
		v := fetchVerdict(t, p, "/lodash")
		if v.status != http.StatusOK {
			t.Fatalf("status %d", v.status)
		}
		for _, h := range []string{"X-Yellowjack-Kind", "X-Yellowjack-Rule", "X-Yellowjack-Source", "X-Yellowjack-Reason"} {
			if got := v.headers.Get(h); got != "" {
				t.Errorf("an ALLOWED response carries %s=%q -- the structured verdict is for refusals", h, got)
			}
		}
	})
}

// TestEveryRefusingDecisionNamesItsRuleAndSource is a DRIFT GUARD in the style of
// TestEveryDeclaredDenyKindHasANextStep: it reads the source and requires every
// Decision literal that sets a denial kind to also set Rule and Source. A refusal
// constructed without them ships with an empty structured verdict, which the
// per-site tests above would only catch for the sites they happen to cover.
func TestEveryRefusingDecisionNamesItsRuleAndSource(t *testing.T) {
	literal := regexp.MustCompile(`(?s)Decision\{[^{}]*?\}`)
	found := 0
	for _, file := range []string{"firewall.go", "npmpackument.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range literal.FindAllString(string(src), -1) {
			if !strings.Contains(m, "Deny:") || strings.Contains(m, "Deny:     kind,") {
				continue // not a refusal literal, or the unscorable one that sets kind conditionally
			}
			if strings.Contains(m, "denyNone") {
				continue
			}
			found++
			if !strings.Contains(m, "Rule:") || !strings.Contains(m, "Source:") {
				t.Errorf("%s: a refusing Decision literal names no Rule/Source:\n%s", file, m)
			}
		}
	}
	// Anti-vacuity: the regex must actually be finding the literals it claims to check.
	if found < 8 {
		t.Fatalf("found only %d refusing Decision literals; the pattern has drifted from the source and this guard checks nothing", found)
	}
}

func TestAuditRecordCarriesTheStructuredVerdict(t *testing.T) {
	a := &auditEmitter{ch: make(chan auditEvent, 4)}
	f := &Firewall{cfg: Config{Ecosystem: "npm"}, audit: a}
	f.auditVerdict("evil", "10.0.0.1", Decision{
		Allowed: false, Deny: denyKnownMalware, Rule: "MAL-2026-1", Source: sourceMalwareFeed, Reason: "listed",
	})
	ev := <-a.ch
	if ev.DenyKind != "known-malware" || ev.Rule != "MAL-2026-1" || ev.Source != sourceMalwareFeed {
		t.Errorf("audit record = %+v; want deny_kind/rule/source filled from the Decision", ev)
	}
	f.auditVerdict("fine", "10.0.0.1", Decision{Allowed: true, Reason: "score ok"})
	if ev := <-a.ch; ev.DenyKind != "" || ev.Rule != "" || ev.Source != "" {
		t.Errorf("an allow stamped a structured verdict onto the audit record: %+v", ev)
	}
}
