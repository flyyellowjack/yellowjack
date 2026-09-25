//go:build e2e

package e2e

// Tier 2 for D182 (#20): the structured verdict -- kind, rule, source -- survives to
// the client on the wire, in every ecosystem whose protocol has room for it. The
// per-client legibility test (blockreason_test.go) proves a HUMAN can read the reason;
// this one proves a MACHINE can, by fetching the refused metadata document exactly as
// the client would and checking the three headers and the three body fields.
//
// PyPI is the documented exception: a refusal there is a PEP 592 yank inside a 200
// index, because pip backtracks around a 403 but reads a yank reason out loud (D22).
// The index format has no field for a rule identifier, so the structured verdict cannot
// travel on that route; the leg asserts the yank reason is present and says so.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBlockVerdictIsStructuredOnTheWire(t *testing.T) {
	bin := buildFirewall(t)
	legs := []struct {
		name, ecosystem, path string
		yankOnly              bool
	}{
		{"npm", "npm", "/express", false},
		{"maven", "maven", "/com/google/guava/guava/33.0.0-jre/guava-33.0.0-jre.pom", false},
		{"oci", "oci", "/v2/library/alpine/manifests/3.20", false},
		{"pypi", "pypi", "/simple/requests/", true},
	}
	for _, leg := range legs {
		t.Run(leg.name, func(t *testing.T) {
			// Control: the same path through a permissive firewall carries NO verdict
			// fields -- the structure is for refusals, not for every response. What the
			// upstream itself answers is not the point: Docker Hub answers a raw manifest
			// GET with its 401 token challenge (crane does the dance, curl does not), and
			// that 401 is relayed as-is.
			//
			// THE STATUS ALONE CANNOT IDENTIFY WHO REFUSED, which this control used to
			// assume ("only OUR refusal -- a 403 -- would break the control"). An allowed
			// request goes to proxyToUpstream -> relay, and relay writes the UPSTREAM's
			// status verbatim, so an upstream 403 arrives at the client as a 403 too. The
			// raw token-less GET above is exactly the shape a registry throttles, and this
			// leg drove a real CI failure that read as "the rig is broken" when the rig was
			// fine and the registry had answered.
			//
			// So ask the question that actually discriminates: D182 puts the verdict kind
			// on every refusal WE make, and the upstream cannot forge our header namespace.
			// That discriminator is not taken on trust -- the strict leg below asserts the
			// same three headers ARE present on our refusal, so if they ever stopped being
			// emitted this control could not quietly start excusing our own 403s.
			func() {
				fw := startFirewall(t, bin, permissiveEnv(leg.ecosystem, nil))
				defer fw.stop()
				code, hdr, _ := rawGetHeaders(t, fwHost(), fw.port, leg.path)
				ours := ""
				for _, h := range []string{"X-Yellowjack-Kind", "X-Yellowjack-Rule", "X-Yellowjack-Source"} {
					if v := hdr.Get(h); v != "" {
						ours = h + "=" + v
						break
					}
				}
				switch {
				case code == 403 && ours != "":
					t.Fatalf("control: GET %s through a PERMISSIVE firewall was refused by US (403, %s) -- the rig is broken", leg.path, ours)
				case code == 403:
					// Not ours: no verdict header, so this is the upstream's own refusal
					// relayed through. The control's claim -- that a permissive firewall
					// does not refuse -- holds.
					t.Logf("control: upstream refused GET %s (403 carrying no verdict header); "+
						"the permissive firewall relayed it rather than refusing", leg.path)
				case ours != "":
					t.Errorf("control: an ALLOWED response (status %d) carried %s", code, ours)
				}
			}()

			fw := startFirewall(t, bin, strictEnv(leg.ecosystem, map[string]string{"FW_UNVERIFIED_POLICY": "closed"}))
			defer fw.stop()
			code, hdr, body := rawGetHeaders(t, fwHost(), fw.port, leg.path)

			if leg.yankOnly {
				if code != 200 || !strings.Contains(string(body), "yanked") {
					t.Fatalf("pypi: expected a 200 index with every release yanked, got %d:\n%s", code, tail(string(body), 20))
				}
				t.Logf("pypi: the refusal is a PEP 592 yank inside the index; the protocol has no field for a rule identifier, so the structured verdict does not travel on this route (the reason text does)")
				return
			}
			if code != 403 {
				t.Fatalf("GET %s: status %d, want 403\n%s", leg.path, code, tail(string(body), 20))
			}
			var doc map[string]any
			if err := json.Unmarshal(body, &doc); err != nil {
				t.Fatalf("refusal body is not JSON: %v\n%s", err, tail(string(body), 20))
			}
			fields := doc
			if errs, ok := doc["errors"].([]any); ok && len(errs) > 0 { // OCI distribution-spec shape
				fields, _ = errs[0].(map[string]any)["detail"].(map[string]any)
			}
			for _, f := range []struct{ header, field, want string }{
				{"X-Yellowjack-Kind", "kind", "score-below-threshold"},
				{"X-Yellowjack-Rule", "rule", ""},
				{"X-Yellowjack-Source", "source", "policy "},
			} {
				h := hdr.Get(f.header)
				b, _ := fields[f.field].(string)
				switch {
				case h == "" || b == "":
					t.Errorf("%s: header %q / body %q -- the structured field did not survive to the wire", f.field, h, b)
				case h != b:
					t.Errorf("%s: header %q != body %q", f.field, h, b)
				case f.want != "" && !strings.Contains(h, f.want):
					t.Errorf("%s = %q, want it to contain %q", f.field, h, f.want)
				}
			}
			if reason := hdr.Get("X-Yellowjack-Reason"); reason == "" {
				t.Error("the prose reason is missing beside the structured fields -- the human half must stay")
			}
		})
	}
}
