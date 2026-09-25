//go:build e2e

package e2e

// #162, tier 2: a real npm, the real registry, the default fail-closed unscorable policy.
//
// Each package below declares its GitHub repository in a spelling npm itself resolves and
// the registry serves verbatim (checked against the live registry when this was written).
// Before #162 the gate refused all three as "does not declare a usable source repository".
// The control declares genuinely no repository and must STILL be refused -- without it, a
// pass here could mean the policy stopped refusing anything at all.

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func npmView(t *testing.T, port int, pkg string) (int, string) {
	t.Helper()
	reg := fmt.Sprintf("http://host.docker.internal:%d/", port)
	out, err := exec.Command("docker", "run", "--rm",
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "npm_config_registry="+reg,
		"-e", "npm_config_cache=/tmp/npmcache",
		"node:22-alpine", "npm", "view", pkg, "version").CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatalf("could not run docker: %v\n%s", err, out)
	}
	return 0, string(out)
}

func TestNpmRepositorySpellingsAreResolved(t *testing.T) {
	bin := buildFirewall(t)
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":         "npm",
		"FW_SCORECARD_MODE":    "stub", // a declared repo scores 7.5, over the default threshold
		"FW_UNSCORABLE_POLICY": "block",
	})

	for _, tc := range []struct {
		pkg, spelling string
	}{
		{"formidable", `"node-formidable/formidable"`},
		{"react-intl", `"git@github.com:formatjs/formatjs.git"`},
		{"ndarray-pixels", `"github:donmccurdy/ndarray-pixels"`},
	} {
		t.Run(tc.pkg, func(t *testing.T) {
			code, out := npmView(t, fw.port, tc.pkg)
			ds := fw.decisionsFor(tc.pkg)
			if len(ds) == 0 {
				t.Fatalf("NO CONTACT: the gate judged nothing for %s -- npm did not reach it (exit %d):\n%s",
					tc.pkg, code, tail(out, 15))
			}
			for _, d := range ds {
				if !d.allowed {
					t.Fatalf("%s declares %s, which npm resolves to GitHub, and the gate still refused it: %q",
						tc.pkg, tc.spelling, d.reason)
				}
			}
			if code != 0 {
				t.Fatalf("the gate allowed %s but npm failed (exit %d):\n%s", tc.pkg, code, tail(out, 15))
			}
			t.Logf("%s (%s) served: %s", tc.pkg, tc.spelling, strings.TrimSpace(tail(out, 1)))
		})
	}

	// THE CONTROL: no repository at all is still refused, with the reason that names it.
	t.Run("control_@types/wrap-ansi_declares_nothing", func(t *testing.T) {
		code, out := npmView(t, fw.port, "@types/wrap-ansi")
		ds := fw.decisionsFor("@types/wrap-ansi")
		if len(ds) == 0 {
			t.Fatalf("NO CONTACT for the control (exit %d):\n%s", code, tail(out, 15))
		}
		refused := false
		for _, d := range ds {
			if !d.allowed && strings.Contains(d.reason, "does not declare a usable source repository") {
				refused = true
			}
		}
		if !refused || code == 0 {
			t.Fatalf("CONTROL BROKEN: a package with no repository was not refused for that reason (exit %d); "+
				"the passes above would then prove nothing.\n%s", code, tail(fw.log.String(), 10))
		}
		t.Logf("control held: refused, %q", ds[0].reason)
	})
}
