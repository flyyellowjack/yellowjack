//go:build e2e

package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// #51 acceptance item 3: "Client-side onboarding cost is asserted: a real client is
// pointed at the firewall with ONE config line and NO new tooling, proven in e2e rather
// than claimed."
//
// WHY THE EXISTING RIGS CANNOT ANSWER IT. `npmInstallCmd` sets FOUR env vars, but three
// are rig hygiene — cache location, muting fund/audit noise — not onboarding. A reader
// counting them would price adoption at 4x its real cost; a reader assuming one would be
// guessing. Each case here passes the MINIMAL configuration and lets the client fail if
// that is not enough, so the number is measured rather than asserted.
//
// MEASURED 2026-09-19, and the headline is not the one #51 assumes:
//
//	npm  1 env var  (npm_config_registry)                       -> works
//	pip  1 env var  (PIP_INDEX_URL)                             -> FAILS
//	pip  2 env vars (+ PIP_TRUSTED_HOST)                        -> works
//
// The second pip variable is not our cost. pip refuses to use a PLAIN-HTTP index and says
// so; over HTTPS the trusted-host line is unnecessary (measured, not assumed: see
// TestGateBehindATLSTerminator in ingress_tls_test.go). So the honest statement of the
// budget is: **one config line per client where TLS is terminated, and one extra knob per
// client where it is not.** That is a deployment property, and it gives the interception
// work (#39) an onboarding benefit nobody had costed.
//
// Maven is the known exception and is NOT claimed here: Maven 3.8.1+ blocks plain-HTTP
// repositories outright, so `-DremoteRepositories` never reaches the gate (measured, see
// the comment on mavenMirrorSettings) and the rigs use a settings.xml FILE. Over HTTPS a
// single `-DremoteRepositories` flag does NOT suffice either, for a different reason: it adds
// a repository, central is consulted first, and the gate is never asked (measured,
// TestMavenBehindATLSTerminator).

// onboardingEnv is the permissive posture: this leg measures CONFIGURATION COST, so a
// verdict must never be what fails an install. A blocked package here would read as
// "onboarding needs another knob", which is the exact wrong conclusion.
func onboardingEnv(ecosystem string) map[string]string {
	return map[string]string{
		"FW_ECOSYSTEM":         ecosystem,
		"FW_SCORECARD_MODE":    "stub",
		"FW_SCORE_THRESHOLD":   "0",
		"FW_UNSCORABLE_POLICY": "allow",
		"FW_UNVERIFIED_POLICY": "open-with-visibility",
	}
}

func runClient(t *testing.T, args ...string) (int, string) {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatalf("could not run %s: %v", args[0], err)
	}
	return 0, string(out)
}

// mustHaveReachedTheGate is the vacuity guard, and the success legs are worthless without
// it.
//
// Found by sabotage while writing this file: renaming `npm_config_registry` to a name npm
// ignores left the leg GREEN — npm fell back to registry.npmjs.org and installed the
// package perfectly well. A success leg that checks only the client's exit code cannot
// tell "onboarding works with one variable" from "the variable did nothing and the public
// registry served it", and the second is what a typo produces.
//
// So each success leg asserts the DECISION LOG names the package: the gate cannot have
// judged something it never saw.
func mustHaveReachedTheGate(t *testing.T, fw *firewall, pkg, client string) {
	t.Helper()
	logs := fw.log.String()
	if !strings.Contains(logs, pkg) {
		t.Fatalf("%s exited 0 but the gate never logged a decision for %q — the client did NOT go "+
			"through the firewall, so this leg measured nothing about onboarding cost. The likeliest "+
			"cause is a config variable name that the client ignores, leaving it to fall back to the "+
			"public registry.\n--- decision log ---\n%s", client, pkg, tail(logs, 25))
	}
}

// TestOnboardingCostIsOneLinePerClient pins the measured cost so a regression — a release
// that needs a second knob to point a client at us — reddens instead of being absorbed
// into a longer setup doc.
func TestOnboardingCostIsOneLinePerClient(t *testing.T) {
	bin := buildFirewall(t)

	t.Run("npm needs exactly one env var", func(t *testing.T) {
		fw := startFirewall(t, bin, onboardingEnv("npm"))
		defer fw.stop()
		code, out := runClient(t, "docker", "run", "--rm", "-w", "/work",
			"--add-host", "host.docker.internal:host-gateway",
			"-e", fmt.Sprintf("npm_config_registry=http://host.docker.internal:%d/", fw.port),
			"node:22-alpine", "npm", "install", "--no-save", "is-number")
		if code != 0 {
			t.Errorf("npm ONBOARDING COST HAS GONE UP: `npm_config_registry` alone no longer installs "+
				"through the gate (exit %d). #51's budget is one config line per client; if a second is "+
				"now required, that is a real adoption cost and belongs in docs/SETUP.md and on #51 — "+
				"not absorbed silently.\n%s", code, tail(out, 20))
		}
		mustHaveReachedTheGate(t, fw, "is-number", "npm")
	})

	// The pip pair is one measurement in two halves, and the FAILING half is the
	// instrument: without it, "pip needs two variables" is indistinguishable from "we
	// set two out of habit" (which is exactly what the npm rig does).
	t.Run("pip refuses a plain-http index with one env var", func(t *testing.T) {
		fw := startFirewall(t, bin, onboardingEnv("pypi"))
		defer fw.stop()
		code, out := runClient(t, "docker", "run", "--rm",
			"--add-host", "host.docker.internal:host-gateway",
			"-e", fmt.Sprintf("PIP_INDEX_URL=http://host.docker.internal:%d/simple/", fw.port),
			"python:3.12-slim", "pip", "install", "--no-cache-dir", "--target", "/tmp/s", "six")
		if code == 0 {
			t.Errorf("pip installed through a PLAIN-HTTP index with only PIP_INDEX_URL. That is a change " +
				"in pip, and a GOOD one for us — onboarding drops to one line over http too. Re-measure " +
				"and update this leg and #51's budget.")
			return
		}
		// Assert the REASON, not just the failure: any broken rig also exits non-zero.
		if !strings.Contains(out, "not a trusted or secure host") {
			t.Errorf("pip failed (exit %d) but NOT for the trusted-host reason this leg is about, so it "+
				"proves nothing about onboarding cost. Something else is broken.\n%s", code, tail(out, 20))
		}
	})

	t.Run("pip needs two over plain http", func(t *testing.T) {
		fw := startFirewall(t, bin, onboardingEnv("pypi"))
		defer fw.stop()
		code, out := runClient(t, "docker", "run", "--rm",
			"--add-host", "host.docker.internal:host-gateway",
			"-e", fmt.Sprintf("PIP_INDEX_URL=http://host.docker.internal:%d/simple/", fw.port),
			"-e", "PIP_TRUSTED_HOST=host.docker.internal",
			"python:3.12-slim", "pip", "install", "--no-cache-dir", "--target", "/tmp/s", "six")
		if code != 0 {
			t.Errorf("pip ONBOARDING COST HAS GONE UP: index-url + trusted-host no longer suffices "+
				"(exit %d). Two is the measured plain-http cost; a third knob is a real adoption "+
				"regression.\n%s", code, tail(out, 20))
		}
		mustHaveReachedTheGate(t, fw, "six", "pip")
	})
}
