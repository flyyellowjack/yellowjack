//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"
)

// FW_MODE=report against a real client path, with the enforce control beside it.
//
// The unit tests drive ServeHTTP directly. This leg proves the property survives being
// put in a container and talked to over the wire, which is where the last two mode-ish
// features broke (a byte gate that only enforced in one mode, an approval stub that
// approved everything).
//
// BOTH LEGS ARE REQUIRED. "report mode served the package" is equally true of a firewall
// that is not blocking anything at all — so the enforce leg, same package, same posture,
// same image, is what makes the report leg mean something. Neither half alone is evidence.
func TestReportModeServesWhatEnforceRefuses(t *testing.T) {
	bin := buildFirewall(t)

	// A posture that refuses deterministically: the stub scorer returns a flat 7.5 for
	// every package and the threshold sits above it, so the verdict does not depend on
	// deps.dev, the network, or which package is chosen.
	posture := func(mode string) map[string]string {
		return map[string]string{
			"FW_ECOSYSTEM":         "npm",
			"FW_SCORECARD_MODE":    "stub",
			"FW_SCORE_THRESHOLD":   "8.0",
			"FW_UNSCORABLE_POLICY": "block",
			"FW_MODE":              mode,
		}
	}

	t.Run("enforce_refuses", func(t *testing.T) {
		fw := startFirewall(t, bin, posture("enforce"))
		code, _ := rawGet(t, fwHost(), fw.port, "/lodash")
		if code != http.StatusForbidden {
			t.Fatalf("control: enforce mode returned %d for /lodash, want 403. Nothing is being "+
				"refused in this posture, so the report leg below would prove nothing.\n--- firewall ---\n%s",
				code, logAround(fw.log.String(), 20))
		}
	})

	t.Run("report_serves_and_says_so", func(t *testing.T) {
		fw := startFirewall(t, bin, posture("report"))

		code, body := rawGet(t, fwHost(), fw.port, "/lodash")
		if code != http.StatusOK {
			t.Fatalf("report mode returned %d for /lodash, want 200 — a verdict must not be enforced "+
				"in report mode\n--- firewall ---\n%s", code, logAround(fw.log.String(), 25, "REPORT MODE"))
		}
		// A 200 is not enough on its own: an empty body would satisfy it while the
		// developer's install still failed. Report mode's promise is that the request is
		// SERVED, so assert real packument content came back.
		if !strings.Contains(string(body), "dist-tags") {
			t.Errorf("report mode returned 200 but not a real packument (%d bytes) — a hollow "+
				"success is still a broken install", len(body))
		}

		// The suppressed verdict must be VISIBLE, or report mode is just a disabled gate.
		// Counting these lines is the entire reason an operator runs this mode.
		log := fw.log.String()
		if !strings.Contains(log, "REPORT MODE: WOULD HAVE REFUSED") {
			t.Errorf("the firewall served a package it would have refused and never said so — "+
				"there is nothing for an operator to count\n--- firewall ---\n%s", logAround(log, 25))
		}
		if !strings.Contains(log, "lodash") {
			t.Errorf("the report line does not name the package, so the output cannot be turned "+
				"into a list of what would have broken\n--- firewall ---\n%s", logAround(log, 25, "REPORT MODE"))
		}

		// The banner must announce it. A gate that is not enforcing while every dashboard
		// is green is the worst state this product can be in, so it is asserted, not hoped.
		if !strings.Contains(log, "REPORT ONLY") {
			t.Errorf("the startup banner does not announce report mode; an operator reading the "+
				"logs would not know the gate is enforcing nothing\n--- firewall ---\n%s", logAround(log, 30))
		}
	})
}
