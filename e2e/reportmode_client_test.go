//go:build e2e

package e2e

// Tier 2 for #114, through a REAL client: the posture that refuses every package under
// enforce refuses none of them under report, and the firewall still records what it
// would have done. reportmode_test.go proves the same on a raw GET; a developer runs
// npm, not curl, so this leg is the one the acceptance text asks for.

import (
	"strings"
	"testing"
)

func TestReportModeBlocksNothingForARealClient(t *testing.T) {
	bin := buildFirewall(t)
	posture := func(mode string) map[string]string {
		return map[string]string{
			"FW_ECOSYSTEM":         "npm",
			"FW_SCORECARD_MODE":    "stub", // flat 7.5
			"FW_SCORE_THRESHOLD":   "8.0",  // above it: EVERY package is refused under enforce
			"FW_UNSCORABLE_POLICY": "block",
			"FW_MODE":              mode,
		}
	}

	// Negative control FIRST: the same corpus must produce blocks under enforce, and the
	// client must see them, or "zero blocks under report" would be true of a posture that
	// blocks nothing anywhere.
	t.Run("control: enforce refuses the install", func(t *testing.T) {
		fw := startFirewall(t, bin, posture("enforce"))
		defer fw.stop()
		code, out := runNpmInstall(t, fw.port, "lodash")
		if code == 0 {
			t.Fatalf("control: `npm install lodash` SUCCEEDED under enforce with threshold 8.0 over a 7.5 stub -- "+
				"nothing is being refused, so the report leg would prove nothing\n%s\n--- firewall ---\n%s",
				tail(out, 20), logAround(fw.log.String(), 20, "allowed=false"))
		}
		if !strings.Contains(out, blockedMarker) {
			t.Errorf("control: the refusal never reached npm's output:\n%s", tail(out, 20))
		}
	})

	t.Run("report: the same install succeeds and every refusal is recorded as would-have", func(t *testing.T) {
		fw := startFirewall(t, bin, posture("report"))
		defer fw.stop()
		code, out := runNpmInstall(t, fw.port, "lodash")
		if code != 0 {
			t.Fatalf("`npm install lodash` FAILED (exit %d) under FW_MODE=report -- report mode must block nothing\n%s\n--- firewall ---\n%s",
				code, tail(out, 20), logAround(fw.log.String(), 25, "REPORT MODE", "allowed=false"))
		}
		if strings.Contains(out, blockedMarker) {
			t.Errorf("report mode still put a refusal in front of the developer:\n%s", tail(out, 20))
		}
		log := fw.log.String()
		wouldHave := strings.Count(log, "REPORT MODE: WOULD HAVE REFUSED")
		if wouldHave == 0 {
			t.Errorf("report mode served packages the posture refuses and recorded nothing -- there is nothing for an operator to count\n--- firewall ---\n%s", tail(log, 30))
		}
		if !strings.Contains(log, "*** REPORT ONLY") {
			t.Errorf("the startup log does not announce report mode -- an operator must never be unsure whether the gate is enforcing\n%s", tail(log, 40))
		}
		t.Logf("report mode: install succeeded; %d would-have-refused record(s) written", wouldHave)
	})
}
