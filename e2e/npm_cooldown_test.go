//go:build e2e

package e2e

// Tier 2 for the npm half of #26: a release cooldown holds back a just-published
// version and a real `npm install` resolves to the settled one, through the same
// packument filter #35 built. The stub registry serves a `time` map only in its full
// packument, the way registry.npmjs.org does, so this leg also proves the firewall asks
// for the full document when a window is active — without that, every version would
// read as "no publish time" and the cooldown would fail the package closed.

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNpmCooldownHoldsBackAJustPublishedRelease(t *testing.T) {
	bin := buildFirewall(t)
	now := time.Now()
	reg := startTwoVersionRegistry(t, map[string]time.Time{
		vfClean:    now.AddDate(0, 0, -400), // settled
		vfPoisoned: now.Add(-2 * time.Hour), // published this morning; upstream's `latest`
	})

	t.Run("control: with no window, npm resolves the just-published latest", func(t *testing.T) {
		fw := startFirewall(t, bin, vfEnv(reg, false))
		defer fw.stop()
		code, out := npmInstallResolving(t, fw.port, vfPkg)
		if code != 0 || !strings.Contains(out, "RESOLVED="+vfPoisoned) {
			t.Fatalf("control: expected npm to resolve %s with NO window configured (exit %d) — the rig is "+
				"broken, so a different resolution in the next leg would prove nothing\n%s\n--- firewall ---\n%s",
				vfPoisoned, code, tail(out, 25), tail(fw.log.String(), 30))
		}
	})

	env := vfEnv(reg, false)
	env["FW_MIN_RELEASE_AGE_DAYS"] = "7"
	fw := startFirewall(t, bin, env)
	defer fw.stop()

	t.Run("a 7-day cooldown steps resolution back to the settled release", func(t *testing.T) {
		code, out := npmInstallResolving(t, fw.port, vfPkg)
		if code != 0 {
			t.Fatalf("npm install FAILED (exit %d) under a cooldown — the window must steer resolution, not fail the "+
				"package\n%s\n--- firewall ---\n%s", code, tail(out, 25), logAround(fw.log.String(), 30, "release-window", "refused"))
		}
		if !strings.Contains(out, "RESOLVED="+vfClean) {
			t.Fatalf("npm installed something other than the settled %s\n%s\n--- firewall ---\n%s", vfClean, tail(out, 25), tail(fw.log.String(), 30))
		}
		for _, want := range []string{
			fmt.Sprintf("[release-window] %s -> version %s removed from the packument (release is within the 7-day cooldown", vfPkg, vfPoisoned),
			fmt.Sprintf(`dist-tag "latest" repointed from refused version %s to %s`, vfPoisoned, vfClean),
		} {
			if !strings.Contains(fw.log.String(), want) {
				t.Errorf("the operator's log lacks %q:\n%s", want, tail(fw.log.String(), 40))
			}
		}
		if strings.Contains(fw.log.String(), "release age could not be verified") {
			t.Errorf("the firewall judged a version with NO publish time — it did not fetch the full packument:\n%s",
				logAround(fw.log.String(), 20, "could not be verified"))
		}
	})

	t.Run("an explicit request for the held-back version does not install it", func(t *testing.T) {
		code, out := npmInstallResolving(t, fw.port, vfPkg+"@"+vfPoisoned)
		if code == 0 {
			t.Fatalf("npm INSTALLED %s@%s inside a 7-day cooldown\n%s\n--- firewall ---\n%s",
				vfPkg, vfPoisoned, tail(out, 25), logAround(fw.log.String(), 30, "release-window"))
		}
		if !strings.Contains(out, "No matching version") && !strings.Contains(out, "ETARGET") {
			t.Errorf("npm failed for an unexpected reason:\n%s", tail(out, 25))
		}
	})
}
