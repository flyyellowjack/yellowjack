//go:build e2e

package e2e

// Tier 2 for the MAVEN half of #26, against the real Maven Central with a real `mvn`.
//
// The unit tests date artifacts with a fake upstream, which proves the logic and
// proves nothing about the premise the whole feature rests on: that Maven Central
// actually serves a per-version `Last-Modified` we can read. Probed by hand
// 2026-09-12 (guava 33.4.0-jre → 2024-12-16, 32.0.0-jre → 2023-05-26), and this leg
// is what keeps that true — if Central stops sending the header, the fail-closed
// branch fires and the "too new"/"too old" legs below start reporting
// "could not be verified" instead, which they assert against by name.
//
// The two bounds are set to ABSURD values on purpose (274 years, and 1 day) so the
// outcome does not depend on the date the suite runs. A leg whose verdict drifts with
// the calendar is a leg that goes red in six months for no reason.

import (
	"strings"
	"testing"
)

// A long-settled release. Any real, old coordinate works; this one is already used by
// the other Maven legs, so a resolution failure here is a shared-rig problem rather
// than something specific to this test.
const cooldownGAV = "com.google.guava:guava:33.0.0-jre"

func mavenCooldownEnv(extra map[string]string) map[string]string {
	env := map[string]string{
		"FW_ECOSYSTEM":       "maven",
		"FW_SCORECARD_MODE":  "api",
		"FW_SCORE_THRESHOLD": "0",
		// Both fail-open knobs, for the reason TestMavenEndToEnd records at length:
		// deps.dev's Maven source-repo coverage is patchy, and with <mirrorOf>*</mirrorOf>
		// maven's own plugin tree crosses the gate. Without these the leg cannot
		// bootstrap and we would be measuring D36, not the release window.
		"FW_UNSCORABLE_POLICY": "allow",
		"FW_UNVERIFIED_POLICY": "open-with-visibility",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

func TestMavenReleaseWindowThroughARealClient(t *testing.T) {
	bin := buildFirewall(t)

	// ── CONTROL ──────────────────────────────────────────────────────────────
	// With no window configured the artifact resolves. Without this, a refusal in
	// the legs below could just as well be the rig failing to reach Central at all.
	t.Run("control: no window configured, mvn resolves", func(t *testing.T) {
		fw := startFirewall(t, bin, mavenCooldownEnv(nil))
		defer fw.stop()
		code, out := runMvnGet(t, fw.port, cooldownGAV)
		if code != 0 {
			anchors := append(mvnFailedArtifacts(out), "guava")
			t.Fatalf("control: `mvn get` failed with NO window configured (exit %d) — the rig is broken, "+
				"so a refusal in the next legs would prove nothing\n%s\n--- firewall ---\n%s",
				code, tail(out, 20), logAround(fw.log.String(), 40, anchors...))
		}
		if strings.Contains(fw.log.String(), "[release-window]") {
			t.Errorf("the release window fired with both bounds unset:\n%s",
				logAround(fw.log.String(), 20, "release-window"))
		}
	})

	// ── THE COOLDOWN EDGE ────────────────────────────────────────────────────
	t.Run("a 274-year cooldown refuses even a settled release", func(t *testing.T) {
		fw := startFirewall(t, bin, mavenCooldownEnv(map[string]string{
			"FW_MIN_RELEASE_AGE_DAYS": "100000",
		}))
		defer fw.stop()
		code, _ := runMvnGet(t, fw.port, cooldownGAV)
		if code == 0 {
			t.Fatalf("`mvn get` SUCCEEDED under a cooldown no release can satisfy — the window "+
				"is not reaching Maven (#26)\n--- firewall ---\n%s", logAround(fw.log.String(), 40, "guava"))
		}
		logs := fw.log.String()
		if !strings.Contains(logs, "[release-window]") {
			t.Fatalf("the refusal did not come from the release window, so this leg proves "+
				"nothing about #26\n%s", logAround(logs, 40, "guava", "allowed=false"))
		}
		if !strings.Contains(logs, "cooldown") {
			t.Errorf("the operator's log does not name the cooldown:\n%s", logAround(logs, 30, "release-window"))
		}
		// THE PREMISE CHECK. If Central stopped sending Last-Modified, the fail-closed
		// branch would also produce a refusal naming the release window — and this leg
		// would keep passing while testing something else entirely.
		if strings.Contains(logs, "could not be verified") {
			t.Errorf("the refusal was the FAIL-CLOSED branch, not the cooldown: Maven Central "+
				"served no readable Last-Modified, so the per-version date this feature "+
				"depends on is gone\n%s", logAround(logs, 30, "could not be verified"))
		}
	})

	// ── THE AGE-FLOOR EDGE ───────────────────────────────────────────────────
	// The same window's other side (D22), which shares one decision function with
	// the cooldown. Asserted separately so a change that fixed one and broke the
	// other cannot pass.
	t.Run("a 1-day age floor refuses a years-old release", func(t *testing.T) {
		fw := startFirewall(t, bin, mavenCooldownEnv(map[string]string{
			"FW_MAX_RELEASE_AGE_DAYS": "1",
		}))
		defer fw.stop()
		code, _ := runMvnGet(t, fw.port, cooldownGAV)
		if code == 0 {
			t.Fatalf("`mvn get` SUCCEEDED under a 1-day age floor\n--- firewall ---\n%s",
				logAround(fw.log.String(), 40, "guava"))
		}
		logs := fw.log.String()
		if !strings.Contains(logs, "age floor") {
			t.Errorf("the refusal does not name the age floor — a developer cannot tell it from "+
				"the cooldown, which would clear on its own while this never will\n%s",
				logAround(logs, 30, "release-window"))
		}
	})
}
