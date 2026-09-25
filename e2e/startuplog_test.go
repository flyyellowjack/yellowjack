//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// TestHealthyBootIsQuiet is the assertion itself (issue #19): a fully configured
// firewall boots without a single complaint.
//
// It runs the REAL container, because the property is about what an operator sees
// in `docker logs` — the place JFrog's own healthy boot emits 404s, 503s and
// "required node services are missing or unhealthy", leaving an operator unable to
// tell healthy from broken. The detector this leg calls is proven able to fail in
// TestStartupNoiseDetector above, which needs no docker.
//
// "Healthy" here means FULLY CONFIGURED, not default. A default npm boot now warns
// that FW_PUBLIC_URL is unset — correctly, since lockfiles are silently
// non-portable without it — so this leg sets it. Asserting silence on a bare boot
// would force us to choose between deleting a true warning and failing this test.
func TestHealthyBootIsQuiet(t *testing.T) {
	bin := buildFirewall(t)

	for _, eco := range []string{"npm", "pypi", "oci", "maven"} {
		t.Run(eco, func(t *testing.T) {
			fw := startFirewall(t, bin, map[string]string{
				"FW_ECOSYSTEM":      eco,
				"FW_SCORECARD_MODE": "stub",
				// Only npm and pypi rewrite bodies, so only they can warn about this;
				// setting it for all four keeps the leg one shape instead of two.
				"FW_PUBLIC_URL": "https://fw.e2e.internal",
			})
			// startFirewall already blocked until /healthz was green, so the banner
			// is complete by now — no sleep, and nothing racy to tune.
			if noise := startupNoise(fw.log.String()); len(noise) != 0 {
				t.Errorf("a healthy %s boot emitted %d complaint(s); an operator cannot tell healthy "+
					"from broken if a clean start looks like this:\n%s\n--- full boot log ---\n%s",
					eco, len(noise), strings.Join(noise, "\n"), fw.log.String())
			}

			// QUIET IS NOT SILENT. This leg boots in stub mode, which scores every package
			// 7.5 against a threshold of 5.0 -- so the score rule allows everything, and the
			// banner has to say so, or an operator reads allow decisions carrying a plausible
			// score as real scoring. The line is deliberately NOT a "WARNING:": every rig here
			// runs stub on purpose, and a severity token would make this very test's healthy
			// boot noisy -- the failure #19 exists to prevent.
			boot := fw.log.String()
			if !strings.Contains(boot, "stub scoring: every package is scored") ||
				!strings.Contains(boot, "ALLOWS EVERY PACKAGE") {
				t.Errorf("a %s boot in stub mode did not state what stub scoring does to this "+
					"threshold; the banner is where an operator learns the score rule is inert:\n%s",
					eco, boot)
			}
		})
	}
}

// A real healthy boot, captured from the firewall binary with a full configuration.
// Kept verbatim rather than hand-written: a detector tuned against invented text is
// a detector tuned against the wrong thing.
const cleanBootLog = `2026/08/08 00:19:33 Yellow Jack starting on 127.0.0.1:18095
2026/08/08 00:19:33   policy 0a4fb2c960e221e0: verdict(3 rules, default=reject) classification(3 rules, default=reject) bytes(3 rules, default=allow-but-log)
2026/08/08 00:19:33   ecosystem:         npm
2026/08/08 00:19:33   upstream:          https://registry.npmjs.org
2026/08/08 00:19:33   public URL:        https://npm.fw.internal
2026/08/08 00:19:33   score threshold:   5.0
2026/08/08 00:19:33   unscorable policy: block
2026/08/08 00:19:33   scorecard mode:    stub
2026/08/08 00:19:33   repo verification: off (scorecard mode "stub" cannot reach deps.dev)
2026/08/08 00:19:33   artifact byte gate: allow-but-log (blocked packages ARE refused; unscorable/unverifiable ones are served and logged — set FW_BYTE_GATE=enforce to refuse those too)
`

// TestStartupNoiseDetector is the negative control for the e2e leg below it.
//
// The leg asserts a clean boot produces no complaints. That assertion is worthless
// unless the detector can actually SEE a complaint, and the detector runs inside a
// container leg where nobody watches it fail — so it is exercised here, against
// literal text, with no docker runner.
func TestStartupNoiseDetector(t *testing.T) {
	t.Run("a clean boot is quiet", func(t *testing.T) {
		if got := startupNoise(cleanBootLog); len(got) != 0 {
			t.Errorf("clean boot reported %d noisy lines, want 0:\n%s", len(got), strings.Join(got, "\n"))
		}
	})

	// Each of these is a real line the firewall can emit. If the detector misses any
	// of them, the e2e leg below would pass through a genuinely noisy boot.
	noisy := map[string]string{
		"unset public URL": "  WARNING: FW_PUBLIC_URL is unset, so artifact URLs follow each request's Host header.",
		"fatal config":     "FATAL: invalid configuration: FW_VERIFY_REPO=\"ture\" is not a boolean (true/false)",
		"error line":       "ERROR: something went wrong during boot",
		"panic":            "panic: runtime error: invalid memory address",
	}
	for name, line := range noisy {
		t.Run(name+" is caught", func(t *testing.T) {
			got := startupNoise(cleanBootLog[:strings.Index(cleanBootLog, "  ecosystem")] + line + "\n")
			if len(got) == 0 {
				t.Errorf("detector missed a noisy boot line, so the e2e leg would pass a broken boot: %q", line)
			}
		})
	}

	// The detector must key on the severity token, not on prose. Several healthy
	// banner lines explain what happens on an error; if those tripped it, a clean
	// boot would fail and the assertion would get deleted rather than the noise fixed.
	t.Run("prose containing the word error is not noise", func(t *testing.T) {
		line := "  unscorable policy: block (an error fetching metadata is not a verdict)\n"
		if got := startupNoise(line); len(got) != 0 {
			t.Errorf("false positive on explanatory prose: %v", got)
		}
	})

	// Traffic is not boot. A WARNING about a package, after the banner, is the
	// firewall doing its job — failing on it would make the assertion untenable.
	t.Run("post-banner traffic is not scanned", func(t *testing.T) {
		withTraffic := cleanBootLog + "2026/08/08 00:20:01 WARNING: package \"left-pad\" served under allow-but-log\n"
		if got := startupNoise(withTraffic); len(got) != 0 {
			t.Errorf("scanned past the boot banner into request traffic: %v", got)
		}
	})
}

// A control that is SET and that the gate cannot ENFORCE must be loud at boot (D299, the
// startup half of #150). This leg exists because inertsettings_test.go can only prove the
// function returns the right text: whether main() ever PRINTS it is a property of the real
// binary, and a helper's own test never proves its call site is wired.
func TestInertSettingIsLoudAtBoot(t *testing.T) {
	bin := buildFirewall(t)
	boot := func(eco string) string {
		fw := startFirewall(t, bin, map[string]string{
			"FW_ECOSYSTEM":            eco,
			"FW_SCORECARD_MODE":       "stub",
			"FW_PUBLIC_URL":           "https://fw.e2e.internal",
			"FW_MIN_RELEASE_AGE_DAYS": "7",
		})
		defer fw.stop()
		return fw.log.String()
	}
	const want = "WARNING: FW_MIN_RELEASE_AGE_DAYS=7 is set but is NOT ENFORCED on this oci gate"
	if log := boot("oci"); !strings.Contains(log, want) {
		t.Errorf("an OCI gate booted with a release cooldown it cannot enforce and did not say so.\n"+
			"want a line containing: %s\n--- boot log ---\n%s", want, log)
	}
	// THE CONTROL: the same knob on a gate that DOES enforce it must not be called inert.
	// Without this the leg passes on a binary that warns about the knob everywhere.
	if log := boot("npm"); strings.Contains(log, "NOT ENFORCED") {
		t.Errorf("an npm gate, which enforces the cooldown, was told it does not:\n%s", log)
	}
}
