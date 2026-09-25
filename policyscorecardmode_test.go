package main

import "testing"

// TestPolicyReportsScorecardModeUnderTheNameTheConsoleReads pins the GATE's half of a
// cross-boundary contract (#151).
//
// The console decides whether to hide its scoring surfaces by reading
// Values["scorecard_mode"] from each replica's reported policy. The console's own
// tests use hand-built fixtures that contain that key, and TestDigestCoversEvery-
// ReportedValue iterates whatever keys EXIST -- so without this test, deleting or
// renaming the key on the gate side reddens nothing anywhere: the console fixtures
// keep passing against a key the real gate no longer sends, and the pages silently
// stop hiding. A helper's own test never proves its call site is wired.
//
// The two services are separate packages that share no constant (each owns its own
// DTO, same rule as the firewall<->approval boundary), so the literal is pinned on
// both sides instead: here, and in console/scoringoff_test.go.
func TestPolicyReportsScorecardModeUnderTheNameTheConsoleReads(t *testing.T) {
	for _, mode := range []string{"stub", "api", "local", scorecardModeOff} {
		cfg := shippedConfig()
		cfg.ScorecardMode = mode
		got, ok := (&Firewall{cfg: cfg}).describePolicy().Values["scorecard_mode"]
		if !ok {
			t.Fatalf("the gate's policy report has no \"scorecard_mode\" key; the console reads exactly that "+
				"name to decide whether to hide scoring surfaces (#151), so with it gone the pages stop "+
				"hiding and nothing else fails (mode under test: %q)", mode)
		}
		if got != mode {
			t.Errorf("scorecard_mode reported as %q, want %q", got, mode)
		}
	}
}
