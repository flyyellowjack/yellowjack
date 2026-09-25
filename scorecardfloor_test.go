package main

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The D271 coverage floor (#133 box 3), driven through the real scanner reply path so a
// leg cannot pass on a helper that main never calls.

// partialReply builds a scheduler reply where the named checks errored and every other
// check in the measured 18-check set scored. The aggregate is arbitrary; the floor never
// reads it except to quote it.
func partialReply(errored ...string) string {
	all := []string{"Binary-Artifacts", "Branch-Protection", "CI-Tests", "CII-Best-Practices", "Code-Review",
		"Contributors", "Dangerous-Workflow", "Dependency-Update-Tool", "Fuzzing", "License", "Maintained",
		"Packaging", "Pinned-Dependencies", "SAST", "Security-Policy", "Signed-Releases", "Token-Permissions",
		"Vulnerabilities"}
	bad := map[string]bool{}
	for _, e := range errored {
		bad[e] = true
	}
	type ck struct {
		Name  string `json:"name"`
		Score int    `json:"score"`
	}
	var checks []ck
	scored := 0
	for _, n := range all {
		s := 7
		if bad[n] {
			s = -1
		} else {
			scored++
		}
		checks = append(checks, ck{n, s})
	}
	b, _ := json.Marshal(map[string]any{
		"repo": "gitlab.example/org/repo", "score": 6.2,
		"scoredChecks": scored, "totalChecks": len(all), "checks": checks,
	})
	return string(b)
}

func floorFirewall(t *testing.T, reply, knob string) *Firewall {
	t.Helper()
	srv := startFakeScanner(t, reply)
	return &Firewall{
		cfg:            Config{ScannerURL: srv.URL, ScoreThreshold: 5.0},
		scannerClient:  srv.Client(),
		requiredChecks: parseRequiredChecks(knob),
	}
}

func TestAPartialReportMissingOnlyLowWeightChecksIsAScore(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	f := floorFirewall(t, partialReply("License", "CI-Tests", "Contributors"), "")
	score, err := f.getScoreFromScanner("gitlab.example/org/repo")
	if err != nil {
		t.Fatalf("a report missing only License, CI-Tests and Contributors was refused: %v. That is the "+
			"availability bug #133 exists to fix, and D271's floor is supposed to let this one through", err)
	}
	if score != 6.2 {
		t.Fatalf("score = %v, want the report's 6.2", score)
	}
	// The acceptance must say what the score was computed WITHOUT.
	for _, want := range []string{"partial report", "accepted", "CI-Tests", "Contributors", "License", "15 of 18"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the acceptance log line does not mention %q; an operator cannot see which checks the "+
				"6.2 lacks:\n%s", want, logs.String())
		}
	}
}

func TestAPartialReportMissingARequiredCheckIsUnscorable(t *testing.T) {
	// One required check errored, alongside two low-weight ones. Fifteen of eighteen
	// scored, the same count as the accepted case above: the COUNT cannot tell these
	// apart, which is the whole reason D271 rejected a count.
	f := floorFirewall(t, partialReply("Dangerous-Workflow", "License", "CI-Tests"), "")
	score, err := f.getScoreFromScanner("gitlab.example/org/repo")
	if err == nil {
		t.Fatalf("a report whose Dangerous-Workflow check ERRORED was returned as a score (%.1f) and would be "+
			"compared to FW_SCORE_THRESHOLD as if that check had passed", score)
	}
	// The refusal names the check, not a count; and names the knob that sets the floor.
	for _, want := range []string{"Dangerous-Workflow", "required", "FW_SCORECARD_REQUIRED_CHECKS", "6.2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "License") {
		t.Errorf("the refusal lists a NON-required check as the reason, so it does not say what actually failed the floor: %v", err)
	}
}

func TestTheOperatorCanNarrowOrDisableTheFloor(t *testing.T) {
	t.Run("a narrowed set accepts what the default refuses", func(t *testing.T) {
		f := floorFirewall(t, partialReply("Dangerous-Workflow"), "Token-Permissions")
		if _, err := f.getScoreFromScanner("gitlab.example/org/repo"); err != nil {
			t.Fatalf("FW_SCORECARD_REQUIRED_CHECKS=Token-Permissions, and Dangerous-Workflow errored, yet refused: %v", err)
		}
	})
	t.Run("a narrowed set still refuses its own member", func(t *testing.T) {
		f := floorFirewall(t, partialReply("Token-Permissions"), "Token-Permissions")
		if _, err := f.getScoreFromScanner("gitlab.example/org/repo"); err == nil {
			t.Fatal("the one required check errored and the report was accepted")
		}
	})
	t.Run("none disables the floor", func(t *testing.T) {
		f := floorFirewall(t, partialReply("Dangerous-Workflow", "Webhooks", "Token-Permissions"), "none")
		if _, err := f.getScoreFromScanner("gitlab.example/org/repo"); err != nil {
			t.Fatalf("FW_SCORECARD_REQUIRED_CHECKS=none, yet a partial report was refused: %v", err)
		}
	})
	t.Run("a nil set is the DEFAULT, not no floor", func(t *testing.T) {
		// Every hand-built &Firewall{} literal in the tests has a nil set. If nil
		// meant "no floor", those tests would pass on a floor production lacks.
		srv := startFakeScanner(t, partialReply("Dangerous-Workflow"))
		f := &Firewall{cfg: Config{ScannerURL: srv.URL, ScoreThreshold: 5.0}, scannerClient: srv.Client()}
		if _, err := f.getScoreFromScanner("gitlab.example/org/repo"); err == nil {
			t.Fatal("a Firewall with a nil required set accepted a report missing Dangerous-Workflow")
		}
	})
}

func TestACompleteReportIgnoresTheFloor(t *testing.T) {
	// Negative control for the whole file: with nothing errored the floor must be inert,
	// whatever the set says -- even a set naming a check the report does not carry.
	f := floorFirewall(t, partialReply(), "Not-A-Real-Check")
	score, err := f.getScoreFromScanner("gitlab.example/org/repo")
	if err != nil || score != 6.2 {
		t.Fatalf("a COMPLETE report was refused or altered by the floor: score=%v err=%v", score, err)
	}
}

// TestTheDefaultRequiredSetIsScorecardsOwnRiskLevels pins the default to the source it
// claims to come from. The fixture is Scorecard's docs/checks/internal/checks.yaml, copied
// verbatim on 2026-09-21; the assertion is that every check that file marks Critical or
// High is in the default and nothing else is. When Scorecard re-rates a check, refresh the
// fixture and the default together -- this test is what makes that a conscious step.
func TestTheDefaultRequiredSetIsScorecardsOwnRiskLevels(t *testing.T) {
	raw, err := os.ReadFile("testdata/scorecard_checks.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Each check is a top-level key under `checks:` indented by two spaces, with a
	// `risk:` line somewhere in its block. The fixture is normalised to LF first: on a
	// Windows checkout git hands it over as CRLF, and a pattern ending in `\n` then
	// matches nothing -- which is how this test passed in CI and failed on the dev host
	// the day after it merged.
	src := strings.ReplaceAll(string(raw), "\r\n", "\n")
	head := regexp.MustCompile(`(?m)^  ([A-Z][\w-]+):\n`)
	blocks := head.Split(src, -1)
	names := head.FindAllStringSubmatch(src, -1)
	if len(names) < 15 {
		t.Fatalf("parsed only %d checks from the fixture; the format has changed or the file is not checks.yaml", len(names))
	}
	risk := regexp.MustCompile(`(?m)^\s+risk:\s*(\w+)`)
	want := map[string]bool{}
	for i, m := range names {
		r := risk.FindStringSubmatch(blocks[i+1])
		if r == nil {
			t.Fatalf("check %s has no risk: line in the fixture", m[1])
		}
		if r[1] == "Critical" || r[1] == "High" {
			want[m[1]] = true
		}
	}
	got := parseRequiredChecks("")
	for n := range want {
		if !got[n] {
			t.Errorf("Scorecard documents %s as Critical/High but it is not in the default required set", n)
		}
	}
	for n := range got {
		if !want[n] {
			t.Errorf("%s is in the default required set but Scorecard does not document it as Critical/High", n)
		}
	}
	if len(want) == 0 {
		t.Fatal("the fixture yielded no Critical/High checks; the guard is vacuous")
	}
}
