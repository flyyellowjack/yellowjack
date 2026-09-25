package main

import (
	"strings"
	"testing"
)

// The startup banner must tell an operator what stub scoring MEANS for their threshold,
// because the shipped defaults combine into the one posture nobody would choose on
// purpose: FW_SCORECARD_MODE defaults to "stub", which scores every repository 7.5, and
// FW_SCORE_THRESHOLD defaults to 5.0 — so an out-of-the-box firewall allows every package
// on the score rule while logging allow decisions that look exactly like real ones.

// TestStubNoticeStatesTheConsequenceForThisThreshold pins the thing that makes the line
// worth printing: it is a statement about the operator's OWN configuration, and it flips
// when the configuration would flip the outcome.
func TestStubNoticeStatesTheConsequenceForThisThreshold(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cfg       Config
		want      string
		wantNot   string
		mustName  []string
		mustBeNil bool
	}{
		{
			name:     "the shipped defaults: everything passes on score",
			cfg:      Config{ScorecardMode: "stub", ScoreThreshold: 5.0},
			want:     "ALLOWS EVERY PACKAGE",
			wantNot:  "REFUSES EVERY PACKAGE",
			mustName: []string{"7.5", "5.0", "operator lists", "known-malware feed", "FW_SCORECARD_MODE=api"},
		},
		{
			name:     "a threshold above the fixed score: nothing passes on score",
			cfg:      Config{ScorecardMode: "stub", ScoreThreshold: 9.0},
			want:     "REFUSES EVERY PACKAGE",
			wantNot:  "ALLOWS EVERY PACKAGE",
			mustName: []string{"7.5", "9.0"},
		},
		{
			name: "exactly at the fixed score is still a pass, as the score rule reads it",
			cfg:  Config{ScorecardMode: "stub", ScoreThreshold: stubScore},
			want: "ALLOWS EVERY PACKAGE",
		},
		{name: "api mode says nothing", cfg: Config{ScorecardMode: "api", ScoreThreshold: 5.0}, mustBeNil: true},
		{name: "local mode says nothing", cfg: Config{ScorecardMode: "local", ScoreThreshold: 5.0}, mustBeNil: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := stubScoringNotice(tc.cfg)
			if tc.mustBeNil {
				if got != "" {
					t.Fatalf("a real scoring mode produced a stub notice: %q", got)
				}
				return
			}
			if got == "" {
				t.Fatal("stub mode produced no notice at all")
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("notice does not say %q:\n%s", tc.want, got)
			}
			if tc.wantNot != "" && strings.Contains(got, tc.wantNot) {
				t.Errorf("notice says %q, which is the opposite of what this threshold does:\n%s", tc.wantNot, got)
			}
			for _, w := range tc.mustName {
				if !strings.Contains(got, w) {
					t.Errorf("notice does not name %q, so the operator cannot check it against what they configured:\n%s", w, got)
				}
			}
		})
	}
}

// TestStubNoticeAgreesWithTheScorer is the point of the named constant. A banner that
// states a number the scorer does not actually return would be worse than no banner: the
// operator would check it, find it consistent, and be wrong.
func TestStubNoticeAgreesWithTheScorer(t *testing.T) {
	f, err := NewFirewall(Config{
		Ecosystem:        "npm",
		UpstreamRegistry: "http://unused.invalid",
		ScorecardMode:    "stub",
		ScoreThreshold:   5.0,
		UnscorablePolicy: "block",
	})
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	got, err := f.getScore("github.com/any/repo")
	if err != nil {
		t.Fatalf("stub getScore: %v", err)
	}
	if got != stubScore {
		t.Fatalf("stub scoring returns %.2f but the banner constant is %.2f — the startup line is telling operators a number the gate does not use", got, stubScore)
	}
	// And the notice quotes that same number rather than a literal of its own.
	if n := stubScoringNotice(Config{ScorecardMode: "stub", ScoreThreshold: 5.0}); !strings.Contains(n, "7.5") {
		t.Errorf("the notice does not quote the stub score it is describing:\n%s", n)
	}
}

// TestStubNoticeIsNotASeverityLine keeps the banner honest AND quiet. #19 asserts a
// healthy boot emits no ERROR/WARN/FATAL, and every e2e rig runs stub deliberately — so a
// severity token here would make the rigs' own healthy boots noisy, which is exactly the
// failure #19 exists to prevent. The line has to be loud to a human and invisible to the
// noise detector, which is what the banner's "***" shape is for.
func TestStubNoticeIsNotASeverityLine(t *testing.T) {
	n := stubScoringNotice(Config{ScorecardMode: "stub", ScoreThreshold: 5.0})
	for _, token := range []string{"WARNING:", "ERROR:", "FATAL:", "panic:"} {
		if strings.Contains(n, token) {
			t.Errorf("the stub notice carries the severity token %q, which makes every e2e rig's healthy boot noisy (#19):\n%s", token, n)
		}
	}
}
