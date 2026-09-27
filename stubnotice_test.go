package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
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

// TestStubNoticeTellsTheTruthAboutUnscorablePackages pins the sentence E123 caught being
// false. "Every package is scored 7.5 ... the only enforcement left is the operator lists and
// the known-malware feed" was printed at the shipped defaults, while a package with no
// resolvable source repository is never scored and FW_UNSCORABLE_POLICY=block refuses it.
// The notice is checked against the gate's OWN verdicts on two real packages, so the words
// and the behaviour cannot part again.
func TestStubNoticeTellsTheTruthAboutUnscorablePackages(t *testing.T) {
	up := npmUpstream(t) // serves "lodash" (declares a repository) and "norepo" (declares none)
	for _, tc := range []struct {
		policy      string
		norepoAllow bool
		say         string
	}{
		{policy: "block", norepoAllow: false, say: "REFUSED (FW_UNSCORABLE_POLICY=block)"},
		{policy: "allow", norepoAllow: true, say: "served"},
		{policy: "", norepoAllow: true, say: "served"}, // unset means allow on this path (policy.go)
	} {
		t.Run("policy="+tc.policy, func(t *testing.T) {
			cfg := Config{Ecosystem: "npm", UpstreamRegistry: up.URL, ScorecardMode: "stub",
				ScoreThreshold: 5.0, UnscorablePolicy: tc.policy}
			f, err := NewFirewall(cfg)
			if err != nil {
				t.Fatalf("NewFirewall: %v", err)
			}
			if d := f.Evaluate("lodash"); !d.Allowed {
				t.Fatalf("control: a package WITH a repository was refused under stub scoring: %s", d.Reason)
			}
			d := f.Evaluate("norepo")
			if d.Allowed != tc.norepoAllow {
				t.Fatalf("the gate's own verdict on a repo-less package: allowed=%v, want %v (%s)", d.Allowed, tc.norepoAllow, d.Reason)
			}
			n := stubScoringNotice(cfg)
			if !strings.Contains(n, tc.say) {
				t.Errorf("the gate %s a repo-less package but the banner does not say %q:\n%s",
					map[bool]string{true: "serves", false: "refuses"}[d.Allowed], tc.say, n)
			}
			if !d.Allowed && strings.Contains(n, "the only enforcement left is") {
				t.Errorf("the banner still claims the lists and feed are the only enforcement while the gate refuses unscorable packages:\n%s", n)
			}
		})
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

// TestTheE2EBannerAssertionsMatchTheBanner reads the strings e2e/startuplog_test.go
// expects in a stub-mode boot and checks each against the banner this package prints for
// that leg's configuration. The e2e leg runs nightly, not on a merge request, so a
// rewording of the banner (!412) left it failing on main with every merge-time gate green.
// This moves the same check to every push.
func TestTheE2EBannerAssertionsMatchTheBanner(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "e2e/startuplog_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Contains" {
			return true
		}
		if id, ok := call.Args[0].(*ast.Ident); !ok || id.Name != "boot" {
			return true
		}
		if lit, ok := call.Args[1].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil {
				want = append(want, s)
			}
		}
		return true
	})
	if len(want) < 2 {
		t.Fatalf("read %d banner assertions from e2e/startuplog_test.go, want at least 2; the parse no longer "+
			"finds them, so this guard would pass having checked nothing", len(want))
	}
	// The e2e leg boots with the defaults: stub scoring, threshold 5.0, unscorable blocked.
	notice := stubScoringNotice(Config{ScorecardMode: "stub", ScoreThreshold: 5.0, UnscorablePolicy: "block"})
	for _, w := range want {
		if !strings.Contains(notice, w) {
			t.Errorf("e2e/startuplog_test.go expects %q in a stub-mode boot, and the banner no longer says it. "+
				"Update the e2e assertion with the banner, or the nightly run fails:\n%s", w, notice)
		}
	}
}
