package main

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"testing"
)

// Tier-1 tests for the policy engine (D76, issue #58 — see policy.go).
//
// Two things are being pinned here, and they fail for different reasons:
//
//  1. THE ENGINE'S CONTRACT — order decides, first match wins, and a request
//     that matches nothing is REJECTED. That last one is the whole point of the
//     epic, so it is tested against an empty ruleset, against a ruleset whose
//     author omitted the block-everything line, and against a rule someone left
//     unfinished.
//
//  2. THE EQUIVALENCE — the shipped default ruleset decides exactly what the old
//     hardcoded `score >= threshold` decided, down to the client-facing reason
//     string. This is what makes increment 1 a no-op for existing deployers, and
//     it is only worth anything if the check can actually fail, so both halves
//     carry a negative control that feeds them a deliberately wrong ruleset and
//     asserts the mismatch is caught.

// ─────────────────────── the engine's contract ───────────────────────

// allowAll / rejectAll / logAll are match-everything rules used to probe
// ordering: with all of them matching, only position can decide the outcome.
func allowAll(name string) Rule {
	return Rule{Name: name, Match: func(Facts) bool { return true }, Action: ActionAllow}
}
func rejectAll(name string) Rule {
	return Rule{Name: name, Match: func(Facts) bool { return true }, Action: ActionReject}
}
func logAll(name string) Rule {
	return Rule{Name: name, Match: func(Facts) bool { return true }, Action: ActionAllowLog}
}

func TestRulesetFirstMatchWins(t *testing.T) {
	// Every rule matches, so ONLY order can decide. Running the same two rules in
	// both orders is the sharpest form of this test: if the engine were order-
	// insensitive (sorting, or "most specific wins", or last-match), one of the
	// two directions would come back wrong.
	cases := []struct {
		name string
		rs   Ruleset
		want Action
	}{
		{"allow before reject", Ruleset{allowAll("first"), rejectAll("second")}, ActionAllow},
		{"reject before allow", Ruleset{rejectAll("first"), allowAll("second")}, ActionReject},
		{"allow-but-log before allow", Ruleset{logAll("first"), allowAll("second")}, ActionAllowLog},
		{"later rules are never consulted", Ruleset{allowAll("first"), rejectAll("2"), rejectAll("3")}, ActionAllow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, got := tc.rs.Decide(Facts{Package: "x", Score: 5, HasScore: true})
			if got != tc.want {
				t.Errorf("Decide() action = %q, want %q", got, tc.want)
			}
			if rule.Name != "first" {
				t.Errorf("Decide() matched rule %q, want the FIRST rule — order is the semantics", rule.Name)
			}
		})
	}
}

func TestRulesetTerminalBlockIsImplicit(t *testing.T) {
	// The property the whole epic exists to establish: there is no fall-through.
	// A ruleset that matches nothing rejects — it does not "return no decision"
	// and it does not pass the request along ungated.
	neverMatches := Rule{Name: "matches nothing", Match: func(Facts) bool { return false }, Action: ActionAllow}

	cases := []struct {
		name string
		rs   Ruleset
	}{
		{"nil ruleset", nil},
		{"empty ruleset", Ruleset{}},
		{"no rule matches", Ruleset{neverMatches, neverMatches}},
		// The one an operator will actually hit: they wrote a policy and forgot
		// the block-everything line. terminalRule is not part of the slice
		// precisely so it cannot be omitted.
		{"author omitted the block-everything line", Ruleset{
			{Name: "allow: score >= 5", Match: func(f Facts) bool { return f.Score >= 5 }, Action: ActionAllow},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Score 1.0 clears none of the conditions above.
			rule, got := tc.rs.Decide(Facts{Package: "x", Score: 1, HasScore: true})
			if got != ActionReject {
				t.Errorf("Decide() on a ruleset that matches nothing = %q, want %q — an unmatched request MUST fail closed", got, ActionReject)
			}
			if !strings.Contains(rule.Name, "terminal") {
				t.Errorf("Decide() attributed the block to rule %q, want the implicit terminal rule", rule.Name)
			}
		})
	}

	// NEGATIVE CONTROL. The assertions above would also pass against an engine
	// that rejects unconditionally — "nothing got through" is what a broken gate
	// produces too. Prove the same call CAN return an allow.
	t.Run("negative control: a matching allow rule is not rejected", func(t *testing.T) {
		rule, got := Ruleset{allowAll("permit")}.Decide(Facts{Package: "x", Score: 1, HasScore: true})
		if got != ActionAllow {
			t.Fatalf("Decide() = %q on a match-all allow rule, want %q — the reject assertions above prove nothing if the engine can only reject", got, ActionAllow)
		}
		if rule.Name != "permit" {
			t.Errorf("Decide() matched rule %q, want %q", rule.Name, "permit")
		}
	})
}

func TestRulesetEveryActionIsReturnedFaithfully(t *testing.T) {
	// D76's taxonomy is reject / allow-but-log / allow, and `drop` is
	// deliberately absent. Each must survive the engine unchanged — an action
	// quietly collapsed into another (allow-but-log silently becoming allow) is
	// the failure mode that would make the migration ramp useless.
	for _, want := range []Action{ActionAllow, ActionAllowLog, ActionReject} {
		t.Run(string(want), func(t *testing.T) {
			rs := Ruleset{{Name: "probe", Match: func(Facts) bool { return true }, Action: want}}
			if _, got := rs.Decide(Facts{Package: "x"}); got != want {
				t.Errorf("Decide() = %q, want %q", got, want)
			}
		})
	}
}

func TestRuleWithNilMatchIsSkipped(t *testing.T) {
	// An unfinished rule must not become an allow-everything. It is skipped, so
	// evaluation continues to the next rule — and, if nothing else matches, to
	// the terminal block.
	rs := Ruleset{
		{Name: "unfinished", Match: nil, Action: ActionAllow},
		rejectAll("real rule"),
	}
	rule, got := rs.Decide(Facts{Package: "x", Score: 10, HasScore: true})
	if got != ActionReject {
		t.Errorf("Decide() = %q, want %q — a nil Match must never match", got, ActionReject)
	}
	if rule.Name != "real rule" {
		t.Errorf("Decide() matched %q, want evaluation to continue past the nil-Match rule", rule.Name)
	}

	// And on its own it falls through to the terminal block rather than allowing.
	if _, got := (Ruleset{{Name: "unfinished", Match: nil, Action: ActionAllow}}).Decide(Facts{Package: "x"}); got != ActionReject {
		t.Errorf("Decide() on a lone nil-Match allow rule = %q, want %q", got, ActionReject)
	}
}

// ─────────────────────── the shipped default ───────────────────────

func TestDefaultRulesetShipsExactlyTwoRules(t *testing.T) {
	// D76 is specific: a default install ships TWO rules — allow at/above the
	// threshold, then block everything. This is a config-surface budget check
	// (#51) as much as a behaviour one: if a later increment quietly grows the
	// shipped default, the operator's "what is my policy?" answer stops being
	// two lines and someone should have to justify that here.
	// The SHIPPED default is what loadConfig produces, not a zero Config —
	// FW_UNSCORABLE_POLICY defaults to "block". Spelling it out here matters: an
	// earlier version of this test passed a zero Config, which reads as the
	// PERMISSIVE unscorable posture and therefore emitted a third rule, and the
	// test then looked like it was failing over a design question when it was
	// really failing over its own fixture.
	rs := defaultRuleset(Config{ScoreThreshold: 5.0, UnscorablePolicy: "block"})
	if len(rs) != 2 {
		t.Fatalf("defaultRuleset() has %d rules, want exactly 2 (D76): %v", len(rs), ruleNames(rs))
	}

	// The other direction: opting OUT of the fail-closed default is what earns a
	// third line. If this ever collapses back to two, the unscorable policy has
	// stopped being expressible as a rule.
	permissive := defaultRuleset(Config{ScoreThreshold: 5.0, UnscorablePolicy: "allow"})
	if len(permissive) != 3 {
		t.Errorf("defaultRuleset(UnscorablePolicy=allow) has %d rules, want 3: %v", len(permissive), ruleNames(permissive))
	}
	if rs[0].Action != ActionAllow {
		t.Errorf("rule 1 action = %q, want %q", rs[0].Action, ActionAllow)
	}
	if rs[1].Action != ActionReject {
		t.Errorf("rule 2 action = %q, want %q — the last line of a firewall config is the block", rs[1].Action, ActionReject)
	}
	// The explicit block-everything line must genuinely be a catch-all, not a
	// condition that happens to hold for the facts we tested elsewhere.
	if !rs[1].Match(Facts{}) || !rs[1].Match(Facts{Score: 10, HasScore: true}) {
		t.Error("rule 2 does not match every request; the shipped block-everything line must be unconditional")
	}
}

func TestDefaultRulesetRequiresAnActualScore(t *testing.T) {
	// "No score at all" must not read as a genuine 0.0 — and, more importantly,
	// must not slip past a threshold of 0.0, where `0 >= 0` would otherwise
	// allow every unscorable package. Absence of a score falls to the block.
	for _, threshold := range []float64{0.0, 5.0} {
		rs := defaultRuleset(Config{ScoreThreshold: threshold})
		if _, got := rs.Decide(Facts{Package: "x", HasScore: false}); got != ActionReject {
			t.Errorf("threshold %.1f: Decide(HasScore=false) = %q, want %q", threshold, got, ActionReject)
		}
		// Negative control: the same facts WITH a score at the threshold allow,
		// so the rejection above is attributable to HasScore and not to the
		// threshold rule being dead.
		if _, got := rs.Decide(Facts{Package: "x", Score: threshold, HasScore: true}); got != ActionAllow {
			t.Errorf("threshold %.1f: Decide(Score=%.1f, HasScore=true) = %q, want %q", threshold, threshold, got, ActionAllow)
		}
	}
}

func TestDefaultRulesetAllowsOnlyOnAScoreAtOrAboveThreshold(t *testing.T) {
	// The invariant stated as a property rather than as a table: across a wide
	// sweep of facts, the shipped ruleset allows EXACTLY when there is a real
	// score at or above the threshold, and rejects otherwise. Nothing else about
	// a request can earn an allow.
	//
	// This is the guard rail for increments 2 and 3. Those add rules ABOVE the
	// threshold rule, and a rule with a too-broad condition is precisely how a
	// blanket allow gets introduced — the failure that #56 and #57 already are in
	// the classification layer. If a later increment changes what the DEFAULT
	// install allows, this fails and the change has to be made deliberately.
	thresholds := []float64{0.0, 5.0, 9.9, 10.0}
	scores := []float64{-1, 0, 0.1, 4.9, 5.0, 5.1, 9.8, 9.9, 10.0, 11}
	packages := []string{"", "lodash", "com.evil:badlib", "library/alpine", "../../etc/passwd"}

	for _, th := range thresholds {
		rs := defaultRuleset(Config{ScoreThreshold: th})
		for _, sc := range scores {
			for _, hasScore := range []bool{true, false} {
				for _, pkg := range packages {
					f := Facts{Package: pkg, Score: sc, HasScore: hasScore}
					_, action := rs.Decide(f)
					gotAllowed := action != ActionReject
					wantAllowed := hasScore && sc >= th
					if gotAllowed != wantAllowed {
						t.Errorf("Decide(%+v) with threshold %.1f allowed=%v, want %v",
							f, th, gotAllowed, wantAllowed)
					}
					// The default install has no allow-but-log rule, so this
					// action must never appear in a default deployment — if it
					// does, the shipped posture has silently become permissive.
					if action == ActionAllowLog {
						t.Errorf("Decide(%+v) returned %q; the default ruleset must never allow-but-log", f, action)
					}
				}
			}
		}
	}
}

// ─────────────────────── equivalence with today's behaviour ───────────────────────

// legacyAllows is the threshold comparison exactly as firewall.go performed it
// before the rule engine landed, copied verbatim as the characterization
// baseline. If a future change to defaultRuleset is meant to alter the verdict
// for scored packages, THIS is the line that has to be consciously edited.
func legacyAllows(score, threshold float64) bool { return score >= threshold }

// equivalenceGrid is the (threshold, score) grid both equivalence checks run.
// It is weighted toward the boundary, because `>=` vs `>` is the realistic way
// this would silently break: a package sitting exactly on the threshold is the
// only input where the two differ, and it is the one real deployments hit.
func equivalenceGrid() (thresholds, scores []float64) {
	return []float64{0.0, 2.5, 5.0, 7.5, 9.9, 10.0},
		[]float64{0.0, 0.1, 2.5, 4.9, 5.0, 5.1, 7.4, 7.5, 7.6, 9.9, 10.0}
}

// rulesetDisagreements reports every (threshold, score) at which rs disagrees
// with the legacy predicate. It RETURNS the mismatches instead of calling
// t.Errorf so that the check can be pointed at a deliberately wrong ruleset and
// asserted to catch it — a check that can only report "green" is worse than
// doing it by hand.
func rulesetDisagreements(build func(Config) Ruleset) []string {
	thresholds, scores := equivalenceGrid()
	var bad []string
	for _, th := range thresholds {
		rs := build(Config{ScoreThreshold: th})
		for _, sc := range scores {
			_, action := rs.Decide(Facts{Package: "pkg", Score: sc, HasScore: true})
			got := action != ActionReject
			if want := legacyAllows(sc, th); got != want {
				bad = append(bad, fmt.Sprintf("threshold=%.1f score=%.1f: ruleset allows=%v, legacy allows=%v", th, sc, got, want))
			}
		}
	}
	return bad
}

func TestDefaultRulesetMatchesLegacyThresholdBehaviour(t *testing.T) {
	if bad := rulesetDisagreements(defaultRuleset); len(bad) > 0 {
		t.Errorf("the default ruleset changed the verdict for scored packages — increment 1 must be a no-op for existing deployers:\n  %s",
			strings.Join(bad, "\n  "))
	}
}

func TestEquivalenceCheckCatchesAMisorderedRuleset(t *testing.T) {
	// THE NEGATIVE CONTROL #58's acceptance criteria asks for by name: "a rule
	// ordering that would wrongly allow a blocked package is caught by an
	// assertion". Put the block-everything line FIRST and the equivalence check
	// must go red; put an allow-everything first and it must also go red. If
	// either comes back clean, TestDefaultRulesetMatchesLegacyThresholdBehaviour
	// is not actually checking anything.
	misordered := map[string]func(Config) Ruleset{
		"block-everything moved to the top": func(cfg Config) Ruleset {
			// Located BY NAME, not by index. An earlier version indexed rs[1]/rs[0],
			// which silently stopped meaning "block-everything first" the moment
			// increment 3 added a category rule — the negative control went green
			// while testing something else entirely. A control that can quietly
			// change meaning is exactly the failure it exists to prevent.
			rs := defaultRuleset(cfg)
			var block Rule
			rest := Ruleset{}
			for _, r := range rs {
				if r.Name == "block everything" {
					block = r
					continue
				}
				rest = append(rest, r)
			}
			if block.Match == nil {
				panic("defaultRuleset no longer contains a rule named \"block everything\"; this control needs updating")
			}
			return append(Ruleset{block}, rest...) // terminal block first: allows nothing
		},
		"allow-everything inserted above the threshold rule": func(cfg Config) Ruleset {
			return append(Ruleset{allowAll("oops: blanket allow")}, defaultRuleset(cfg)...)
		},
	}
	for name, build := range misordered {
		t.Run(name, func(t *testing.T) {
			if bad := rulesetDisagreements(build); len(bad) == 0 {
				t.Error("the equivalence check passed a deliberately wrong ruleset — it cannot detect a reordering, so its green result is meaningless")
			}
		})
	}
}

// legacyDecideFinal is Firewall.decideFinal exactly as it read before the rule
// engine landed — including its reason strings, which are client-facing and are
// asserted on by the e2e suites. Kept verbatim so the equivalence covers the
// whole Decision, not just the allow/block bit.
func legacyDecideFinal(cfg Config, pkgName string, score float64, source string) Decision {
	suffix := ""
	if source != "" {
		suffix = " [" + source + "]"
	}
	if score >= cfg.ScoreThreshold {
		return Decision{
			Allowed:  true,
			Score:    score,
			HasScore: true,
			Reason:   fmt.Sprintf("score %.1f >= threshold %.1f%s", score, cfg.ScoreThreshold, suffix),
		}
	}
	return Decision{
		Allowed:  false,
		Score:    score,
		HasScore: true,
		Deny:     denyScore,
		Reason:   fmt.Sprintf("BLOCKED: %q scored %.1f, below required %.1f%s", pkgName, score, cfg.ScoreThreshold, suffix),
	}
}

// decisionDisagreements compares the real decideFinal against legacyDecideFinal
// across the grid, for a firewall built by `build`. Returns mismatches rather
// than reporting them, for the same negative-control reason as above.
func decisionDisagreements(build func(Config) *Firewall) []string {
	thresholds, scores := equivalenceGrid()
	var bad []string
	for _, th := range thresholds {
		cfg := Config{ScoreThreshold: th}
		f := build(cfg)
		for _, sc := range scores {
			for _, src := range []string{"", "human-supplied repo github.com/o/n"} {
				got := f.decideFinal("lodash", sc, src)
				// The attributable half (D182: which rule, which policy) is new and has
				// no legacy counterpart; it is asserted by its own test. This comparison
				// is about the verdict and the reason text, as it always was.
				got.Rule, got.Source = "", ""
				want := legacyDecideFinal(cfg, "lodash", sc, src)
				if got != want {
					bad = append(bad, fmt.Sprintf("threshold=%.1f score=%.1f source=%q:\n    got  %+v\n    want %+v", th, sc, src, got, want))
				}
			}
		}
	}
	return bad
}

func TestDecideFinalMatchesLegacyDecision(t *testing.T) {
	// Whole-Decision equivalence: Allowed, Score, HasScore, Deny AND the exact
	// reason text. The reason strings are surfaced to developers and asserted on
	// by the e2e suites, so drifting them is a user-visible change even when the
	// allow/block verdict is identical.
	//
	// Built as a bare &Firewall{} literal on purpose — that exercises the nil-
	// ruleset fallback in f.ruleset(), which fourteen existing test call sites
	// depend on and which would otherwise block every package.
	build := func(cfg Config) *Firewall { return &Firewall{cfg: cfg} }
	if bad := decisionDisagreements(build); len(bad) > 0 {
		t.Errorf("decideFinal changed its Decision for scored packages:\n  %s", strings.Join(bad, "\n  "))
	}

	// The same equivalence must hold for a firewall constructed the normal way,
	// with rules populated by NewFirewall — otherwise the fallback and the real
	// path could drift.
	t.Run("via NewFirewall", func(t *testing.T) {
		withRules := func(cfg Config) *Firewall {
			cfg.Ecosystem, cfg.UpstreamRegistry = "npm", "https://registry.npmjs.org"
			f, err := NewFirewall(cfg)
			if err != nil {
				t.Fatalf("NewFirewall: %v", err)
			}
			return f
		}
		if bad := decisionDisagreements(withRules); len(bad) > 0 {
			t.Errorf("decideFinal disagrees with the legacy decision when rules come from NewFirewall:\n  %s", strings.Join(bad, "\n  "))
		}
	})
}

func TestDecisionEquivalenceCheckCatchesAWrongRuleset(t *testing.T) {
	// Negative control for TestDecideFinalMatchesLegacyDecision: give the
	// firewall a ruleset that blocks everything and confirm the comparison
	// notices. Without this, "no mismatches" could just mean the comparison is
	// inert.
	build := func(cfg Config) *Firewall {
		return &Firewall{cfg: cfg, rules: Ruleset{rejectAll("deny all")}}
	}
	if bad := decisionDisagreements(build); len(bad) == 0 {
		t.Error("the decision-equivalence check passed a block-everything ruleset — it is not actually comparing anything")
	}
}

// ─────────────────────── allow-but-log ───────────────────────

func TestAllowButLogServesAndRecords(t *testing.T) {
	// allow-but-log's entire value is the record: an allow-but-log that logged
	// nothing would be an ordinary allow, and the migration ramp increment 2
	// depends on would silently be a hole. So assert on the log output, not just
	// on the verdict.
	var buf bytes.Buffer
	restore := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(restore)

	f := &Firewall{
		cfg:   Config{ScoreThreshold: 9.9},
		rules: Ruleset{logAll("allow-but-log: unscorable category")},
	}
	// A score far below the threshold: under the default ruleset this would be a
	// block, so an allow here can only come from the rule.
	dec := f.decideFinal("lodash", 1.0, "")
	if !dec.Allowed {
		t.Fatalf("decideFinal() blocked under an allow-but-log rule: %+v", dec)
	}
	out := buf.String()
	if !strings.Contains(out, "allow-but-log: unscorable category") {
		t.Errorf("log does not name the matched rule; got:\n%s", out)
	}
	if !strings.Contains(out, "lodash") {
		t.Errorf("log does not name the package; got:\n%s", out)
	}

	// Negative control: a plain allow must NOT emit the allow-but-log line, or
	// the marker an operator greps for would fire on every ordinary request and
	// tell them nothing.
	buf.Reset()
	f2 := &Firewall{cfg: Config{ScoreThreshold: 5.0}, rules: defaultRuleset(Config{ScoreThreshold: 5.0})}
	if dec := f2.decideFinal("lodash", 7.5, ""); !dec.Allowed {
		t.Fatalf("decideFinal() blocked a passing score: %+v", dec)
	}
	if strings.Contains(buf.String(), "allow-but-log") {
		t.Errorf("an ordinary allow emitted the allow-but-log marker; got:\n%s", buf.String())
	}
}

// ruleNames is a small helper for failure messages.
func ruleNames(rs Ruleset) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}
