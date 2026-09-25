package main

import (
	"fmt"
	"testing"
)

// Tier 1 for issue #58 increment 4: FW_BYTE_GATE's allow-vs-refuse axis, moved off
// an inlined mode ladder and onto an ordered ruleset (D76).
//
// The thing being protected here is COMPATIBILITY. The byte gate is the one place
// where a policy change silently alters which bytes reach a developer's machine
// without any status code moving, so every verdict is pinned against a verbatim copy
// of the pre-increment logic across every mode and every decision shape.
//
// What this file does NOT cover, on purpose, is the retryability sequence
// (Pending/Unavailable -> 503) and the "off" short-circuit. Those are not verdicts
// and stayed in proxyArtifactBytes — see byteGateRuleset. bytegate_test.go and the
// #60 tests own them, and TestByteGateOffRulesetAgreesWithTheShortCircuit below
// pins the one seam between the two representations.

// legacyByteRejects restates, VERBATIM, the allow-vs-refuse test proxyArtifactBytes
// performed before the ruleset existed:
//
//	off           -> never evaluated, so never refused
//	allow-but-log -> refuse iff decision.hardDeny()
//	enforce       -> refuse iff !decision.Allowed
//
// The hardDeny expression is written out INLINE rather than calling d.hardDeny().
// That is the whole point of a baseline: hardDeny() now delegates to hardDenyKind,
// which is the same function the rule under test calls, so calling it here would
// compare the implementation against itself and agree no matter how wrong both were.
func legacyByteRejects(mode string, d Decision) bool {
	switch byteGateMode(mode) {
	case byteGateOff:
		return false
	case byteGateEnforce:
		return !d.Allowed
	default: // allow-but-log
		return !d.Allowed && (d.Deny == denyScore || d.Deny == denyHuman)
	}
}

// byteGateModeSpellings is every FW_BYTE_GATE value an operator actually produces —
// the three documented ones, plus the unset and misspelled cases, which are the ones
// that matter: byteGateMode resolves them to the DEFAULT, and a regression there
// would silently drop deployments into the wrong posture.
func byteGateModeSpellings() []string {
	return []string{
		byteGateOff,
		byteGateAllowButLog,
		byteGateEnforce,
		"",         // unset
		"Enforce",  // right word, wrong case — must NOT enforce
		"OFF",      // right word, wrong case — must NOT disable the gate
		"blok",     // typo
		"disabled", // plausible-but-wrong guess
	}
}

// byteDecisionShapes is the set of verdicts the byte gate can be handed. It
// deliberately includes an unknown future denyKind and the contradictory
// allowed-with-a-stray-kind shape, because both are how a later change reaches this
// code without anyone editing it.
func byteDecisionShapes() []struct {
	name string
	d    Decision
} {
	return []struct {
		name string
		d    Decision
	}{
		{"allowed", Decision{Allowed: true, HasScore: true, Score: 8}},
		{"below threshold", Decision{Allowed: false, HasScore: true, Score: 2, Deny: denyScore}},
		{"human denied", Decision{Allowed: false, Deny: denyHuman}},
		{"unscorable", Decision{Allowed: false, Deny: denyUnscorable}},
		{"unverified", Decision{Allowed: false, Deny: denyUnverified}},
		{"unknown future kind", Decision{Allowed: false, Deny: denyKind("something-new")}},
		{"allowed with a stray kind", Decision{Allowed: true, Deny: denyScore}},
		{"pending", Decision{Allowed: false, Pending: true}},
		{"unavailable", Decision{Allowed: false, Unavailable: true}},
		{"unscorable but allowed by policy", Decision{Allowed: true, Deny: denyNone}},
	}
}

// byteFactsFor builds the Facts proxyArtifactBytes builds, in one place, so the test
// and the handler cannot disagree about which fields the byte route populates.
func byteFactsFor(pkg string, d Decision) Facts {
	return Facts{
		Package:  pkg,
		Allowed:  d.Allowed,
		Deny:     d.Deny,
		Score:    d.Score,
		HasScore: d.HasScore,
	}
}

// byteRulesetDisagreements compares a candidate ruleset builder against the legacy
// ladder across every mode and shape, RETURNING the mismatches instead of failing.
// Returning them is what lets the negative control below point this at a knowingly
// wrong builder and assert that the comparison actually notices — an equivalence
// check that has never been shown to fail is not evidence of anything.
func byteRulesetDisagreements(build func(Config) Ruleset) []string {
	var bad []string
	for _, mode := range byteGateModeSpellings() {
		rs := build(Config{ByteGate: mode})
		for _, shape := range byteDecisionShapes() {
			_, action := rs.Decide(byteFactsFor("pkg", shape.d))
			got := action == ActionReject
			if want := legacyByteRejects(mode, shape.d); got != want {
				bad = append(bad, fmt.Sprintf("mode=%q shape=%q: ruleset rejects=%v, legacy rejects=%v",
					mode, shape.name, got, want))
			}
		}
	}
	return bad
}

func TestByteGateRulesetMatchesLegacyLadder(t *testing.T) {
	for _, d := range byteRulesetDisagreements(byteGateRuleset) {
		t.Errorf("byte gate verdict changed: %s", d)
	}
}

// TestByteGateEquivalenceCheckCatchesAWrongRuleset is the negative control for the
// test above. It feeds the comparison a builder that ignores the mode and always
// returns the ENFORCE ruleset — the most plausible real mistake, since it is what a
// "simplify this switch" refactor would produce, and it would silently start
// refusing every unscorable package's bytes in the default deployment.
func TestByteGateEquivalenceCheckCatchesAWrongRuleset(t *testing.T) {
	alwaysEnforce := func(Config) Ruleset { return byteGateRuleset(Config{ByteGate: byteGateEnforce}) }
	if len(byteRulesetDisagreements(alwaysEnforce)) == 0 {
		t.Fatal("the equivalence check passed a ruleset that enforces in every mode — " +
			"it cannot distinguish the postures, so TestByteGateRulesetMatchesLegacyLadder proves nothing")
	}
}

// TestByteGateAllowButLogIsAllowLogNotAllow pins the distinction the mode is named
// after. Serving a package the gate would have refused under enforce MUST come back
// as allow-but-log, because the log line is the entire security value of the mode —
// downgrade it to a plain allow and the default deployment goes quiet while still
// serving the bytes, which is the worst of both postures.
func TestByteGateAllowButLogIsAllowLogNotAllow(t *testing.T) {
	rs := byteGateRuleset(Config{ByteGate: byteGateAllowButLog})
	for _, shape := range []Decision{
		{Allowed: false, Deny: denyUnscorable},
		{Allowed: false, Deny: denyUnverified},
		{Allowed: false, Pending: true},
		{Allowed: false, Unavailable: true},
	} {
		_, action := rs.Decide(byteFactsFor("pkg", shape))
		if action != ActionAllowLog {
			t.Errorf("deny=%q pending=%v unavailable=%v: action = %q, want %q",
				shape.Deny, shape.Pending, shape.Unavailable, action, ActionAllowLog)
		}
	}
}

// TestByteGateOffRulesetAgreesWithTheShortCircuit pins the one place where "off" has
// two representations: the pre-evaluation short-circuit in proxyArtifactBytes, and
// the single-rule ruleset here. They must mean the same thing, or a later change
// that removes the short-circuit (reasonably — it looks redundant) would flip the
// escape hatch into an enforcing gate.
func TestByteGateOffRulesetAgreesWithTheShortCircuit(t *testing.T) {
	rs := byteGateRuleset(Config{ByteGate: byteGateOff})
	for _, shape := range byteDecisionShapes() {
		rule, action := rs.Decide(byteFactsFor("pkg", shape.d))
		if action != ActionAllow {
			t.Errorf("%s: off mode gave %q via rule %q, want %q — off must serve every shape, "+
				"including a hard deny; it is the only setting that does",
				shape.name, action, rule.Name, ActionAllow)
		}
	}
}

// TestByteGateTerminalDiffersByMode pins the asymmetry that makes this ruleset unlike
// the other two in the epic.
//
// The score and classification rulesets end in a block, which is #58's entire thesis.
// This one ends in an ALLOW under the shipped default, because D49 chose visibility
// first for artifact bytes. That is a deliberate exception, not a gap — and the way it
// is written matters: the last rule matches everything, so the implicit terminalRule
// is unreachable here. If someone "tidies up" that catch-all on the grounds that the
// engine already has a terminal, the default deployment silently starts refusing
// bytes it is supposed to serve.
func TestByteGateTerminalDiffersByMode(t *testing.T) {
	// A shape nothing else in either ruleset claims: not allowed, not a hard deny.
	fallsThrough := Decision{Allowed: false, Deny: denyUnscorable}

	_, visibility := byteGateRuleset(Config{ByteGate: byteGateAllowButLog}).Decide(byteFactsFor("pkg", fallsThrough))
	if visibility == ActionReject {
		t.Errorf("allow-but-log terminal = %q; it must NOT inherit the engine's fail-closed terminal — "+
			"the catch-all allow-but-log rule is load-bearing (D49)", visibility)
	}

	_, enforced := byteGateRuleset(Config{ByteGate: byteGateEnforce}).Decide(byteFactsFor("pkg", fallsThrough))
	if enforced != ActionReject {
		t.Errorf("enforce terminal = %q, want %q", enforced, ActionReject)
	}
}

// TestByteGateNewDenyKindDefaultsToSoft pins hardDenyKind's whitelist shape from the
// RULESET side. A denial reason added later must fall to the visibility rule rather
// than start blocking artifact fetches on its own — someone has to opt it in.
//
// This runs opposite to the epic's fail-closed default and that is a deliberate project decision
// (D49/D72). It is pinned precisely BECAUSE it is an exception: an exception nobody
// tests is indistinguishable from a bug, and the next person to read #58's thesis
// would be right to "fix" it.
func TestByteGateNewDenyKindDefaultsToSoft(t *testing.T) {
	future := Decision{Allowed: false, Deny: denyKind("supply-chain-anomaly")}

	rule, action := byteGateRuleset(Config{ByteGate: byteGateAllowButLog}).Decide(byteFactsFor("pkg", future))
	if action != ActionAllowLog {
		t.Errorf("a new deny kind gave %q via rule %q under allow-but-log, want %q — "+
			"new kinds default to the SOFT side (D72)", action, rule.Name, ActionAllowLog)
	}

	// ...but enforce still refuses it, which is what makes the soft default safe to
	// ship: the operator who wants everything blocked has a setting that does that.
	if _, action := byteGateRuleset(Config{ByteGate: byteGateEnforce}).Decide(byteFactsFor("pkg", future)); action != ActionReject {
		t.Errorf("a new deny kind gave %q under enforce, want %q", action, ActionReject)
	}
}

// TestByteRulesetFallbackKeepsTheShippedPosture is the nil-safety guard, and it
// matters more here than for the other two rulesets because it fails in the opposite
// direction. A hand-built &Firewall{} literal — which many tests use — has a nil
// byteRules; without the fallback it would match nothing, inherit the engine's
// terminal block, and start REFUSING artifact bytes. Not a crash, not a compile
// error: just a firewall that is stricter than the one we ship, in the tests that
// are supposed to tell us what we ship.
func TestByteRulesetFallbackKeepsTheShippedPosture(t *testing.T) {
	f := &Firewall{cfg: Config{}} // no rules installed, no ByteGate set
	if f.byteRules != nil {
		t.Fatal("fixture is wrong: byteRules must be nil for this to test the fallback")
	}

	// An unscorable denial: refused by the terminal, served by the real default.
	_, action := f.byteRuleset().Decide(byteFactsFor("pkg", Decision{Allowed: false, Deny: denyUnscorable}))
	if action != ActionAllowLog {
		t.Errorf("nil byteRules resolved to %q, want %q — the fallback must reproduce the "+
			"shipped visibility-first posture, not the engine's fail-closed terminal", action, ActionAllowLog)
	}

	// The carve-out survives the fallback too: a hard deny is still refused.
	if _, action := f.byteRuleset().Decide(byteFactsFor("pkg", Decision{Allowed: false, Deny: denyScore})); action != ActionReject {
		t.Errorf("nil byteRules served a hard deny (%q), want %q (D72)", action, ActionReject)
	}
}

// TestByteGateRuleCountsStayLegible is the config-surface budget (#51) applied to the
// third ruleset. Two lines per mode is what makes "what does the byte gate do?"
// answerable by reading, which is the entire operator-facing point of D76. It is also
// the assertion that caught increment 3 shipping a four-rule default.
func TestByteGateRuleCountsStayLegible(t *testing.T) {
	for mode, want := range map[string]int{
		byteGateOff:         1,
		byteGateAllowButLog: 2,
		byteGateEnforce:     2,
	} {
		if got := len(byteGateRuleset(Config{ByteGate: mode})); got != want {
			t.Errorf("FW_BYTE_GATE=%s ships %d rules, want %d: %v",
				mode, got, want, ruleNames(byteGateRuleset(Config{ByteGate: mode})))
		}
	}
}
