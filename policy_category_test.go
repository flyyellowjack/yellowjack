package main

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"testing"
)

// Tier-1 tests for the CATEGORY rules (issue #58 increment 3, D76).
//
// Increment 3 moves the two policies D76 calls "categories" — unscorable and
// unverified provenance — off direct `cfg` reads and onto rules in the same
// ordered ruleset as the score verdict. Like increment 1, the contract is that no
// existing deployment changes its VERDICT, so the equivalence is pinned against a
// verbatim copy of the pre-increment logic.
//
// The one deliberate change is a log line: an unscorable package that policy lets
// through now emits an allow-but-log record (D76's example rule 3), because
// "we served something we could not score" is exactly what that mode exists to
// make visible. Verdict unchanged; visibility added.

// legacyUnscorableAllowed is the unscorable posture exactly as firewall.go
// computed it before the category rule landed. If a future change is meant to
// alter which packages this lets through, THIS is the line that has to be
// consciously edited.
func legacyUnscorableAllowed(policy string) bool { return policy != "block" }

// unscorablePolicyValues covers the documented settings plus the shapes an
// operator actually produces by accident. The unset and misspelled cases are the
// interesting ones: here they resolve to ALLOW, which is the opposite of
// FW_UNKNOWN_PATH_POLICY's fail-closed normalization, and that asymmetry is
// intentional (an unscorable package is a legitimate package with thin metadata;
// an unrecognised request path is the shape four bypasses used).
var unscorablePolicyValues = []string{"block", "allow", "", "Block", "BLOCK", "blok", "allow-but-log", "yes"}

func TestUnscorableMatchesLegacyPolicy(t *testing.T) {
	for _, policy := range unscorablePolicyValues {
		t.Run("policy="+policy, func(t *testing.T) {
			cfg := Config{UnscorablePolicy: policy} // ApprovalURL empty -> no human ruling
			f := &Firewall{cfg: cfg}

			got := f.unscorable("left-pad", "no repo declared")
			wantAllowed := legacyUnscorableAllowed(policy)

			if got.Allowed != wantAllowed {
				t.Errorf("unscorable() Allowed = %v, want %v (legacy: policy != %q)", got.Allowed, wantAllowed, "block")
			}
			// The denial KIND matters beyond the bit: the artifact byte gate keys on
			// it (D72), so getting it wrong changes whether a blocked package's bytes
			// are refused, not just whether its metadata is.
			wantKind := denyUnscorable
			if wantAllowed {
				wantKind = denyNone
			}
			if got.Deny != wantKind {
				t.Errorf("unscorable() Deny = %q, want %q", got.Deny, wantKind)
			}
			if got.HasScore {
				t.Error("unscorable() reported HasScore=true; there is by definition no score")
			}
			// Reason text is client-facing and asserted on by the e2e suites.
			wantReason := fmt.Sprintf("unscorable (%s); policy=%s", "no repo declared", policy)
			if got.Reason != wantReason {
				t.Errorf("unscorable() Reason = %q, want %q", got.Reason, wantReason)
			}
		})
	}
}

func TestUnscorableEquivalenceCheckCatchesAnInvertedRule(t *testing.T) {
	// Negative control for the test above. Install a ruleset whose unscorable rule
	// is inverted relative to the policy and confirm the comparison notices —
	// otherwise "every policy matched" could just mean the check is inert.
	inverted := Ruleset{
		{
			Name:   "inverted unscorable rule",
			Match:  func(f Facts) bool { return f.Deny == denyUnscorable },
			Action: ActionReject, // reject even under an ALLOW policy
		},
		{Name: "block everything", Match: func(Facts) bool { return true }, Action: ActionReject},
	}
	f := &Firewall{cfg: Config{UnscorablePolicy: "allow"}, rules: inverted}
	if got := f.unscorable("left-pad", "why"); got.Allowed {
		t.Fatal("setup: the inverted ruleset did not actually reject; this control proves nothing")
	}
	// And the legacy expectation for policy=allow is TRUE, so the two disagree —
	// which is precisely what TestUnscorableMatchesLegacyPolicy would report.
	if !legacyUnscorableAllowed("allow") {
		t.Fatal("legacy helper is wrong: policy=allow must mean allowed")
	}
}

func TestUnscorableAllowEmitsAnAllowButLogRecord(t *testing.T) {
	// D76's example rule 3. Serving a package we could not score is exactly the
	// case that owes the operator a record — an allow-but-log that logged nothing
	// would be an ordinary allow.
	var buf bytes.Buffer
	restore := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(restore)

	f := &Firewall{cfg: Config{UnscorablePolicy: "allow"}}
	if dec := f.unscorable("left-pad", "no repo declared"); !dec.Allowed {
		t.Fatalf("unscorable() blocked under policy=allow: %+v", dec)
	}
	out := buf.String()
	if !strings.Contains(out, "allow-but-log") || !strings.Contains(out, "left-pad") {
		t.Errorf("no allow-but-log record naming the package; got:\n%s", out)
	}
	if !strings.Contains(out, string(denyUnscorable)) {
		t.Errorf("the record does not name the category %q; got:\n%s", denyUnscorable, out)
	}

	// Negative control: under the fail-closed default there is no allow to log, so
	// the marker must NOT appear — otherwise an operator grepping for it would get
	// a hit on every blocked package and learn nothing.
	buf.Reset()
	f2 := &Firewall{cfg: Config{UnscorablePolicy: "block"}}
	if dec := f2.unscorable("left-pad", "no repo declared"); dec.Allowed {
		t.Fatalf("unscorable() allowed under policy=block: %+v", dec)
	}
	if strings.Contains(buf.String(), "allow-but-log") {
		t.Errorf("a BLOCKED unscorable package emitted the allow-but-log marker; got:\n%s", buf.String())
	}
}

func TestUnverifiedCategoryRefuses(t *testing.T) {
	// Unverified provenance refuses under every shipped configuration, including
	// the permissive unscorable posture. That separation is D36 Ruling A: "I accept
	// unscorable packages" must not silently also mean "I accept unverifiable
	// provenance claims", and collapsing the two is the regression this guards.
	for _, policy := range []string{"block", "allow", ""} {
		f := &Firewall{cfg: Config{UnscorablePolicy: policy}}
		dec := f.unverified("evil-pkg", "deps.dev has no source-repo mapping")
		if dec.Allowed {
			t.Errorf("UnscorablePolicy=%q: unverified() allowed the package — the unscorable posture must not leak into provenance (D36 Ruling A)", policy)
		}
		if dec.Deny != denyUnverified {
			t.Errorf("UnscorablePolicy=%q: unverified() Deny = %q, want %q", policy, dec.Deny, denyUnverified)
		}
		if dec.HasScore {
			t.Errorf("UnscorablePolicy=%q: unverified() carried a score for a repo we refused to trust", policy)
		}
	}
}

func TestUnverifiedHonoursAnOperatorAllowRule(t *testing.T) {
	// The reason unverified() consults the ruleset at all despite the shipped rule
	// always rejecting: if an operator ever orders an allow above it, that must
	// take effect rather than being silently overridden by a hardcoded block. This
	// is what makes the ordered list the actual source of truth.
	f := &Firewall{
		cfg:   Config{},
		rules: Ruleset{allowAll("operator: accept unverified provenance")},
	}
	if dec := f.unverified("evil-pkg", "why"); !dec.Allowed {
		t.Error("an operator rule ordered above the unverified refusal was ignored; the ruleset is not authoritative")
	}
}

func TestCategoryRuleIsOrderedBeforeTheTerminalBlock(t *testing.T) {
	// Order is the semantics. Under a permissive unscorable policy the category
	// rule must be reached BEFORE block-everything, or the policy has no effect.
	// ScoreThreshold is set explicitly: at the zero value every score is "at or
	// above threshold", so the disjointness check at the bottom would pass
	// vacuously against the score rule rather than testing anything.
	rs := defaultRuleset(Config{ScoreThreshold: 5.0, UnscorablePolicy: "allow"})
	rule, action := rs.Decide(Facts{Package: "left-pad", Deny: denyUnscorable})
	if action == ActionReject {
		t.Fatalf("unscorable fell through to a reject (rule %q) under policy=allow", rule.Name)
	}
	if !strings.Contains(rule.Name, "unscorable") {
		t.Errorf("matched rule %q, want the unscorable category rule", rule.Name)
	}

	// And a SCORED package must not be captured by the category rule — the two
	// conditions have to stay disjoint, or a low score would be re-routed through
	// the unscorable posture and silently allowed.
	rule, action = rs.Decide(Facts{Package: "left-pad", Score: 1.0, HasScore: true})
	if action != ActionReject {
		t.Errorf("a below-threshold SCORED package matched %q and was not rejected; the category rule is over-matching", rule.Name)
	}
}
