package main

import (
	"testing"
)

// The decision record as EVIDENCE (#28), not as a log line.
//
// #28's obligation is EU CRA Annex I Part II / Article 13 due diligence: produce a
// durable record an auditor can read months later. The distinction that matters —
// and the one these tests pin — is that a record saying what we CONCLUDED is not
// the same as a record saying what we concluded it AGAINST. "score 4.2, blocked"
// is not reproducible by anyone who was not there; "score 4.2 against threshold
// 5.0 under policy 1f1dc107" is.
//
// The existing audit tests already cover delivery and the source IP. These cover
// the inputs, because that is the part an auditor's question turns on.

// emitAndRead runs one verdict through auditVerdict and returns the queued event.
// A buffered channel with no consumer is the same trick TestAuditVerdictSetsSourceIP
// uses: it reads exactly what was queued, with no network and no goroutine race.
func emitAndRead(t *testing.T, f *Firewall, d Decision) auditEvent {
	t.Helper()
	a := &auditEmitter{ch: make(chan auditEvent, 4)}
	f.audit = a
	f.auditVerdict("left-pad", "203.0.113.5", d)
	select {
	case e := <-a.ch:
		return e
	default:
		t.Fatal("auditVerdict queued no event at all")
		return auditEvent{}
	}
}

// TestAnAuditorCanReproduceABlockFromTheRecordAlone is the requirement in one test.
// Everything else in this file exists to stop this one passing for a bad reason.
func TestAnAuditorCanReproduceABlockFromTheRecordAlone(t *testing.T) {
	f := &Firewall{
		cfg:          Config{Ecosystem: "npm", ScoreThreshold: 5.0},
		policyDigest: "d34db33f",
	}
	e := emitAndRead(t, f, Decision{Allowed: false, Score: 4.2, HasScore: true, Reason: "score 4.2 below threshold"})

	if e.Threshold == nil {
		t.Fatal("the record carries a score but no threshold, so the verdict cannot be " +
			"checked: an auditor cannot tell whether 4.2 failed a bar of 5.0 or whether the " +
			"block came from somewhere else and the score is incidental")
	}
	if *e.Threshold != 5.0 {
		t.Errorf("threshold = %v, want 5.0 (the value actually in force)", *e.Threshold)
	}
	// The arithmetic an auditor would do, done here: the record must be internally
	// consistent with its own verdict.
	if e.Score == nil {
		t.Fatal("a scored verdict recorded no score")
	}
	if !(*e.Score < *e.Threshold) || e.Action != auditActionBlock {
		t.Errorf("record is self-inconsistent: score=%v threshold=%v action=%q — an auditor "+
			"recomputing the verdict from these three fields gets a different answer than we did",
			*e.Score, *e.Threshold, e.Action)
	}
	if e.PolicyDigest == "" {
		t.Error("the record does not say which policy was in force, so two verdicts made " +
			"under different policies are indistinguishable in the export")
	}
}

// TestAnAllowIsEvidenceToo. #28 is explicit: "Must record allows, not just blocks.
// 'Nothing was blocked' is not evidence of due diligence." So the inputs have to be
// present on the permissive path as well, which is the easier one to leave bare.
func TestAnAllowIsEvidenceToo(t *testing.T) {
	f := &Firewall{cfg: Config{Ecosystem: "npm", ScoreThreshold: 5.0}, policyDigest: "d34db33f"}
	e := emitAndRead(t, f, Decision{Allowed: true, Score: 7.5, HasScore: true, Reason: "ok"})

	if e.Action != auditActionAllow {
		t.Fatalf("action = %q, want allow", e.Action)
	}
	if e.Threshold == nil || *e.Threshold != 5.0 || e.PolicyDigest == "" {
		t.Errorf("an ALLOW was recorded without the inputs that justified it "+
			"(threshold=%v policy=%q). 'Here is every component that entered, and why each "+
			"was permitted' is the claim; a bare allow does not support it",
			e.Threshold, e.PolicyDigest)
	}
}

// TestAVerdictThatNeverScoredRecordsNoThreshold — the honesty case, and the reason
// Threshold is a pointer.
//
// A known-malware refusal (layer 1) happens before any score is fetched. Stamping
// the configured threshold on that record would tell an auditor the package was
// scored and failed, which is a different and untrue story. Writing 0.0 would be
// worse still: it reads as "the bar was zero".
func TestAVerdictThatNeverScoredRecordsNoThreshold(t *testing.T) {
	f := &Firewall{cfg: Config{Ecosystem: "npm", ScoreThreshold: 5.0}, policyDigest: "d34db33f"}
	e := emitAndRead(t, f, Decision{
		Allowed: false,
		Deny:    denyKnownMalware,
		Reason:  `"left-pad" is listed as known malware (MAL-2024-1); refused without contacting upstream`,
	})

	if e.Threshold != nil {
		t.Errorf("threshold = %v on a verdict that never consulted a score — the record now "+
			"implies the package was scored against a bar and failed, which is not what happened",
			*e.Threshold)
	}
	if e.Score != nil {
		t.Errorf("score = %v on an unscored verdict", *e.Score)
	}
	// The policy in force is still recorded: it is a property of the deployment, not
	// of the scoring path, and it is what says which ruleset produced this refusal.
	if e.PolicyDigest == "" {
		t.Error("an unscored refusal recorded no policy either, so nothing in the record " +
			"identifies the configuration that produced it")
	}
}

// realFirewallConfig is shippedConfig plus the two fields NewFirewall requires that
// the policy-view tests never needed (they build a Firewall by hand). The policy
// values stay exactly the shipped ones, so the digest under test is the real one.
func realFirewallConfig() Config {
	cfg := shippedConfig()
	cfg.Ecosystem = "npm"
	cfg.UpstreamRegistry = "https://registry.npmjs.org"
	return cfg
}

// TestTheRecordedPolicyDigestIsTheRealOne — anti-vacuity for the field above.
//
// Every test so far hand-sets policyDigest on a struct literal, so they would all
// pass against a Firewall that never computes one. This asserts the constructor
// actually fills it, and fills it with what describePolicy reports.
func TestTheRecordedPolicyDigestIsTheRealOne(t *testing.T) {
	f, err := NewFirewall(realFirewallConfig())
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	if f.policyDigest == "" {
		t.Fatal("NewFirewall left the policy digest empty, so every record it stamps carries " +
			"an absent policy_digest while the tests above pass on hand-set values")
	}
	if want := f.describePolicy().Digest; f.policyDigest != want {
		t.Errorf("stamped digest %q != the policy actually in force %q", f.policyDigest, want)
	}
}

// TestADifferentPolicyProducesADifferentRecord is the NEGATIVE CONTROL for the
// whole policy_digest idea.
//
// Every assertion above is satisfied by a constant — `policyDigest = "policy"` would
// pass all of them, and the field would be decoration: an auditor comparing two
// exports could not tell a threshold change from no change at all. This proves the
// stamped value discriminates.
func TestADifferentPolicyProducesADifferentRecord(t *testing.T) {
	a, err := NewFirewall(realFirewallConfig())
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	changed := realFirewallConfig()
	changed.ScoreThreshold = a.cfg.ScoreThreshold + 1.5
	b, err := NewFirewall(changed)
	if err != nil {
		t.Fatalf("NewFirewall (changed policy): %v", err)
	}
	if a.policyDigest == b.policyDigest {
		t.Errorf("two firewalls with different score thresholds stamp the same policy digest "+
			"(%q). The field cannot distinguish policies, so it is not evidence of which one "+
			"was in force", a.policyDigest)
	}
}
