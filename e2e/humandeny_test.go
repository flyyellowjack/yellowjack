//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// #132 / D272: a human deny must refuse a package the policy allows on its own.
//
// WHAT THIS EXISTS TO CATCH, AND WHY THE UNIT TEST IS NOT ENOUGH. The unit reversal
// (TestHumanDenyOutranksAPassingScore) calls decideByScore directly. #132 was not a
// bug in decideByScore's arithmetic — it was a bug in WHICH PATH a request takes:
// the allow branch returned before the approval service was ever asked. A test that
// calls the decision function cannot tell you that a real npm install reaches it,
// and #132 was found by an operator installing a package, not by reading Go. So the
// property gets an e2e leg driving the real client.
//
// THE POSTURE. FW_SCORE_THRESHOLD=0 against the flat stub score, so every package
// passes on its merits and NOTHING here is blocked by policy. That makes a refusal
// attributable: the only thing in the deployment that can produce one is the human
// ruling. It is also the posture #132 measured in — the reference deployment served
// is-number at score 7.5 while the console displayed a `denied` badge for it.
//
// THREE LEGS, AND ALL THREE ARE LOAD-BEARING:
//
//  1. control — with no approval service at all, the client installs. Without this a
//     refusal in leg 2 could just be a broken registry path.
//  2. the property — the same install, with a deny on record, is refused, and the
//     firewall says WHY in a way an operator can attribute to their own ruling.
//  3. the discriminator — the same firewall, the same approval service, a DIFFERENT
//     package the service holds no record for, still installs. Without it, leg 2
//     passes for a firewall that refuses everything the moment FW_APPROVAL_URL is
//     set, which is a different (and much worse) bug wearing the same green tick.
func TestAHumanDenyRefusesAPackageThePolicyAllows(t *testing.T) {
	bin := buildFirewall(t)

	// Nothing is blocked by policy in this posture. Kept in one place so legs 1 and
	// 2 differ in exactly one variable: whether an approval service holds a deny.
	permissive := func(approvalURL string) map[string]string {
		env := map[string]string{
			"FW_ECOSYSTEM":         "npm",
			"FW_SCORECARD_MODE":    "stub",
			"FW_SCORE_THRESHOLD":   "0", // the flat stub score clears it: policy ALLOWS
			"FW_UNSCORABLE_POLICY": "allow",
			"FW_UNVERIFIED_POLICY": "open-with-visibility",
		}
		if approvalURL != "" {
			env["FW_APPROVAL_URL"] = approvalURL
		}
		return env
	}

	const denied = "is-number" // the package #132 measured
	const other = "lodash"     // no record on the approval service

	t.Run("control_the_policy_really_does_allow_it", func(t *testing.T) {
		fw := startFirewall(t, bin, permissive(""))
		if code, out := runNpmInstall(t, fw.port, denied); code != 0 {
			t.Fatalf("PREMISE BROKEN: npm install %s fails (exit %d) with NO approval service and a "+
				"threshold of 0, so this deployment refuses the package for some reason of its own and a "+
				"refusal in the next leg would prove nothing about the human ruling.\n%s\n--- firewall ---\n%s",
				denied, code, tail(out, 20), logAround(fw.log.String(), 25, denied))
		}
	})

	// Legs 2 and 3 share ONE firewall and ONE approval service on purpose: leg 3 is
	// only a control for leg 2 if nothing else differs between them.
	fw := startFirewall(t, bin, permissive(startApprovalStub(t, denied, "denied")))

	t.Run("a_recorded_deny_refuses_a_package_the_policy_allows", func(t *testing.T) {
		code, out := runNpmInstall(t, fw.port, denied)
		if code == 0 {
			t.Fatalf("npm install %s SUCCEEDED with a human deny on record. This is exactly #132: the "+
				"console records and displays the deny, the approval service holds it, and the gate serves "+
				"the package anyway because its score cleared the threshold. D272 says the deny wins.\n%s\n"+
				"--- firewall ---\n%s", denied, tail(out, 20), logAround(fw.log.String(), 30, denied))
		}

		// CONTACT, not just an exit code. A non-zero npm is cheap to produce by
		// accident — a dead container, a DNS failure, a typo'd package name all
		// score one. The refusal only counts if the gate made it and said so.
		logs := fw.log.String()
		if !strings.Contains(logs, "DENIED by human") {
			t.Errorf("the client was refused but the firewall never logged a human deny, so the refusal "+
				"is not attributable to the operator's ruling — and an operator reading this log cannot "+
				"tell their own decision from an outage.\n--- firewall ---\n%s", logAround(logs, 30, denied))
		}
		// The reason has to name the score it overrode. An operator who set the
		// threshold themselves needs to see that the package PASSED and was denied
		// anyway; "blocked" alone reads as a scoring failure and sends them to the
		// wrong dial.
		if !strings.Contains(logs, "overriding a passing score") {
			t.Errorf("the human deny does not say it overrode a PASSING score, so the log is "+
				"indistinguishable from a score block.\n--- firewall ---\n%s", logAround(logs, 30, denied))
		}
	})

	t.Run("discriminator_a_package_with_no_ruling_still_installs", func(t *testing.T) {
		if code, out := runNpmInstall(t, fw.port, other); code != 0 {
			t.Fatalf("npm install %s fails (exit %d) on the SAME firewall that refused %s, though the "+
				"approval service holds no record for it. The allow path is refusing on the presence of an "+
				"approval service rather than on a ruling — which would block every package in any "+
				"deployment with FW_APPROVAL_URL set.\n%s\n--- firewall ---\n%s",
				other, code, denied, tail(out, 20), logAround(fw.log.String(), 30, other))
		}
	})
}
