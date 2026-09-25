//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"
)

// Tier 3 for the npm half of issue #67, against the real binary in a container.
//
// TestAdversarialNpmTarballPathCannotBeConfused already covers this attack, but it sets
// FW_URL_SIGNING_KEY — so it measures the SIGNED deployment. D159 rules that the DEFAULT
// one must be safe: "the measured 318KB npm bypass is closed for an operator who installs
// us and changes nothing". That operator has no key, so the existing leg does not test
// the claim, and a unit test does not test the binary. This does both.
//
// The distinction is not academic. Before D159 this exact configuration served 318 KB of
// a blocked package's tarball under an allowed package's name, and the only fix on offer
// was one the operator had to know to switch on.
func TestAdversarialNpmDefaultDeploymentRefusesTheConfusedDeputy(t *testing.T) {
	bin := buildFirewall(t)

	// lodash's tarball path in the registry's own convention — the shape a lockfile
	// records, and what "/_tarball/<pkg>/" wraps.
	const target = "/lodash/-/lodash-4.17.21.tgz"

	approvalURL := startSelectiveApprovalStub(t, "express")
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":         "npm",
		"FW_SCORECARD_MODE":    "stub",
		"FW_SCORE_THRESHOLD":   "8.0", // above the flat stub score: nothing passes on merit
		"FW_UNSCORABLE_POLICY": "block",
		"FW_UNVERIFIED_POLICY": "closed",
		"FW_BYTE_GATE":         "enforce",
		"FW_APPROVAL_URL":      approvalURL,
		// NO FW_URL_SIGNING_KEY. That omission is the entire point of this test: the
		// refusal below has to come from the prefix/object-path binding, which is on
		// unconditionally, and not from a feature the operator opted into.
	})

	// Anti-vacuity 1: the target really is blocked on its own route. Without this, a
	// refusal below could just mean lodash was never servable here.
	if code, body := rawGet(t, fwHost(), fw.port, target); code == http.StatusOK && leaked(body) != "" {
		t.Fatalf("control: lodash is NOT blocked (%d, %s) — the test is vacuous\n--- firewall ---\n%s",
			code, leaked(body), logAround(fw.log.String(), 20))
	}

	// Anti-vacuity 2: the approved decoy really does serve tarball bytes through the URL
	// the firewall minted for it, with no key configured. This proves the unsigned relay
	// WORKS, so the refusal in the attack is specific to the mismatched pair rather than
	// the whole "/_tarball/" route being broken — which is the way this test would most
	// plausibly pass for the wrong reason.
	code, packument := rawGet(t, fwHost(), fw.port, "/express")
	if code != http.StatusOK {
		t.Fatalf("control: could not read the decoy packument (%d)\n--- firewall ---\n%s",
			code, logAround(fw.log.String(), 20))
	}
	m := npmMintedTarballRe.FindSubmatch(packument)
	if m == nil {
		t.Fatalf("control: no minted /_tarball/express/... URL in the packument; the relay shape changed")
	}
	minted := string(m[1])
	if strings.Contains(minted, "_yjsig=") {
		t.Fatalf("control: the minted URL carries a signature (%q) — a key leaked into this "+
			"deployment, so this leg is measuring the signed path, not the default one", minted)
	}
	if code, body := rawGet(t, fwHost(), fw.port, minted); code != http.StatusOK || leaked(body) == "" {
		t.Fatalf("control: approved decoy 'express' served no tarball from its own minted URL "+
			"(%d, %d bytes) — the confused-deputy attack cannot be evaluated\n--- firewall ---\n%s",
			code, len(body), logAround(fw.log.String(), 20))
	}

	// The attack: the allowed package's prefix, the blocked package's object path.
	attack := "/_tarball/express" + target
	code, body := rawGet(t, fwHost(), fw.port, attack)
	if what := leaked(body); what != "" {
		t.Errorf("GATE BYPASS (confused deputy, DEFAULT deployment): GET %s returned %d with %d bytes of %s.\n"+
			"The byte gate evaluated the ALLOWED package named in the prefix and forwarded the BLOCKED "+
			"package's object path verbatim — with no signing key, which is what a stock install runs.\n"+
			"--- firewall ---\n%s",
			attack, code, len(body), what, logAround(fw.log.String(), 25))
	}
	if code >= 200 && code < 300 {
		t.Errorf("GET %s returned %d and was RELAYED (%d bytes) — it must be refused before reaching upstream",
			attack, code, len(body))
	}
}
