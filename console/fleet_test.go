package main

import (
	"strings"
	"testing"
	"time"
)

// Gates of different ecosystems are MEANT to run different policies. Found on the first
// live run of the demo (npm + OCI): the Overview said "Differs" and "2 different policies
// in force" about a healthy deployment.
func gateOf(name, eco, digest, feed, allow string) instanceHealth {
	return instanceHealth{Instance: name, Ecosystem: eco, ReportedAt: time.Now().UTC(), PolicyDigest: digest,
		Policy: &policyDoc{Digest: digest, Values: map[string]string{
			"known_malware_feed": feed, "operator_allow_list": allow, "operator_deny_list": "off"}}}
}

func TestOverviewComparesGatesWithinAnEcosystem(t *testing.T) {
	healthy := []instanceHealth{
		gateOf("npm-1", "npm", "aaaa111", "4 enforced (4 package-wide, 0 version-pinned), sha256:x", "1 entries, sha256:y"),
		gateOf("oci-1", "oci", "bbbb222", "off", "off"),
	}
	body := getPage(t, newTestServer(&fakeApproval{health: healthy}), "/")
	for _, bad := range []string{">Differs<", "different policies", "Differs among"} {
		if strings.Contains(body, bad) {
			t.Errorf("a healthy npm + OCI deployment is reported as %q", bad)
		}
	}
	for _, want := range []string{">4<", "Enforced on npm; off on OCI.", "2 gates · each ecosystem consistent", "npm 1 entry"} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}

	// The discriminator: two npm gates that disagree ARE a finding, and must still say so.
	split := append(healthy, gateOf("npm-2", "npm", "cccc333", "5 enforced (5 package-wide, 0 version-pinned), sha256:z", "1 entries, sha256:y"))
	body = getPage(t, newTestServer(&fakeApproval{health: split}), "/")
	for _, want := range []string{">Differs<", "Gates for npm report different known-malware lists.", "Differs among npm gates"} {
		if !strings.Contains(body, want) {
			t.Errorf("two npm gates that disagree: overview lacks %q", want)
		}
	}
}

// The policy page's own divergence banner, by the same rule.
func TestPolicyDivergenceIsWithinAnEcosystem(t *testing.T) {
	now := time.Now().UTC()
	healthy := []instanceHealth{
		gateOf("npm-1", "npm", "aaaa111", "off", "off"),
		gateOf("oci-1", "oci", "bbbb222", "off", "off"),
	}
	if v := buildPolicyView(healthy, now); v.Diverged {
		t.Errorf("npm and OCI gates with different policies were flagged as diverged")
	}
	split := append(healthy, gateOf("npm-2", "npm", "cccc333", "off", "off"))
	v := buildPolicyView(split, now)
	if !v.Diverged || v.FreshGroups != 2 || v.DivergedIn != "npm" {
		t.Errorf("two npm gates on different policies: diverged=%v groups=%d in=%q", v.Diverged, v.FreshGroups, v.DivergedIn)
	}
}

// With more than one ecosystem the rules are per ecosystem, chosen by tab.
func TestPolicyRulesFollowTheChosenEcosystem(t *testing.T) {
	gates := []instanceHealth{
		// maven sorts before npm, so this is what shows npm is the default on purpose
		// rather than by alphabet.
		gateOf("maven-1", "maven", "dddd444", "off", "off"),
		gateOf("npm-1", "npm", "aaaa111", "4 enforced (4 package-wide, 0 version-pinned), sha256:x", "1 entries, sha256:y"),
		gateOf("oci-1", "oci", "bbbb222", "off", "off"),
	}
	s := newTestServer(&fakeApproval{health: gates})
	npm := getPage(t, s, "/policy")
	if !strings.Contains(npm, "4 advisories") || !strings.Contains(npm, `href="/policy?eco=oci"`) {
		t.Errorf("the default tab is not npm's rules, or there is no OCI tab")
	}
	oci := getPage(t, s, "/policy?eco=oci")
	if !strings.Contains(oci, "No known-malware list is loaded") || strings.Contains(oci, "4 advisories") {
		t.Errorf("the OCI tab does not show OCI's own rules")
	}
}
