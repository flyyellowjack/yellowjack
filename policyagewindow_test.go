package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// #150: /policy must not present the release-age knobs as in force on a gate that
// deliberately does not enforce them.
//
// The documentation was already right -- CONFIGURATION.md says "OCI is deliberately NOT
// covered, and this is a measurement" -- and the PROVABILITY SURFACE contradicted it: an
// OCI gate with FW_MIN_RELEASE_AGE_DAYS=7 reported `min_release_age_days: 7` exactly as
// an npm gate would. whyOCIHasNoReleaseWindow's own reasoning is that a window there
// would be worse than none "because the operator would believe the window applied to
// containers"; the bare number on the policy page produced precisely that belief.

func gateFor(ecosystem string, eco Ecosystem, min, max int) *Firewall {
	cfg := shippedConfig()
	cfg.Ecosystem = ecosystem
	cfg.MinReleaseAgeDays = min
	cfg.MaxReleaseAgeDays = max
	return &Firewall{cfg: cfg, eco: eco}
}

func TestPolicyViewDoesNotClaimAnUnenforcedReleaseWindow(t *testing.T) {
	// Controls FIRST: on ecosystems that DO enforce the window the value is the bare
	// number. Without these, "OCI is annotated" passes for a view that annotates everyone.
	for _, tc := range []struct {
		name string
		f    *Firewall
	}{
		{"npm", gateFor("npm", nil, 7, 365)},
		{"pypi", gateFor("pypi", nil, 7, 365)},
		{"maven", gateFor("maven", mavenEcosystem{}, 7, 365)},
	} {
		v := tc.f.describePolicy().Values
		if v["min_release_age_days"] != "7" || v["max_release_age_days"] != "365" {
			t.Errorf("%s ENFORCES the window, so its policy view must show the bare values; got min=%q max=%q",
				tc.name, v["min_release_age_days"], v["max_release_age_days"])
		}
	}

	oci := gateFor("oci", ociEcosystem{}, 7, 365).describePolicy().Values
	for _, key := range []string{"min_release_age_days", "max_release_age_days"} {
		if !strings.Contains(oci[key], "NOT ENFORCED") || !strings.Contains(oci[key], "oci") {
			t.Errorf("an OCI gate reports %s=%q. The window is deliberately not applied to OCI, so a bare "+
				"number here tells the operator a cooldown is in force when it is not", key, oci[key])
		}
	}
	// The operator's own number must survive: they need to see WHAT they set as well as
	// that it does nothing, or the page hides their mistake instead of explaining it.
	if !strings.HasPrefix(oci["min_release_age_days"], "7 ") {
		t.Errorf("the annotation lost the configured value: %q", oci["min_release_age_days"])
	}

	// Zero is not annotated: nothing was asked for, so there is nothing to mislead about,
	// and a wall of NOT ENFORCED on every default OCI gate would be noise that teaches
	// operators to ignore the phrase.
	quiet := gateFor("oci", ociEcosystem{}, 0, 0).describePolicy().Values
	if quiet["min_release_age_days"] != "0" || quiet["max_release_age_days"] != "0" {
		t.Errorf("an OCI gate with the window OFF must report plain zeros; got min=%q max=%q",
			quiet["min_release_age_days"], quiet["max_release_age_days"])
	}
}

// TestTheDigestStillMovesWithAnUnenforcedValue: annotating must not freeze the digest.
// Two OCI replicas configured differently still differ, and /policy exists to show that.
func TestTheDigestStillMovesWithAnUnenforcedValue(t *testing.T) {
	a := gateFor("oci", ociEcosystem{}, 7, 0).describePolicy().Digest
	b := gateFor("oci", ociEcosystem{}, 14, 0).describePolicy().Digest
	if a == b {
		t.Error("two OCI gates with different cooldown values digest identically; the annotation swallowed the value")
	}
}

// TestAnUnenforcedWindowSeparatesTheGateOnThePolicyPage pins a deliberate cost. The
// console shows ONE policy per digest group, taken from the first replica it meets. If
// an OCI gate that ignores the cooldown digested the same as an npm gate that enforces
// it, the group would display either a bare 7 for both or NOT ENFORCED for both,
// depending on row order. So the two must land in different groups.
//
// The control is the zero case: with no window asked for, the ecosystems MUST still
// digest identically, or this change has made every mixed fleet look diverged.
func TestAnUnenforcedWindowSeparatesTheGateOnThePolicyPage(t *testing.T) {
	if n, o := gateFor("npm", nil, 0, 0).describePolicy().Digest, gateFor("oci", ociEcosystem{}, 0, 0).describePolicy().Digest; n != o {
		t.Fatalf("with the window OFF an npm and an OCI gate must digest identically (npm %s, oci %s); "+
			"otherwise every mixed fleet shows a divergence nobody can clear", n, o)
	}
	if n, o := gateFor("npm", nil, 7, 0).describePolicy().Digest, gateFor("oci", ociEcosystem{}, 7, 0).describePolicy().Digest; n == o {
		t.Error("an npm gate that enforces a 7-day cooldown and an OCI gate that ignores one share a digest, " +
			"so the console will show them as one group with one of the two descriptions wrong")
	}
}

// TestEveryEcosystemIsClassifiedForTheReleaseWindow is the coverage guard. The defect in
// #150 was a silent omission, so the guard asserts COVERAGE rather than adding one more
// per-ecosystem case somebody can forget: the ecosystem list is read from config.go's
// own enum, and an ecosystem missing from the table below fails until it is classified.
func TestEveryEcosystemIsClassifiedForTheReleaseWindow(t *testing.T) {
	src, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatalf("read config.go: %v", err)
	}
	m := regexp.MustCompile(`c\.enum\("FW_ECOSYSTEM",\s*([^)]*)\)`).FindStringSubmatch(string(src))
	if m == nil {
		t.Fatal("could not find the FW_ECOSYSTEM enum in config.go; this guard is reading nothing")
	}
	seen := map[string]bool{}
	for _, q := range regexp.MustCompile(`"([a-z]+)"`).FindAllStringSubmatch(m[1], -1) {
		seen[q[1]] = true
	}
	if len(seen) < 4 {
		t.Fatalf("parsed only %d ecosystem(s) from the enum (%v); the parser is not reading the list", len(seen), seen)
	}

	want := map[string]struct {
		eco      Ecosystem
		enforced bool
	}{
		"npm":   {nil, true},              // index filter (proxy.go)
		"pypi":  {nil, true},              // index filter (proxy.go)
		"maven": {mavenEcosystem{}, true}, // releaseDated (mavenage.go)
		"oci":   {ociEcosystem{}, false},  // deliberately not -- whyOCIHasNoReleaseWindow, #127
	}
	var names []string
	for e := range seen {
		names = append(names, e)
	}
	sort.Strings(names)
	for _, e := range names {
		w, ok := want[e]
		if !ok {
			t.Errorf("ecosystem %q is in the FW_ECOSYSTEM enum but is not classified here. Decide whether the "+
				"release-age window is ENFORCED for it, add it to this table, and make sure /policy tells the "+
				"truth either way -- the silent version of this omission is issue #150", e)
			continue
		}
		if got := gateFor(e, w.eco, 7, 0).releaseWindowEnforced(); got != w.enforced {
			t.Errorf("releaseWindowEnforced() for %q = %v, want %v", e, got, w.enforced)
		}
	}
}
