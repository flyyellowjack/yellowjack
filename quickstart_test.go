package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// QUICKSTART.md is the page an evaluator reads first, and #107 is explicit about why it matters:
// an open-source security tool is adopted on "a demo that lands in about thirty seconds, and a
// number". A quickstart that has rotted is worse than none, because the first command a stranger
// runs is the one that fails.
//
// So it is guarded like CONFIGURATION.md is, and for a defect that had ALREADY happened: README.md
// told readers to switch ecosystems with "npm|pypi|oci" while config.go had accepted `maven` for
// months. Nothing caught it, because no test read the prose. TestDocsNameEveryEcosystem below reads
// both pages against the enum, so that class cannot come back.

const quickstartPath = "QUICKSTART.md"

// ecosystemEnumRe pulls the accepted values out of the one call that defines them:
//
//	ecosystem := c.enum("FW_ECOSYSTEM", "npm", "npm", "pypi", "oci", "maven")
//
// Reading the source rather than restating the list is the point -- a restated list is another
// copy to rot.
var ecosystemEnumRe = regexp.MustCompile(`c\.enum\("FW_ECOSYSTEM"([^)]*)\)`)
var quotedRe = regexp.MustCompile(`"([a-z0-9]+)"`)

func supportedEcosystems(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(configSourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", configSourcePath, err)
	}
	m := ecosystemEnumRe.FindSubmatch(b)
	if m == nil {
		t.Fatalf("could not find the FW_ECOSYSTEM enum in %s -- the extraction broke, so this test "+
			"proves nothing about the docs", configSourcePath)
	}
	seen := map[string]bool{}
	var out []string
	for _, q := range quotedRe.FindAllSubmatch(m[1], -1) {
		v := string(q[1])
		if !seen[v] { // the default is repeated as the first value; count it once
			seen[v] = true
			out = append(out, v)
		}
	}
	if len(out) < 2 {
		t.Fatalf("extracted %v from the FW_ECOSYSTEM enum -- too few to be the real list", out)
	}
	sort.Strings(out)
	return out
}

// TestDocsNameEveryEcosystem is the regression test for a defect that shipped: README.md said
// "npm|pypi|oci" and omitted maven, which config.go had accepted all along.
func TestDocsNameEveryEcosystem(t *testing.T) {
	eco := supportedEcosystems(t)
	for _, doc := range []string{quickstartPath, "README.md"} {
		b, err := os.ReadFile(doc)
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		text := string(b)
		for _, e := range eco {
			if !strings.Contains(text, e) {
				t.Errorf("%s never mentions the %q ecosystem, but FW_ECOSYSTEM accepts it (%v). A "+
					"reader is being told a shorter list than the product supports -- this is the "+
					"exact defect README.md carried for months.", doc, e, eco)
			}
		}
	}
}

// TestQuickstartOnlyNamesRealSettings stops the page telling a stranger to export something that
// does not exist. Their first run failing is the worst possible first impression.
func TestQuickstartOnlyNamesRealSettings(t *testing.T) {
	inDoc := configVarsIn(t, quickstartPath)
	inCode := configVarsIn(t, configSourcePath)
	if len(inDoc) == 0 {
		t.Fatalf("no FW_* settings found in %s -- either the page stopped showing how to configure "+
			"anything, or the extraction broke; both make this test vacuous", quickstartPath)
	}
	for _, v := range sorted(inDoc) {
		if !inCode[v] {
			t.Errorf("%s tells the reader to set %s, which does not appear in %s", quickstartPath, v, configSourcePath)
		}
	}
}

// TestQuickstartActuallyDemonstratesARefusal pins the SHAPE of the page, not its wording.
//
// Before this file existed the only quickstart was in README.md and it built three binaries,
// started one, and stopped -- it never showed the product doing its job. #107 says the demo is
// half of why anyone adopts the tool, so "it still builds" is not the property to protect.
func TestQuickstartActuallyDemonstratesARefusal(t *testing.T) {
	b, err := os.ReadFile(quickstartPath)
	if err != nil {
		t.Fatalf("read %s: %v", quickstartPath, err)
	}
	text := string(b)
	for _, want := range []struct{ needle, why string }{
		{"403", "the page must show a refusal, not just a successful build"},
		{"FW_DENY_LIST", "the demo runs on the one signal that needs no network, no scanner and no account"},
		{"200", "a gate that blocks everything is not a gate; the page must show something being ALLOWED too"},
		{"X-Yellowjack-Kind", "the refusal is machine-readable, and a reader integrating us needs to see that"},
	} {
		if !strings.Contains(text, want.needle) {
			t.Errorf("%s no longer contains %q: %s", quickstartPath, want.needle, want.why)
		}
	}
}

// TestQuickstartGuardsCanFail is the negative control. Every check above is a substring test over
// prose, which is exactly the kind that quietly stops matching anything -- a typo'd path, a renamed
// file, an empty read -- and then passes forever. This proves the extraction and the comparison
// both still bite.
func TestQuickstartGuardsCanFail(t *testing.T) {
	eco := supportedEcosystems(t)
	if len(eco) == 0 {
		t.Fatal("the ecosystem extraction returned nothing, so TestDocsNameEveryEcosystem cannot fail")
	}
	// A document that names no ecosystem must be detectable as such.
	if strings.Contains("a page that mentions nothing", eco[0]) {
		t.Fatalf("control text unexpectedly contains %q; the containment check is not discriminating", eco[0])
	}
	// A setting that cannot exist must not be found in config.go.
	if configVarsIn(t, configSourcePath)["FW_THIS_SETTING_DOES_NOT_EXIST"] {
		t.Fatal("config.go appears to contain an invented setting, so the membership check proves nothing")
	}
	// And the refusal check must be able to notice an absence.
	if strings.Contains("build it and run it", "403") {
		t.Fatal("the refusal check matched text that has no 403 in it")
	}
}
