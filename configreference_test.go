package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The config reference (docs/CONFIGURATION.md) is the deliverable of issue #51's
// first acceptance item: the FW_* surface enumerated, with the count stated as a
// budget to defend.
//
// A hand-maintained reference drifts the moment someone adds a knob — and it
// drifts SILENTLY, which is the failure mode that matters here. The project named
// undocumented settings as one of three things he would hold against the product:
// "generally the settings are not well documented and I have to guess at what they
// are doing". A doc that is 90% right is arguably worse than none, because an
// operator acts on it.
//
// So the doc is kept honest by this test rather than by review.

const (
	configSourcePath = "config.go"
	configDocPath    = "docs/CONFIGURATION.md"
)

var fwVarRe = regexp.MustCompile(`FW_[A-Z0-9_]+`)

// configVarsIn returns the distinct FW_* names appearing in a file.
func configVarsIn(t *testing.T, path string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := map[string]bool{}
	for _, m := range fwVarRe.FindAllString(string(b), -1) {
		out[m] = true
	}
	return out
}

func sorted(m map[string]bool) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}

// TestConfigReferenceIsComplete is the drift guard, in both directions.
func TestConfigReferenceIsComplete(t *testing.T) {
	inCode := configVarsIn(t, configSourcePath)
	inDoc := configVarsIn(t, configDocPath)

	// Anti-vacuity: if either side parsed to nothing, every comparison below
	// would pass for the wrong reason. Seen for real elsewhere in this repo —
	// a check that can only print green converts an unknown into confidence.
	if len(inCode) == 0 {
		t.Fatalf("no FW_* variables found in %s — the extraction broke, so this test proves nothing", configSourcePath)
	}
	if len(inDoc) == 0 {
		t.Fatalf("no FW_* variables found in %s — the extraction broke, so this test proves nothing", configDocPath)
	}

	var undocumented []string
	for _, v := range sorted(inCode) {
		if !inDoc[v] {
			undocumented = append(undocumented, v)
		}
	}
	if len(undocumented) > 0 {
		t.Errorf("%d setting(s) exist in %s but are NOT in %s: %s\n"+
			"Add a row with its default and a one-line justification, and update the stated count. "+
			"An undocumented knob is one an operator has to guess at.",
			len(undocumented), configSourcePath, configDocPath, strings.Join(undocumented, ", "))
	}

	var stale []string
	for _, v := range sorted(inDoc) {
		if !inCode[v] {
			stale = append(stale, v)
		}
	}
	if len(stale) > 0 {
		t.Errorf("%d setting(s) are documented in %s but no longer exist in %s: %s\n"+
			"A reference that describes a knob you cannot set is worse than a missing row.",
			len(stale), configDocPath, configSourcePath, strings.Join(stale, ", "))
	}
}

// TestConfigReferenceCountIsHonest pins the number the doc claims against reality.
// The count is not decoration: issue #51 asks for it to be stated as a budget, and
// a budget nobody recomputes is just a sentence.
func TestConfigReferenceCountIsHonest(t *testing.T) {
	inCode := configVarsIn(t, configSourcePath)

	b, err := os.ReadFile(configDocPath)
	if err != nil {
		t.Fatalf("read %s: %v", configDocPath, err)
	}
	m := regexp.MustCompile(`\*\*(\d+) environment variables`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("%s no longer states a count in the form \"**N environment variables\" — "+
			"the budget is meant to be stated, per issue #51", configDocPath)
	}
	claimed, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("parse claimed count %q: %v", m[1], err)
	}
	if claimed != len(inCode) {
		t.Errorf("%s claims %d environment variables; %s actually defines %d.\n"+
			"Update the stated budget — the number is the point of stating it.",
			configDocPath, claimed, configSourcePath, len(inCode))
	}
}

// TestConfigReferenceGuardCanFail is the negative control.
//
// Both tests above compare two sets. If the comparison were inert — a bad regex, a
// path typo swallowed by a permissive read — they would pass no matter what, and a
// green suite would mean nothing. This proves the comparison actually discriminates
// by running it against a doc that is deliberately missing a setting.
func TestConfigReferenceGuardCanFail(t *testing.T) {
	inCode := configVarsIn(t, configSourcePath)
	if len(inCode) < 2 {
		t.Fatalf("need at least 2 settings to construct the control, found %d", len(inCode))
	}

	all := sorted(inCode)
	omitted := all[0]

	// A stand-in doc containing every setting EXCEPT one.
	var sb strings.Builder
	for _, v := range all[1:] {
		fmt.Fprintf(&sb, "| `%s` | x | y |\n", v)
	}
	docVars := fwVarRe.FindAllString(sb.String(), -1)
	present := map[string]bool{}
	for _, v := range docVars {
		present[v] = true
	}

	if present[omitted] {
		t.Fatalf("control is malformed: %q was supposed to be omitted", omitted)
	}
	missing := 0
	for v := range inCode {
		if !present[v] {
			missing++
		}
	}
	if missing != 1 {
		t.Errorf("the completeness comparison did NOT discriminate: a doc missing exactly one "+
			"setting (%q) was measured as missing %d. If this does not detect one absent knob, "+
			"TestConfigReferenceIsComplete cannot be trusted to detect a real one.", omitted, missing)
	}
}

// ── EVERY SERVICE, NOT JUST THE FIREWALL ────────────────────────────────────
//
// The check above guards FW_* against config.go. For a long time that was the whole
// guard, and docs/CONFIGURATION.md said so in its own text: "This section is NOT
// drift-checked, and the rest of this document is." Recording the gap was right, and
// it is what made this fixable rather than invisible — but a stated gap is still a
// gap, and 33 of the other services' settings were undocumented behind it.
//
// Two differences from the FW_ check above, both learned the hard way:
//
//  1. QUOTED LITERALS ONLY. A bare `CONSOLE_[A-Z_]+` regex matches the string
//     "CONSOLE_MVP_SCOPE.md" in a comment — a DOC FILENAME, not a setting — and the
//     first measurement of this gap reported it as an undocumented variable. An env
//     var name in Go is always a string literal, so requiring the quotes removes a
//     whole class of false positive.
//  2. THE WHOLE TREE, not one file. The firewall has a single config.go; the other
//     services read their environment where they use it. Scanning every tracked
//     non-test .go file means a new service cannot escape the check by not having a
//     config.go — which is exactly how the firewall's guard failed to cover them.
//
// Test files are excluded deliberately: APPROVAL_TEST_DSN is a test harness input,
// not an operator setting, and documenting it would tell a deployer to set something
// that does nothing.
var configPrefixes = []string{"FW", "APPROVAL", "CONSOLE", "SCHEDULER", "SCANNER", "CACHE"}

// quotedVarRe matches an env var name as it appears in Go source: inside quotes.
var quotedVarRe = regexp.MustCompile(`"((?:FW|APPROVAL|CONSOLE|SCHEDULER|SCANNER|CACHE)_[A-Z0-9_]+)"`)

// docVarRe matches a name as it appears in the reference: in a table cell, in
// backticks. The trailing `[A-Z0-9]` is what stops it matching the PREFIXES the prose
// uses ("APPROVAL_SMTP_*", "APPROVAL_ALERT_*"), which name a family rather than a
// setting and would otherwise read as documented-but-nonexistent.
var docVarRe = regexp.MustCompile(`\b((?:FW|APPROVAL|CONSOLE|SCHEDULER|SCANNER|CACHE)_[A-Z0-9_]*[A-Z0-9])\b`)

// envVarsInTree returns every env var name appearing as a quoted literal in tracked,
// non-test Go source.
func envVarsInTree(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip dot-dirs and vendored/build trees. The CI module cache lives
			// INSIDE the checkout (GOMODCACHE=.gocache), so walking blindly from "."
			// scans every dependency and fails only in CI — a trap this repo has
			// already been caught by once.
			name := info.Name()
			if path != "." && (strings.HasPrefix(name, ".") || name == "builds" || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range quotedVarRe.FindAllStringSubmatch(string(b), -1) {
			out[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk source tree: %v", err)
	}
	return out
}

func docVars(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(configDocPath)
	if err != nil {
		t.Fatalf("read %s: %v", configDocPath, err)
	}
	out := map[string]bool{}
	for _, m := range docVarRe.FindAllStringSubmatch(string(b), -1) {
		out[m[1]] = true
	}
	return out
}

// TestEveryServicesConfigIsDocumented extends the guard to the whole stack.
func TestEveryServicesConfigIsDocumented(t *testing.T) {
	inCode := envVarsInTree(t)
	inDoc := docVars(t)

	// Anti-vacuity, per prefix rather than in total: a walk that silently stopped
	// early would still find plenty of FW_ names and pass a whole-set check while
	// covering nothing else.
	for _, p := range configPrefixes {
		n := 0
		for v := range inCode {
			if strings.HasPrefix(v, p+"_") {
				n++
			}
		}
		if n == 0 {
			t.Fatalf("no %s_* variables found anywhere in the source tree — the extraction "+
				"broke, so this test proves nothing for that service", p)
		}
	}

	var undocumented []string
	for _, v := range sorted(inCode) {
		if !inDoc[v] {
			undocumented = append(undocumented, v)
		}
	}
	if len(undocumented) > 0 {
		t.Errorf("%d setting(s) are read from the environment but are NOT in %s: %s\n"+
			"Add a row with its default and a one-line justification. The project named undocumented "+
			"settings as one of three things he would hold against the product; an operator who "+
			"has to guess is the failure this file exists to prevent.",
			len(undocumented), configDocPath, strings.Join(undocumented, ", "))
	}

	var stale []string
	for _, v := range sorted(inDoc) {
		if !inCode[v] {
			stale = append(stale, v)
		}
	}
	if len(stale) > 0 {
		t.Errorf("%d setting(s) are documented in %s but are read nowhere in the source: %s\n"+
			"A reference that describes a knob you cannot set is worse than a missing row.",
			len(stale), configDocPath, strings.Join(stale, ", "))
	}
}

// TestTheExtractorIgnoresProse is the codified form of a false positive that actually
// happened while this guard was being written.
//
// A bare `CONSOLE_[A-Z_]+` regex matches "CONSOLE_MVP_SCOPE.md" — a reference to a
// DOCUMENT, sitting in a comment in console/lookup.go — and the first measurement of
// the documentation gap reported it as an undocumented setting. Acting on that would
// have meant documenting a variable nobody can set, which the stale-direction check
// would then have failed on: a false finding that generates a second false finding.
//
// This pins the fix (quoted literals only) rather than trusting that the comment
// stays phrased the way it is today.
func TestTheExtractorIgnoresProse(t *testing.T) {
	const src = `
// See CONSOLE_MVP_SCOPE.md and the SCHEDULER_NOTES.md file for background.
// An operator sets APPROVAL_SOMETHING_ELSE, allegedly.
func f() { _ = os.Getenv("CONSOLE_AUTH_USER") }
`
	got := map[string]bool{}
	for _, m := range quotedVarRe.FindAllStringSubmatch(src, -1) {
		got[m[1]] = true
	}
	if !got["CONSOLE_AUTH_USER"] {
		t.Fatal("the extractor missed a real quoted variable, so the assertions below prove nothing")
	}
	for _, prose := range []string{"CONSOLE_MVP_SCOPE", "SCHEDULER_NOTES", "APPROVAL_SOMETHING_ELSE"} {
		if got[prose] {
			t.Errorf("%q was extracted from a comment as if it were a setting; a document "+
				"filename is not a knob, and reporting it as one sends someone to document "+
				"a variable that cannot be set", prose)
		}
	}
}

// TestTheDocPatternIgnoresFamilyPrefixes — the mirror of the above, on the doc side.
// The reference talks about "APPROVAL_SMTP_*" and "APPROVAL_ALERT_*" as families. Those
// are prose, not settings, and matching them would report two permanently-stale
// entries that no one can fix without making the prose worse.
func TestTheDocPatternIgnoresFamilyPrefixes(t *testing.T) {
	const doc = "The `APPROVAL_SMTP_` family and `APPROVAL_ALERT_` variables. Also `CACHE_TTL`."
	got := map[string]bool{}
	for _, m := range docVarRe.FindAllStringSubmatch(doc, -1) {
		got[m[1]] = true
	}
	if !got["CACHE_TTL"] {
		t.Fatal("the doc pattern missed a real variable, so the assertions below prove nothing")
	}
	for _, family := range []string{"APPROVAL_SMTP_", "APPROVAL_ALERT_"} {
		if got[family] {
			t.Errorf("%q was read as a setting name; it is a family prefix in prose", family)
		}
	}
}

// TestStackWideCountIsHonest pins the whole-stack total the same way
// TestConfigReferenceCountIsHonest pins the firewall's.
//
// The doc's own rule, in its own words: a budget nobody recomputes is just a sentence.
// The firewall's 31 has been defended by a test since #51; the stack's 67 would
// otherwise be a number that was true on the day it was typed.
func TestStackWideCountIsHonest(t *testing.T) {
	inCode := envVarsInTree(t)

	b, err := os.ReadFile(configDocPath)
	if err != nil {
		t.Fatalf("read %s: %v", configDocPath, err)
	}
	m := regexp.MustCompile(`whole stack: (\d+) environment variables`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("%s no longer states a stack-wide count in the form "+
			"\"whole stack: N environment variables\"", configDocPath)
	}
	claimed, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("parse claimed stack count %q: %v", m[1], err)
	}
	if claimed != len(inCode) {
		t.Errorf("%s claims %d environment variables across the stack; the source reads %d.\n"+
			"Update the stated total — the number is the point of stating it.",
			configDocPath, claimed, len(inCode))
	}
}
