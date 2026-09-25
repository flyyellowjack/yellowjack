package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// docs/FAILURE_MODES.md is the operator-facing answer to #24: for every way the gate or
// something it depends on can fail, what the developer reads, what the pipeline does,
// and the test that pins it. A page like that rots in one specific way: a cited test is
// renamed or deleted, a drill leg is renumbered, and the sentence it was holding up goes
// on being quoted with nothing behind it. These checks make that a failing build.
//
// Three things are asserted, each with a negative control below:
//   - every `TestX` named on the page is defined in some *_test.go in this tree;
//   - every "`e2e/<script>.sh` leg N" citation names a leg that script actually has;
//   - the load-bearing sentences are still there (the needle list, each with its why).
const failureModesDocPath = "docs/FAILURE_MODES.md"

var (
	citedTestRe = regexp.MustCompile("`(Test[A-Za-z0-9_]+)`")
	testFuncRe  = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
	// "`e2e/ha_drill.sh` leg 3", "`e2e/registry_front.sh` legs 3–5", "legs 7 and 8".
	drillCiteRe = regexp.MustCompile("`(e2e/[a-z_]+\\.sh)` legs? ([0-9][0-9 ,–-]*(?:and [0-9]+)?)")
	drillLegRe  = regexp.MustCompile(`(?m)^say "([0-9]+)\)`)
)

// citedTests returns the distinct test names the page cites, in order of first mention.
func citedTests(doc string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range citedTestRe.FindAllStringSubmatch(doc, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// missingCitations returns every cited name that is not defined.
func missingCitations(cited []string, defined map[string]bool) []string {
	var missing []string
	for _, name := range cited {
		if !defined[name] {
			missing = append(missing, name)
		}
	}
	return missing
}

// testFuncsInTree walks every *_test.go under root and returns the set of test function
// names. Dot-directories are skipped (the CI module cache lives in .gocache/ inside the
// checkout), and so is builds/, a stray runner tree a dev host may carry.
func testFuncsInTree(t *testing.T, root string) map[string]bool {
	t.Helper()
	defined := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "builds" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range testFuncRe.FindAllStringSubmatch(string(src), -1) {
			defined[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return defined
}

// drillLegsCited returns, per script, the leg numbers the page attributes to it. A range
// written "3–5" (or "3-5") expands; "7 and 8" lists both.
func drillLegsCited(doc string) map[string][]int {
	out := map[string][]int{}
	for _, m := range drillCiteRe.FindAllStringSubmatch(doc, -1) {
		script, spec := m[1], m[2]
		spec = strings.ReplaceAll(spec, "and", ",")
		for _, part := range strings.Split(spec, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			lo, hi := part, part
			for _, dash := range []string{"–", "-"} {
				if i := strings.Index(part, dash); i > 0 {
					lo, hi = strings.TrimSpace(part[:i]), strings.TrimSpace(part[i+len(dash):])
					break
				}
			}
			a, errA := strconv.Atoi(lo)
			b, errB := strconv.Atoi(hi)
			if errA != nil || errB != nil || b < a {
				continue
			}
			for n := a; n <= b; n++ {
				out[script] = append(out[script], n)
			}
		}
	}
	for script := range out {
		sort.Ints(out[script])
	}
	return out
}

// legsInScript returns the leg numbers a drill script announces with its say "N) ..."
// banners, which is how every drill in e2e/ labels its legs.
func legsInScript(src string) map[int]bool {
	legs := map[int]bool{}
	for _, m := range drillLegRe.FindAllStringSubmatch(src, -1) {
		n, err := strconv.Atoi(m[1])
		if err == nil {
			legs[n] = true
		}
	}
	return legs
}

// missingLegs returns the cited legs a script does not announce.
func missingLegs(cited []int, have map[int]bool) []int {
	var missing []int
	for _, n := range cited {
		if !have[n] {
			missing = append(missing, n)
		}
	}
	return missing
}

// failureModeNeedles are the sentences the page cannot lose without lying. Each carries
// the reason, so whoever trips it can decide whether the page or the product changed.
var failureModeNeedles = []struct{ needle, why string }{
	{"no-store", "pending and unavailable are sent Cache-Control: no-store so an intermediary cannot cache a state about to change (D102); the page must say so or a corporate proxy surprises someone"},
	{"falling back to policy", "the approval-down row rests on that log line; it is what an operator greps for during the outage"},
	{"FW_PENDING_RETRY_AFTER", "the pending wait the developer is told is a knob, and the page must name it"},
	{"not a verdict", "the whole page rests on D17/D102: an outage is never reported as a fact about the package"},
	{"FW_MODE=report", "report mode is the zero-blast-radius way to deploy, and the page is where an operator learns that"},
	{"#19", "readiness is liveness today and the open box must stay named until it is closed"},
	{"nothing retries", "D102 removed the automatic retry; a page that implied self-healing would set the wrong expectation"},
}

func failureModeNeedlesMissing(doc string) []string {
	var missing []string
	for _, want := range failureModeNeedles {
		if !strings.Contains(doc, want.needle) {
			missing = append(missing, want.needle+": "+want.why)
		}
	}
	return missing
}

func TestFailureModesDocCitesOnlyRealTests(t *testing.T) {
	doc := readTextFile(t, failureModesDocPath)
	cited := citedTests(doc)
	// Anti-vacuity: the page is built on citations, so a page with few of them is a
	// different document from the one this guard was written for.
	if len(cited) < 30 {
		t.Fatalf("%s cites only %d tests; the guard expects the page to rest on its citations", failureModesDocPath, len(cited))
	}
	defined := testFuncsInTree(t, ".")
	if len(defined) < 200 {
		t.Fatalf("instrument: found only %d test functions in the tree, so an absence below would prove nothing", len(defined))
	}
	for _, name := range missingCitations(cited, defined) {
		t.Errorf("%s cites `%s`, which no *_test.go in this tree defines. Either the test was "+
			"renamed (update the page) or the behaviour lost its pin (restore the test); "+
			"do not leave the sentence standing on nothing.", failureModesDocPath, name)
	}
}

func TestFailureModesDocCitesRealDrillLegs(t *testing.T) {
	doc := readTextFile(t, failureModesDocPath)
	cited := drillLegsCited(doc)
	if len(cited) < 2 {
		t.Fatalf("%s cites legs of only %d drill scripts; the guard expects the HA and registry-front drills at least", failureModesDocPath, len(cited))
	}
	for script, legs := range cited {
		src := readTextFile(t, script)
		have := legsInScript(src)
		if len(have) < 3 {
			t.Fatalf("instrument: %s announces only %d legs with say \"N)\"; the check below would misfire", script, len(have))
		}
		for _, n := range missingLegs(legs, have) {
			t.Errorf("%s attributes leg %d to %s, which announces no such leg -- the drill was "+
				"renumbered or the leg removed; re-read the script before fixing the number", failureModesDocPath, n, script)
		}
	}
}

func TestFailureModesDocKeepsItsClaims(t *testing.T) {
	doc := readTextFile(t, failureModesDocPath)
	for _, m := range failureModeNeedlesMissing(doc) {
		t.Errorf("%s no longer says %s", failureModesDocPath, m)
	}
	// The page has to be reachable from the front page, or it is a trust artefact
	// nobody finds.
	if readme := readTextFile(t, "README.md"); !strings.Contains(readme, failureModesDocPath) {
		t.Errorf("README.md no longer links %s", failureModesDocPath)
	}
}

// TestFailureModesGuardsCanFail is the negative control: each extractor and each check
// is pointed at input built to trip it, so a green run above means the checks looked.
func TestFailureModesGuardsCanFail(t *testing.T) {
	// A cited test that does not exist must be reported, and one that does must not.
	cited := citedTests("pinned by `TestReal` and `TestNoSuchThing`, and `TestReal` again")
	if len(cited) != 2 {
		t.Fatalf("citedTests did not dedupe: %v", cited)
	}
	if got := missingCitations(cited, map[string]bool{"TestReal": true}); len(got) != 1 || got[0] != "TestNoSuchThing" {
		t.Fatalf("missingCitations should name exactly TestNoSuchThing, got %v", got)
	}
	// The tree walker must see this very file, or the definition set is not the tree.
	if !testFuncsInTree(t, ".")["TestFailureModesGuardsCanFail"] {
		t.Fatalf("testFuncsInTree did not find the test that is running")
	}

	// A leg range must expand, "and" must list, and an absent leg must be reported.
	legs := drillLegsCited("see `e2e/x_drill.sh` legs 3–5 and 7, then `e2e/y.sh` leg 2.")
	if got := legs["e2e/x_drill.sh"]; len(got) != 4 || got[0] != 3 || got[3] != 7 {
		t.Fatalf("drillLegsCited expanded 'legs 3–5 and 7' to %v", got)
	}
	if got := legs["e2e/y.sh"]; len(got) != 1 || got[0] != 2 {
		t.Fatalf("drillLegsCited read 'leg 2' as %v", got)
	}
	have := legsInScript("say \"3) first\"\necho x\nsay \"4) second\"\n")
	if got := missingLegs(legs["e2e/x_drill.sh"], have); len(got) != 2 || got[0] != 5 || got[1] != 7 {
		t.Fatalf("missingLegs should name 5 and 7, got %v", got)
	}

	// A needle that is gone must be named, and a page carrying all of them must pass.
	var full strings.Builder
	for _, n := range failureModeNeedles {
		full.WriteString(n.needle + "\n")
	}
	if got := failureModeNeedlesMissing(full.String()); len(got) != 0 {
		t.Fatalf("a page carrying every needle was reported missing %v", got)
	}
	if got := failureModeNeedlesMissing(strings.Replace(full.String(), "no-store", "", 1)); len(got) != 1 || !strings.HasPrefix(got[0], "no-store") {
		t.Fatalf("dropping no-store should be reported alone, got %v", got)
	}
}
