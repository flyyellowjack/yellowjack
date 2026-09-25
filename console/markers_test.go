package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The approval service reports availability as marker STRINGS and the console switches
// on those literals. They are separate binaries sharing no constant, so nothing at
// compile time connects a marker added on one side to an explanation on the other.
//
// explainAvailability fails SOFT on purpose -- an unknown marker renders as
// "Reported as: <marker>" rather than as nothing -- but soft is still a regression: the
// reader gets a slug instead of a sentence telling them what to do. #139 added a marker,
// which is exactly when this would have happened silently.
//
// So the marker list is DERIVED from the approval service's source instead of being
// written here, where it would be bounded by whoever last remembered to update it.
func TestEveryApprovalAvailabilityMarkerIsExplained(t *testing.T) {
	src, err := os.ReadFile("../approval/packagestatus.go")
	if err != nil {
		t.Fatalf("read the approval service's markers: %v", err)
	}
	found := regexp.MustCompile(`(?m)^\s*(avail[A-Za-z]+)\s*=\s*"([^"]+)"`).FindAllStringSubmatch(string(src), -1)
	if len(found) < 8 {
		t.Fatalf("derived only %d availability marker(s) from approval/packagestatus.go; the pattern has "+
			"stopped matching and this test would pass by checking nothing", len(found))
	}

	for _, m := range found {
		name, marker := m[1], m[2]
		got := explainAvailability(marker)
		if strings.HasPrefix(got, "Reported as:") {
			t.Errorf("%s (%q) has no explanation in the console: a reader sees the raw slug. "+
				"Add a case to explainAvailability.", name, marker)
		}
		if marker != "present" && got == "" {
			t.Errorf("%s (%q) renders as an EMPTY explanation, which reads as \"no problem found\"", name, marker)
		}
	}

	// NEGATIVE CONTROL for the soft-fail path the assertions above depend on: if an
	// unknown marker stopped producing the "Reported as:" prefix, the loop could no
	// longer detect a missing case at all.
	if got := explainAvailability("a-marker-nobody-has-written-yet"); !strings.HasPrefix(got, "Reported as:") {
		t.Fatalf("an unknown marker rendered as %q; this test detects a missing explanation by that "+
			"prefix, so it can no longer fail", got)
	}
}

// TestTooLargeIsNotExplainedAsAConnectivityProblem pins the point of the #139 split: the
// two explanations must send the reader in different directions.
func TestTooLargeIsNotExplainedAsAConnectivityProblem(t *testing.T) {
	tooLarge := explainAvailability("registry-metadata-too-large-to-read")
	unreachable := explainAvailability("upstream-registry-unreachable")
	if tooLarge == unreachable {
		t.Fatal("the two markers render identically, so splitting them changed nothing a reader can see")
	}
	if !strings.Contains(tooLarge, "answered") || !strings.Contains(tooLarge, "not a connectivity problem") {
		t.Errorf("the too-large explanation must say the registry ANSWERED and that this is not "+
			"connectivity; got: %s", tooLarge)
	}
}
