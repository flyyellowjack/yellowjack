package main

import (
	"fmt"
	"sort"
	"strings"
)

// The coverage floor for a PARTIAL Scorecard report (#133, D271).
//
// Scorecard exits non-zero when any one check hits a runtime error, and still writes a
// complete report whose aggregate EXCLUDES the errored checks. The scanner salvages that
// report (#133 box 1) and carries the counts through, and until this file every partial
// report was refused as unscorable, because an 11-of-18 score is computed over a different
// denominator from the one FW_SCORE_THRESHOLD was set against.
//
// D271 ruled the floor's shape, and ruled out the obvious one: a COUNT of checks cannot be
// the floor, because Scorecard's checks are not interchangeable. Losing Dangerous-Workflow
// and Token-Permissions is not the same event as losing License and CI-Tests, and no
// threshold expressed as "N of 18" can tell them apart. So:
//
//	A partial report is a real score if and only if every check on a NAMED REQUIRED SET
//	scored. If any required check errored, the report is UNSCORABLE, and the refusal
//	names the check.
//
// The default set is derived from Scorecard's OWN documented risk levels, not from an
// impression of them: docs/checks/internal/checks.yaml in the ossf/scorecard tree carries
// a `risk:` per check, and the default is every check it marks Critical or High (read
// 2026-09-21; 20 checks documented, 10 at those two levels). An operator can widen or
// narrow it with FW_SCORECARD_REQUIRED_CHECKS.

// defaultRequiredChecks is Scorecard's Critical and High risk checks, in its own names.
var defaultRequiredChecks = []string{
	"Dangerous-Workflow", // Critical
	"Webhooks",           // Critical
	"Binary-Artifacts",   // High
	"Branch-Protection",  // High
	"Code-Review",        // High
	"Dependency-Update-Tool",
	"Maintained",
	"Signed-Releases",
	"Token-Permissions",
	"Vulnerabilities",
}

// parseRequiredChecks turns the knob's value into a set. Empty means the default. The
// literal "none" disables the floor: every partial report is then accepted on its
// aggregate, which is the operator saying they know what the score means. Names are
// matched exactly as Scorecard spells them, because a check name that does not exist
// would otherwise be a required check that can never error and never protect.
func parseRequiredChecks(v string) map[string]bool {
	set := map[string]bool{}
	v = strings.TrimSpace(v)
	if strings.EqualFold(v, "none") {
		return set
	}
	names := defaultRequiredChecks
	if v != "" {
		names = strings.Split(v, ",")
	}
	for _, n := range names {
		if n = strings.TrimSpace(n); n != "" {
			set[n] = true
		}
	}
	return set
}

// missingRequiredChecks returns, sorted, the required checks that errored in this
// report. A report that lists no checks at all reports nothing missing: it predates the
// per-check fields or the scanner sent none, and "no information" must not read as "the
// required checks failed" (the same reason Partial() treats TotalChecks == 0 as complete).
func missingRequiredChecks(required map[string]bool, checks []scannerCheck) []string {
	var missing []string
	for _, c := range checks {
		if c.Score < 0 && required[c.Name] {
			missing = append(missing, c.Name)
		}
	}
	sort.Strings(missing)
	return missing
}

// erroredCheckNames lists every check that did not score, for the log line that says a
// partial report was accepted: an operator must be able to see WHICH low-weight checks a
// passing score was computed without.
func erroredCheckNames(checks []scannerCheck) []string {
	var names []string
	for _, c := range checks {
		if c.Score < 0 {
			names = append(names, c.Name)
		}
	}
	sort.Strings(names)
	return names
}

// scoreCoverage is the part of a report that says what its score MEANS: the aggregate
// was computed over ScoredChecks of TotalChecks, without the checks named. It travels
// with the score to the L2 cache so a partial score that passed the floor is legible
// wherever the number is later shown (#133's second acceptance box, on the far side of
// the scanner). A full report has ScoredChecks == TotalChecks and nothing in
// ComputedWithout; an older scanner's reply has zeros, which reads as "unknown", not
// as "partial".
type scoreCoverage struct {
	ScoredChecks    int
	TotalChecks     int
	ComputedWithout []string
}

func coverageOf(sr scannerResponse) scoreCoverage {
	return scoreCoverage{ScoredChecks: sr.ScoredChecks, TotalChecks: sr.TotalChecks, ComputedWithout: erroredCheckNames(sr.Checks)}
}

// partialReportVerdict decides what the firewall does with a partial report: nil means
// the aggregate may be compared to the threshold; an error means unscorable, with the
// operator-legible reason. It is the ONE place the floor is evaluated.
//
// A nil required set means "the default", never "no floor": a hand-built &Firewall{}
// literal (every unit test builds one) must get the same floor a configured gate does,
// or a test could pass on a floor that production does not have. Disabling is an explicit
// "none" in the knob, which parses to an EMPTY, non-nil set.
func partialReportVerdict(repo string, sr scannerResponse, required map[string]bool, threshold float64) error {
	if !sr.Partial() {
		return nil
	}
	if required == nil {
		required = parseRequiredChecks("")
	}
	if len(sr.Checks) == 0 && len(required) > 0 {
		// Counts say partial, but the reply carries no per-check names to evaluate
		// the floor against (an older scanner in a rolling deploy). Refusing is the
		// pre-D271 behaviour, and the honest one: the floor cannot be checked.
		return fmt.Errorf("scanner: partial report for %s: only %d of %d checks scored (%.1f) and the reply names no "+
			"checks, so the required-check floor cannot be evaluated; treated as unscorable (#133)",
			repo, sr.ScoredChecks, sr.TotalChecks, sr.Score)
	}
	if missing := missingRequiredChecks(required, sr.Checks); len(missing) > 0 {
		return fmt.Errorf("scanner: partial report for %s: required check(s) %s did not run, so its %.1f is "+
			"NOT comparable to FW_SCORE_THRESHOLD (%.1f); treated as unscorable (%d of %d checks scored; "+
			"FW_SCORECARD_REQUIRED_CHECKS names the set)",
			repo, strings.Join(missing, ", "), sr.Score, threshold, sr.ScoredChecks, sr.TotalChecks)
	}
	return nil
}
