package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// scorecardRunner runs OpenSSF Scorecard against a repo and returns its raw JSON
// output. It's an interface purely so tests (and later, alternative backends) can
// supply output without invoking the real binary.
type scorecardRunner interface {
	run(ctx context.Context, repo string) ([]byte, error)
}

// execRunner runs the real `scorecard` binary as a subprocess. We shell out to
// the binary rather than importing Scorecard as a Go library on purpose: it keeps
// Scorecard's large dependency tree out of our own binary (and therefore out of
// our attack surface — this is security software), and keeps the license boundary
// clean. If we ever want in-process embedding, only this type changes; the
// service's HTTP contract stays the same.
type execRunner struct {
	bin   string
	token string
}

func (e *execRunner) run(ctx context.Context, repo string) ([]byte, error) {
	// --repo takes host/owner/name (e.g. github.com/openssf/scorecard); --format=json
	// makes Scorecard write a machine-readable report to stdout.
	cmd := exec.CommandContext(ctx, e.bin, "--repo="+repo, "--format=json")
	cmd.Env = append(os.Environ(), "GITHUB_AUTH_TOKEN="+e.token)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// ⚠️ RETURN STDOUT ANYWAY (#133). Scorecard exits NON-ZERO whenever any single
		// check hits a runtime error, while still writing a complete, valid JSON report
		// to stdout. Measured 2026-09-15 on scorecard v5.2.1: --repo=gitlab.com/
		// gitlab-org/gitlab-runner with no credential gave exit=1, score 4.8, all 18
		// checks present and parseable, 7 of them errored. This function used to return
		// `nil, err` there, so a perfectly usable report became "scan failed" -> the
		// unscorable verdict -> a blocked install under the default policy. It is not
		// GitLab-specific: a transient GitHub 5xx inside one check produces the same
		// shape on github.com.
		//
		// Deciding whether the bytes are a report is the PARSING layer's job, not this
		// one's, so both are returned and scan() adjudicates. The error text is still
		// Scorecard's own, so a genuinely failed run reports the same reason it always
		// did.
		return stdout.Bytes(), fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// ScanResult is our cleaned-up view of a Scorecard run: the aggregate score plus
// the full per-check breakdown. We deliberately keep every check (not just the
// score), because the reasons behind a low score are what a human reviewer — and
// later the package->project knowledge base — actually need.
type ScanResult struct {
	Repo   string        `json:"repo"`
	Score  float64       `json:"score"`
	Commit string        `json:"commit,omitempty"`
	Date   string        `json:"date,omitempty"`
	Checks []CheckResult `json:"checks"`

	// COVERAGE (#133). Scorecard EXCLUDES an errored check from its aggregate rather
	// than zeroing it, so a report where 7 checks errored has its Score computed over
	// the other 11 — and that number is NOT comparable to a full run's. Comparing it
	// to FW_SCORE_THRESHOLD silently changes what the threshold means. Carrying the
	// two counts is what makes a partial run legible downstream instead of
	// indistinguishable from a complete one.
	//
	// ⚠️ WHAT THE DENOMINATOR IS. TotalChecks is the number of checks PRESENT IN THIS
	// REPORT — not a constant 18, and not "the checks Scorecard knows about". A
	// future Scorecard release that adds or retires a check changes it, which is the
	// correct behaviour: the question downstream needs answered is "what fraction of
	// what this run attempted actually produced a number?". Every hop that copies
	// these fields must mean the same thing by them, which is asserted end-to-end
	// rather than trusted (TestCoverageCountsSurviveEveryHop) — a ratio whose
	// denominator is computed in another component is a ratio nobody can defend.
	ScoredChecks int `json:"scoredChecks"`
	TotalChecks  int `json:"totalChecks"`
}

// Partial reports whether this result's Score was computed over fewer checks than
// the run emitted, which makes it incomparable to a full score. Deliberately a
// method rather than a stored bool: one derivation, no field that can disagree with
// the counts it summarises.
//
// TotalChecks == 0 is NOT partial. An empty report is a different failure and is
// rejected in scan() before it can reach here.
func (r ScanResult) Partial() bool {
	return r.TotalChecks > 0 && r.ScoredChecks < r.TotalChecks
}

// CheckResult is one Scorecard check. Score is 0-10, or -1 when Scorecard could
// not evaluate the check (e.g. an internal error or missing data).
type CheckResult struct {
	Name   string `json:"name"`
	Score  int    `json:"score"`
	Reason string `json:"reason"`
}

// scorecardJSON models the subset of Scorecard's --format=json output we consume.
// We decode only the fields we use, so new/renamed fields upstream don't break us.
type scorecardJSON struct {
	Date string `json:"date"`
	Repo struct {
		Name   string `json:"name"`
		Commit string `json:"commit"`
	} `json:"repo"`
	Score  float64 `json:"score"`
	Checks []struct {
		Name   string `json:"name"`
		Score  int    `json:"score"`
		Reason string `json:"reason"`
	} `json:"checks"`
}

// scan runs Scorecard via the runner and maps its output into a ScanResult.
func scan(ctx context.Context, runner scorecardRunner, repo string) (ScanResult, error) {
	raw, err := runner.run(ctx, repo)

	var sc scorecardJSON
	parseErr := json.Unmarshal(raw, &sc)

	// SALVAGE (#133). A non-zero exit is not by itself a statement that nothing
	// usable came back — see execRunner.run. Keep the run only if the bytes really
	// are a Scorecard report: valid JSON AND carrying at least one check. The second
	// half is what stops `{}`, `null`, an HTML error page that happens to parse, or a
	// truncated document from being promoted into a score of 0.0 over 0 checks, which
	// would be far worse than the availability bug this fixes.
	//
	// Measured shape of the "nothing usable" case (2026-09-15): with no credential at
	// all, Scorecard refuses github.com outright and writes NO STDOUT WHATSOEVER,
	// where gitlab.com degrades to a partial report. So both branches below are real
	// and observed, not defensive guesses.
	if err != nil {
		if parseErr != nil || len(sc.Checks) == 0 {
			return ScanResult{}, err // unchanged: today's failure, today's reason
		}
	} else if parseErr != nil {
		return ScanResult{}, fmt.Errorf("parsing scorecard output: %w", parseErr)
	}

	result := ScanResult{
		Repo:   sc.Repo.Name,
		Score:  sc.Score,
		Commit: sc.Repo.Commit,
		Date:   sc.Date,
	}
	// Fall back to the requested repo if Scorecard didn't echo one back.
	if result.Repo == "" {
		result.Repo = repo
	}
	for _, c := range sc.Checks {
		result.Checks = append(result.Checks, CheckResult{Name: c.Name, Score: c.Score, Reason: c.Reason})
		// A check Scorecard could not evaluate carries -1, per CheckResult's contract.
		// Counted here rather than by the consumer so exactly one component decides
		// what "scored" means.
		if c.Score >= 0 {
			result.ScoredChecks++
		}
	}
	result.TotalChecks = len(sc.Checks)

	// The counts are computed for EVERY run, not only a salvaged one. If Scorecard
	// ever exits zero with an errored check, that report is just as incomparable as a
	// salvaged one and must be just as visible — tying coverage to the exit status
	// would make the exit status the thing we trust, which is the defect being fixed.
	if err != nil {
		log.Printf("scan %s: scorecard exited non-zero but wrote a usable report (%d of %d checks scored); "+
			"salvaged rather than discarded (#133). Its error was: %v", result.Repo, result.ScoredChecks, result.TotalChecks, err)
	}
	return result, nil
}
