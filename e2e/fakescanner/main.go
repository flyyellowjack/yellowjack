// Command fake-scorecard stands in for the real OpenSSF `scorecard` binary inside
// the run-once scanner container, so the async local-mode e2e can CHOOSE the scan
// outcome instead of inheriting whatever GitHub happens to do.
//
// It is a drop-in for exactly the invocation scanner/scorecard.go makes:
//
//	scorecard --repo=<host/owner/name> --format=json
//
// writing a Scorecard-shaped JSON report to stdout and exiting 0, or writing a
// message to stderr and exiting non-zero to simulate a repo Scorecard cannot score.
//
// WHY THIS EXISTS — see e2e/fakescanner/README.md for the full account. Short
// version: e2e/async_local.sh used to get its "unscorable" outcome from the real
// scorecard binary FAILING AUTH because CI has no GITHUB_TOKEN. That made the
// required gate green because scanning was broken, and it would have gone red the
// day scanning was fixed. The async contract is about our wiring — firewall ->
// scheduler -> container -> sink -> L2 -> firewall — not about Scorecard's scoring,
// so the third-party binary is the right thing to make deterministic.
//
// Stdlib only, no module dependencies: it is compiled standalone inside the fixture
// image's build stage (see the Dockerfile), not as part of the main module's build.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Behavior is baked into the fixture IMAGE at build time (ARG -> ENV), not passed
// per-run: the scheduler's launchers forward a fixed set of env vars to the scanner
// container (SCANNER_REPO, SCANNER_SINK_URL, GITHUB_TOKEN, the timeout) and nothing
// else, so per-scan configuration is not available to us. The image IS the test
// configuration, which is also why the rig rebuilds it when it wants a different
// score (see the NEGATIVE CONTROL section of the README).
const (
	envScore      = "FAKE_SCORECARD_SCORE"             // aggregate score to report
	envUnscorable = "FAKE_SCORECARD_UNSCORABLE_SUBSTR" // repos containing this fail
	// PARTIAL reports (#133, D271). A repo containing envPartialSubstr gets the shape
	// the real binary produces when checks hit runtime errors: a COMPLETE report on
	// stdout whose named checks carry score -1, AND exit status 1. Both halves matter:
	// the exit code is what used to discard the report, and the -1 by NAME is what the
	// firewall's required-check floor evaluates. envPartialErrored lists the check
	// names to error, comma-separated; every other documented check scores 7.
	envPartialSubstr  = "FAKE_SCORECARD_PARTIAL_SUBSTR"
	envPartialErrored = "FAKE_SCORECARD_PARTIAL_ERRORED"
	// A second partial shape, so one image can exercise BOTH sides of the floor.
	envPartial2Substr  = "FAKE_SCORECARD_PARTIAL2_SUBSTR"
	envPartial2Errored = "FAKE_SCORECARD_PARTIAL2_ERRORED"
)

// scorecardChecks is the 18-check set the real binary emitted on the #133 measurement.
var scorecardChecks = []string{"Binary-Artifacts", "Branch-Protection", "CI-Tests", "CII-Best-Practices",
	"Code-Review", "Contributors", "Dangerous-Workflow", "Dependency-Update-Tool", "Fuzzing", "License",
	"Maintained", "Packaging", "Pinned-Dependencies", "SAST", "Security-Policy", "Signed-Releases",
	"Token-Permissions", "Vulnerabilities"}

type checkOut struct {
	Name   string `json:"name"`
	Score  int    `json:"score"`
	Reason string `json:"reason"`
}

// partialFor returns the errored-check list for this repo, and whether a partial
// shape applies at all.
func partialFor(repo string) ([]string, bool) {
	for _, pair := range [][2]string{{envPartialSubstr, envPartialErrored}, {envPartial2Substr, envPartial2Errored}} {
		if sub := os.Getenv(pair[0]); sub != "" && strings.Contains(repo, sub) {
			var names []string
			for _, n := range strings.Split(os.Getenv(pair[1]), ",") {
				if n = strings.TrimSpace(n); n != "" {
					names = append(names, n)
				}
			}
			return names, true
		}
	}
	return nil, false
}

func main() {
	repo := flag.String("repo", "", "target repo, host/owner/name")
	format := flag.String("format", "", "output format; only json is supported")
	flag.Parse()

	// Fail loudly on an invocation we don't model. If scanner/scorecard.go ever
	// changes its arguments, this fixture must be updated with it — silently
	// ignoring an unknown shape is how a fake starts testing something else.
	if *repo == "" {
		fmt.Fprintln(os.Stderr, "fake-scorecard: --repo is required (invocation changed?)")
		os.Exit(2)
	}
	if *format != "json" {
		fmt.Fprintf(os.Stderr, "fake-scorecard: --format=%q unsupported, expected json (invocation changed?)\n", *format)
		os.Exit(2)
	}

	// The "Scorecard ran but could not score this repo" outcome. The real binary
	// exits non-zero with its reason on stderr (repo gone, auth failure, ...), which
	// scanner/scorecard.go surfaces verbatim; runBackgroundScan then records the
	// durable NEGATIVE MARKER. Reproducing the exit code + stderr shape is all that
	// the firewall's classification actually keys on.
	if sub := os.Getenv(envUnscorable); sub != "" && strings.Contains(*repo, sub) {
		fmt.Fprintf(os.Stderr, "fake-scorecard: cannot score %s (deliberate fixture outcome: repo matches %s=%q)\n", *repo, envUnscorable, sub)
		os.Exit(1)
	}

	score := 9.0
	if v := os.Getenv(envScore); v != "" {
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			// Do NOT fall back to the default: a typo'd score would silently produce
			// a passing run that proves the wrong thing, which is the exact failure
			// mode this fixture was written to remove.
			fmt.Fprintf(os.Stderr, "fake-scorecard: invalid %s=%q: %v\n", envScore, v, err)
			os.Exit(2)
		}
		score = parsed
	}

	// Only the fields scanner/scorecard.go's scorecardJSON actually decodes. The
	// checks list is populated because ScanResult carries it through to the approval
	// DB, so a realistic report exercises that path rather than a null.
	report := struct {
		Date string `json:"date"`
		Repo struct {
			Name   string `json:"name"`
			Commit string `json:"commit"`
		} `json:"repo"`
		Score  float64    `json:"score"`
		Checks []checkOut `json:"checks"`
	}{
		Date:  time.Now().UTC().Format("2006-01-02"),
		Score: score,
	}
	report.Repo.Name = *repo
	report.Repo.Commit = "0000000000000000000000000000000000000000" // fixture: not a real commit

	errored, partial := partialFor(*repo)
	if partial {
		bad := map[string]bool{}
		for _, n := range errored {
			bad[n] = true
		}
		for _, n := range scorecardChecks {
			c := checkOut{Name: n, Score: 7, Reason: "emitted by e2e/fakescanner, not a real Scorecard run"}
			if bad[n] {
				c.Score, c.Reason = -1, "internal error: fixture-errored check (deliberate)"
			}
			report.Checks = append(report.Checks, c)
		}
	} else {
		report.Checks = append(report.Checks, checkOut{Name: "Fixture-Deterministic-Score", Score: int(score), Reason: "emitted by e2e/fakescanner, not a real Scorecard run"})
	}

	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "fake-scorecard: encoding report: %v\n", err)
		os.Exit(2)
	}
	if partial {
		// The real binary's shape: the report is already on stdout, and the exit
		// status says a check errored. scanner/scorecard.go must keep the report.
		fmt.Fprintf(os.Stderr, "fake-scorecard: %d check(s) errored (deliberate fixture outcome: repo matches a PARTIAL substring)\n", len(errored))
		os.Exit(1)
	}
}
