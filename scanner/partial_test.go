package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// The scorecard stdout that started #133, and the wire shape it must produce.
// Shared with scheduler/ and the firewall root package so all three hops are
// pinned against ONE artifact rather than three lookalike literals.
//
// The fixtures are the real 2026-09-15 measurement with the FORGE HOST DEFANGED to
// gitlab.example (scripts/fixture-hygiene.sh, issue #46: a fixture must not name
// anything resolvable). The real repo was gitlab.com/gitlab-org/gitlab-runner and
// is named in the prose below, because what was measured is a fact about that repo;
// the host is not load-bearing for anything asserted here — these tests count
// checks, they verify nothing against the forge — so it is defanged rather than
// added to e2e/fixture-hosts.txt.
const (
	partialStdoutPath = "../testdata/scorecard_partial_stdout.json"
	partialWirePath   = "../testdata/scanresult_partial_wire.json"
)

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", path, err)
	}
	return b
}

// TestScanSalvagesAUsableReportFromANonZeroExit is #133's first acceptance box.
//
// Scorecard exits NON-ZERO whenever any single check hits a runtime error, while
// still writing a complete, valid JSON report to stdout. Measured 2026-09-15 on
// scorecard v5.2.1 against the real gitlab.com/gitlab-org/gitlab-runner with no
// credential: exit=1, score 4.8, all 18 checks present, 7 errored with HTTP 401. The
// old execRunner.run returned `nil, err` there, so a usable report became
// "scan failed" -> unscorable -> a blocked install under the default policy.
//
// The fixture is that measurement. This is NOT a GitLab-only shape: one transient
// GitHub 5xx inside one check produces it on github.com too.
func TestScanSalvagesAUsableReportFromANonZeroExit(t *testing.T) {
	raw := readFixture(t, partialStdoutPath)
	exit1 := errors.New("exit status 1: 7 checks returned an error")

	got, err := scan(context.Background(), &fakeRunner{out: raw, err: exit1}, "gitlab.example/gitlab-org/gitlab-runner")
	if err != nil {
		t.Fatalf("a non-zero exit carrying a complete report must be SALVAGED, not discarded (#133); got error: %v", err)
	}
	if got.Score != 4.8 || got.Repo != "gitlab.example/gitlab-org/gitlab-runner" {
		t.Errorf("salvaged score/repo = %v/%q, want 4.8/gitlab.example/gitlab-org/gitlab-runner", got.Score, got.Repo)
	}
	if got.ScoredChecks != 11 || got.TotalChecks != 18 {
		t.Errorf("coverage = %d of %d, want 11 of 18 — the counts are what make this report legible "+
			"downstream instead of indistinguishable from a full one", got.ScoredChecks, got.TotalChecks)
	}
	if !got.Partial() {
		t.Error("a report with 7 errored checks must report Partial(), or the firewall will compare its " +
			"subset score to FW_SCORE_THRESHOLD as though it were a full measurement")
	}
}

// TestNothingUsableStillFails is the negative control #133's fourth box requires,
// and it is the half that keeps the salvage honest. Each case below is a non-zero
// exit whose stdout is NOT a Scorecard report; every one must fail exactly as it
// did before, with Scorecard's own reason.
//
// The empty case is measured, not invented: with no credential at all, Scorecard
// refuses github.com outright and writes NO STDOUT WHATSOEVER, where gitlab.com
// degraded to the partial report above. The two forges fail differently, which is
// precisely why salvaging on "the process wrote something" would be wrong.
//
// `{}` and `{"checks":[]}` matter most. Both are valid JSON, so a salvage keyed
// only on parseability would promote them into a score of 0.0 over 0 checks — a
// hard block on a package nobody measured, which is worse than the availability
// bug being fixed here.
func TestNothingUsableStillFails(t *testing.T) {
	exit1 := errors.New("exit status 1: scorecard: repo unreachable")
	for _, tc := range []struct {
		name   string
		stdout string
	}{
		{"no stdout at all (measured: github.com with no token)", ""},
		{"not JSON (an error page or a panic trace)", "FATAL: could not resolve repo\n"},
		{"truncated mid-document", `{"repo":{"name":"github.com/a/b"},"checks":[{"name":"Fuzz`},
		{"valid JSON, no report in it", `{}`},
		{"a report shell with no checks", `{"repo":{"name":"github.com/a/b"},"score":0,"checks":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := scan(context.Background(), &fakeRunner{out: []byte(tc.stdout), err: exit1}, "github.com/a/b")
			if err == nil {
				t.Fatal("stdout carrying no usable report must still be a failed scan; salvaging it would " +
					"invent a score for a repo nothing measured")
			}
			if !strings.Contains(err.Error(), "repo unreachable") {
				t.Errorf("the failure must keep Scorecard's OWN reason so an operator debugging it sees what "+
					"the binary said; got %q", err.Error())
			}
		})
	}
}

// TestCoverageIsCountedRegardlessOfExitStatus pins the decision NOT to tie coverage
// to the exit code.
//
// If Scorecard ever exits zero with an errored check, that report's aggregate is
// computed over a subset just as much as a salvaged one's, and is just as
// incomparable to FW_SCORE_THRESHOLD. Keying the counts off the exit status would
// put the trust back in the signal whose unreliability caused #133 in the first
// place. The pre-existing sampleScorecardJSON is exactly this shape — 2 checks, one
// at -1, returned with a nil error — so it was ALREADY a partial score being
// compared to the threshold, silently, before this change.
func TestCoverageIsCountedRegardlessOfExitStatus(t *testing.T) {
	got, err := scan(context.Background(), &fakeRunner{out: []byte(sampleScorecardJSON)}, "github.com/example/pkg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ScoredChecks != 1 || got.TotalChecks != 2 {
		t.Fatalf("coverage = %d of %d, want 1 of 2", got.ScoredChecks, got.TotalChecks)
	}
	if !got.Partial() {
		t.Error("a zero-exit report with an errored check is still a subset score and must say so")
	}

	// And a complete report is not partial, whatever the exit status was. This is the
	// case where salvage genuinely CHANGES the verdict — from unscorable to a real
	// score — and it is sound precisely because nothing was excluded from the
	// aggregate.
	full := `{"repo":{"name":"github.com/a/b"},"score":7.5,"checks":[
	  {"name":"License","score":10,"reason":"ok"},{"name":"SAST","score":5,"reason":"ok"}]}`
	got, err = scan(context.Background(), &fakeRunner{out: []byte(full), err: errors.New("exit status 1: warning")}, "github.com/a/b")
	if err != nil {
		t.Fatalf("a COMPLETE report from a non-zero exit is usable: %v", err)
	}
	if got.Partial() || got.ScoredChecks != 2 || got.TotalChecks != 2 {
		t.Errorf("a report where every check scored must not be partial; got %d of %d, partial=%v",
			got.ScoredChecks, got.TotalChecks, got.Partial())
	}
}

// TestTheWireShapeMatchesTheFixtureEveryHopReads is the scanner's end of the
// cross-boundary agreement.
//
// THE RISK IT ADDRESSES: `scoredChecks`/`totalChecks` cross two HTTP boundaries into
// two independently-owned DTOs, and "total" is exactly the kind of denominator that
// quietly changes meaning in transit — a ratio whose denominator is computed in
// another component is a ratio nobody can defend. The three hops are pinned against
// ONE fixture rather than three lookalike struct literals, so a rename or a
// re-derivation on any hop fails somebody's test.
//
// Its siblings are TestSchedulerReadsTheSameCoverageTheScannerWrote (scheduler) and
// TestFirewallReadsTheSameCoverageTheScannerWrote (root package). All three read
// ../testdata/scanresult_partial_wire.json.
func TestTheWireShapeMatchesTheFixtureEveryHopReads(t *testing.T) {
	got, err := scan(context.Background(), &fakeRunner{out: readFixture(t, partialStdoutPath),
		err: errors.New("exit status 1")}, "gitlab.example/gitlab-org/gitlab-runner")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var produced, fixture map[string]any
	if err := json.Unmarshal(encoded, &produced); err != nil {
		t.Fatalf("unmarshal produced: %v", err)
	}
	if err := json.Unmarshal(readFixture(t, partialWirePath), &fixture); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	for _, field := range []string{"scoredChecks", "totalChecks", "score", "repo"} {
		if produced[field] != fixture[field] {
			t.Errorf("field %q: scanner emits %v, the shared fixture says %v. Either the scanner changed "+
				"what it counts or the fixture is stale — and the downstream hops read the FIXTURE, so they "+
				"would go on agreeing with each other while disagreeing with the scanner",
				field, produced[field], fixture[field])
		}
	}
}
