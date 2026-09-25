package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// This file exists because a sabotage PASSED.
//
// #133's fix has two halves: execRunner.run must stop throwing stdout away on a
// non-zero exit, and scan() must decide whether those bytes are a usable report.
// Every other test in this package drives scan() through fakeRunner — which
// returns (out, err) directly and never touches execRunner. So restoring the
// original `return nil, err` in execRunner.run reddened NOTHING: the half of the
// fix that actually reads the subprocess had no test that could reach it.
//
// A sabotage that breaks no test does not mean the code is robust; it can mean the
// property is structurally unreachable from the suite. These tests close that,
// by running a real subprocess.
//
// THE MECHANISM. The test binary re-executes ITSELF as the "scorecard" binary
// (TestMain below intercepts before the testing flag parser sees execRunner's
// --repo/--format arguments, which would otherwise be a flag error). That keeps it
// portable across the Windows dev host and the Linux CI image with no shell script,
// no temp executable and no build step.

const (
	fakeExitEnv   = "YJ_FAKE_SCORECARD_EXIT"
	fakeStdoutEnv = "YJ_FAKE_SCORECARD_STDOUT"
	fakeStderrEnv = "YJ_FAKE_SCORECARD_STDERR"
)

func TestMain(m *testing.M) {
	if code, impersonating := os.LookupEnv(fakeExitEnv); impersonating {
		fmt.Fprint(os.Stdout, os.Getenv(fakeStdoutEnv))
		fmt.Fprint(os.Stderr, os.Getenv(fakeStderrEnv))
		n, err := strconv.Atoi(code)
		if err != nil {
			n = 99
		}
		os.Exit(n)
	}
	os.Exit(m.Run())
}

// fakeScorecard returns an execRunner whose "binary" is this test process, set up
// to write the given stdout/stderr and exit with the given code.
func fakeScorecard(t *testing.T, exit int, stdout, stderr string) *execRunner {
	t.Helper()
	t.Setenv(fakeExitEnv, strconv.Itoa(exit))
	t.Setenv(fakeStdoutEnv, stdout)
	t.Setenv(fakeStderrEnv, stderr)
	// execRunner.run builds its child env from os.Environ(), so t.Setenv reaches it.
	return &execRunner{bin: os.Args[0]}
}

// TestExecRunnerKeepsStdoutOnANonZeroExit is the direct test of the half the
// sabotage exposed as unreachable. Measured shape (2026-09-15, scorecard v5.2.1
// against the real gitlab.com/gitlab-org/gitlab-runner with no credential): exit=1,
// a complete 18-check JSON report on stdout, diagnostics on stderr. The literals
// below are defanged to gitlab.example; the measurement was against the real repo.
func TestExecRunnerKeepsStdoutOnANonZeroExit(t *testing.T) {
	const report = `{"repo":{"name":"gitlab.example/a/b"},"score":4.8,"checks":[{"name":"License","score":10}]}`
	r := fakeScorecard(t, 1, report, "7 checks returned an error")

	out, err := r.run(context.Background(), "gitlab.example/a/b")
	if err == nil {
		t.Fatal("a non-zero exit must still be reported as an error — scan() decides whether the bytes " +
			"are usable, and it can only do that if it is told the process failed")
	}
	if string(out) != report {
		t.Fatalf("execRunner discarded the report a failed run wrote (#133). got %q, want the full report.\n"+
			"This is the exact defect: one errored check makes scorecard exit non-zero, and throwing stdout "+
			"away turns a usable score into an unscorable verdict and a blocked install", string(out))
	}
	if !strings.Contains(err.Error(), "7 checks returned an error") {
		t.Errorf("the error must carry scorecard's OWN stderr so an operator sees what the binary said; got %v", err)
	}
}

// TestExecRunnerOnACleanRunIsUnchanged is the control. Without it the assertion
// above is also satisfied by a runner that returns stdout and an error for
// everything, including a perfectly good scan.
func TestExecRunnerOnACleanRunIsUnchanged(t *testing.T) {
	const report = `{"repo":{"name":"github.com/a/b"},"score":7.5,"checks":[{"name":"License","score":10}]}`
	r := fakeScorecard(t, 0, report, "")

	out, err := r.run(context.Background(), "github.com/a/b")
	if err != nil {
		t.Fatalf("a zero-exit run must return no error; got %v", err)
	}
	if string(out) != report {
		t.Errorf("clean-run stdout = %q, want the full report", string(out))
	}
}

// TestExecRunnerReturnsNothingWhenTheProcessWroteNothing pins the measured "nothing
// usable" case end to end through a real subprocess: with no credential at all,
// scorecard refuses github.com outright and writes NO STDOUT WHATSOEVER. scan()
// must fail here, and it must fail for scorecard's own reason.
func TestExecRunnerReturnsNothingWhenTheProcessWroteNothing(t *testing.T) {
	r := fakeScorecard(t, 1, "", "scorecard: GITHUB_AUTH_TOKEN is required")

	out, err := r.run(context.Background(), "github.com/a/b")
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(out) != 0 {
		t.Errorf("expected no stdout, got %q", string(out))
	}
	if _, serr := scan(context.Background(), r, "github.com/a/b"); serr == nil {
		t.Fatal("a run that wrote no stdout must remain a FAILED scan — salvaging it would invent a score " +
			"for a repo nothing measured")
	} else if !strings.Contains(serr.Error(), "GITHUB_AUTH_TOKEN is required") {
		t.Errorf("the failure lost scorecard's reason: %v", serr)
	}
}

// TestScanSalvagesThroughTheRealRunner is the whole path in one: a real subprocess
// exits non-zero with the measured 18-check partial report, and scan() salvages it
// with the right coverage. The other salvage tests prove scan()'s logic; this one
// proves it is WIRED to the runner that actually reads a process, which is the
// thing fakeRunner cannot show.
func TestScanSalvagesThroughTheRealRunner(t *testing.T) {
	raw := readFixture(t, partialStdoutPath)
	r := fakeScorecard(t, 1, string(raw), "7 checks returned an error")

	got, err := scan(context.Background(), r, "gitlab.example/gitlab-org/gitlab-runner")
	if err != nil {
		t.Fatalf("the salvage does not survive the real runner: %v", err)
	}
	if got.ScoredChecks != 11 || got.TotalChecks != 18 || !got.Partial() {
		t.Errorf("coverage through the real runner = %d of %d (partial=%v), want 11 of 18 partial",
			got.ScoredChecks, got.TotalChecks, got.Partial())
	}
}
