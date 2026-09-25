//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
)

// Tests for the failure-dump window (#75). Pure string handling — no Docker, no network —
// so this runs in milliseconds inside the e2e job that already builds this package.

// buildLog makes an n-line log with `needle` planted at index `at`.
func buildLog(n, at int, needle string) string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf("line %d: routine proxy chatter", i)
	}
	lines[at] = fmt.Sprintf("line %d: %s", at, needle)
	return strings.Join(lines, "\n")
}

// THE POINT OF THE WHOLE CHANGE, and the negative control the issue asked for: an
// interesting line far from the end must appear in the dump. `tail` is asserted to MISS
// it in the same test, so this cannot pass for the wrong reason — if someone reverts
// logAround to a tail, this fails.
func TestLogAroundShowsFailuresFarFromTheEnd(t *testing.T) {
	const needle = "GET guava -> refused"
	log := buildLog(500, 100, needle) // 400 lines of noise after the interesting one

	if strings.Contains(tail(log, 25), needle) {
		t.Fatal("control failed: tail(log, 25) unexpectedly contains a line 400 lines from the end — " +
			"the bug this fixes is not reproduced, so the assertion below proves nothing")
	}
	got := logAround(log, 25, "guava")
	if !strings.Contains(got, needle) {
		t.Errorf("logAround did not include the anchored line:\n%s", got)
	}
	if !strings.Contains(got, "log line 101 of 500") {
		t.Errorf("header does not locate the window in the log:\n%s", strings.SplitN(got, "\n", 2)[0])
	}
}

// When nothing matches, the dump must SAY the failure may be outside the window.
// This is the property that stops "no line about X" being read as "X never happened".
func TestLogAroundFallbackSaysAbsenceProvesNothing(t *testing.T) {
	got := logAround(buildLog(500, 100, "irrelevant"), 25, "guava", "commons-lang")

	if !strings.Contains(got, "MAY BE OUTSIDE THIS WINDOW") {
		t.Errorf("fallback does not warn that the window may miss the failure:\n%s", got)
	}
	if !strings.Contains(got, "absence here is not evidence") {
		t.Errorf("fallback does not say absence proves nothing:\n%s", got)
	}
	// The anchors it looked for must be named, or a reader cannot tell what was searched.
	if !strings.Contains(got, `"guava"`) || !strings.Contains(got, `"commons-lang"`) {
		t.Errorf("fallback does not name the anchors it tried:\n%s", got)
	}
	if strings.Contains(got, "lines around") {
		t.Errorf("fallback is mislabelled as an anchored window:\n%s", got)
	}
}

// A log that fits is shown whole and labelled as such — no truncation, and no ambiguity
// about whether something was cut.
func TestLogAroundShortLogShownWhole(t *testing.T) {
	log := buildLog(10, 3, "GET guava -> refused")
	got := logAround(log, 25, "nothing-matches-this")

	if !strings.Contains(got, "full log (10 lines)") {
		t.Errorf("a log shorter than the window was not labelled as complete:\n%s", got)
	}
	if !strings.Contains(got, "line 0:") || !strings.Contains(got, "line 9:") {
		t.Errorf("full-log dump dropped lines:\n%s", got)
	}
	// It must NOT warn about a window it did not truncate.
	if strings.Contains(got, "MAY BE OUTSIDE") {
		t.Errorf("a complete log was labelled as possibly missing the failure:\n%s", got)
	}
}

// The LAST match wins: a package fetched repeatedly should anchor on the occurrence
// nearest the failure, not the first one hundreds of lines earlier.
func TestLogAroundAnchorsOnLastMatch(t *testing.T) {
	lines := make([]string, 300)
	for i := range lines {
		lines[i] = fmt.Sprintf("line %d: chatter", i)
	}
	lines[10] = "line 10: GET guava -> allowed"
	lines[250] = "line 250: GET guava -> refused"

	got := logAround(strings.Join(lines, "\n"), 20, "guava")
	if !strings.Contains(got, "GET guava -> refused") {
		t.Errorf("did not anchor on the LAST match:\n%s", got)
	}
	if strings.Contains(got, "GET guava -> allowed") {
		t.Errorf("anchored on the first match instead of the last:\n%s", got)
	}
}

// Windows near either end must stay inside the log and still be full width, rather than
// silently returning fewer lines than asked for.
func TestLogAroundClampsAtBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   int
	}{
		{"first line", 0},
		{"last line", 199},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := logAround(buildLog(200, tc.at, "needle-here"), 20, "needle-here")
			if !strings.Contains(got, "needle-here") {
				t.Errorf("anchored line missing at boundary:\n%s", got)
			}
			if n := strings.Count(got, "\n"); n < 20 {
				t.Errorf("window shrank at the boundary: %d body lines, want 20", n)
			}
		})
	}
}

// mvnFailedArtifacts is what turns a Maven failure into an anchored dump, so it is
// exercised against the REAL text from the #68 failure rather than an invented sample —
// an anchor extractor that silently matches nothing would put us straight back to a
// bare tail while looking like it worked.
func TestMvnFailedArtifactsParsesRealOutput(t *testing.T) {
	out := `[INFO] Scanning for projects...
[ERROR] Failed to execute goal org.apache.maven.plugins:maven-dependency-plugin:2.8:get (default-cli):
[ERROR] Failed to read artifact descriptor for commons-lang:commons-lang:jar:2.4
[ERROR] Failed to read artifact descriptor for org.apache.velocity:velocity-tools:jar:2.0
[ERROR] Failed to read artifact descriptor for commons-lang:commons-lang:jar:2.4
[INFO] BUILD FAILURE`

	got := mvnFailedArtifacts(out)
	want := []string{"commons-lang", "velocity-tools"}
	if len(got) != len(want) {
		t.Fatalf("mvnFailedArtifacts = %v, want %v (duplicates must collapse)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mvnFailedArtifacts[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMvnFailedArtifactsNoMatches(t *testing.T) {
	if got := mvnFailedArtifacts("[INFO] BUILD SUCCESS"); len(got) != 0 {
		t.Errorf("mvnFailedArtifacts invented anchors from clean output: %v", got)
	}
}

func TestLogAroundEmptyLog(t *testing.T) {
	if got := logAround("", 25, "guava"); !strings.Contains(got, "EMPTY") {
		t.Errorf("an empty log must say so rather than looking like a window: %q", got)
	}
}
