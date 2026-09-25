package main

import (
	"os"
	"strings"
	"testing"
)

// The GATE half of the shared line corpus (issue #58 increment 3b).
//
// testdata/operator_list_lines.tsv is read by two packages that cannot import each
// other: this one, whose parseOperatorList decides whether the firewall will START on a
// list file, and console/liststore.go, whose validateEntry decides whether the console
// will WRITE a line into one.
//
// Why that pair needs pinning, in one sentence: if the console accepts something this
// parser rejects, the console can author a file that a RESTARTING replica refuses to
// boot on -- the console bricking the gate through the gate's own safety check, at a
// time nobody chose. The corpus makes that a test failure instead of an incident.
//
// This test asserts the "gate" column. console/liststore_test.go asserts the "console"
// column and the one-way property (console accepts => gate accepts) that keeps the pair
// safe, and carries a negative control proving the corpus can fail.

const gateCorpusPath = "testdata/operator_list_lines.tsv"

type gateCorpusRow struct {
	gateOK    bool
	consoleOK bool
	ecosystem string
	line      string
	note      string
	n         int
}

func loadGateCorpus(t *testing.T) []gateCorpusRow {
	t.Helper()
	b, err := os.ReadFile(gateCorpusPath)
	if err != nil {
		t.Fatalf("read shared corpus %s: %v", gateCorpusPath, err)
	}
	var rows []gateCorpusRow
	for i, raw := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		f := strings.Split(raw, "\t")
		if len(f) < 4 {
			t.Fatalf("corpus line %d: want at least 4 tab-separated fields, got %d: %q", i+1, len(f), raw)
		}
		note := ""
		if len(f) > 4 {
			note = f[4]
		}
		rows = append(rows, gateCorpusRow{
			gateOK:    f[0] == "ok",
			consoleOK: f[1] == "ok",
			ecosystem: f[2],
			// A literal tab cannot survive a tab-separated file, so it is spelled \t.
			line: strings.ReplaceAll(f[3], `\t`, "\t"),
			note: note,
			n:    i + 1,
		})
	}
	// Anti-vacuity: a corpus that silently failed to parse would leave the table tests
	// below passing over zero rows and printing green.
	if len(rows) < 15 {
		t.Fatalf("corpus parsed only %d rows; the format has broken", len(rows))
	}
	return rows
}

// TestParseOperatorListMatchesTheCorpus runs each corpus line through the real parser,
// as a one-line file.
func TestParseOperatorListMatchesTheCorpus(t *testing.T) {
	for _, r := range loadGateCorpus(t) {
		_, err := parseOperatorList("deny", r.ecosystem, strings.NewReader(r.line+"\n"))
		if r.gateOK && err != nil {
			t.Errorf("corpus line %d (%s %q): the gate should ACCEPT it (%s) but got: %v",
				r.n, r.ecosystem, r.line, r.note, err)
		}
		if !r.gateOK && err == nil {
			t.Errorf("corpus line %d (%s %q): the gate should REJECT it (%s) but the file parsed",
				r.n, r.ecosystem, r.line, r.note)
		}
	}
}

// TestCorpusActuallyExercisesBothDirections is the structural anti-vacuity check.
//
// Three ways this corpus could rot into a test that cannot fail, all of which have a
// green table test as their symptom:
//
//  1. every row is "ok", so nothing pins a REJECTION -- the case that matters, because
//     an over-permissive parser is the one that lets a bad line reach a replica's boot;
//  2. every row is "bad", so nothing pins an ACCEPTANCE and a parser that refused
//     everything would pass;
//  3. the two verdict columns are identical everywhere, which would mean the corpus is
//     one column wearing two headings and the console/gate ASYMMETRY -- the whole reason
//     for the second column -- is not being exercised at all.
//
// The third is the one that would happen by accident, when someone adds rows and copies
// the first column across without thinking about it.
func TestCorpusActuallyExercisesBothDirections(t *testing.T) {
	rows := loadGateCorpus(t)
	var gateOK, gateBad, differ int
	for _, r := range rows {
		if r.gateOK {
			gateOK++
		} else {
			gateBad++
		}
		if r.gateOK != r.consoleOK {
			differ++
		}
	}
	if gateOK == 0 {
		t.Error("no corpus row is accepted by the gate: a parser that refused everything would pass")
	}
	if gateBad == 0 {
		t.Error("no corpus row is rejected by the gate: a parser that accepted everything would pass")
	}
	if differ == 0 {
		t.Error("the gate and console columns agree on every row, so the deliberate asymmetry " +
			"(a comment line is legal in a FILE but is not an ENTRY) is not being pinned")
	}
	t.Logf("corpus: %d accepted, %d rejected, %d rows where console and gate deliberately differ",
		gateOK, gateBad, differ)
}
