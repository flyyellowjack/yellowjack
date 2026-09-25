package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusRow is one line of testdata/operator_list_lines.tsv.
//
// The corpus lives at the REPO ROOT rather than under console/testdata, because its
// entire purpose is to be read by two packages that cannot import each other. A copy
// under each would be two files that drift, which is the failure it exists to prevent.
type corpusRow struct {
	GateOK    bool
	ConsoleOK bool
	Ecosystem string
	Line      string
	Note      string
	N         int // 1-based line number in the corpus, for failure messages
}

// corpusPath is relative because `go test ./...` runs each package in its own
// directory. From console/ the corpus is one level up.
const corpusPath = "../testdata/operator_list_lines.tsv"

func loadCorpus(t *testing.T, path string) []corpusRow {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shared corpus %s: %v", path, err)
	}
	var rows []corpusRow
	for i, raw := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(raw), "#") || strings.TrimSpace(raw) == "" {
			continue
		}
		f := strings.Split(raw, "\t")
		if len(f) < 4 {
			t.Fatalf("corpus %s line %d: want at least 4 tab-separated fields, got %d: %q",
				path, i+1, len(f), raw)
		}
		note := ""
		if len(f) > 4 {
			note = f[4]
		}
		rows = append(rows, corpusRow{
			GateOK:    verdict(t, path, i+1, f[0]),
			ConsoleOK: verdict(t, path, i+1, f[1]),
			Ecosystem: f[2],
			// A literal tab cannot survive a tab-separated file, so the corpus spells
			// it \t and it is restored here. That case matters: a tab is one of the
			// two ways "name version" gets typed by mistake.
			Line: strings.ReplaceAll(f[3], `\t`, "\t"),
			Note: note,
			N:    i + 1,
		})
	}
	// Anti-vacuity. A corpus that failed to parse would leave every table test passing
	// over zero rows and reporting green -- the "automation that reports success must
	// itself be verified" rule, and the exact shape of a check that can only print OK.
	if len(rows) < 15 {
		t.Fatalf("corpus %s parsed only %d rows; it is meant to carry the whole accept/reject "+
			"boundary and something has gone wrong with the format", path, len(rows))
	}
	return rows
}

func verdict(t *testing.T, path string, n int, s string) bool {
	t.Helper()
	switch s {
	case "ok":
		return true
	case "bad":
		return false
	}
	t.Fatalf("corpus %s line %d: verdict must be \"ok\" or \"bad\", got %q", path, n, s)
	return false
}

// TestValidateEntryMatchesTheCorpus is the console half of the shared pin.
func TestValidateEntryMatchesTheCorpus(t *testing.T) {
	for _, r := range loadCorpus(t, corpusPath) {
		// The corpus is the DENY boundary: parseOperatorList is called with "deny" on the
		// gate side too. The allow-only rule (a version on an allow line is refused) has its
		// own paired test in each package, because the corpus carries no kind column.
		err := validateEntry(r.Ecosystem, "deny", r.Line)
		if r.ConsoleOK && err != nil {
			t.Errorf("corpus line %d (%s %q): console should ACCEPT it (%s) but got: %v",
				r.N, r.Ecosystem, r.Line, r.Note, err)
		}
		if !r.ConsoleOK && err == nil {
			t.Errorf("corpus line %d (%s %q): console should REJECT it (%s) but it was accepted",
				r.N, r.Ecosystem, r.Line, r.Note)
		}
	}
}

// TestConsoleIsNeverLooserThanTheGate is the property the pair's safety rests on.
//
// It is asserted over the CORPUS COLUMNS rather than over the two implementations,
// because the console cannot import the gate's parser. That makes this test a check on
// the corpus itself: a row saying "the console accepts something the gate rejects" is a
// declaration that we have decided to brick a replica's boot, and it should be
// impossible to write one by accident. The other direction is fine and is used.
func TestConsoleIsNeverLooserThanTheGate(t *testing.T) {
	for _, r := range loadCorpus(t, corpusPath) {
		if r.ConsoleOK && !r.GateOK {
			t.Errorf("corpus line %d (%s %q): the console would write a line the gate REFUSES to "+
				"parse. A replica that restarts on this file does not come up. (%s)",
				r.N, r.Ecosystem, r.Line, r.Note)
		}
	}
}

// TestCorpusCanFailTheValidator is the NEGATIVE CONTROL for the two tests above.
//
// Both of them can only ever print PASS from a caller's point of view, and a validator
// that accepted everything would pass one of them silently if the corpus had no
// rejections in it. So this test runs the corpus against a DELIBERATELY BROKEN
// validator -- one with the version-pin rule removed, which is the single most likely
// way for the real one to drift -- and fails if the corpus does NOT catch it.
//
// Without this, "the corpus pins the parser" is a claim with no evidence behind it.
func TestCorpusCanFailTheValidator(t *testing.T) {
	looseValidate := func(ecosystem, entry string) error {
		// Everything validateEntry does EXCEPT rejectVersionPinEntry.
		if entry == "" {
			return errString("empty")
		}
		if strings.ContainsAny(entry, " \t\r\n") {
			return errString("whitespace")
		}
		if strings.Contains(entry, "#") {
			return errString("comment")
		}
		return nil
	}

	caught := 0
	for _, r := range loadCorpus(t, corpusPath) {
		if !r.ConsoleOK && looseValidate(r.Ecosystem, r.Line) == nil {
			caught++
		}
	}
	if caught == 0 {
		t.Fatal("the corpus did not catch a validator with the version-pin rule removed. " +
			"That means TestValidateEntryMatchesTheCorpus cannot fail for the most likely " +
			"drift, and its green is not evidence of anything.")
	}
	t.Logf("negative control: the corpus catches the pin-less validator on %d rows", caught)
}

type errString string

func (e errString) Error() string { return string(e) }

// --- listDoc: the edit must not damage the file ------------------------------------

// TestEditPreservesCommentsAndOrder is the reason listDoc is line-based.
//
// The comments in an operator's list file are the only record of WHY an entry is there.
// A parse-to-set-and-rewrite edit would delete all of it and the loss would be invisible
// until someone went looking for the reason six months later.
func TestEditPreservesCommentsAndOrder(t *testing.T) {
	const original = `# our deny list
# reviewed 2026-08-01 by security

left-pad          # removed from npm once already
event-stream      # the 2018 incident
`
	d, err := parseListDoc(listDeny, "deny.txt", "npm", []byte(original))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := d.Entries(); len(got) != 2 || got[0] != "left-pad" || got[1] != "event-stream" {
		t.Fatalf("entries = %v, want [left-pad event-stream]", got)
	}

	if added, err := d.add("is-odd"); err != nil || !added {
		t.Fatalf("add: added=%v err=%v", added, err)
	}
	out := string(d.Render())

	for _, want := range []string{
		"# our deny list",
		"# reviewed 2026-08-01 by security",
		"left-pad          # removed from npm once already",
		"event-stream      # the 2018 incident",
		"is-odd",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("edited file lost %q:\n%s", want, out)
		}
	}
	// The header must still be the FIRST thing in the file: appending must not reorder.
	if !strings.HasPrefix(out, "# our deny list\n") {
		t.Errorf("the file no longer starts with its header:\n%s", out)
	}
}

// TestEditKeepsCRLF pins the round-trip that keeps git log -p readable.
//
// The audit trail is the whole justification for choosing git (D193 option (c)). A
// console that rewrote line endings would turn every one-entry change into a
// whole-file diff, and the free audit trail would not be one.
func TestEditKeepsCRLF(t *testing.T) {
	d, err := parseListDoc(listAllow, "allow.txt", "npm", []byte("# hdr\r\nlodash\r\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := d.add("chalk"); err != nil {
		t.Fatalf("add: %v", err)
	}
	got := string(d.Render())
	if want := "# hdr\r\nlodash\r\nchalk\r\n"; got != want {
		t.Errorf("CRLF not preserved:\ngot  %q\nwant %q", got, want)
	}
	if strings.Contains(strings.ReplaceAll(got, "\r\n", ""), "\n") {
		t.Errorf("a bare LF leaked into a CRLF file: %q", got)
	}
}

// TestRemoveTakesEveryCaseVariant: removal is of a policy EFFECT, not of a line.
//
// Two spellings of one package are one entry to the gate. Removing only the line the
// operator clicked would leave the block in force while the console showed it gone --
// the worst available outcome, because they would believe the package was unblocked.
func TestRemoveTakesEveryCaseVariant(t *testing.T) {
	d, err := parseListDoc(listDeny, "deny.txt", "npm", []byte("LoDash\nchalk\nlodash\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if n := d.remove("lodash"); n != 2 {
		t.Fatalf("remove removed %d lines, want 2 (both spellings)", n)
	}
	if got := d.Entries(); len(got) != 1 || got[0] != "chalk" {
		t.Fatalf("entries after remove = %v, want [chalk]", got)
	}
	if n := d.remove("nothing-here"); n != 0 {
		t.Errorf("removing an absent entry reported %d, want 0", n)
	}
}

// TestAddRefusesDuplicateAndBadEntry.
func TestAddRefusesDuplicateAndBadEntry(t *testing.T) {
	d, err := parseListDoc(listAllow, "allow.txt", "npm", []byte("lodash\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if added, err := d.add("LODASH"); err != nil || added {
		t.Errorf("adding a case variant of an existing entry: added=%v err=%v, want added=false", added, err)
	}
	// A version-scoped entry is VALID as of #155/D312 — on an allow list it is how an
	// administrator says which release they judged — so this one is added, not refused.
	if added, err := d.add("lodash@4.17.20"); err != nil || !added {
		t.Errorf("a version-scoped allow entry was refused: added=%v err=%v", added, err)
	}
	// Still malformed in every list, and the refusal half of this test: whitespace is
	// how "name version" gets typed by mistake, and the gate will not start on it.
	if _, err := d.add("lodash 4.17.20"); err == nil {
		t.Error("an entry containing whitespace was accepted; the gate would refuse to start on it")
	}
	if got := d.Count(); got != 2 {
		t.Errorf("count = %d, want 2 (the name, plus the version-scoped entry; the whitespace add refused)", got)
	}
}

// TestParseRefusesAFileTheGateWouldRefuse.
//
// Editing a file we have misread is worse than refusing to edit it: the read-modify-write
// would write back our misreading. And a file with a bad line is one the gate is already
// refusing to boot on, so there is nothing to preserve by being lenient.
func TestParseRefusesAFileTheGateWouldRefuse(t *testing.T) {
	if _, err := parseListDoc(listDeny, "deny.txt", "npm", []byte("lodash 4.17.20\n")); err == nil {
		t.Error("a file with a whitespace line parsed cleanly; the gate refuses to start on it")
	}
	if _, err := parseListDoc(listDeny, "deny.txt", "npm", []byte("requests==2.31.0\n")); err == nil {
		t.Error("a file with a version pin parsed cleanly; the gate refuses to start on it")
	}
	// oci is the documented exception and must still parse.
	if _, err := parseListDoc(listDeny, "deny.txt", "oci", []byte("library/nginx:1.25\n")); err != nil {
		t.Errorf("oci tag rejected, but for oci the reference is part of the identity (D164): %v", err)
	}
}

// TestEmptyFileRoundTrips: a configured-but-empty list is not the same as no list, and
// the empty case is where an off-by-one in the line handling would hide.
func TestEmptyFileRoundTrips(t *testing.T) {
	d, err := parseListDoc(listAllow, "allow.txt", "npm", nil)
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if d.Count() != 0 {
		t.Fatalf("empty file has %d entries", d.Count())
	}
	if got := d.Render(); len(got) != 0 {
		t.Errorf("rendering an untouched empty file produced %q, want nothing", got)
	}
	if _, err := d.add("lodash"); err != nil {
		t.Fatalf("add to empty: %v", err)
	}
	if got, want := string(d.Render()), "lodash\n"; got != want {
		t.Errorf("render = %q, want %q", got, want)
	}
}

// TestCorpusFileIsWhereBothPackagesLookFor it: a guard against someone moving it and
// only fixing one of the two readers.
func TestCorpusFileIsWhereBothPackagesLookForIt(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "testdata", "operator_list_lines.tsv")); err != nil {
		t.Fatalf("the shared corpus is not at the path the firewall's test also uses: %v", err)
	}
}

// TestMixedLineEndingsAreNotNormalised is the regression test for a defect the UNIT
// tests could not have found and the e2e did.
//
// A hand-written fixture is uniform; a real list file is not. It acquires mixed endings
// as soon as two tools touch it -- authored on one host, appended to by a script on
// another, edited by a console in a Linux container. The first renderer chose ONE
// terminator for the whole file, so writing it back rewrote every line that had the
// other one: async_local.sh leg 23 measured +2/-1 for a one-entry add, against a file
// whose fixture lines were CRLF and whose appended line was LF.
//
// That matters beyond tidiness. The audit trail is the entire justification for
// committing to git (D193 option (c)), and an audit trail whose every commit rewrites
// untouched lines is not reviewable.
func TestMixedLineEndingsAreNotNormalised(t *testing.T) {
	// Exactly the shape the e2e hit: CRLF body, one LF line appended by another tool.
	const mixed = "# header\r\nleft-pad\r\nlodash\n"
	d, err := parseListDoc(listDeny, "deny.txt", "npm", []byte(mixed))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Untouched round-trip first: if this is not byte-exact, nothing below means anything.
	if got := string(d.Render()); got != mixed {
		t.Fatalf("an untouched mixed-ending file did not round-trip:\ngot  %q\nwant %q", got, mixed)
	}

	if _, err := d.add("body-parser"); err != nil {
		t.Fatalf("add: %v", err)
	}
	got := string(d.Render())
	// Every pre-existing byte must be unchanged; only the new line is added, and it
	// takes the terminator of the line it follows.
	if want := mixed + "body-parser\n"; got != want {
		t.Errorf("adding one entry rewrote existing lines:\ngot  %q\nwant %q", got, want)
	}
}

// TestFileWithNoTrailingNewlineGainsOneOnlyWhereNeeded.
//
// The other shape that turns a one-line add into a two-line diff: a file whose last line
// has no terminator. Appending after it must give it one -- otherwise two entries are
// glued into a single line and the gate reads a package name nobody typed -- but a file
// nobody appends to must keep its missing newline, or "\ No newline at end of file"
// flips in the diff for no reason.
func TestFileWithNoTrailingNewlineGainsOneOnlyWhereNeeded(t *testing.T) {
	const noTrailing = "left-pad\nlodash"
	d, err := parseListDoc(listDeny, "deny.txt", "npm", []byte(noTrailing))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := string(d.Render()); got != noTrailing {
		t.Fatalf("untouched file did not round-trip:\ngot  %q\nwant %q", got, noTrailing)
	}
	if got := d.Entries(); len(got) != 2 || got[1] != "lodash" {
		t.Fatalf("entries = %v, want [left-pad lodash]", got)
	}

	if _, err := d.add("chalk"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if got, want := string(d.Render()), "left-pad\nlodash\nchalk\n"; got != want {
		t.Errorf("append to a file with no trailing newline:\ngot  %q\nwant %q", got, want)
	}
	// The glued-together failure this prevents, stated as an assertion rather than a hope.
	if strings.Contains(string(d.Render()), "lodashchalk") {
		t.Error("two entries were glued into one line")
	}
}

// TestRemovePreservesTheOtherLinesTerminators.
func TestRemovePreservesTheOtherLinesTerminators(t *testing.T) {
	d, err := parseListDoc(listDeny, "deny.txt", "npm", []byte("a\r\nb\nc\r\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if n := d.remove("b"); n != 1 {
		t.Fatalf("remove removed %d, want 1", n)
	}
	if got, want := string(d.Render()), "a\r\nc\r\n"; got != want {
		t.Errorf("remove disturbed the surviving lines:\ngot  %q\nwant %q", got, want)
	}
}

// TestTheConsoleAndTheGateAgreeOnALLOWGrammar is the console half of the pair whose gate
// half lives in adminoverride_test.go. The shared corpus covers the DENY boundary only
// (both readers are called with "deny" there), and the two kinds now differ: an OCI ALLOW
// may name a digest (#155/D312). Without this pair a console that drifted would author a
// line the gate refuses to start on — the failure the corpus exists to prevent, in the one
// place the corpus cannot see.
func TestTheConsoleAndTheGateAgreeOnALLOWGrammar(t *testing.T) {
	for _, c := range []struct {
		eco, entry string
		ok         bool
	}{
		{"oci", "library/nginx@sha256:" + strings.Repeat("a", 64), true},
		{"oci", "library/nginx:1.25", true},
		{"npm", "lodash@4.17.20", true},
		{"npm", "lodash@", false},
		{"pypi", "requests:2.31.0", false},
	} {
		err := validateEntry(c.eco, "allow", c.entry)
		if c.ok && err != nil {
			t.Errorf("console REFUSED a well-formed allow entry (%s %q): %v", c.eco, c.entry, err)
		}
		if !c.ok && err == nil {
			t.Errorf("console ACCEPTED a malformed allow entry (%s %q)", c.eco, c.entry)
		}
	}
}
