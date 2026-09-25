package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests drive a REAL git binary against a real repository in a temp dir.
//
// Faking git here would test the wrong thing. The reason D193 chose git is that the
// audit trail comes from git rather than from us, so what needs proving is that a commit
// actually lands, carries the operator's name, and is findable afterwards -- none of
// which a fake can tell us. golang:1.26 (the CI image for unit-tests) ships git.

// newTestRepo makes an initialised repository and returns its path.
func newTestRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		// Deliberately a failure, not a skip. A skipped test reports green, and this
		// package's whole write path is untested without it -- the "automation that
		// reports success must itself be verified" rule applies to skips most of all.
		t.Fatalf("git is not on PATH; the console's write path cannot be tested without it: %v", err)
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	run("init", "-b", "main")
	// Local config only, so a developer's global signing key or identity is neither
	// required nor used by the fixture.
	run("config", "user.name", "fixture")
	run("config", "user.email", "fixture@example.invalid")
	run("config", "commit.gpgsign", "false")
	return dir
}

func newTestStore(t *testing.T, repo string) *gitListStore {
	t.Helper()
	s, err := newGitListStore(repo, "allow.txt", "deny.txt", "npm", "")
	if err != nil {
		t.Fatalf("newGitListStore: %v", err)
	}
	return s
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestApplyCommitsAndTheAuditTrailNamesTheOperator.
//
// This is the increment's central claim: an edit made in the console becomes a git
// commit that says who made it. If that is not true, the mechanism chosen in D193 has
// bought nothing over writing a file.
func TestApplyCommitsAndTheAuditTrailNamesTheOperator(t *testing.T) {
	repo := newTestRepo(t)
	s := newTestStore(t, repo)

	res, err := s.Apply(listDeny, "left-pad", "alice", true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Changed {
		t.Fatal("Apply reported no change for a fresh add")
	}
	if res.Rev == "" {
		t.Error("no revision recorded, so the operator has no handle for the change")
	}

	body := readFile(t, filepath.Join(repo, "deny.txt"))
	if !strings.Contains(body, "left-pad") {
		t.Errorf("the entry is not in the file:\n%s", body)
	}
	if !strings.Contains(body, "# Yellow Jack operator deny-list.") {
		t.Errorf("a newly created file did not get its explanatory header:\n%s", body)
	}

	// The file must be readable by the GATE's parser shape: no whitespace lines, no pins.
	// (The parser itself lives in another package; the corpus pins the rules. Here we
	// only assert the console did not invent a format.)
	for i, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		if e, ok := entryOnLine(line); ok {
			if err := validateEntry("npm", "deny", e); err != nil {
				t.Errorf("line %d of the written file is not a valid entry (%q): %v", i+1, e, err)
			}
		}
	}

	hist, err := s.History(listDeny, 5)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 1 {
		t.Fatalf("history has %d commits, want 1", len(hist))
	}
	if !strings.Contains(hist[0].Author, "alice") {
		t.Errorf("the commit author %q does not name the operator who acted", hist[0].Author)
	}
	if want := "policy(deny): add left-pad"; hist[0].Subject != want {
		t.Errorf("subject = %q, want %q", hist[0].Subject, want)
	}

	// The body carries the facts an auditor asks for.
	out, err := s.git("log", "-1", "--format=%B")
	if err != nil {
		t.Fatalf("git log: %v", err)
	}
	for _, want := range []string{"actor:   alice", "action:  add", "entry:   left-pad", "entries: 0 -> 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("the commit body is missing %q:\n%s", want, out)
		}
	}
}

// TestNoCommitWhenNothingChanged: a no-op must not manufacture history.
//
// An audit trail full of "add left-pad" commits that changed nothing is an audit trail
// nobody reads, and the reason D193's mechanism is worth anything is that someone reads it.
func TestNoCommitWhenNothingChanged(t *testing.T) {
	repo := newTestRepo(t)
	s := newTestStore(t, repo)

	if _, err := s.Apply(listAllow, "lodash", "alice", true); err != nil {
		t.Fatalf("first add: %v", err)
	}
	res, err := s.Apply(listAllow, "LODASH", "bob", true)
	if err != nil {
		t.Fatalf("duplicate add: %v", err)
	}
	if res.Changed {
		t.Error("adding an existing entry (differing only in case) reported a change")
	}
	if !res.Existing {
		t.Error("the result does not say the entry was already there, so the operator is told nothing")
	}

	res, err = s.Apply(listAllow, "never-added", "bob", false)
	if err != nil {
		t.Fatalf("remove absent: %v", err)
	}
	if res.Changed || !res.Absent {
		t.Errorf("removing an absent entry: Changed=%v Absent=%v, want false/true", res.Changed, res.Absent)
	}

	hist, err := s.History(listAllow, 10)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 1 {
		t.Errorf("history has %d commits after one real edit and two no-ops, want 1", len(hist))
	}
}

// TestApplyRefusesToEditAnUnparseableFileAndLeavesItAlone.
//
// This is the console-side form of "never blank the list from a failed read". A file we
// cannot parse is one we have not understood, and a read-modify-write on a misread file
// writes back the misreading. For the deny list that is the fail-OPEN direction, so the
// assertion is not just that Apply errors -- it is that the bytes on disk are untouched.
func TestApplyRefusesToEditAnUnparseableFileAndLeavesItAlone(t *testing.T) {
	repo := newTestRepo(t)
	s := newTestStore(t, repo)

	const bad = "left-pad\nlodash 4.17.20\nevent-stream\n"
	path := filepath.Join(repo, "deny.txt")
	if err := os.WriteFile(path, []byte(bad), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, err := s.Apply(listDeny, "is-odd", "alice", true); err == nil {
		t.Fatal("Apply edited a file the gate refuses to parse")
	}
	if got := readFile(t, path); got != bad {
		t.Errorf("the unparseable file was modified:\ngot  %q\nwant %q", got, bad)
	}

	// And the same for a remove, which is the direction that weakens policy.
	if _, err := s.Apply(listDeny, "left-pad", "alice", false); err == nil {
		t.Fatal("Apply removed an entry from a file it could not parse")
	}
	if got := readFile(t, path); got != bad {
		t.Errorf("the unparseable file was modified by a remove:\ngot  %q\nwant %q", got, bad)
	}
}

// TestRemovingTheLastEntryIsAllowed: emptying a list on purpose is a legitimate act.
//
// The never-blank rule is about arriving at empty by ACCIDENT. Conflating the two would
// leave an operator unable to undo their own last entry, which is the kind of "safety"
// that gets a product routed around.
func TestRemovingTheLastEntryIsAllowed(t *testing.T) {
	repo := newTestRepo(t)
	s := newTestStore(t, repo)

	if _, err := s.Apply(listDeny, "left-pad", "alice", true); err != nil {
		t.Fatalf("add: %v", err)
	}
	res, err := s.Apply(listDeny, "left-pad", "alice", false)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !res.Changed || res.Removed != 1 {
		t.Errorf("remove: Changed=%v Removed=%d, want true/1", res.Changed, res.Removed)
	}
	doc, err := s.Load(listDeny)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if doc.Count() != 0 {
		t.Errorf("list still has %d entries after removing the only one", doc.Count())
	}
	// The header survives: the file is empty of entries, not empty of meaning.
	if body := readFile(t, filepath.Join(repo, "deny.txt")); !strings.Contains(body, "# Yellow Jack") {
		t.Errorf("the file lost its header when it lost its last entry:\n%q", body)
	}
}

// TestVerifyRoundTripCatchesADamagedRender is the NEGATIVE CONTROL for the pre-write guard.
//
// The guard in Apply is invisible when it works: every passing test would pass with it
// deleted. So it is proven able to fail here, against a render that has dropped an entry
// -- the exact damage it exists to catch, and the one that matters, because a dropped
// entry on the DENY list is a package silently served.
func TestVerifyRoundTripCatchesADamagedRender(t *testing.T) {
	want := []string{"chalk", "left-pad"}

	// The healthy case: the guard must PASS, or its failure below proves nothing.
	if err := verifyRoundTrip(listDeny, "deny.txt", "npm", []byte("left-pad\nchalk\n"), want); err != nil {
		t.Fatalf("the guard rejected a correct render, so it cannot be trusted to accept one: %v", err)
	}

	// The damaged case: an entry silently missing from the bytes about to be written.
	err := verifyRoundTrip(listDeny, "deny.txt", "npm", []byte("left-pad\n"), want)
	if err == nil {
		t.Fatal("the guard accepted a render that had lost an entry; it would not catch a " +
			"truncated deny list, which is the fail-open direction")
	}
	if !strings.Contains(err.Error(), "unchanged") {
		t.Errorf("the refusal does not tell the operator the file on disk is untouched: %v", err)
	}

	// And a render that does not parse at all.
	if err := verifyRoundTrip(listDeny, "deny.txt", "npm", []byte("left pad\n"), want); err == nil {
		t.Fatal("the guard accepted a render the gate could not parse")
	}
}

// TestWriteFileAtomicLeavesNoDebris.
//
// The temp-file-then-rename exists because os.WriteFile truncates first: a failure partway
// leaves a SHORTER file, and a shorter deny list is a weaker policy on a file the gate
// re-reads every few seconds. This checks the happy path is complete and tidy; the
// truncation it prevents is not reproducible portably, which is why the reasoning is
// recorded at the function rather than only here.
func TestWriteFileAtomicLeavesNoDebris(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "deny.txt")
	if err := writeFileAtomic(path, []byte("left-pad\n")); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	if got := readFile(t, path); got != "left-pad\n" {
		t.Errorf("content = %q", got)
	}
	if err := writeFileAtomic(path, []byte("left-pad\nchalk\n")); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if got := readFile(t, path); got != "left-pad\nchalk\n" {
		t.Errorf("content after rewrite = %q", got)
	}
	ents, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".ylist-") {
			t.Errorf("a temp file was left behind: %s", e.Name())
		}
	}
}

// TestStoreRefusesAPathOutsideTheRepo: a write outside the repository would be a write
// outside the audit trail, which is the entire justification for this mechanism.
func TestStoreRefusesAPathOutsideTheRepo(t *testing.T) {
	repo := newTestRepo(t)
	if _, err := newGitListStore(repo, "../escape.txt", "deny.txt", "npm", ""); err == nil {
		t.Error("a list path escaping the repo was accepted")
	}
	if _, err := newGitListStore("relative/path", "allow.txt", "deny.txt", "npm", ""); err == nil {
		t.Error("a relative CONSOLE_LIST_REPO was accepted; it is chosen by the launcher, not the operator")
	}
	if _, err := newGitListStore(t.TempDir(), "allow.txt", "deny.txt", "npm", ""); err == nil {
		t.Error("a plain directory that is not a git repository was accepted, so writes would have no record")
	}
}

// TestCommentsSurviveARealCommit: the round-trip that matters for the audit trail, all
// the way through git rather than only through listDoc.
func TestCommentsSurviveARealCommit(t *testing.T) {
	repo := newTestRepo(t)
	s := newTestStore(t, repo)
	path := filepath.Join(repo, "deny.txt")

	const seeded = "# reviewed 2026-08-01 by security\nleft-pad   # the 2016 unpublish\n"
	if err := os.WriteFile(path, []byte(seeded), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// The seed must be COMMITTED before the assertion below means anything. Against an
	// untracked file the console's commit is the file's first, so the whole file reads
	// as added and a +1/-0 check would be measuring the wrong thing -- it would pass for
	// a console that rewrote every line.
	for _, args := range [][]string{{"add", "--", "deny.txt"}, {"commit", "-m", "seed"}} {
		if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("seed commit: %v: %s", err, out)
		}
	}
	if _, err := s.Apply(listDeny, "event-stream", "alice", true); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	body := readFile(t, path)
	for _, want := range []string{
		"# reviewed 2026-08-01 by security",
		"left-pad   # the 2016 unpublish",
		"event-stream",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the commit lost %q:\n%s", want, body)
		}
	}
	// A file that already had content must NOT acquire the generated header: it is the
	// operator's file, and rewriting the top of it is not ours to do.
	if strings.Contains(body, "# Yellow Jack operator") {
		t.Errorf("the console prepended its own header to an operator-authored file:\n%s", body)
	}

	// The diff for a one-entry change must be a one-line diff, or `git log -p` is not
	// the readable audit trail the mechanism was chosen for.
	diff, err := s.git("show", "--format=", "--unified=0", "HEAD")
	if err != nil {
		t.Fatalf("git show: %v", err)
	}
	added, removed := 0, 0
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "+++"), strings.HasPrefix(line, "---"):
		case strings.HasPrefix(line, "+"):
			added++
		case strings.HasPrefix(line, "-"):
			removed++
		}
	}
	if added != 1 || removed != 0 {
		t.Errorf("a one-entry add produced +%d/-%d lines; the audit diff is not readable:\n%s",
			added, removed, diff)
	}
}

// TestGitEnvDoesNotForwardTheParentEnvironment (issue #38 / CVE-2025-64726).
//
// The console spawns git. Forwarding its own environment into that subprocess is the
// CVE's mechanism: a variable that reached this process reaches git, and several are
// arbitrary code execution before any of our controls run. configsurface_test.go catches
// a literal os.Environ() in this file at the SOURCE level; this catches the same mistake
// made a different way -- a passthrough list that quietly grew, or a helper that merged
// the parent env back in.
//
// The positive half is not decoration: an allowlist that forwarded NOTHING would pass the
// negative assertions while breaking every push, so PATH is asserted present.
func TestGitEnvDoesNotForwardTheParentEnvironment(t *testing.T) {
	// Names chosen because each is a real pre-execution hook rather than a placeholder:
	// two loader hooks, and two git-specific ones that run a command of the setter's
	// choosing.
	for _, danger := range []string{"LD_PRELOAD", "NODE_OPTIONS", "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF"} {
		t.Setenv(danger, "/tmp/attacker-controlled")
	}
	t.Setenv("PATH", os.Getenv("PATH"))

	env := gitEnv()
	seen := map[string]string{}
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			seen[kv[:i]] = kv[i+1:]
		}
	}

	for _, danger := range []string{"LD_PRELOAD", "NODE_OPTIONS", "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF"} {
		if v, ok := seen[danger]; ok {
			t.Errorf("%s=%q was forwarded to git; a variable set on the console becomes code "+
				"execution inside the subprocess", danger, v)
		}
	}
	if _, ok := seen["PATH"]; !ok {
		t.Error("PATH was not forwarded, so git cannot find its own helpers — an allowlist that " +
			"passes nothing would satisfy the assertions above while breaking every push")
	}
	if seen["GIT_TERMINAL_PROMPT"] != "0" {
		t.Errorf("GIT_TERMINAL_PROMPT=%q, want \"0\" — without it a push needing a credential "+
			"hangs in the helper and the console request never returns", seen["GIT_TERMINAL_PROMPT"])
	}
}
