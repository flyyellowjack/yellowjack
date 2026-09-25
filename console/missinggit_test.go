package main

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// A console image with no git is not a misconfigured console. D199 (2026-09-08)
// ruled that git stays OPT-IN, which makes the git-less image the SHIPPED DEFAULT
// and therefore the common case -- so the message an operator gets there has to
// name the real remedy.
//
// Before this, it did not. newGitListStore validated the repository by running
// `git rev-parse --git-dir`, so a missing binary surfaced as
//
//	CONSOLE_LIST_REPO "/lists" is not a git repository: exec: "git": executable
//	file not found in $PATH
//
// The repository was fine. That message sends an operator to re-init the repo,
// check the bind mount and check ownership -- three dead ends, because no value of
// CONSOLE_LIST_REPO can supply a binary. Same family as the reason-vs-status
// lessons elsewhere in this tree: the STATUS was right (editing is off) and the
// REASON named the wrong subject.

// stubGitMissing makes the process look like the distroless console image.
func stubGitMissing(t *testing.T) {
	t.Helper()
	prev := lookGit
	lookGit = func() error { return errors.New(`exec: "git": executable file not found in $PATH`) }
	t.Cleanup(func() { lookGit = prev })
}

func gitOnThisMachine(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed here, so the git-present control cannot run")
	}
}

func TestMissingGitBinaryNamesTheImageNotTheRepository(t *testing.T) {
	gitOnThisMachine(t) // the repo fixture itself needs git
	repo := newTestRepo(t)
	stubGitMissing(t)

	_, err := newGitListStore(repo, "allow.txt", "deny.txt", "npm", "")
	if err == nil {
		t.Fatal("a console with no git accepted a list store; editing would fail later, at the write")
	}
	if !errors.Is(err, errNoGitBinary) {
		t.Fatalf("want errNoGitBinary, got %v", err)
	}

	msg := err.Error()
	// The remedy has to be nameable. "Something is wrong" is what we already had.
	if !strings.Contains(msg, "console-git") {
		t.Errorf("the message never names the fix (the console-git image target):\n  %s", msg)
	}
	// The regression guard: the OLD message blamed the repository, which is the one
	// thing that is definitely not the problem here.
	if strings.Contains(msg, "is not a git repository") {
		t.Errorf("the message still blames the repository, which is intact:\n  %s", msg)
	}
}

// TestGitPresentStillDiagnosesANonRepository is the negative control for the check
// above. A new branch that returns early is also a branch that can SWALLOW the
// diagnosis it was added beside: if every failure now reported "no git binary", an
// operator with a genuinely wrong CONSOLE_LIST_REPO would be sent to rebuild an
// image that was never the problem -- the same defect, pointing the other way.
func TestGitPresentStillDiagnosesANonRepository(t *testing.T) {
	gitOnThisMachine(t)
	plain := t.TempDir() // a directory, deliberately NOT a git repository

	_, err := newGitListStore(plain, "allow.txt", "deny.txt", "npm", "")
	if err == nil {
		t.Fatal("a plain directory was accepted as a list store, so writes would have no audit trail")
	}
	if errors.Is(err, errNoGitBinary) {
		t.Fatalf("git IS present, but the missing-binary branch claimed this failure: %v", err)
	}
	if !strings.Contains(err.Error(), "is not a git repository") {
		t.Errorf("the real diagnosis was lost; want it to still name the repository:\n  %s", err)
	}
}

// TestGitLookupIsWiredToTheRealLookPath is anti-vacuity for the seam itself.
// lookGit is a var so a test can simulate a git-less image on any platform, but an
// injectable seam that nothing pins is how a detector quietly stops detecting: a
// future edit could leave it returning nil forever and every test above would still
// pass, because they all install their own stub.
func TestGitLookupIsWiredToTheRealLookPath(t *testing.T) {
	_, want := exec.LookPath("git")
	got := lookGit()

	if (want == nil) != (got == nil) {
		t.Fatalf("lookGit disagrees with exec.LookPath: lookGit=%v, LookPath=%v", got, want)
	}
	if want == nil && !gitBinaryAvailable() {
		t.Error("git is on PATH but gitBinaryAvailable() says otherwise")
	}
	if want != nil && gitBinaryAvailable() {
		t.Error("git is NOT on PATH but gitBinaryAvailable() says it is")
	}

	// The agreement check above cannot catch a lookGit hard-wired to return nil, because
	// on a machine that HAS git the two agree by luck. Emptying PATH removes that luck: a
	// real lookup must now fail, a constant one cannot.
	t.Setenv("PATH", "")
	if err := lookGit(); err == nil {
		t.Error("lookGit succeeded with an empty PATH, so it is not really looking anything up")
	}
	if gitBinaryAvailable() {
		t.Error("gitBinaryAvailable() is true with an empty PATH")
	}
}

// TestListsPageNamesTheRightRemedyForEachState drives the real handler and asserts
// the three states give three DIFFERENT answers. Ordering is the substance: a
// missing binary has to outrank an unset repository, because on the default image
// "set CONSOLE_LIST_REPO" is advice that cannot work.
func TestListsPageNamesTheRightRemedyForEachState(t *testing.T) {
	gitOnThisMachine(t)

	cases := []struct {
		name        string
		gitMissing  bool
		store       listStore
		user        string
		wantPhrase  string
		wantAbsent  string
		description string
	}{
		{
			name:        "no git binary, repo unset",
			gitMissing:  true,
			store:       nil,
			user:        "admin",
			wantPhrase:  "console-git",
			wantAbsent:  "set CONSOLE_LIST_REPO to a git working tree",
			description: "the shipped default image: naming the variable here is the original bug",
		},
		{
			name:        "no git binary, repo SET anyway",
			gitMissing:  true,
			store:       &fakeListStore{},
			user:        "admin",
			wantPhrase:  "console-git",
			wantAbsent:  "read-only",
			description: "configuring the variable must not hide the real blocker",
		},
		{
			name:        "git present, repo unset",
			gitMissing:  false,
			store:       nil,
			user:        "admin",
			wantPhrase:  "set CONSOLE_LIST_REPO",
			wantAbsent:  "console-git",
			description: "here, and only here, the variable really is the fix",
		},
		{
			name:        "git present, repo set, no credential",
			gitMissing:  false,
			store:       &fakeListStore{},
			user:        "",
			wantPhrase:  "CONSOLE_AUTH_USER",
			wantAbsent:  "console-git",
			description: "auth is the blocker and neither of the other two messages applies",
		},
	}

	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := listsServer(t, tc.store, tc.user, nil)
			s.gitMissing = tc.gitMissing

			body := getLists(t, s)
			if !strings.Contains(body, tc.wantPhrase) {
				t.Errorf("%s\n  want the page to contain %q\n  it did not", tc.description, tc.wantPhrase)
			}
			if strings.Contains(body, tc.wantAbsent) {
				t.Errorf("%s\n  the page also said %q, which is the wrong remedy for this state",
					tc.description, tc.wantAbsent)
			}
			seen[tc.wantPhrase] = true
		})
	}

	// The classifier must be able to DISAGREE. Three distinct remedies had better be
	// reachable, or this table is asserting one message four times.
	if len(seen) < 3 {
		t.Errorf("only %d distinct remedies were reached; the states are not being told apart", len(seen))
	}
}
