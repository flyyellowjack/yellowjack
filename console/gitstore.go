package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// errNoGitBinary reports that this console IMAGE has no git, which is a different
// problem from a misconfigured repository and has a different fix: a different
// image, not a different setting.
//
// D199 (2026-09-08) ruled that git stays OPT-IN, so the shipped default console is
// distroless/static and has no git. That makes this the COMMON case rather than an
// edge one, and it is exactly why the message matters: before this check, a missing
// binary surfaced through the rev-parse below as
//
//	CONSOLE_LIST_REPO "/lists" is not a git repository: exec: "git": executable
//	file not found in $PATH
//
// which names the wrong thing. The repository is fine. An operator reading that goes
// and re-inits the repo, checks the bind mount, checks ownership -- every one a dead
// end, because no value of CONSOLE_LIST_REPO can fix a missing binary.
var errNoGitBinary = errors.New(
	"this console image ships without git, so it cannot write the operator lists: " +
		"build or pull the console-git image target (docker build --target console-git), " +
		"or leave CONSOLE_LIST_REPO unset to hide the editor. The default image is " +
		"distroless and has no git on purpose (D199) -- git plus a shell in the one " +
		"service holding the operator credential is a footprint we decline by default")

// lookGit reports whether a git binary is runnable. It is a var so a test can
// simulate a git-less image deterministically on any platform; TestGitLookupIsWired
// pins that the default really is exec.LookPath rather than a stub that always
// passes -- an injectable seam that nothing checks is how a detector quietly stops
// detecting.
var lookGit = func() error {
	_, err := exec.LookPath("git")
	return err
}

// gitBinaryAvailable is the question the console asks at startup so /lists can name
// the right remedy even when CONSOLE_LIST_REPO is unset -- the default image's own
// state, where the old message told the operator to set a variable that could not
// have helped.
func gitBinaryAvailable() bool { return lookGit() == nil }

// The git-backed store for the operator lists -- D193's option (c).
//
// D193 chose "console writes to git; replicas read the file" over the two alternatives
// (a second core-owned store, or promoting Postgres into the core) for one reason that
// is worth restating where the code is: it is the only option that lets the UI edit the
// whitelist WITHOUT making the enforcement plane stateful, which D103 forbids. The audit
// trail is not a feature we build here -- it is git log, which already answers who,
// what and when, and answers it in a form an auditor can verify independently of us.
//
// WHAT THIS INCREMENT DOES AND DOES NOT DO. It makes the write durable and audited: the
// console edits its working tree, commits, and pushes. It does NOT distribute the file
// to replicas. A firewall still reads whatever is at FW_ALLOW_LIST / FW_DENY_LIST on its
// own filesystem, and re-reads it every listReloadTTL, so a co-located deployment (the
// console's working tree mounted where the gate reads) works end to end today. Multiple
// replicas pulling from the remote is a separate increment, and it is separate on
// purpose: putting a git pull inside the enforcement plane gives the gate a network
// dependency and a credential, which is a posture change that deserves its own decision
// rather than arriving as a side effect of a UI feature.
//
// Until that lands, this store is honest about it: pushed is reported per write, and the
// page says what has reached the remote rather than implying it has reached the fleet.

// listStore is the seam between the console's handlers and where writes land.
//
// An interface rather than the concrete type so the handler tests do not need a git
// binary, and so D193's fallback -- "(a) a small core-owned store" -- can be dropped in
// without touching the handler if a git round-trip ever proves too slow to feel like a
// UI. That is a real possibility rather than a hypothetical: a push to a remote over a
// slow link happens inside an HTTP request here.
type listStore interface {
	// Load returns the authored list, or an error if it cannot be read or parsed.
	Load(kind string) (*listDoc, error)
	// Apply adds or removes one entry and commits the result.
	Apply(kind, entry, actor string, add bool) (writeResult, error)
	// History returns the most recent commits touching a list, newest first.
	History(kind string, n int) ([]commitLine, error)
	// Describe names where writes go, for the page and the startup log.
	Describe() string
}

// writeResult is what the operator is told about a write.
//
// Every field exists because the alternative is a UI that says "saved" for something
// that did not fully happen. Changed distinguishes a real edit from a no-op; Removed
// carries how many lines went, because removing a package that was not there is not the
// same as removing one that was; Pushed and PushErr separate "committed here" from
// "shared with the fleet", which is exactly the distinction that would otherwise be
// papered over.
type writeResult struct {
	Changed  bool
	Removed  int
	Rev      string
	Pushed   bool
	PushErr  string
	Detail   string
	Entry    string
	Kind     string
	Absent   bool // a remove that matched nothing
	Existing bool // an add of something already listed
}

// commitLine is one row of the audit trail, as git already records it.
type commitLine struct {
	Short   string
	Author  string
	When    string
	Subject string
}

// gitListStore edits list files inside a git working tree.
type gitListStore struct {
	// mu serialises read-modify-write. Two operators with two tabs is the ordinary case,
	// not the exotic one, and without this the second write reads before the first has
	// written and silently drops it.
	mu sync.Mutex

	repo      string            // absolute path to the working tree
	files     map[string]string // kind -> path relative to repo
	ecosystem string
	remote    string // "" => commit locally, do not push

	// timeout bounds every git invocation.
	timeout time.Duration
}

// gitCommandTimeout bounds a single git call.
//
// A constant rather than a knob (#51 is a budget), and it exists for a specific observed
// failure rather than as general caution: a git push that needs a credential HANGS in the
// credential helper rather than failing. On a dev host that is an annoyance; here it is an
// HTTP handler that never returns, holding the console's connection open, with the
// operator watching a spinner. GIT_TERMINAL_PROMPT=0 below stops the prompt and this
// bounds anything else that stalls.
const gitCommandTimeout = 20 * time.Second

// newGitListStore validates the configuration and returns a store, or nil with the
// reason list editing is unavailable.
//
// Returning the REASON rather than a bare nil is what lets the page tell an operator why
// the buttons are missing. "Editing is off" with no explanation is the kind of dead end
// D137 objects to for blocks, and it applies to the operator's own UI as much as to a
// developer's failed install.
func newGitListStore(repo, allowFile, denyFile, ecosystem, remote string) (*gitListStore, error) {
	if repo == "" {
		return nil, errors.New("CONSOLE_LIST_REPO is not set, so the console has nowhere to write list changes")
	}
	if !filepath.IsAbs(repo) {
		// Same reasoning as the gate's absolute-path requirement (#38 / CVE-2025-64726):
		// a relative path resolves against whatever directory the process was launched
		// from, so it is chosen by the launcher rather than by the operator. It matters
		// more here than there, because this path is written to.
		return nil, fmt.Errorf("CONSOLE_LIST_REPO %q must be an absolute path: a relative path is "+
			"chosen by wherever the process was launched rather than by the operator", repo)
	}
	st, err := os.Stat(repo)
	if err != nil {
		return nil, fmt.Errorf("CONSOLE_LIST_REPO %q: %w", repo, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("CONSOLE_LIST_REPO %q is not a directory", repo)
	}
	// Before anything else: a missing binary makes every later check misleading.
	if err := lookGit(); err != nil {
		return nil, fmt.Errorf("%w (%v)", errNoGitBinary, err)
	}
	s := &gitListStore{
		repo:      repo,
		files:     map[string]string{listAllow: allowFile, listDeny: denyFile},
		ecosystem: ecosystem,
		remote:    remote,
		timeout:   gitCommandTimeout,
	}
	for kind, rel := range s.files {
		if rel == "" {
			return nil, fmt.Errorf("no file configured for the %s list", kind)
		}
		// A path escaping the repo would put the console's writes outside the audit
		// trail that is the entire justification for this mechanism.
		if clean := filepath.Clean(rel); filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
			return nil, fmt.Errorf("the %s list path %q must be inside CONSOLE_LIST_REPO", kind, rel)
		}
	}
	if _, err := s.git("rev-parse", "--git-dir"); err != nil {
		return nil, fmt.Errorf("CONSOLE_LIST_REPO %q is not a git repository: %w — the audit trail "+
			"is git history, so a plain directory would give writes no record at all", repo, err)
	}
	return s, nil
}

// git runs one git command in the repo and returns its trimmed stdout.
func (s *gitListStore) git(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	// -c safe.directory is not optional in a container deployment, and the failure it
	// prevents is opaque: when the repo on a bind mount is owned by a different uid than
	// the process, git refuses EVERY command with "detected dubious ownership", so list
	// editing appears broken with an error that says nothing about mounts or users. The
	// check exists to stop a process being tricked into using a repo it did not choose --
	// and here the operator chose it, by name, in CONSOLE_LIST_REPO. Declaring it per
	// invocation rather than writing a global gitconfig keeps the claim scoped to the one
	// path we were pointed at.
	base := []string{"-c", "safe.directory=" + s.repo, "-C", s.repo}
	cmd := exec.CommandContext(ctx, "git", append(base, args...)...)
	cmd.Env = gitEnv()

	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", fmt.Errorf("git %s timed out after %s (a credential prompt or an unreachable "+
			"remote will do this): %s", args[0], s.timeout, strings.TrimSpace(errb.String()))
	}
	if err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// gitEnvPassthrough is the ONLY environment this service forwards to git.
//
// An explicit allowlist rather than os.Environ(), and the reason is issue #38 /
// CVE-2025-64726 rather than tidiness: forwarding the parent environment into a
// subprocess is the CVE's own mechanism. A variable that reached the console -- from an
// orchestrator, an operator's shell, a compromised sibling process -- would otherwise
// reach git, and several of them are arbitrary code execution before any of our controls
// run (LD_PRELOAD, NODE_OPTIONS, and git's own GIT_SSH_COMMAND, GIT_EXTERNAL_DIFF,
// GIT_PROXY_COMMAND, GIT_CONFIG_* -- the last of which can inject config that runs a
// command). scheduler/launcher.go established this pattern for the scanner container;
// this is the same rule applied to the only other subprocess we spawn.
//
// What is here and why: git needs to find its own helpers (PATH), read the deployment's
// git identity and credential helper configuration (HOME and the Windows equivalents),
// and authenticate a push (SSH_AUTH_SOCK for an agent). Nothing else has a reason, and
// notably no GIT_* variable is passed through -- the two we DO want are set below,
// explicitly, rather than inherited.
var gitEnvPassthrough = []string{
	"PATH",
	"HOME",
	"SSH_AUTH_SOCK",
	// Windows equivalents of HOME, needed for the same reasons.
	"USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
	"SystemRoot", "ProgramData", "TEMP", "TMP",
}

// gitEnv builds the subprocess environment.
func gitEnv() []string {
	env := make([]string, 0, len(gitEnvPassthrough)+3)
	for _, k := range gitEnvPassthrough {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	// GIT_TERMINAL_PROMPT=0 turns a credential prompt into an error. Without it a push
	// to a remote needing auth blocks forever inside the credential helper, and the
	// symptom is a console request that never returns rather than a message anyone can
	// act on. GIT_ASKPASS empty and GCM_INTERACTIVE=never close the GUI-prompt routes to
	// the same hang.
	return append(env, "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "GCM_INTERACTIVE=never")
}

func (s *gitListStore) rel(kind string) (string, error) {
	rel, ok := s.files[kind]
	if !ok {
		return "", fmt.Errorf("unknown list %q", kind)
	}
	return rel, nil
}

// Load reads and parses one list file.
//
// A MISSING FILE IS NOT AN ERROR: it is a list nobody has written yet, and the console
// is the thing that will write it. A file that exists but cannot be READ is a different
// matter and is reported, because acting as though an unreadable deny list were empty is
// the fail-open direction.
func (s *gitListStore) Load(kind string) (*listDoc, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked(kind)
}

func (s *gitListStore) loadLocked(kind string) (*listDoc, error) {
	rel, err := s.rel(kind)
	if err != nil {
		return nil, err
	}
	body, err := os.ReadFile(filepath.Join(s.repo, rel))
	switch {
	case errors.Is(err, os.ErrNotExist):
		body = nil
	case err != nil:
		return nil, fmt.Errorf("read %s list %s: %w", kind, rel, err)
	}
	d, err := parseListDoc(kind, rel, s.ecosystem, body)
	if err != nil {
		return nil, err
	}
	if rev, err := s.git("log", "-1", "--format=%H", "--", rel); err == nil {
		d.Rev = rev
	}
	return d, nil
}

// Apply is the read-modify-write, and it is the whole of the write path.
//
// THE ORDER IS THE SAFETY PROPERTY. Every byte written is derived from a read that
// SUCCEEDED and a parse that SUCCEEDED. There is no path through this function that
// writes a file assembled from a failed read, which is the console-side form of the rule
// the gate already keeps: a blanked list must never be the result of a failure. The
// asymmetry is the same one -- a blanked ALLOW list breaks builds, visibly; a blanked
// DENY list serves everything the operator blocked, silently, and that is fail-OPEN.
//
// Emptying a list deliberately is still allowed. An operator may remove the last entry.
// What is not allowed is arriving at an empty file by accident.
func (s *gitListStore) Apply(kind, entry, actor string, add bool) (writeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res := writeResult{Kind: kind, Entry: entry}

	rel, err := s.rel(kind)
	if err != nil {
		return res, err
	}
	if err := validateEntry(s.ecosystem, kind, entry); err != nil {
		return res, err
	}

	// READ. A failure here ends the write; nothing is assembled from a partial read.
	doc, err := s.loadLocked(kind)
	if err != nil {
		return res, err
	}
	before := doc.Count()
	fresh := len(doc.lines) == 0

	// MODIFY.
	var want []string
	if add {
		added, err := doc.add(entry)
		if err != nil {
			return res, err
		}
		if !added {
			res.Existing = true
			res.Detail = fmt.Sprintf("%q is already on the %s list; nothing changed.", entry, kind)
			return res, nil
		}
	} else {
		n := doc.remove(entry)
		res.Removed = n
		if n == 0 {
			res.Absent = true
			res.Detail = fmt.Sprintf("%q was not on the %s list; nothing changed.", entry, kind)
			return res, nil
		}
	}
	if fresh && add {
		// A file the console is creating gets a header explaining the format. A file
		// that already had content does not: it is the operator's, and rewriting the
		// top of it is not ours to do.
		doc.prependHeader(newListFileHeader(kind))
	}
	want = sortedEntries(doc)

	// VERIFY BEFORE WRITING. Render, re-parse the rendered bytes, and check the entry
	// set is what we intended. A writer's success is a claim about work attempted, not
	// about bytes retained, and this is the cheapest place to turn that claim into a
	// measurement -- before it reaches the file the gate reads, rather than after.
	rendered := doc.Render()
	if err := verifyRoundTrip(kind, rel, s.ecosystem, rendered, want); err != nil {
		return res, err
	}

	// WRITE, atomically. os.WriteFile truncates before it writes, so an error partway
	// through leaves a shorter file -- and for the deny list a shorter file is a weaker
	// policy. Temp-file-then-rename means the gate, which is re-reading this path every
	// few seconds, only ever sees a complete file.
	abs := filepath.Join(s.repo, rel)
	if err := writeFileAtomic(abs, rendered); err != nil {
		return res, err
	}
	// `want` is the entry set verifyRoundTrip has just confirmed the written bytes parse
	// back to, so it is the measured count rather than an assumed one.
	after := len(want)
	res.Changed = true

	// COMMIT.
	subject, body := commitMessage(kind, entry, add, res.Removed, actor, before, after)
	if _, err := s.git("add", "--", rel); err != nil {
		return res, fmt.Errorf("the %s list file was updated but could not be staged: %w", kind, err)
	}
	if _, err := s.git(
		"-c", "user.name="+gitIdentityName(actor),
		"-c", "user.email="+gitIdentityEmail(actor),
		"commit", "-m", subject, "-m", body, "--", rel,
	); err != nil {
		return res, fmt.Errorf("the %s list file was updated but the commit failed, so the change "+
			"has no audit record and will not reach the remote: %w", kind, err)
	}
	if rev, err := s.git("rev-parse", "HEAD"); err == nil {
		res.Rev = rev
	}

	// PUSH. A push failure does NOT fail the write: the file is already changed and the
	// commit already exists, so pretending otherwise would be the lie. It is reported
	// instead, because "committed here" and "shared with the fleet" are different states
	// and only one of them is what the operator thinks they clicked.
	if s.remote == "" {
		res.Detail = "Committed locally. No remote is configured, so this change is not shared with other replicas."
		return res, nil
	}
	if _, err := s.git("push", s.remote, "HEAD"); err != nil {
		res.PushErr = err.Error()
		res.Detail = fmt.Sprintf("Committed locally as %s, but the push to %q FAILED. The gate "+
			"reading this working tree will pick the change up; other replicas will not until the "+
			"push succeeds.", shortRev(res.Rev), s.remote)
		return res, nil
	}
	res.Pushed = true
	res.Detail = fmt.Sprintf("Committed as %s and pushed to %q.", shortRev(res.Rev), s.remote)
	return res, nil
}

// History returns recent commits touching a list file -- the audit trail, shown rather
// than merely claimed.
//
// The point of choosing git was that who/what/when comes for free. It only comes for
// free if someone can SEE it without a shell on the console host, so the page renders it.
func (s *gitListStore) History(kind string, n int) ([]commitLine, error) {
	rel, err := s.rel(kind)
	if err != nil {
		return nil, err
	}
	// %x1f is the ASCII unit separator: a commit subject can contain anything, including
	// whatever delimiter looked safe.
	out, err := s.git("log", fmt.Sprintf("-%d", n), "--format=%h%x1f%an%x1f%ar%x1f%s", "--", rel)
	if err != nil {
		return nil, err
	}
	var rows []commitLine
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\x1f")
		if len(f) < 4 {
			continue
		}
		rows = append(rows, commitLine{Short: f[0], Author: f[1], When: f[2], Subject: f[3]})
	}
	return rows, nil
}

func (s *gitListStore) Describe() string {
	remote := s.remote
	if remote == "" {
		remote = "(none — commits stay local)"
	}
	return fmt.Sprintf("git %s, remote %s", s.repo, remote)
}

// verifyRoundTrip re-reads the bytes we are about to write and checks they say what the
// edit meant.
//
// A writer's success is a claim about work attempted, not about bytes retained. This
// turns the claim into a measurement at the cheapest possible point -- before the bytes
// reach the file the gate is re-reading every few seconds, rather than after.
//
// It is a separate function ONLY so it can be given a negative control. A guard of this
// kind is invisible when it works, so "it would catch a damaged render" is a claim that
// needs its own evidence; see TestVerifyRoundTripCatchesADamagedRender.
func verifyRoundTrip(kind, rel, ecosystem string, rendered []byte, want []string) error {
	check, err := parseListDoc(kind, rel, ecosystem, rendered)
	if err != nil {
		return fmt.Errorf("refusing to write: the edited %s list does not parse (%v). The file "+
			"on disk is unchanged", kind, err)
	}
	if got := sortedEntries(check); !sameStrings(got, want) {
		return fmt.Errorf("refusing to write: the rendered %s list does not read back as the "+
			"edit that was made (got %v, want %v). The file on disk is unchanged", kind, got, want)
	}
	return nil
}

// writeFileAtomic writes via a temp file in the same directory and renames.
//
// os.WriteFile opens with O_TRUNC: the old contents are gone BEFORE the new ones are
// written, so a crash or a full disk in between leaves a truncated file. This repo has
// already lost an irreplaceable file to exactly that pattern. Here the file is a policy
// the gate re-reads every few seconds, so a truncated deny list is not just data loss --
// it is a window during which blocked packages are served.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".ylist-*")
	if err != nil {
		return fmt.Errorf("create temp file next to %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename has succeeded

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	// Flush to the device before the rename, so a crash cannot leave a renamed-but-empty
	// file -- the failure this function exists to prevent, arriving by another route.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// commitMessage builds the audit record.
//
// The subject is what shows in git log --oneline; the body carries the facts an auditor
// asks for. The BEFORE and AFTER counts are in it deliberately: a commit that says
// "remove left-pad" and took the list from 40 entries to 0 is a very different event
// from one that took it from 40 to 39, and the diff is the only other place that shows.
func commitMessage(kind, entry string, add bool, removed int, actor string, before, after int) (string, string) {
	verb := "remove"
	if add {
		verb = "add"
	}
	subject := fmt.Sprintf("policy(%s): %s %s", kind, verb, entry)

	var b strings.Builder
	fmt.Fprintf(&b, "Operator %s-list edit made through the Yellow Jack console.\n\n", kind)
	fmt.Fprintf(&b, "actor:   %s\n", displayActor(actor))
	fmt.Fprintf(&b, "action:  %s\n", verb)
	fmt.Fprintf(&b, "entry:   %s\n", entry)
	if !add {
		fmt.Fprintf(&b, "lines:   %d removed\n", removed)
	}
	fmt.Fprintf(&b, "entries: %d -> %d\n", before, after)
	return subject, b.String()
}

// gitIdentityName / gitIdentityEmail put the acting operator into the commit's author
// field, which is what makes git log answer "who" without a second system to consult.
//
// The email is synthetic and uses the reserved .invalid TLD (RFC 2606) so it can never
// resolve to a real mailbox. There is no identity provider here yet -- the console has
// one shared credential (#13 item 2 is still awaiting a project decision) -- so the honest thing is a
// name that says where the claim came from rather than one that looks like a verified
// person.
func gitIdentityName(actor string) string {
	return fmt.Sprintf("%s (Yellow Jack console)", displayActor(actor))
}

func gitIdentityEmail(actor string) string {
	a := displayActor(actor)
	a = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, a)
	return a + "@console.yellowjack.invalid"
}

func displayActor(actor string) string {
	if strings.TrimSpace(actor) == "" {
		// Writes are gated on a configured credential, so this should not happen. If it
		// does, the record says so rather than inventing a name.
		return "unknown-operator"
	}
	return strings.TrimSpace(actor)
}

func shortRev(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
