package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// This file asserts the security invariant behind issue #38:
//
//	Yellow Jack reads configuration from the process environment only. It does not
//	read, discover, or execute any file from the current working directory, the
//	request path, or any location influenced by a client or by inspected content.
//
// WHY IT IS ASSERTED RATHER THAN ASSUMED. CVE-2025-64726: a competing package
// firewall (sfw, < 0.15.5) discovered a per-project .sfw.config out of the directory
// it was pointed at and populated those values into a subprocess environment, so
// NODE_OPTIONS=--require … executed attacker-controlled code BEFORE the tool's
// controls activated. The security tool became the attack surface, and the gate
// could not catch it because the payload ran first.
//
// We are on the right side of this by construction — env-only config, stateless,
// a server that is pointed at rather than a wrapper run in a developer's cwd. But
// that has been a property of how we happen to be written, not something that fails
// when it stops being true. Someone adding a convenience .yellowjack.yml loader
// would get a green suite and it would look like a feature.

// TestConfigIgnoresWorkingDirectory is the behavioural half: seed a working
// directory with every config-looking filename an attacker might plant — including
// the exact one from the CVE — and prove the loaded Config is byte-identical to one
// loaded from an empty directory.
func TestConfigIgnoresWorkingDirectory(t *testing.T) {
	// Pin the environment so the comparison isolates the FILESYSTEM as the only
	// variable. Without this, an FW_* var set by the surrounding shell could make
	// both sides equal for the wrong reason.
	for _, k := range []string{
		"FW_ECOSYSTEM", "FW_UPSTREAM", "FW_SCORE_THRESHOLD", "FW_SCORECARD_MODE",
		"FW_UNSCORABLE_POLICY", "FW_VERIFY_REPO", "FW_BYTE_GATE", "FW_PUBLIC_URL",
	} {
		t.Setenv(k, "")
	}

	clean := t.TempDir()
	seeded := t.TempDir()

	// Each of these would be a plausible discovery target, and each carries a payload
	// that would be visible in the resulting Config if it were ever read.
	planted := map[string]string{
		".sfw.config":      `{"NODE_OPTIONS":"--require /tmp/evil.js","FW_SCORE_THRESHOLD":"0"}`, // the CVE's own filename
		".yellowjack.yml":  "score_threshold: 0\nbyte_gate: off\nunscorable_policy: allow\n",
		"yellowjack.yml":   "score_threshold: 0\n",
		".yellowjack.json": `{"FW_SCORE_THRESHOLD":"0","FW_BYTE_GATE":"off"}`,
		"config.json":      `{"FW_SCORE_THRESHOLD":"0"}`,
		".env":             "FW_SCORE_THRESHOLD=0\nFW_BYTE_GATE=off\nFW_UNSCORABLE_POLICY=allow\n",
		"yellowjack.conf":  "FW_SCORE_THRESHOLD=0\n",
	}
	for name, body := range planted {
		if err := os.WriteFile(filepath.Join(seeded, name), []byte(body), 0o600); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	// Returns the ERROR as well as the Config, deliberately. A planted file that made
	// loadConfig fail would be just as much a breach of the invariant as one that
	// changed a value — and if this helper aborted on error instead, the test would
	// report "not a number" rather than "the working directory influenced config".
	// That is not hypothetical: it is what the negative control for this test did on
	// the first run.
	loadIn := func(dir string) (Config, error) {
		t.Helper()
		prev, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		if err := os.Chdir(dir); err != nil {
			t.Fatalf("chdir %s: %v", dir, err)
		}
		defer func() { _ = os.Chdir(prev) }()
		return loadConfig()
	}

	// CLEAN FIRST, and the order is load-bearing. The CVE's mechanism is a loader that
	// populates ENVIRONMENT VARIABLES from the discovered file, and os.Setenv is
	// process-wide — so a seeded load that leaked into the process would contaminate a
	// subsequent clean load and make the two agree for the worst possible reason. Read
	// the uncontaminated baseline before anything has had the chance to plant.
	want, wantErr := loadIn(clean)
	got, gotErr := loadIn(seeded)

	if (gotErr == nil) != (wantErr == nil) {
		t.Fatalf("CONFIG LOADING WAS INFLUENCED BY THE WORKING DIRECTORY — this is CVE-2025-64726's shape.\n"+
			"in a seeded dir: err=%v\nin an empty dir: err=%v", gotErr, wantErr)
	}
	if gotErr != nil {
		t.Fatalf("loadConfig failed in BOTH directories, so this test is not measuring what it claims: %v", gotErr)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CONFIG WAS INFLUENCED BY THE WORKING DIRECTORY — this is CVE-2025-64726's shape.\n"+
			"in a seeded dir: %+v\nin an empty dir: %+v", got, want)
	}
	// Belt and braces: name the specific settings the planted files tried to weaken,
	// so a future partial read is caught even if DeepEqual is somehow satisfied.
	if got.ScoreThreshold == 0 || got.ByteGate == byteGateOff || got.UnscorablePolicy == "allow" {
		t.Errorf("a planted file appears to have relaxed policy: threshold=%v byteGate=%q unscorable=%q",
			got.ScoreThreshold, got.ByteGate, got.UnscorablePolicy)
	}
}

// HOW THIS CHECK KNOWS WHAT TO WATCH — and why it is no longer a list of dangerous calls.
//
// It used to hold 13 call shapes its authors had thought of. That is the defect the check
// exists to catch, turned inward: a hand-written corpus is bounded by its author, so the
// drift it is named for is precisely what it cannot see. It missed `filepath.Glob` (pure
// discovery, while its siblings Walk and WalkDir were both watched) and every write shape
// but `os.Create` — including an `os.CreateTemp` that had been sitting in
// console/gitstore.go, unwatched, since the console gained a write path (#138).
//
// So the question is inverted. Every call into a filesystem-bearing stdlib package is
// DERIVED from the source by parsing it, and each one must be either:
//
//   - classified INERT here (it cannot reach the filesystem: os.Getenv, filepath.Join…), or
//   - allowlisted for that exact file, with the reason (fileAccessAllowed).
//
// Anything else is a violation, including a call nobody has classified yet. That is the
// point: `os.OpenRoot` did not exist when this check was written, and a guard whose failure
// mode is "a shape I never heard of is fine" is not a guard. The cost is a false POSITIVE
// when the standard library grows a harmless function — noise, noticed immediately — instead
// of a false NEGATIVE that ships green for a year.
//
// It paid for itself on its first run: `os.Stat`, `os.MkdirAll`, `os.Remove` and `os.Rename`
// in console/gitstore.go were reported immediately. None is dangerous — all five of that
// file's paths descend from CONSOLE_LIST_REPO — but under the old list they were not
// "allowed", they were never looked for, and the difference is the whole argument.
//
// Matched by IMPORT PATH rather than by the identifier in the source, so `import fsys "os"`
// cannot hide a call from it.
var fsPackages = map[string]bool{
	"os": true, "io/ioutil": true, "path/filepath": true,
	"html/template": true, "text/template": true, "io/fs": true,
}

// inertCalls are calls into those packages that cannot touch the filesystem or the
// process's notion of "here". Everything absent from this map is treated as if it could.
//
// os.Environ is deliberately NOT here: it is the subprocess-inheritance half of #38 and has
// its own check and its own allowlist below.
var inertCalls = map[string]bool{
	// environment and process
	"os.Getenv": true, "os.LookupEnv": true, "os.Exit": true, "os.Hostname": true,
	// pure string manipulation of paths — no syscall, no filesystem
	"filepath.Join": true, "filepath.Dir": true, "filepath.Base": true, "filepath.Clean": true,
	"filepath.Ext": true, "filepath.IsAbs": true, "filepath.ToSlash": true, "filepath.FromSlash": true,
	// template construction; ParseFiles/ParseGlob are NOT here, they read from disk
	"template.New": true, "template.Must": true, "template.URL": true, "template.HTMLEscapeString": true,
	"template.JSEscapeString": true,
}

// fsCall is one call into a filesystem-bearing package, as the parser found it.
type fsCall struct {
	name string // "os.ReadFile", by import path — never the local alias
	line int
}

// fsCallsIn parses src and returns every call into an fsPackage. AST rather than a text
// scan for three reasons a regexp gets wrong: a call split across lines, the same text
// inside a string or comment, and an aliased import.
func fsCallsIn(path string, src []byte) ([]fsCall, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, err
	}
	// local name -> import path, for the fs packages this file imports
	byLocal := map[string]string{}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || !fsPackages[p] {
			continue
		}
		local := p[strings.LastIndex(p, "/")+1:]
		if imp.Name != nil {
			local = imp.Name.Name
		}
		byLocal[local] = p
	}
	var calls []fsCall
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		pkgPath, ok := byLocal[ident.Name]
		if !ok {
			return true
		}
		// Report under the package's LAST path element, which is how the allowlist and the
		// inert map read ("os.ReadFile", "filepath.Glob"), regardless of any alias.
		short := pkgPath[strings.LastIndex(pkgPath, "/")+1:]
		calls = append(calls, fsCall{name: short + "." + sel.Sel.Name, line: fset.Position(call.Pos()).Line})
		return true
	})
	return calls, nil
}

// fileAccessAllowed records each production file that legitimately touches a file at
// runtime, and the EXACT calls it is allowed to make. Keyed narrowly on purpose: a
// whole-file exemption would let a future os.ReadFile appear in the same file and
// ship green, which is the shape this check exists to catch.
//
// A LIST per file rather than one call (#138): console/gitstore.go legitimately does two
// different things, and with a single-call map the second could only be expressed by
// pardoning the file. The narrow-key property is preserved — an entry still names the exact
// call — it is merely no longer limited to one of them.
//
// The bar an entry must clear is the one this test's own failure message states —
// an explicit operator-given ABSOLUTE path, never discovery. An entry here is not a
// pardon; it is a claim that the path cannot come from the working directory, and the
// code has to enforce that itself.
var fileAccessAllowed = map[string][]string{
	// D172 layer 1: the known-malware feed. Its path comes from FW_MALWARE_LIST and
	// nowhere else, and loadMalwareList REFUSES a relative path outright — so the file
	// read is against a value the operator stated, not one the filesystem suggested.
	// Feed-shipped-with-the-deployment is also what makes the verdict cost no egress,
	// which is the point of the layer.
	"malware.go": {"os.Open"},
	// #160: the same feed, re-read while the gate runs. The path is the same value from
	// FW_MALWARE_LIST — this file never composes one — and the actual read still goes
	// through loadMalwareList, which is where the absolute-path refusal lives. The
	// os.Stat is the cheap gate that decides whether to re-parse at all, so it reads no
	// bytes and can only answer "unchanged" or "look again"; a stat of a path the
	// working directory suggested would still be wrong, which is why it is listed here
	// with its reason rather than waved through as harmless.
	"malwarereload.go": {"os.Stat"},
	// #157: the feed's DETACHED SIGNATURE. The path is not configured at all -- it is
	// FW_MALWARE_LIST plus ".sig", so it inherits that value's absolute-path refusal
	// and cannot be pointed anywhere else. Deliberately not a second knob: a signature
	// configured separately from its feed can be half-updated, and a valid signature
	// over the PREVIOUS snapshot is the replay case arriving by accident.
	//
	// The read itself is the one place where reading the WRONG file fails SAFE: an
	// unreadable or non-matching signature refuses the snapshot and leaves the last
	// good feed in force. That is the opposite of upstreamcred.go below, where a
	// wrong file is presented upstream as our credential.
	"feedsig.go": {"os.ReadFile"},
	// #157: the snapshot PULL writes what it fetched to FW_MALWARE_LIST and its .sig,
	// by temp file and rename in the same directory, and stats the path once at
	// startup to decide whether it must seed. Every one of those paths is
	// FW_MALWARE_LIST (absolute, refused otherwise at load) or derived from it; the
	// temp file is created in that same directory by name pattern, never from the
	// working directory. The bytes written have already been verified against the
	// operator's key, so a write can only ever install a snapshot the key signed.
	"feedfetch.go": {"os.CreateTemp", "os.Remove", "os.Rename", "os.Stat", "os.IsNotExist"},
	// #157 release tooling: scripts/feedsign is a command a human runs with explicit
	// flags, never a service and never in an image -- the gate's Dockerfile builds `.`
	// alone, so this package is not in the shipped binary. Its paths come from argv
	// (-key, -in), which is the operator naming a file directly rather than the
	// working directory suggesting one, and it is listed here with that reason rather
	// than excluded by a skip rule: a broader skip would create a directory where
	// production code could later be added unchecked.
	"scripts/feedsign/main.go": {"os.ReadFile", "os.WriteFile"},
	// #53/D177: the upstream credential, re-read so a short-lived token (CodeArtifact,
	// Chainguard) survives rotation without a restart. Its path comes from
	// FW_UPSTREAM_AUTH_FILE and nowhere else, and loadConfig REFUSES a relative path
	// at startup — so, as with the malware feed, the read is against a value the
	// operator stated rather than one the working directory suggested. The stake is
	// higher here than for the feed, because this file holds a secret: a
	// CWD-relative read would let anyone who controls the working directory choose
	// which file we present upstream as our credential.
	"upstreamcred.go": {"os.ReadFile"},
	// D193: the operator's own allow/deny lists. Paths come from FW_ALLOW_LIST and
	// FW_DENY_LIST and nowhere else, and loadOperatorList REFUSES a relative path
	// outright -- the same bar the feed above clears.
	//
	// Worth stating why this entry is NOT merely "the same as malware.go": that file can
	// only ever DENY, so a bad read fails toward blocking. This one can ALLOW. A
	// CWD-relative read here would let whoever controls the working directory choose
	// which packages we serve without scoring, which is a strictly worse outcome than
	// the feed's, and it is why the absolute-path check is enforced in code rather than
	// documented.
	"operatorlist.go": {"os.Open"},
	// #137 / #39 class 7: the upstream CA bundle, the roots we verify our OWN outbound
	// TLS against when an enterprise proxy terminates it in front of us. The path comes
	// from FW_UPSTREAM_CA_BUNDLE and nowhere else, and loadConfig REFUSES a relative one
	// before this code runs — the same bar as the three above.
	//
	// Why this one deserves its own sentence rather than "as above": it decides which
	// certificates we ACCEPT. A working-directory-relative read would let whoever
	// controls the working directory add a root of their choosing, and from then on the
	// firewall accepts that CA's certificate for registry.npmjs.org — a silent
	// interception of everything we fetch, with every verdict still computed over bytes
	// an attacker supplied. Read ONCE at startup, never re-read, so the trusted set
	// cannot change under a running process either.
	"upstreamtrust.go": {"os.ReadFile"},
	// D193 / #58 increment 3b: the console's WRITE path for those same lists. The path
	// comes from CONSOLE_LIST_REPO and nowhere else, and newGitListStore REFUSES a
	// relative repo path, refuses a list path that escapes the repo, and refuses a
	// directory that is not a git repository -- so the read is against a location the
	// operator stated, and one whose every change is recorded.
	//
	// This is the write-side twin of operatorlist.go's entry and carries its stake plus
	// one more: this code does not merely READ a file that can allow packages, it
	// AUTHORS it. A path chosen by the working directory would let whoever controls that
	// directory pick which file becomes the organisation's policy.
	// Its WRITE half (#138), and the whole of it: the list file is authored by
	// temp-file-then-rename, so the bytes land atomically and a reader never sees a
	// half-written policy. Stat checks the repo is a directory; MkdirAll creates the list's
	// parent; CreateTemp writes beside it; Rename publishes; Remove cleans up the temp on
	// the failure path.
	//
	// Every one of them takes a path DERIVED from CONSOLE_LIST_REPO, which newGitListStore
	// refuses if it is relative, if the list path escapes the repo, or if the directory is
	// not a git repository — so the read entry above is what actually bounds this file's
	// reach, and these five inherit that bound. They are listed rather than waved through
	// because the derived check has no way to know that, and neither would the next reader.
	//
	// ⚠️ Four of these five were found by the check itself on its first run under the
	// derived design. Under the old hand-written list, os.Stat, os.MkdirAll, os.Remove and
	// os.Rename were invisible — not allowed, simply never looked for.
	"console/gitstore.go": {"os.ReadFile", "os.CreateTemp", "os.Stat", "os.MkdirAll", "os.Remove", "os.Rename"},
	// D151 phase 1 increment 7: the interception listener's signing CA. The path comes
	// from FW_INTERCEPT_CA_FILE and nowhere else, and loadConfig REFUSES a relative path
	// at startup. The stake is the highest in this table: the file holds the key that
	// signs certificates for the registry hostname, so a CWD-relative read would let
	// whoever controls the working directory choose which CA the gate impersonates
	// registries with -- the capability D105 exists to keep out of our hands entirely.
	"intercept.go": {"os.ReadFile"},
}

// optionalVariantFiles are production files that exist only in a tree carrying an optional
// build variant (`-tags intercept`). Everywhere else, a missing file with an allowance is a
// stale pardon and fails the check.
var optionalVariantFiles = map[string]bool{"intercept.go": true}

// envInheritAllowed records the ONE place production code forwards the parent
// environment into a subprocess, with the reason. Anything new fails.
//
// This is the CVE's actual mechanism — config values reaching a subprocess env,
// where NODE_OPTIONS/LD_PRELOAD/etc. execute before controls activate — so it gets
// an explicit allowlist rather than a blanket exemption.
var envInheritAllowed = map[string]string{
	// The scanner runs INSIDE its own run-once container, whose environment is the
	// explicit -e allowlist scheduler/launcher.go passes (SCANNER_REPO, SCANNER_SINK_URL,
	// GITHUB_TOKEN, SCANNER_SCAN_TIMEOUT_SECS) — not the firewall's environment and not
	// anything a client set. Inheriting there inherits a controlled env.
	"scanner/scorecard.go": "scanner container's own env, populated by an explicit -e allowlist",
}

// TestNoRuntimeFileAccessInProductionCode is the source-level half, and the one that
// catches the future change the issue is really about: a convenience config loader
// added months from now, which would otherwise ship green.
// allowedFileCall reports whether rel is permitted to make exactly this call.
func allowedFileCall(rel, call string) bool {
	for _, allowed := range fileAccessAllowed[rel] {
		if allowed == call {
			return true
		}
	}
	return false
}

// unclassifiedFsCalls is the check itself, for ONE file: derive every call into a
// filesystem-bearing package and return the ones that are neither classified inert nor
// allowlisted for this exact file. Marks the allowances it used, so a stale one still fires.
//
// A function rather than a loop inside the walk, and that is not tidiness. The fail-closed
// default — an unclassified call is a violation — cannot be exercised against our own source,
// because our own source has no unclassified call in it: the sabotage that deleted that
// branch entirely left every test GREEN. A property no test can reach is a property nobody
// is maintaining, so the decision now lives somewhere a fixture can reach it.
func unclassifiedFsCalls(rel, path string, src []byte, usedAllowance map[string]bool) ([]string, error) {
	calls, err := fsCallsIn(path, src)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range calls {
		switch {
		case inertCalls[c.name]:
			// cannot reach the filesystem
		case c.name == "os.Environ":
			// the subprocess-inheritance half; it has its own check and allowlist
		case allowedFileCall(rel, c.name):
			usedAllowance[rel+" "+c.name] = true
		default:
			out = append(out, fmt.Sprintf("%s:%d: %s", rel, c.line, c.name))
		}
	}
	return out, nil
}

// fsGuardFixture is a source file that makes one call of every shape this check has to get
// right. It is parsed by the same fsCallsIn the walk uses, so the control exercises the real
// classifier rather than a description of it.
//
// It carries an ALIASED import on purpose: a text scan for "os." misses `fsys.ReadFile`
// entirely, and an alias is the cheapest way for a filesystem call to hide from a guard that
// greps. It also names a call in a comment and in a string literal, because those are the
// false positives a grep produces and the reason this is an AST walk.
const fsGuardFixture = `package sample

import (
	"os"
	fsys "os"
	"path/filepath"
)

func f() {
	_ = os.Getenv("FW_UPSTREAM")            // inert: no filesystem
	_ = filepath.Join("a", "b")             // inert: string manipulation
	_, _ = os.ReadFile("/etc/passwd")       // watched: read
	_ = os.WriteFile("/x", nil, 0o600)      // watched: write
	_, _ = os.OpenRoot("/d")                // watched: a call this guard never classified
	_, _ = fsys.Open("/aliased")            // watched, and invisible to a text scan
	// os.Remove("/commented-out") is not a call
	_ = "os.Chdir(/in-a-string) is not a call either"
}
`

func TestTheFilesystemCallClassifierCanFail(t *testing.T) {
	calls, err := fsCallsIn("fixture.go", []byte(fsGuardFixture))
	if err != nil {
		t.Fatalf("the fixture does not parse, so this control proves nothing: %v", err)
	}
	found := map[string]bool{}
	for _, c := range calls {
		found[c.name] = true
	}

	// Every call the walk must SEE.
	for _, want := range []string{"os.ReadFile", "os.WriteFile", "os.OpenRoot", "os.Open"} {
		if !found[want] {
			t.Errorf("the classifier did not see %s, so production code could make that call and this "+
				"check would stay green", want)
		}
	}
	// os.Open here came through an ALIAS. A text scan would have missed it entirely.
	// os.OpenRoot is the fail-closed property: nobody classified it, so it must not be inert.
	if inertCalls["os.OpenRoot"] || inertCalls["os.WriteFile"] {
		t.Error("a filesystem call is classified INERT; the allowlist is then never consulted for it")
	}
	// And the two shapes a grep gets wrong.
	if found["os.Remove"] {
		t.Error("a call inside a COMMENT was counted — every doc comment naming a call becomes a violation")
	}
	if found["os.Chdir"] {
		t.Error("a call inside a STRING was counted")
	}
	// Inert calls must be seen by the parser but pass the classifier, or the allowlist fills
	// up with pardons for os.Getenv.
	if !found["os.Getenv"] || !inertCalls["os.Getenv"] {
		t.Errorf("os.Getenv should be parsed (%v) and classified inert (%v)", found["os.Getenv"], inertCalls["os.Getenv"])
	}
}

// TestTheAllowlistOnlyPardonsTheExactCall keeps the narrow-key property from being lost in
// the widening to a list (#138). An allowance for one call must not cover another.
func TestTheAllowlistOnlyPardonsTheExactCall(t *testing.T) {
	const f = "console/gitstore.go" // the file with the most allowances
	if !allowedFileCall(f, "os.ReadFile") || !allowedFileCall(f, "os.CreateTemp") {
		t.Fatalf("%s should be allowed both of its recorded calls", f)
	}
	if allowedFileCall(f, "os.WriteFile") {
		t.Errorf("an allowance for one call pardoned a DIFFERENT call in the same file — that is a " +
			"whole-file exemption by another name, and the shape this check exists to catch")
	}
	if allowedFileCall("proxy.go", "os.ReadFile") {
		t.Errorf("a file with no allowance at all was pardoned")
	}
}

// TestAnUnclassifiedFilesystemCallIsAViolation is the fail-closed property, exercised on the
// real check rather than on a description of it.
//
// It exists because a sabotage that deleted the default branch — making an unrecognised call
// pass silently, which is the exact defect #138 was filed about — left every other test in
// this file GREEN. Our own source has no unclassified call in it, so nothing could have
// noticed. The fixture supplies one.
func TestAnUnclassifiedFilesystemCallIsAViolation(t *testing.T) {
	used := map[string]bool{}
	got, err := unclassifiedFsCalls("sample.go", "sample.go", []byte(fsGuardFixture), used)
	if err != nil {
		t.Fatalf("the fixture does not parse, so this control proves nothing: %v", err)
	}
	joined := strings.Join(got, "\n")

	// os.OpenRoot is classified NOWHERE: not inert, not allowlisted. That is the whole
	// property — a call the guard has never heard of must fail, not pass.
	for _, want := range []string{"os.OpenRoot", "os.WriteFile", "os.ReadFile", "os.Open"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%s was not reported for a file with no allowances, so an unclassified "+
				"filesystem call would ship green — the defect this whole check exists to prevent.\n"+
				"reported:\n%s", want, joined)
		}
	}
	// And the other direction, or the allowlist fills up with pardons for os.Getenv.
	for _, inert := range []string{"os.Getenv", "filepath.Join"} {
		if strings.Contains(joined, inert) {
			t.Errorf("%s was reported as a violation; a call that cannot reach the filesystem must "+
				"not need an allowance", inert)
		}
	}
	// An allowlisted call is silent AND marks its allowance used, which is what keeps the
	// stale-allowance check from firing on a live entry.
	usedReal := map[string]bool{}
	real, err := unclassifiedFsCalls("console/gitstore.go", "gitstore.go", []byte(fsGuardFixture), usedReal)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(real, "\n"), "os.ReadFile") {
		t.Error("os.ReadFile was reported for console/gitstore.go, which is allowlisted for exactly that call")
	}
	if !usedReal["console/gitstore.go os.ReadFile"] {
		t.Error("an allowance was honoured but not marked used, so the stale-allowance check would " +
			"report a live entry as dead")
	}
}

// TestTheWalkReportsAViolatingFile proves the check is WIRED, not merely correct.
//
// Every other test here exercises the classifier. None of them could tell you whether the
// walk still collects what the classifier returns — and when that line was deleted as a
// sabotage, the whole suite stayed green, because our own tree contains no violating file
// for it to drop. So this plants one.
//
// It also pins the two skip rules that have cost us a CI-only failure before: a dot-directory
// (CI puts GOMODCACHE at .gocache/ inside the checkout) and a directory carrying its own
// go.mod. A planted violation inside either must NOT be reported, or the check drowns in
// other people's source the next time it runs in CI rather than on a laptop.
func TestTheWalkReportsAViolatingFile(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const violating = "package p\n\nimport \"os\"\n\nfunc f() { _ = os.WriteFile(\"/x\", nil, 0o600) }\n"
	const clean = "package p\n\nimport \"os\"\n\nfunc g() string { return os.Getenv(\"FW_UPSTREAM\") }\n"

	write("planted.go", violating)
	write("ok.go", clean)
	write("planted_test.go", violating)         // a _test.go file is not production code
	write(".gocache/dep/planted.go", violating) // a dot-directory is skipped (the CI failure)
	write("vendored/go.mod", "module vendored\n")
	write("vendored/planted.go", violating) // its own go.mod makes it a different module

	got, _, scanned, err := scanTreeForFsViolations(root, map[string]bool{})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	joined := strings.Join(got, "\n")

	if !strings.Contains(joined, "planted.go") || !strings.Contains(joined, "os.WriteFile") {
		t.Fatalf("the walk did not report a planted os.WriteFile, so nothing connects the classifier "+
			"to the failure this test exists to produce.\nreported:\n%s", joined)
	}
	if strings.Contains(joined, "ok.go") {
		t.Errorf("an inert call was reported: %s", joined)
	}
	for _, skipped := range []string{"planted_test.go", ".gocache", "vendored"} {
		if strings.Contains(joined, skipped) {
			t.Errorf("the walk descended into %s, which it must skip — in CI that is other people's "+
				"source and the check drowns in it:\n%s", skipped, joined)
		}
	}
	if scanned != 2 { // planted.go and ok.go, and nothing else
		t.Errorf("expected exactly 2 production files scanned, got %d — a skip rule is wrong in one "+
			"direction or the other", scanned)
	}
}

func TestNoRuntimeFileAccessInProductionCode(t *testing.T) {
	// Which allowances actually fired. An exemption that no longer matches anything is
	// a stale pardon sitting in the allowlist waiting to cover something else, so it is
	// an error rather than a shrug — the same anti-vacuity reasoning as the `scanned`
	// floor below.
	usedFileAllowance := map[string]bool{}

	fileViolations, envViolations, scanned, err := scanTreeForFsViolations(".", usedFileAllowance)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// A security check that silently scans NOTHING is worse than no check: it reports
	// green forever. The skip rules above are broad by necessity (see .gocache), so
	// prove they did not swallow our own source. Both files are load-bearing — config.go
	// is where a cwd loader would land, proxy.go is the largest production file.
	if scanned < 20 {
		t.Errorf("only %d production files scanned — the skip rules are too broad and this "+
			"check has become vacuous", scanned)
	}
	for _, must := range []string{"config.go", "proxy.go", "scheduler/launcher.go", "scanner/scorecard.go"} {
		if _, err := os.Stat(filepath.FromSlash(must)); err != nil {
			t.Errorf("expected to scan %s but it is not where the walk would find it: %v", must, err)
		}
	}

	for rel, calls := range fileAccessAllowed {
		// An optional build variant's file is absent from a tree built without it; its
		// allowance is then moot rather than stale. Only files named here get that pass.
		if _, err := os.Stat(filepath.FromSlash(rel)); err != nil && optionalVariantFiles[rel] {
			continue
		}
		for _, call := range calls {
			if usedFileAllowance[rel+" "+call] {
				continue
			}
			t.Errorf("the runtime-file-access allowance for %s (%q) matched nothing. Either the "+
				"call moved — in which case it is now UNCHECKED — or it is gone and the "+
				"allowance should be deleted before it pardons something else.", rel, call)
		}
	}

	if len(fileViolations) > 0 {
		t.Errorf("production code calls into a filesystem package at RUNTIME with no classification "+
			"(issues #38, #138). Config must come from the environment only — a discovered file is "+
			"CVE-2025-64726's entry point — and we never author another tool's configuration (#39 "+
			"class 4). Each call below must be either classified INERT (it cannot reach the "+
			"filesystem) or allowlisted for THAT FILE AND THAT CALL, with the reason its path "+
			"cannot come from the working directory:\n  %s",
			strings.Join(fileViolations, "\n  "))
	}
	if len(envViolations) > 0 {
		t.Errorf("production code forwards the parent environment into a subprocess (issue #38). "+
			"That is the CVE's mechanism: NODE_OPTIONS/LD_PRELOAD in an inherited env execute "+
			"before controls activate. Pass an explicit allowlist, as scheduler/launcher.go does, "+
			"or add an entry to envInheritAllowed WITH a reason:\n  %s",
			strings.Join(envViolations, "\n  "))
	}
}

// TestEnvInheritAllowlistIsHonest keeps the allowlist from outliving its subject. An
// entry naming a file that no longer inherits the environment is a standing permission
// nobody re-examined, and would silently re-authorise a future reintroduction.
func TestEnvInheritAllowlistIsHonest(t *testing.T) {
	for path, reason := range envInheritAllowed {
		if reason == "" {
			t.Errorf("%s is allowlisted with no reason", path)
		}
		src, err := os.ReadFile(filepath.FromSlash(path))
		if err != nil {
			t.Errorf("allowlist names %s, which does not exist: %v", path, err)
			continue
		}
		if !strings.Contains(string(src), "os.Environ()") {
			t.Errorf("%s is allowlisted for inheriting the environment but no longer does — "+
				"remove the entry rather than leaving a standing permission", path)
		}
	}
}

// scanTreeForFsViolations is the whole check over a TREE: walk it, derive every filesystem
// call in each production file, and return the unclassified ones plus the os.Environ
// inheritances.
//
// Parameterised on root for one reason: with the walk inlined in the test, deleting the line
// that COLLECTS what the classifier found left every test green -- our own tree has no
// violation in it, so discarding the result is unobservable. That is the same shape as #136
// (a feature wired in only one configuration, with green unit tests), and the fix is the
// same: give a fixture somewhere to stand. TestTheWalkReportsAViolatingFile plants one.
func scanTreeForFsViolations(root string, usedFileAllowance map[string]bool) (fileViolations, envViolations []string, scanned int, err error) {
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			// Any DOT-directory. This is not cosmetic: CI points GOMODCACHE at
			// .gocache/ INSIDE the repo, so a walk from "." descends into every
			// vendored dependency's source — pgx opens files, x/mod walks trees, and
			// the check drowns in other people's code. It passed locally (no .gocache
			// there) and failed in CI, which is the only reason we know.
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			// A directory carrying its own go.mod is a DIFFERENT MODULE, so it is not
			// our source whatever it is called. Belt to the dot-directory braces: it
			// catches a future cache or vendor dir that does not happen to start with
			// a dot.
			if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
				return filepath.SkipDir
			}
			switch d.Name() {
			// reference/ is the worked example, never built into the product; e2e/ is
			// the test harness, which legitimately drives docker and reads fixtures.
			case "reference", "e2e", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		rel := filepath.ToSlash(path)

		found, parseErr := unclassifiedFsCalls(rel, path, src, usedFileAllowance)
		if parseErr != nil {
			return fmt.Errorf("%s: %w", rel, parseErr)
		}
		fileViolations = append(fileViolations, found...)

		for _, line := range strings.Split(string(src), "\n") {
			code := strings.TrimSpace(line)
			if strings.HasPrefix(code, "//") { // a mention in a comment is not a call
				continue
			}
			if strings.Contains(code, "os.Environ()") {
				if _, ok := envInheritAllowed[rel]; !ok {
					envViolations = append(envViolations, rel+": "+code)
				}
			}
		}
		return nil
	})
	return fileViolations, envViolations, scanned, err
}
