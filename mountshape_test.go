package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// MOUNT SHAPE: a file this process RE-READS must never be bind-mounted as a FILE.
//
// ── the defect this exists to prevent ────────────────────────────────────────
//
// Found on 2026-09-07 by async_local.sh leg 23, and it is the only defect of the
// operator-list write path (!185) that would have reached a customer. Two individually
// correct decisions collide:
//
//  1. a writer replaces the file ATOMICALLY — temp file, then rename — because
//     os.WriteFile truncates first and a truncated deny list is a window during which
//     blocked packages are served. A rename swings the directory entry to a NEW INODE.
//  2. the consumer bind-mounts the FILE. A file bind mount pins THAT INODE into the
//     container's mount table.
//
// So the reader re-reads its own path faithfully forever and keeps getting the old
// inode. The atomicity that protects the file is exactly what makes the update
// invisible, and NEITHER SIDE REPORTS THE CONFLICT: the writer succeeds, git history is
// perfect, only enforcement is missing.
//
// ── why this check is in Go rather than in the e2e rig ───────────────────────
//
// Because the bug is PLATFORM-MASKED and an e2e leg therefore cannot be trusted to
// catch it. Docker Desktop resolves file bind mounts by path, so the Windows dev host
// shows a file mount working; Linux pins the inode, and Linux is what deployments run.
// Six consecutive local runs of the leg passed. A test that reproduces the mask instead
// of catching it is worse than no test, so the real guard has to be STRUCTURAL — it
// reads the compose text and needs no daemon, no platform, and no luck.
//
// TestUpstreamCredentialRotation (e2e) is the behavioural half; this is the half that
// holds on every platform, in the unit gate, on every change.
//
// ── the negative control is permanent, not a one-off ─────────────────────────
//
// TestFileMountCheckerCatchesAFileMount runs the same checker over a synthetic compose
// document that DOES mount the file, and fails if the checker stays quiet. A structural
// check whose only observed outcome is "green" converts an unknown into false
// confidence, which this project treats as worse than doing it by hand.

// reReadPathVars maps each config env var whose file is re-read WHILE RUNNING to the
// Config field that carries it.
//
// Membership here is the whole question, and it is not a matter of taste: a load-once
// file may be mounted as a file quite safely (FW_MALWARE_LIST is, today, and that is
// fine), while a re-read file may not. TestReReadPathVarsMatchTheCode keeps this table
// honest against firewall.go, because "someone made X reloadable" is precisely the
// change that silently invalidates the mount shape three files away.
var reReadPathVars = map[string]string{
	"FW_ALLOW_LIST":         "AllowListPath",
	"FW_DENY_LIST":          "DenyListPath",
	"FW_UPSTREAM_AUTH_FILE": "UpstreamAuthFile",
}

// composeMount is one entry of a service's `volumes:` list.
type composeMount struct {
	source string // host path or named volume
	target string // the path INSIDE the container — the field that matters here
	line   int
	raw    string
}

// mountLine matches a compose volume entry: a list item holding a "src:dst" pair.
// Anchored on the leading "- " so an environment value never parses as a mount.
var mountLine = regexp.MustCompile(`^\s+-\s+(\S+:\S+)\s*$`)

// envLine matches both environment spellings compose accepts:
//
//	FW_ALLOW_LIST: "/etc/yellowjack/lists/allow.txt"     (mapping form)
//	- FW_ALLOW_LIST=/etc/yellowjack/lists/allow.txt      (list form)
var envMapLine = regexp.MustCompile(`^\s+([A-Z][A-Z0-9_]*):\s*(.+?)\s*$`)
var envListLine = regexp.MustCompile(`^\s+-\s+([A-Z][A-Z0-9_]*)=(.*?)\s*$`)

// parseComposeMounts extracts every volume entry from a compose document.
//
// A hand parser rather than a YAML library on purpose: this is security software and
// every dependency is our own attack surface (CLAUDE.md), so a parser used by one test
// over five files we ourselves write is not worth a module-graph entry. The cost of
// that choice is that the parser can mis-read and pass vacuously, which is why the
// callers assert they found something before believing a clean result.
func parseComposeMounts(src string) []composeMount {
	var out []composeMount
	for i, line := range strings.Split(src, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		m := mountLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		parts := strings.Split(strings.Trim(m[1], `"'`), ":")
		if len(parts) < 2 {
			continue
		}
		out = append(out, composeMount{
			source: parts[0],
			target: parts[1],
			line:   i + 1,
			raw:    strings.TrimSpace(line),
		})
	}
	return out
}

// parseComposeEnvPaths returns, for each re-read config var, every value the document
// assigns to it. A slice rather than a single value because one file configures several
// services and they need not agree.
func parseComposeEnvPaths(src string) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		var key, val string
		if m := envListLine.FindStringSubmatch(line); m != nil {
			key, val = m[1], m[2]
		} else if m := envMapLine.FindStringSubmatch(line); m != nil {
			key, val = m[1], m[2]
		} else {
			continue
		}
		if _, ok := reReadPathVars[key]; !ok {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if val == "" {
			continue // "unset here" is not a path
		}
		out[key] = append(out[key], val)
	}
	return out
}

// fileMountViolations reports every place the document mounts something AT a path it
// also uses as a re-read config value.
//
// Equality with the mount TARGET is the whole test, and it is sufficient rather than
// merely indicative: Docker requires a file source to have a file target, so any
// file-level mount of P shows up as target == P. A mount of P's parent DIRECTORY is
// the correct shape and is what a clean document looks like.
//
// Paths are compared across the whole document rather than per service. That is
// deliberate: container-side paths are a convention we choose, so two services
// disagreeing about what /etc/yellowjack/lists/allow.txt is would itself be worth
// stopping on, and per-service association would need real YAML structure for no gain.
func fileMountViolations(name, src string) []string {
	mounts := parseComposeMounts(src)
	envPaths := parseComposeEnvPaths(src)

	var out []string
	for v, paths := range envPaths {
		for _, p := range paths {
			for _, m := range mounts {
				if m.target != p {
					continue
				}
				out = append(out, fmt.Sprintf(
					"%s:%d mounts %s AS A FILE (%q), and that path is %s — a re-read config file. "+
						"A file bind mount pins the inode, so an atomic rewrite (temp file + rename) "+
						"installs a new inode the container can never see: the re-read succeeds and "+
						"returns the OLD bytes forever, with no error on either side. "+
						"Mount the DIRECTORY %s instead and let the container resolve the name.",
					name, m.line, m.target, m.raw, v, filepath.ToSlash(filepath.Dir(p))))
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestReReadFilesAreMountedAsDirectories(t *testing.T) {
	files, err := filepath.Glob("docker-compose*.yml")
	if err != nil {
		t.Fatalf("glob compose files: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no docker-compose*.yml found; this check examined nothing")
	}

	var (
		violations  []string
		totalMounts int
		totalPaths  int
		covered     []string
	)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		src := string(b)
		violations = append(violations, fileMountViolations(f, src)...)
		totalMounts += len(parseComposeMounts(src))
		for v, paths := range parseComposeEnvPaths(src) {
			totalPaths += len(paths)
			for _, p := range paths {
				covered = append(covered, v+"="+p)
			}
		}
	}

	// ANTI-VACUITY. A hand parser that matched nothing would report a clean corpus, and
	// a clean report is the outcome this check will almost always produce — so the two
	// are indistinguishable unless the instrument states what it actually saw. Both
	// halves are needed: mounts prove the volume parser works, re-read paths prove the
	// env parser does, and the check is only meaningful where the two meet.
	if totalMounts < 3 {
		t.Fatalf("only %d volume entries were parsed across %d compose files; the mount parser is "+
			"matching almost nothing, so a clean result here means nothing", totalMounts, len(files))
	}
	if totalPaths == 0 {
		t.Fatalf("no re-read config path (%s) was found in any compose file, so this check compared "+
			"mount targets against an empty set. Either the env parser broke or those settings moved, "+
			"and in both cases the mount shape is now UNCHECKED", strings.Join(sortedKeys(reReadPathVars), ", "))
	}

	if len(violations) > 0 {
		t.Errorf("re-read config files are bind-mounted as files:\n  %s", strings.Join(violations, "\n  "))
	}
	sort.Strings(covered)
	t.Logf("checked %d volume entries against %d re-read config paths: %s",
		totalMounts, totalPaths, strings.Join(covered, ", "))
}

// TestFileMountCheckerCatchesAFileMount is the negative control, kept as a test rather
// than performed once by hand so it cannot rot: if a future edit to the parser makes it
// stop recognising mounts or env values, the corpus check above would quietly go green
// forever and this one goes red immediately.
//
// The fixture is the ACTUAL broken shape that shipped — the two list files mounted
// individually, exactly as docker-compose.asyncfake.yml had them before leg 23 found it.
func TestFileMountCheckerCatchesAFileMount(t *testing.T) {
	const broken = `services:
  firewall:
    image: yellowjack:local
    environment:
      FW_ALLOW_LIST: "/etc/yellowjack/lists/allow.txt"
      FW_DENY_LIST: "/etc/yellowjack/lists/deny.txt"
    volumes:
      - ./.e2e-lists/allow.txt:/etc/yellowjack/lists/allow.txt:ro
      - ./.e2e-lists/deny.txt:/etc/yellowjack/lists/deny.txt:ro
`
	got := fileMountViolations("synthetic.yml", broken)
	if len(got) != 2 {
		t.Fatalf("the checker found %d violations in a document that mounts BOTH list files "+
			"individually; want 2. The corpus check is therefore not proven able to fail, and its "+
			"green result carries no information.\ngot: %v", len(got), got)
	}
	for _, want := range []string{"allow.txt", "deny.txt", "FW_ALLOW_LIST", "FW_DENY_LIST"} {
		if !strings.Contains(strings.Join(got, "\n"), want) {
			t.Errorf("the violation message never mentions %q, so it does not tell the reader which "+
				"setting is broken:\n%s", want, strings.Join(got, "\n"))
		}
	}

	// The positive control on the same fixture: mounting the DIRECTORY must be accepted,
	// or the check would be a blanket ban on mounting lists at all and would be
	// "fixed" by deleting it.
	const fixed = `services:
  firewall:
    environment:
      FW_ALLOW_LIST: "/etc/yellowjack/lists/allow.txt"
      FW_DENY_LIST: "/etc/yellowjack/lists/deny.txt"
    volumes:
      - ./.e2e-lists:/etc/yellowjack/lists:ro
`
	if got := fileMountViolations("synthetic.yml", fixed); len(got) != 0 {
		t.Errorf("mounting the DIRECTORY is the prescribed fix and must be accepted; got: %v", got)
	}
}

// reReadCall matches a call to one of the re-reading constructors. The `func ` guard in
// the loop excludes the declarations themselves.
var reReadCall = regexp.MustCompile(`\b(newReloadingList|reloadingList|fileCredential)\(`)
var cfgField = regexp.MustCompile(`\bcfg\.([A-Za-z][A-Za-z0-9]*)`)

// TestReReadPathVarsMatchTheCode keeps reReadPathVars from going stale.
//
// This is the drift that the mount rule depends on and that nothing else would notice:
// making a load-once file reloadable is a one-line change in firewall.go, it is
// obviously correct on its own, every unit test still passes — and it silently moves
// that file into a category where its existing compose mount is now broken. The table
// above is the link between the two, so it has to be checked against the source rather
// than maintained by memory.
func TestReReadPathVarsMatchTheCode(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob sources: %v", err)
	}

	want := map[string]string{} // Config field -> env var
	for env, field := range reReadPathVars {
		want[field] = env
	}

	found := map[string]string{} // Config field -> "file:line"
	for _, f := range sources {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			line = strings.TrimRight(line, "\r")
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "func ") {
				continue
			}
			if !reReadCall.MatchString(line) {
				continue
			}
			// A re-read call site must name exactly one path field, and that field
			// must already be in the table. cfg.Ecosystem and friends ride along on
			// the same line, so the test is membership, not arity.
			var pathFields []string
			for _, m := range cfgField.FindAllStringSubmatch(line, -1) {
				if _, ok := want[m[1]]; ok {
					pathFields = append(pathFields, m[1])
				}
			}
			where := fmt.Sprintf("%s:%d", f, i+1)
			if len(pathFields) == 0 {
				t.Errorf("%s re-reads a file on a timer but names no field from reReadPathVars:\n  %s\n"+
					"If this made another config file reloadable, ADD it to reReadPathVars — its "+
					"compose mount must now be a DIRECTORY, and nothing else checks that.", where, trimmed)
				continue
			}
			for _, pf := range pathFields {
				if prev, dup := found[pf]; dup {
					t.Errorf("cfg.%s is re-read from two places (%s and %s)", pf, prev, where)
				}
				found[pf] = where
			}
		}
	}

	for field, env := range want {
		if _, ok := found[field]; !ok {
			t.Errorf("reReadPathVars claims %s (cfg.%s) is re-read while running, but no call to "+
				"reloadingList/fileCredential names it. Either it is now read ONCE — in which case "+
				"remove it here, because a stale entry makes the mount rule look enforced where it "+
				"is not — or the constructor was renamed and this whole check is now blind.", env, field)
		}
	}
	if len(found) == 0 {
		t.Fatal("no re-read call site was found at all; the source scan matched nothing")
	}
}
