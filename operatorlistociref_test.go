package main

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// An OCI operator-list entry naming a tag is enforced against the WHOLE repository,
// and until now nothing said so (#128).
//
// rejectVersionPin's own comment claimed "we say so out loud rather than let them find
// out from a served pull". It returned nil for OCI and said nothing at all. The
// sentence described an intention; these tests are what makes it true, because a
// comment is exactly what failed here.
//
// The measured behaviour these pin, taken before any of this was written:
//
//	deny entry "library/alpine"       blocks :3.19 = true   :latest = true
//	deny entry "library/alpine:3.19"  blocks :3.19 = true   :latest = true   <- widened
//
// The second row is the defect. An operator blocking one bad tag of a base image
// their builds depend on takes out every build using any tag of it, and the refusal
// names the repository, so the log reads as though they had written the repository.

// ── 1. THE DEFECT ITSELF, PINNED AS BEHAVIOUR ────────────────────────────────
//
// Asserted rather than assumed: if OCI list matching ever becomes tag-exact, this
// fails and whoever changed it must decide what the warning should now say.

func TestOCIDenyEntryWithATagIsEnforcedRepositoryWide(t *testing.T) {
	l, err := parseOperatorList("deny", "oci", strings.NewReader("library/alpine:3.19\n"))
	if err != nil {
		t.Fatalf("a tagged OCI entry must PARSE — refusing it would break a legitimate deny: %v", err)
	}
	if !l.has("oci", "library/alpine:3.19") {
		t.Error("the tag that was written is not blocked, so the entry does nothing at all")
	}
	if !l.has("oci", "library/alpine:latest") {
		t.Error("a DIFFERENT tag is not blocked — if this is now the behaviour, the widening " +
			"warning this file exists for is wrong and must be removed, not left to mislead")
	}
}

// ── 2. THE WARNING EXISTS AND NAMES WHAT HAPPENED ────────────────────────────

func TestOCITaggedEntryWarnsThatItWasWidened(t *testing.T) {
	l, err := parseOperatorList("deny", "oci", strings.NewReader("library/alpine:3.19\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.warnings) != 1 {
		t.Fatalf("expected exactly one warning, got %d: %v", len(l.warnings), l.warnings)
	}
	w := l.warnings[0]
	for _, want := range []string{
		"library/alpine:3.19", // what they wrote
		"library/alpine",      // what is enforced
		"WHOLE repository",    // the fact
		"deny-list line 1",    // where to look
	} {
		if !strings.Contains(w, want) {
			t.Errorf("the warning does not contain %q, so it cannot be acted on:\n  %s", want, w)
		}
	}
	// It must not read as a failure: the entry IS working, and an operator who thinks
	// it was dropped will go looking for a block that is already in force. Asserted
	// positively — that the message says so — rather than by hunting for words like
	// "error", which the message legitimately uses to say "this is not an error".
	if !strings.Contains(w, "is enforced") {
		t.Errorf("the warning never says the entry is in force, so it reads like a refusal:\n  %s", w)
	}
}

// ── 3. THE QUIET CASES. Without these, "warns" is satisfied by warning always. ──

func TestOCIReferenceWarningStaysQuietWhenThereIsNothingToSay(t *testing.T) {
	cases := []struct {
		name, ecosystem, entry string
	}{
		{"a plain repository is exactly what it says", "oci", "library/alpine"},
		{"a registry PORT is not a tag", "oci", "registry.internal:5000/team/app"},
		{"npm is not OCI and has its own guard", "npm", "left-pad"},
		{"an npm scope is not a reference", "npm", "@acme/widget"},
		{"pypi", "pypi", "requests"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, err := parseOperatorList("deny", c.ecosystem, strings.NewReader(c.entry+"\n"))
			if err != nil {
				t.Fatalf("%q should parse: %v", c.entry, err)
			}
			if len(l.warnings) != 0 {
				t.Errorf("%q produced a warning it should not have: %v", c.entry, l.warnings)
			}
		})
	}
}

// The registry-port case is the one a naive "does it contain a colon" check gets
// wrong, so it is also asserted to still WORK, not merely to stay quiet.
func TestOCIRegistryPortEntryStillMatches(t *testing.T) {
	l, err := parseOperatorList("deny", "oci", strings.NewReader("registry.internal:5000/team/app\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !l.has("oci", "registry.internal:5000/team/app:v2") {
		t.Error("an entry naming a host:port repository stopped matching pulls of it — a " +
			"colon-based reference check has eaten the port")
	}
}

// ── 4. A DIGEST IS A REFERENCE TOO ───────────────────────────────────────────

func TestOCIDigestEntryAlsoWarns(t *testing.T) {
	l, err := parseOperatorList("deny", "oci",
		strings.NewReader("library/alpine@sha256:0000000000000000000000000000000000000000000000000000000000000000\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.warnings) != 1 {
		t.Fatalf("a digest-pinned entry is widened exactly like a tag and must warn; got %v", l.warnings)
	}
	if !strings.Contains(l.warnings[0], "library/alpine") {
		t.Errorf("the warning does not name the repository actually enforced: %s", l.warnings[0])
	}
}

// ── 4b. THE ALLOW LIST IS TOLD ABOUT THE SPELLING THAT DOES WORK ─────────────
//
// Since #155 an ALLOW entry may name exactly one image by digest. The warning's closing
// sentence -- "per-tag entries are not supported" -- was written before that, and !370
// made it false for the allow list without touching it: an operator who wrote a tag was
// told there was no exact form, when there is one. The DENY list is the control. Its
// text is quoted verbatim in docs/REFERENCE_DEPLOYMENT.md and must not move.
func TestOCITaggedAllowEntryIsPointedAtTheDigestForm(t *testing.T) {
	allow, err := parseOperatorList("allow", "oci", strings.NewReader("library/nginx:1.27-alpine\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(allow.warnings) != 1 {
		t.Fatalf("a tagged allow entry is still widened and must still warn; got %v", allow.warnings)
	}
	w := allow.warnings[0]
	if !strings.Contains(w, `"library/nginx@sha256:<digest>"`) {
		t.Errorf("the allow-list warning does not show the digest spelling that allows exactly one image: %s", w)
	}
	if strings.Contains(w, "not supported") {
		t.Errorf("the allow-list warning still says exact entries are unsupported, which stopped being "+
			"true when digest-scoped allows shipped: %s", w)
	}

	// CONTROL: the deny list cannot name less than a repository, so its sentence is
	// still true and is quoted verbatim in the reference deployment guide.
	deny, err := parseOperatorList("deny", "oci", strings.NewReader("library/nginx:1.27-alpine\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(deny.warnings) != 1 || !strings.HasSuffix(deny.warnings[0], "and note that per-tag entries are not supported.") {
		t.Errorf("the DENY warning changed; docs/REFERENCE_DEPLOYMENT.md quotes it verbatim: %v", deny.warnings)
	}
	if strings.Contains(deny.warnings[0], "@sha256") {
		t.Errorf("the deny list was offered a digest form it does not accept: %s", deny.warnings[0])
	}
}

// ── 5. THE OPERATOR ACTUALLY SEES IT, AND NOT EVERY 5 SECONDS ────────────────
//
// The warning lives on the parsed list, and the reload timer re-parses. A warning
// repeated every 5 seconds forever is one an operator learns to scroll past, so it
// rides the same digest guard as the reload line. This asserts both halves: it is
// logged once, and it comes back when the file really changes.

type countingLog struct {
	mu    sync.Mutex
	lines []string
}

func (c *countingLog) logf(f string, a ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(f, a...))
}

func (c *countingLog) matching(sub string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, l := range c.lines {
		if strings.Contains(l, sub) {
			n++
		}
	}
	return n
}

func TestOCIWideningWarningIsLoggedOncePerChangeNotPerReload(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/deny.txt"
	writeListFile(t, path, "library/alpine:3.19\n")

	log := &countingLog{}
	// ttl 0 so every call re-reads: the worst case for repetition.
	src := reloadingList("deny", "oci", path, log.logf, 0)

	for i := 0; i < 5; i++ {
		if l := src(); l == nil {
			t.Fatal("list failed to load")
		}
	}
	if n := log.matching("WHOLE repository"); n != 1 {
		t.Errorf("the widening warning was logged %d times across 5 reloads of an UNCHANGED "+
			"file; an operator will learn to ignore a line that repeats forever", n)
	}

	// A real edit that leaves the entry widened must say so again — the file changed,
	// so the operator is looking, and the entry is still not what it reads as.
	time.Sleep(10 * time.Millisecond)
	writeListFile(t, path, "library/alpine:3.19\nlibrary/busybox\n")
	src()
	if n := log.matching("WHOLE repository"); n != 2 {
		t.Errorf("after a real edit the warning was logged %d times total, want 2 — a changed "+
			"file is exactly when it is worth repeating", n)
	}
}

// ── 6. ANTI-VACUITY ──────────────────────────────────────────────────────────
//
// Every assertion above is about a warning being present or absent. If the parser
// stopped producing warnings at all, cases 3 and 5's "quiet" halves would still pass.
// This pins that the mechanism is live.
func TestWarningsMechanismIsNotInert(t *testing.T) {
	widened, err := parseOperatorList("deny", "oci", strings.NewReader("a/b:1\nc/d:2\ne/f\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(widened.warnings) != 2 {
		t.Fatalf("expected one warning per widened entry (2 of 3 lines), got %d: %v",
			len(widened.warnings), widened.warnings)
	}
}
