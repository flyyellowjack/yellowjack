package main

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// No tracked document may carry a person's contact details.
//
// WHY THIS EXISTS. docs/SETUP.md was tracked for months with a personal mailbox, a named
// colleague and password-vault steps in its last three sections -- a two-person onboarding
// runbook appended to an operator guide. The publication register (docsmanifest_test.go)
// caught it, but only because a human read the file and wrote "needsWork". Nothing would
// have caught the NEXT one: a verdict is set once, and the document keeps changing under it.
//
// So this checks the CONTENT of every document whose verdict says it ships, on every run.
// It is deliberately narrow -- an email address is unambiguous, greppable and never
// belongs in an operator guide -- rather than a vocabulary scan, which the register's own
// header explains cannot separate a publishable document from an unpublishable one.
var emailShaped = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)

// allowedAddress reports whether an address-shaped string is one a public document may
// carry: reserved example domains, and strings that only LOOK like addresses.
func allowedAddress(s string) bool {
	l := strings.ToLower(s)
	for _, ok := range []string{"@example.com", "@example.org", "@example.net", "@example.test"} {
		if strings.HasSuffix(l, ok) {
			return true
		}
	}
	// `git@gitlab.com:...` is a transport, and `name@sha256...` is an image reference.
	return strings.HasPrefix(l, "git@") || strings.Contains(l, "@sha256")
}

func personalContactIn(text string) []string {
	var found []string
	for _, m := range emailShaped.FindAllString(text, -1) {
		if !allowedAddress(m) {
			found = append(found, m)
		}
	}
	return found
}

func TestShippingDocsCarryNoPersonalContact(t *testing.T) {
	// Every TRACKED markdown file, not a curated subset: a tracked document is one that can
	// be published, and a real mailbox belongs in none of them. Asked of git rather than the
	// filesystem, because untracked local notes on a developer's disk are not published.
	out, err := exec.Command("git", "ls-files", "*.md").Output()
	if err != nil {
		t.Skipf("not a git checkout (%v); this guard reads the tracked set", err)
	}
	checked := 0
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Errorf("%s is tracked but cannot be read: %v", f, err)
			continue
		}
		checked++
		if hits := personalContactIn(string(b)); len(hits) > 0 {
			t.Errorf("%s is tracked and carries address(es) %v.\nA published document never needs a real "+
				"mailbox. Move the passage to an untracked local document, or use an example.* address.", f, hits)
		}
	}
	// ANTI-VACUITY: a tracked set this small means git is not answering, not that the docs went.
	if checked < 10 {
		t.Fatalf("only %d tracked markdown files were checked -- this guard is reading almost nothing", checked)
	}
}

// The detector has to be able to fail, and has to stay quiet on the look-alikes that
// appear all over this repository's docs.
func TestPersonalContactDetector(t *testing.T) {
	for name, tc := range map[string]struct {
		text string
		want int
	}{
		"a real-looking mailbox is flagged":    {"forward it to jane.doe@proton.me today", 1},
		"a work address is flagged too":        {"ask sam@yellowjack.io for access", 1},
		"two in one line are both flagged":     {"a@b.io and c@d.co.uk", 2},
		"an example domain is allowed":         {"sign in as alice@example.test", 0},
		"a git transport is not an address":    {"git clone git@gitlab.com:yellowjack/yellowjack.git", 0},
		"an image digest is not an address":    {"nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2", 0},
		"an npm scope is not an address":       {"npm install @scope/pkg@1.2.3", 0},
		"prose with an at-sign is not flagged": {"pinned @ the digest, not the tag", 0},
	} {
		t.Run(name, func(t *testing.T) {
			if got := personalContactIn(tc.text); len(got) != tc.want {
				t.Errorf("found %v, want %d hit(s) in %q", got, tc.want, tc.text)
			}
		})
	}
}
