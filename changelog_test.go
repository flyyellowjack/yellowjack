package main

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// CHANGELOG.md, kept honest by test rather than by intention (#51-adjacent, OSS
// launch hygiene).
//
// A changelog is the file most likely to be written once and then quietly diverge,
// because nothing breaks when it does. The two failure modes are opposite and both
// real:
//
//	a version is released and not written down  -> users cannot tell what changed
//	a version is written down and never released -> the file describes software that
//	                                                does not exist, which is worse,
//	                                                because it reads as authoritative
//
// The second is the one this project is actually exposed to right now: there are zero
// tags, so the temptation is to back-fill a "1.0.0" that was never cut. The check
// below refuses that.

const changelogPath = "CHANGELOG.md"

func changelogText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(changelogPath)
	if err != nil {
		t.Fatalf("read %s: %v", changelogPath, err)
	}
	return string(b)
}

// gitTags returns the repository's tags, or nil when git is unavailable.
func gitTags(t *testing.T) ([]string, bool) {
	t.Helper()
	out, err := exec.Command("git", "tag").Output()
	if err != nil {
		return nil, false
	}
	var tags []string
	for _, line := range strings.Split(string(out), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			tags = append(tags, s)
		}
	}
	return tags, true
}

// versionHeadingRe matches a released-version heading: "## [1.2.3] - 2026-01-01".
// The Unreleased section deliberately does not match — it is not a version.
var versionHeadingRe = regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+[^\]]*)\]`)

// TestChangelogDoesNotClaimUnreleasedVersions is the check that bites today.
//
// Every version section in the file must correspond to a real tag. With zero tags,
// that means: no version sections at all. A "1.0.0" heading appearing here without a
// tag behind it is a claim about software nobody can obtain.
func TestChangelogDoesNotClaimUnreleasedVersions(t *testing.T) {
	tags, ok := gitTags(t)
	if !ok {
		t.Skip("git unavailable; this check needs the tag list to mean anything")
	}
	tagged := map[string]bool{}
	for _, tag := range tags {
		tagged[strings.TrimPrefix(tag, "v")] = true
	}

	claimed := versionHeadingRe.FindAllStringSubmatch(changelogText(t), -1)
	for _, m := range claimed {
		if !tagged[strings.TrimPrefix(m[1], "v")] {
			t.Errorf("%s has a section for version %q but no such tag exists. "+
				"A changelog entry for a version nobody can check out is a claim about "+
				"software that does not exist — and it reads as authoritative.",
				changelogPath, m[1])
		}
	}

	// The honest state must be SAID, not merely implied by an absence of sections.
	// A file with no version headings is indistinguishable from one somebody forgot
	// to fill in; the sentence is what makes it a deliberate statement.
	if len(tags) == 0 && !strings.Contains(changelogText(t), "no released versions yet") {
		t.Error("there are no tags, and the changelog does not say so. An empty version " +
			"history that does not explain itself reads as neglect rather than as a fact.")
	}
}

// TestEveryTagHasAChangelogSection is the other direction.
//
// ⚠️ VACUOUS TODAY, deliberately and with the vacuity stated: there are zero tags, so
// the loop body does not execute. That is acceptable ONLY because it is paired with
// the check above, which is not vacuous, and because this one's whole purpose is to
// fire at the moment of the first release — which is exactly when a missing changelog
// entry costs something and when nobody is thinking about this file.
func TestEveryTagHasAChangelogSection(t *testing.T) {
	tags, ok := gitTags(t)
	if !ok {
		t.Skip("git unavailable")
	}
	if len(tags) == 0 {
		t.Log("no tags yet — this check is inert until the first release, by design; " +
			"TestChangelogDoesNotClaimUnreleasedVersions carries the weight until then")
		return
	}
	text := changelogText(t)
	for _, tag := range tags {
		version := strings.TrimPrefix(tag, "v")
		if !strings.Contains(text, "["+version+"]") {
			t.Errorf("tag %q has no section in %s — a release nobody wrote down", tag, changelogPath)
		}
	}
}

// TestTheChangelogNamesEveryEcosystemWeGate is the non-vacuous drift guard, and the
// reason this file is not just a formatting check.
//
// "Which package managers does it support" is the first question anyone arriving at
// the repo asks, and the changelog is where they will look. Adding a fifth ecosystem
// and forgetting to say so is a silent failure of exactly the kind this project keeps
// converting into a test.
func TestTheChangelogNamesEveryEcosystemWeGate(t *testing.T) {
	// The names newEcosystem accepts, taken from its own error message so the two
	// cannot drift: adding a case without updating that message is already a bug.
	_, err := newEcosystem("definitely-not-an-ecosystem", "")
	if err == nil {
		t.Fatal("newEcosystem accepted a nonsense name, so its error cannot be used to " +
			"enumerate the real ones")
	}
	names := regexp.MustCompile(`"([a-z]+)"`).FindAllStringSubmatch(err.Error(), -1)
	if len(names) < 4 {
		t.Fatalf("expected at least 4 ecosystem names in %q, found %d — the extraction "+
			"broke and this test proves nothing", err.Error(), len(names))
	}

	text := strings.ToLower(changelogText(t))
	for _, m := range names {
		eco := m[1]
		if !strings.Contains(text, eco) {
			t.Errorf("the firewall gates %q but %s never mentions it. The first question a "+
				"reader asks is which package managers are supported, and this is where "+
				"they look.", eco, changelogPath)
		}
	}
}

// TestTheChangelogStatesItsLimitations.
//
// The launch risk this guards is not an omission, it is a TONE: a changelog that
// lists only what works reads as a product claim. Two limitations are load-bearing
// enough that finding them out later would feel like being misled — cooperative
// enforcement (a developer can simply not point at us) and the unauthenticated
// approval service.
func TestTheChangelogStatesItsLimitations(t *testing.T) {
	text := strings.ToLower(changelogText(t))
	for _, want := range []struct{ needle, why string }{
		{"cooperative", "enforcement is bypassable by not pointing at us — the single most " +
			"important thing a buyer must know before deploying"},
		{"no authentication", "the approval service's mutating endpoints are open (#13 item 2)"},
	} {
		if !strings.Contains(text, want.needle) {
			t.Errorf("%s does not disclose: %s", changelogPath, want.why)
		}
	}
}
