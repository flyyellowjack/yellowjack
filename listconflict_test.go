package main

import (
	"strings"
	"testing"
)

// When two sources of policy disagree about one package, the verdict is only half the
// answer. The other half is telling the operator that their OTHER entry was overridden,
// because otherwise the only trace is the rule name on a 403 and the natural next move
// -- re-adding the package to the allow list -- cannot work and does not say why.
//
// Two such conflicts exist. Neither was tested before #124:
//
//	feed  vs allow-list   logged since !179, never asserted
//	deny-list vs allow    SILENT until #124, which is what this file fixes
//
// Every leg here is paired with a control on a package in ONE list, because a firewall
// that printed the conflict line on every pull would satisfy a bare "the line appears"
// test while making the log useless.

const (
	conflictLogBoth = "is on BOTH operator lists"
	// The NAME-scoped case. Reworded by #155/D312: a name-scoped allow still loses to an
	// advisory, and the line now says so and tells the operator how to say what they
	// mean (pin the release). A version-scoped allow that names the advisory's release
	// WINS, and that path is covered in adminoverride_test.go.
	conflictLogFeed = "is on the operator allow-list by NAME and in the known-malware feed"
)

// listConflictFirewall builds a gate whose upstream FAILS the test if contacted, so
// every assertion below is also an assertion that these decisions cost no egress.
func listConflictFirewall(t *testing.T, cfg Config) *Firewall {
	t.Helper()
	up, _ := deadUpstream(t)
	cfg.Ecosystem = "npm"
	cfg.UpstreamRegistry = up.URL
	cfg.DepsDevBase = up.URL
	cfg.ScorecardMode = "stub"
	cfg.ScoreThreshold = 5.0
	f, err := NewFirewall(cfg)
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	return f
}

// TestDenyListOverridingAllowListIsLogged is the #124 fix.
func TestDenyListOverridingAllowListIsLogged(t *testing.T) {
	const pkg = "contested-pkg"

	t.Run("on both lists: refused, and the override is stated", func(t *testing.T) {
		f := listConflictFirewall(t, Config{
			DenyListPath:  writeList(t, "deny.txt", pkg),
			AllowListPath: writeList(t, "allow.txt", pkg),
		})
		buf := captureStdLog(t)

		d := f.Evaluate(pkg)

		// The verdict must not move. Fail-closed is the right outcome and this change
		// is about legibility; a "fix" that let the allow list win would be a bypass.
		if d.Allowed {
			t.Fatalf("a package on the deny list was ALLOWED because it was also on the "+
				"allow list — the deny list must win (reason %q)", d.Reason)
		}
		if d.Deny != denyOperator {
			t.Errorf("Deny = %q, want %q", d.Deny, denyOperator)
		}
		if got := buf.String(); !strings.Contains(got, conflictLogBoth) {
			t.Errorf("the package is on BOTH operator lists and nothing said so.\n"+
				"An operator who allow-listed it sees only a 403 whose rule name is "+
				"deny-list:%s, and re-adding it to the allow list cannot help.\ngot log:\n%s",
				pkg, got)
		}
	})

	// CONTROL. The reason the leg above is not satisfied by a gate that prints the line
	// unconditionally.
	t.Run("control: deny list only, no conflict claimed", func(t *testing.T) {
		f := listConflictFirewall(t, Config{
			DenyListPath: writeList(t, "deny.txt", pkg),
		})
		buf := captureStdLog(t)

		if d := f.Evaluate(pkg); d.Allowed {
			t.Fatalf("deny-listed package was allowed (reason %q)", d.Reason)
		}
		if got := buf.String(); strings.Contains(got, conflictLogBoth) {
			t.Errorf("a package on ONE list was reported as a conflict; the line is being "+
				"printed unconditionally, which makes it noise rather than a signal\ngot log:\n%s", got)
		}
	})

	t.Run("control: allow list only, served and silent", func(t *testing.T) {
		f := listConflictFirewall(t, Config{
			AllowListPath: writeList(t, "allow.txt", pkg),
		})
		buf := captureStdLog(t)

		if d := f.Evaluate(pkg); !d.Allowed {
			t.Fatalf("allow-listed package was refused (reason %q)", d.Reason)
		}
		if got := buf.String(); strings.Contains(got, conflictLogBoth) {
			t.Errorf("an allow-listed package with no deny entry reported a conflict\ngot log:\n%s", got)
		}
	})
}

// TestMalwareFeedOverridingAllowListIsLogged pins the conflict !179 already logs.
//
// It is here because #124 rests on the claim that this one IS reported -- and that claim
// was read out of the source, never asserted. An untested log line is a comment.
func TestMalwareFeedOverridingAllowListIsLogged(t *testing.T) {
	const pkg = "evil-but-vetted"
	feed := writeFeed(t, `{"id":"MAL-2026-9999","ecosystem":"npm","name":"`+pkg+`"}`)

	t.Run("feed beats the allow list, and says so", func(t *testing.T) {
		f := listConflictFirewall(t, Config{
			MalwareListPath: feed,
			AllowListPath:   writeList(t, "allow.txt", pkg),
		})
		buf := captureStdLog(t)

		d := f.Evaluate(pkg)
		if d.Allowed {
			t.Fatalf("a package in the known-malware feed was ALLOWED by the allow list "+
				"(reason %q) — an operator cannot opt out of a published advisory", d.Reason)
		}
		if d.Deny != denyKnownMalware {
			t.Errorf("Deny = %q, want %q — the feed's reason carries the advisory ID, which "+
				"is the more useful of the two", d.Deny, denyKnownMalware)
		}
		if got := buf.String(); !strings.Contains(got, conflictLogFeed) {
			t.Errorf("the allow-list entry was overridden by the feed and nothing said so\ngot log:\n%s", got)
		}
	})

	t.Run("control: feed only, no conflict claimed", func(t *testing.T) {
		f := listConflictFirewall(t, Config{MalwareListPath: feed})
		buf := captureStdLog(t)

		if d := f.Evaluate(pkg); d.Allowed {
			t.Fatalf("known-malware package was allowed (reason %q)", d.Reason)
		}
		if got := buf.String(); strings.Contains(got, conflictLogFeed) {
			t.Errorf("a package with no allow-list entry was reported as a conflict\ngot log:\n%s", got)
		}
	})
}

// TestListConflictLogsAreDistinguishable stops the two lines collapsing into one wording
// during a later tidy-up. They are different facts with different remedies: the feed case
// is "your allow list cannot override a published advisory, go argue with the advisory",
// the deny case is "your own two files disagree, go edit one of them".
func TestListConflictLogsAreDistinguishable(t *testing.T) {
	if strings.Contains(conflictLogBoth, conflictLogFeed) || strings.Contains(conflictLogFeed, conflictLogBoth) {
		t.Fatal("the two conflict markers now match each other's text, so the tests above " +
			"can no longer tell which conflict fired")
	}
	const pkg = "both-and-malware"
	// A package in ALL THREE: the feed must win, and only its line may appear -- the
	// deny/allow line lives below the feed's early return and must not be reached.
	f := listConflictFirewall(t, Config{
		MalwareListPath: writeFeed(t, `{"id":"MAL-2026-8888","ecosystem":"npm","name":"`+pkg+`"}`),
		DenyListPath:    writeList(t, "deny.txt", pkg),
		AllowListPath:   writeList(t, "allow.txt", pkg),
	})
	buf := captureStdLog(t)

	d := f.Evaluate(pkg)
	if d.Deny != denyKnownMalware {
		t.Errorf("Deny = %q, want %q — the feed outranks both operator lists", d.Deny, denyKnownMalware)
	}
	got := buf.String()
	if !strings.Contains(got, conflictLogFeed) {
		t.Errorf("the feed/allow conflict was not reported\ngot log:\n%s", got)
	}
	if strings.Contains(got, conflictLogBoth) {
		t.Errorf("the deny/allow line fired for a package the FEED refused. It sits after "+
			"the feed's early return, so reaching it means the ordering changed\ngot log:\n%s", got)
	}
}
