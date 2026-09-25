package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests for reloading the operator lists (D195, issue #58 increment 3a).
//
// D193 has the console editing these lists while the process runs, so the question
// this file answers is not "does a file get read" but "what happens at the moments
// around an edit". Three of those moments can hurt someone, and each has a test:
//
//  1. the edit lands  -> the gate must enforce the NEW list without a restart
//  2. the file breaks -> the gate must keep enforcing the LAST GOOD list. For the
//     DENY list this is a security property, not an availability one: dropping it
//     makes every blocked package servable again, silently, which is fail-OPEN.
//  3. the list legitimately empties -> honour it, but say so, because "my blocks
//     stopped applying" is otherwise indistinguishable from "my blocks were removed"
//
// The TTL is injected rather than slept through: a test that waits out the real
// 5-second interval would be slow enough that someone eventually deletes it.

// NOTE: captureLog(t) and discard() come from upstreamcred_test.go. Reused rather
// than re-declared -- this file is modelled on that one, so duplicating its helper
// was the first thing the compiler caught.

func TestAnEditedListIsPickedUpWithoutARestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deny.txt")
	writeListFile(t, path, "first-blocked\n")

	logf, _ := captureLog(t)
	// Zero TTL: every call re-reads, so the test drives the transition rather than
	// waiting for one.
	src := reloadingList("deny", "npm", path, logf, 0)

	if !src().has("npm", "first-blocked") {
		t.Fatal("the initial list was not loaded")
	}
	writeListFile(t, path, "second-blocked\n")

	if src().has("npm", "first-blocked") {
		t.Error("the OLD entry is still enforced after the file changed — the list is " +
			"not being re-read, so a console edit would never reach a running replica")
	}
	if !src().has("npm", "second-blocked") {
		t.Error("the NEW entry is not enforced after the file changed")
	}
}

// TestABrokenListKeepsEnforcingTheLastGoodOne is the one that matters.
//
// A blanked DENY list fails OPEN: every package the operator blocked silently becomes
// servable. Writers are not all atomic, so a read landing mid-rewrite is ordinary, not
// exotic — and a deleted file, a permission change and a full disk look the same.
func TestABrokenListKeepsEnforcingTheLastGoodOne(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deny.txt")
	writeListFile(t, path, "still-blocked\n")

	logf, logged := captureLog(t)
	src := reloadingList("deny", "npm", path, logf, 0)
	if !src().has("npm", "still-blocked") {
		t.Fatal("the initial list was not loaded")
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("removing the list: %v", err)
	}
	if !src().has("npm", "still-blocked") {
		t.Fatal("THE DENY LIST WAS DROPPED when the file became unreadable. Every package " +
			"the operator blocked is now servable, and nothing said so — this is the " +
			"fail-open direction and the whole reason last-good retention exists here.")
	}

	// A garbage file is the other half: it parses to an error rather than a read error,
	// and must be treated identically.
	writeListFile(t, path, "not a valid entry with spaces\n")
	if !src().has("npm", "still-blocked") {
		t.Error("the deny list was dropped when the file became UNPARSEABLE (as opposed " +
			"to unreadable); both are mid-rewrite shapes and both must retain the last good list")
	}

	// And the operator has to be told, with the fact that matters first: are we still
	// enforcing anything?
	if out := logged(); !strings.Contains(out, "STILL ENFORCING") {
		t.Errorf("the degraded log does not say whether anything is still being enforced.\nGot:\n%s", out)
	}
}

// TestAListThatEmptiesIsHonouredButAnnounced.
//
// An operator IS allowed to empty a list, so this must not be refused. But an empty
// list that parsed cleanly is also what a truncated write or a wrong mount looks like,
// and for the deny list that is fail-open — so it may not pass silently.
func TestAListThatEmptiesIsHonouredButAnnounced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deny.txt")
	writeListFile(t, path, "was-blocked\n")

	logf, logged := captureLog(t)
	src := reloadingList("deny", "npm", path, logf, 0)
	if !src().has("npm", "was-blocked") {
		t.Fatal("the initial list was not loaded")
	}

	writeListFile(t, path, "# everything removed\n")
	if src().has("npm", "was-blocked") {
		t.Error("the emptied list was not honoured — an operator must be able to clear one")
	}
	if out := logged(); !strings.Contains(out, "to ZERO") {
		t.Errorf("a list going from entries to empty was not announced. That transition is "+
			"indistinguishable from a truncated write, and for a deny list it is fail-open.\nGot:\n%s", out)
	}
}

// TestTheTTLBoundsHowOftenWeTouchTheFilesystem — the reason the source caches at all.
// Without it every package lookup would stat and re-parse, on the request path.
func TestTheTTLBoundsHowOftenWeTouchTheFilesystem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deny.txt")
	writeListFile(t, path, "blocked\n")

	logf, _ := captureLog(t)
	src := reloadingList("deny", "npm", path, logf, time.Hour)
	if !src().has("npm", "blocked") {
		t.Fatal("the initial list was not loaded")
	}

	// Change the file, then look up again well inside the TTL.
	writeListFile(t, path, "different\n")
	if !src().has("npm", "blocked") {
		t.Error("the file was re-read inside the TTL; the cache is not bounding filesystem " +
			"work on the request path")
	}
	// Anti-vacuity: with the TTL out of the way the SAME source must see the change.
	// Without this, a source that never re-read anything would pass the assertion above.
	fresh := reloadingList("deny", "npm", path, logf, 0)
	if !fresh().has("npm", "different") {
		t.Error("even with no TTL the new content was not picked up — the test above was " +
			"passing because nothing ever reloads, not because the cache works")
	}
}

func writeListFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
