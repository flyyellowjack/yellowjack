package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The cooldown (#26) and the staleness floor (D22) are inverse bounds on the same
// publication window, and they are deliberately ONE type with one unknown-age answer.
// These tests exist because the failure mode of getting that wrong is silent: an entry
// yanked by the wrong bound, or by neither, looks identical to the developer -- they
// see "no matching distribution", not which rule fired.
//
// Every case asserts the REASON, not just that something was yanked. A test that only
// counted yanks would pass on an implementation that yanked everything, which is the
// exact shape of check this project treats as worse than none.

const ageIdxJSON = `{"files":[
 {"filename":"pkg-1.0.tar.gz"},
 {"filename":"pkg-2.0.tar.gz"},
 {"filename":"pkg-3.0.tar.gz"}
]}`

func ageTimes(now time.Time) map[string]time.Time {
	return map[string]time.Time{
		"pkg-1.0.tar.gz": now.AddDate(0, 0, -400), // ancient
		"pkg-2.0.tar.gz": now.AddDate(0, 0, -30),  // comfortably in the middle
		"pkg-3.0.tar.gz": now.AddDate(0, 0, -1),   // published yesterday
	}
}

// yanksOf parses the filtered index and returns filename -> yank reason ("" = served).
func yanksOf(t *testing.T, body []byte) map[string]string {
	t.Helper()
	var doc struct {
		Files []map[string]any `json:"files"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("filtered index is not valid JSON: %v\n%s", err, body)
	}
	out := map[string]string{}
	for _, f := range doc.Files {
		name, _ := f["filename"].(string)
		reason, _ := f["yanked"].(string)
		out[name] = reason
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 entries back, got %d — the filter dropped entries instead of yanking them", len(out))
	}
	return out
}

func TestAgeWindowCooldownYanksOnlyTooNew(t *testing.T) {
	now := time.Now()
	w := ageWindow{
		tooNewAfter:  now.AddDate(0, 0, -7),
		tooNewReason: "within the 7-day cooldown",
	}
	got := yanksOf(t, ageYankIndex([]byte(ageIdxJSON), "application/json", w, ageTimes(now), malwarePin{}))

	// The one-day-old release is the whole point: it is the window a supply-chain
	// attack lives in, and it is the only entry that may be withheld here.
	if got["pkg-3.0.tar.gz"] != "within the 7-day cooldown" {
		t.Errorf("the 1-day-old release was not held by a 7-day cooldown; got %q", got["pkg-3.0.tar.gz"])
	}
	// A cooldown must NOT withhold old releases. If it does it has become a
	// staleness floor with a different name, and the operator's installs break.
	for _, old := range []string{"pkg-1.0.tar.gz", "pkg-2.0.tar.gz"} {
		if got[old] != "" {
			t.Errorf("cooldown wrongly yanked the older release %s with %q — a cooldown bounds "+
				"NEW releases only", old, got[old])
		}
	}
}

// The negative control: with no bound configured, nothing may be yanked. Without this,
// an implementation that yanked unconditionally would pass every positive test above.
func TestAgeWindowInactiveYanksNothing(t *testing.T) {
	now := time.Now()
	got := yanksOf(t, ageYankIndex([]byte(ageIdxJSON), "application/json", ageWindow{}, ageTimes(now), malwarePin{}))
	for name, reason := range got {
		if reason != "" {
			t.Errorf("an inactive window yanked %s with %q — it must be a no-op", name, reason)
		}
	}
	// ...and an inactive window must not fail closed on an unknown age either,
	// or every deployment with the feature off would start withholding releases.
	got = yanksOf(t, ageYankIndex([]byte(ageIdxJSON), "application/json", ageWindow{}, nil, malwarePin{}))
	for name, reason := range got {
		if reason != "" {
			t.Errorf("an inactive window yanked %s (unknown age) with %q — off means off", name, reason)
		}
	}
}

// The staleness floor must keep behaving exactly as it did before the cooldown existed.
// This is the regression guard on D22, which the window refactor could have broken
// invisibly.
func TestAgeWindowFloorStillYanksOnlyTooOld(t *testing.T) {
	now := time.Now()
	w := ageWindow{
		tooOldBefore: now.AddDate(0, 0, -365),
		tooOldReason: "older than the age floor",
	}
	got := yanksOf(t, ageYankIndex([]byte(ageIdxJSON), "application/json", w, ageTimes(now), malwarePin{}))
	if got["pkg-1.0.tar.gz"] != "older than the age floor" {
		t.Errorf("the 400-day-old release was not yanked by a 365-day floor; got %q", got["pkg-1.0.tar.gz"])
	}
	if got["pkg-3.0.tar.gz"] != "" {
		t.Errorf("the floor yanked a 1-day-old release with %q — the floor bounds OLD releases only",
			got["pkg-3.0.tar.gz"])
	}
}

// Both bounds at once, which is the case the doc entry in modematrix_test.go promises
// is covered. This is why the two are one type: each entry must get the reason for the
// bound that actually excluded it, and the middle entry must survive both.
func TestAgeWindowBothBoundsGiveTheRightReasonEach(t *testing.T) {
	now := time.Now()
	w := ageWindow{
		tooOldBefore: now.AddDate(0, 0, -365),
		tooOldReason: "too old",
		tooNewAfter:  now.AddDate(0, 0, -7),
		tooNewReason: "too new",
	}
	got := yanksOf(t, ageYankIndex([]byte(ageIdxJSON), "application/json", w, ageTimes(now), malwarePin{}))
	for name, want := range map[string]string{
		"pkg-1.0.tar.gz": "too old",
		"pkg-2.0.tar.gz": "",
		"pkg-3.0.tar.gz": "too new",
	} {
		if got[name] != want {
			t.Errorf("%s: reason = %q, want %q — with both bounds active each entry must carry "+
				"the reason for the bound that excluded it, not a merged one", name, got[name], want)
		}
	}
}

// An entry we cannot date is exactly the one an attacker would arrange for us not to be
// able to date, so an active window fails closed on it (the D100 posture).
func TestAgeWindowUnknownAgeFailsClosedWhenActive(t *testing.T) {
	now := time.Now()
	w := ageWindow{tooNewAfter: now.AddDate(0, 0, -7), tooNewReason: "within cooldown"}
	got := yanksOf(t, ageYankIndex([]byte(ageIdxJSON), "application/json", w, map[string]time.Time{}, malwarePin{}))
	for name, reason := range got {
		if !strings.Contains(reason, "could not be verified") {
			t.Errorf("%s: an undatable entry was served under an ACTIVE window (reason %q); it must "+
				"fail closed, or degrading one endpoint silently switches the guard off", name, reason)
		}
	}
}
