package main

import (
	"testing"
	"time"
)

// Tests for the queue's AGE (#50).
//
// The issue's target is "a queue measured in HOURS", against the three months one
// operator reported. That target is only meaningful if the number we show is the time
// the package has actually been waiting — and the ways it can quietly stop being that
// are the point of this file.
//
// The failure mode is silent in the worst way: the queue keeps rendering a small,
// entirely plausible age while packages rot in it. Nothing goes red, no page looks
// broken, and the operator concludes the queue is healthy. So each way the enqueue
// time can be lost gets an assertion rather than a comment.

// TestFirstSeenSurvivesAReRecord is THE regression guard.
//
// The firewall only calls recordPending on the first sighting today, so age works. If
// that ever changes — a retry, a re-queue, a note update on each pull — an incoming
// write carries no FirstSeen, and a store that took the caller's zero value would reset
// the wait to zero on EVERY pull. A package waiting three months would show as new.
func TestFirstSeenSurvivesAReRecord(t *testing.T) {
	s := newMemStore()

	first, err := s.Put(Decision{Package: "left-pad", Verdict: VerdictPending, Note: "unscorable"})
	if err != nil {
		t.Fatalf("first put: %v", err)
	}
	if first.FirstSeen.IsZero() {
		t.Fatal("FirstSeen is zero on the first write — the queue has no clock at all")
	}

	// The shape of a re-record: exactly what recordPending sends, with no FirstSeen.
	time.Sleep(2 * time.Millisecond)
	again, err := s.Put(Decision{Package: "left-pad", Verdict: VerdictPending, Note: "unscorable"})
	if err != nil {
		t.Fatalf("second put: %v", err)
	}
	if !again.FirstSeen.Equal(first.FirstSeen) {
		t.Errorf("FirstSeen moved on a re-record: %v -> %v. The queue would report every "+
			"package as newly arrived no matter how long it had been waiting.",
			first.FirstSeen, again.FirstSeen)
	}
	if !again.UpdatedAt.After(first.UpdatedAt) {
		t.Error("UpdatedAt did not move — the two timestamps are not actually distinct, " +
			"so this test would pass even if FirstSeen were just an alias for UpdatedAt")
	}
}

// TestFirstSeenSurvivesAHumanRuling: deciding a package must not erase how long it waited.
//
// This is the one that makes the queue auditable after the fact. "How long did this sit
// before someone acted?" is the accountability half of #50, and it is unanswerable if
// the act of answering overwrites the evidence.
func TestFirstSeenSurvivesAHumanRuling(t *testing.T) {
	s := newMemStore()
	queued, _ := s.Put(Decision{Package: "lodash", Verdict: VerdictPending})

	time.Sleep(2 * time.Millisecond)
	ruled, err := s.Put(Decision{
		Package:   "lodash",
		Verdict:   VerdictApproved,
		DecidedBy: "admin",
		Note:      "reviewed the repo by hand",
	})
	if err != nil {
		t.Fatalf("ruling put: %v", err)
	}
	if !ruled.FirstSeen.Equal(queued.FirstSeen) {
		t.Errorf("the ruling overwrote the enqueue time (%v -> %v), so the wait it ended "+
			"can no longer be measured", queued.FirstSeen, ruled.FirstSeen)
	}
	if ruled.UpdatedAt.Equal(ruled.FirstSeen) {
		t.Error("UpdatedAt equals FirstSeen after a ruling — the record cannot distinguish " +
			"'queued at' from 'decided at', which is the whole point of carrying both")
	}
}

// TestFirstSeenIsReadBackFromTheStore: List and Get must carry it, not just Put's return.
//
// A value that is only correct in the reply to the write is useless — the console reads
// the queue with List, and every age it renders comes from there.
func TestFirstSeenIsReadBackFromTheStore(t *testing.T) {
	s := newMemStore()
	put, _ := s.Put(Decision{Package: "chalk", Verdict: VerdictPending})

	got, ok, err := s.Get("chalk")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if !got.FirstSeen.Equal(put.FirstSeen) {
		t.Errorf("Get lost FirstSeen: %v != %v", got.FirstSeen, put.FirstSeen)
	}

	list, err := s.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list returned %d rows, want 1", len(list))
	}
	if list[0].FirstSeen.IsZero() {
		t.Error("List returned a zero FirstSeen — the console renders ages from List, so " +
			"every queue entry would show an age of 'since the epoch'")
	}
}

// TestFirstSeenIsPreservedNotRecomputed is the NEGATIVE CONTROL for the two tests above.
//
// They both compare a stored value against another stored value, so an implementation
// that simply set FirstSeen = now() on every write would satisfy neither — but only
// because of the sleeps, which is a thin thread to hang an invariant on. This one hands
// the store an explicit, old FirstSeen and requires it to come back unchanged, so the
// assertion fails on a recompute regardless of timing.
func TestFirstSeenIsPreservedNotRecomputed(t *testing.T) {
	s := newMemStore()
	old := time.Now().UTC().Add(-72 * time.Hour)

	seeded, err := s.Put(Decision{Package: "old-timer", Verdict: VerdictPending, FirstSeen: old})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !seeded.FirstSeen.Equal(old) {
		t.Fatalf("a supplied FirstSeen was not honoured: %v != %v", seeded.FirstSeen, old)
	}

	after, _ := s.Put(Decision{Package: "old-timer", Verdict: VerdictApproved, DecidedBy: "admin"})
	if !after.FirstSeen.Equal(old) {
		t.Errorf("FirstSeen was recomputed rather than preserved: %v != %v", after.FirstSeen, old)
	}
	if age := time.Since(after.FirstSeen); age < 71*time.Hour {
		t.Errorf("age reads as %v for a package queued 72h ago — this is the exact number "+
			"an operator would use to decide the queue is healthy", age)
	}
}

// TestAFutureFirstSeenIsRefusedAtTheStore closes the other half of the tier-3 finding.
//
// The console renders an impossible enqueue time as unmeasurable, which stops THAT page
// lying. But PUT /v1/decisions decodes firstSeen straight from its body, so the value is
// chosen by whoever reaches this service, and the console is not its only reader: the
// CLI dry-run (D137) and the compliance export (#28) consume the same records. Correcting
// it only at the point of display would leave every other consumer showing a package
// parked in the queue as the newest arrival.
func TestAFutureFirstSeenIsRefusedAtTheStore(t *testing.T) {
	s := newMemStore()
	far := time.Now().UTC().Add(365 * 24 * time.Hour)

	saved, err := s.Put(Decision{Package: "parked", Verdict: VerdictPending, FirstSeen: far})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if saved.FirstSeen.Equal(far) {
		t.Error("a firstSeen a year in the future was stored verbatim. Age is now-FirstSeen, " +
			"so every reader computes a negative age and renders the row as brand new — " +
			"forever, because the value never ages.")
	}
	if age := time.Since(saved.FirstSeen); age < 0 {
		t.Errorf("the stored enqueue time is still in the future (age %v)", age)
	}

	// It must be readable back corrected, not just returned corrected.
	got, ok, _ := s.Get("parked")
	if !ok {
		t.Fatal("get: not found")
	}
	if got.FirstSeen.After(time.Now().UTC()) {
		t.Error("Get returned a future enqueue time; the correction was applied to the " +
			"reply but not to what was stored")
	}
}

// TestOrdinaryClockSkewIsNotTreatedAsAnAttack is the CONTROL for the test above.
//
// This service and the firewall that posts to it are separate processes, possibly on
// separate hosts. A guard strict enough to fire on a second of drift would rewrite
// legitimate timestamps on every healthy deployment — a correction that is itself the
// corruption.
func TestOrdinaryClockSkewIsNotTreatedAsAnAttack(t *testing.T) {
	s := newMemStore()
	slightlyAhead := time.Now().UTC().Add(3 * time.Second)

	saved, err := s.Put(Decision{Package: "skewed", Verdict: VerdictPending, FirstSeen: slightlyAhead})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if !saved.FirstSeen.Equal(slightlyAhead) {
		t.Errorf("three seconds of clock skew was rewritten (%v -> %v); this fires on "+
			"healthy two-process deployments", slightlyAhead, saved.FirstSeen)
	}
}
