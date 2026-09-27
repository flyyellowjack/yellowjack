package main

import (
	"sort"
	"time"
)

// A REPLACED replica is not a DEAD one.
//
// Every replica is keyed by its hostname, and a redeploy (a new pod, a recreated container)
// comes back under a new one. The old row stays, because ListInstanceHealth deliberately
// keeps silent replicas: a firewall that stopped reporting is the most important row in the
// view. But nothing told "stopped" apart from "was replaced", so every redeploy left one
// permanent CRITICAL "has stopped reporting" alert per replaced replica, and the console's
// sidebar read "1 of 3 not reporting" for ever. Found rehearsing a customer demo
// (2026-09-25): one restarted container turned the sidebar amber fifteen minutes later.
//
// The distinction is a fact the rows already carry. A silent replica was REPLACED when a
// replica of the same ecosystem that is reporting now STARTED around the time the silent one
// went quiet: that is what a rolling update, a container recreate and a pod reschedule all
// look like. Each successor accounts for at most one predecessor, and a successor is only
// credited if it started within replacementWindow of the predecessor's last heartbeat. That
// window is what keeps a real death visible: after a scale-up, the added replica started long
// before a later crash, so it cannot explain the crash away. A silent replica with no
// successor, or one whose start time is unknown, is still silent, exactly as before.
//
// Computed on read, never stored, and never settable by a heartbeat (ingest copies fields
// one by one). The staleness window is the caller's, as the store's comment requires.
const replacementWindow = 10 * time.Minute

// markReplaced sets ReplacedBy on every silent row a successor accounts for. It mutates the
// slice it is given; pass a copy where the caller's rows must stay untouched.
func markReplaced(rows []InstanceHealth, now time.Time, silentAfter time.Duration) {
	type pair struct {
		silent, successor int
		gap               time.Duration
	}
	var pairs []pair
	for i, s := range rows {
		if now.Sub(s.ReportedAt) <= silentAfter || s.StartedAt.IsZero() {
			continue
		}
		for j, f := range rows {
			if i == j || f.Ecosystem != s.Ecosystem || f.StartedAt.IsZero() {
				continue
			}
			if now.Sub(f.ReportedAt) > silentAfter || !f.StartedAt.After(s.StartedAt) {
				continue // a successor is alive, and younger than what it replaced
			}
			gap := f.StartedAt.Sub(s.ReportedAt)
			if gap < 0 {
				gap = -gap
			}
			if gap > replacementWindow {
				continue
			}
			pairs = append(pairs, pair{i, j, gap})
		}
	}
	// Closest start-to-last-heartbeat first, so with two silent replicas and one successor
	// the one it actually replaced is the one credited.
	sort.Slice(pairs, func(a, b int) bool {
		if pairs[a].gap != pairs[b].gap {
			return pairs[a].gap < pairs[b].gap
		}
		if pairs[a].silent != pairs[b].silent {
			return pairs[a].silent < pairs[b].silent
		}
		return pairs[a].successor < pairs[b].successor
	})
	usedSilent, usedSuccessor := map[int]bool{}, map[int]bool{}
	for _, p := range pairs {
		if usedSilent[p.silent] || usedSuccessor[p.successor] {
			continue
		}
		usedSilent[p.silent], usedSuccessor[p.successor] = true, true
		rows[p.silent].ReplacedBy = rows[p.successor].Instance
	}
}
