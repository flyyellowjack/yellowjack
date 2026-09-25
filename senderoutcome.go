package main

import "sync/atomic"

// Reading the control plane's ANSWER, not just whether the request left (#153).
//
// Every gate-to-control-plane sender handled a transport error and then treated any
// response at all as success: `closeDrained(resp.Body)` with no look at the status. So a
// 400 or a 500 -- the control plane saying "I did not store that" -- was indistinguishable
// from a 201, on a path where the thing not stored is the audit trail.
//
// outcomeLog is the small shared piece: it lets a sender say what happened ONCE PER CHANGE
// of outcome rather than once per request. That is not a nicety. During an outage the
// audit sender is refused on every single pull; a line per event is the first thing an
// operator filters out, and then the line that mattered is gone with it.
type outcomeLog struct{ last atomic.Int32 }

// changed records status and reports whether it differs from the previous one, along with
// that previous status (0 before the first answer).
func (o *outcomeLog) changed(status int) (prev int, changed bool) {
	prev = int(o.last.Swap(int32(status)))
	return prev, prev != status
}

// undeliverable is the outcome recorded when no answer arrived at all, so that "could not
// connect" and "connected and was refused" are different outcomes and a change between
// them is logged. Not a real HTTP status, deliberately: it must never collide with one.
const undeliverable = -1

// accepted reports whether the control plane took what it was sent.
func accepted(status int) bool { return status >= 200 && status <= 299 }
