package main

import (
	"context"
	"net/http"
)

// verdictHold carries a request's ALLOW verdict from the control point that reached it
// (ServeHTTP, after Evaluate) to the relay that can still overrule it, so the audit log
// records what the client actually got.
//
// The case it exists for (D346): npm's version filter runs inside the relay, AFTER
// Evaluate allowed the package, and refuses the request when nothing compliant remains
// (every version pinned as malware, denied, or inside the release window) or when the
// request named a refused version. The allow used to be audited before the relay ran, so
// the record said "allowed" while the developer got a 403. The filter's verdict now
// REPLACES the allow in the one record for that request; it is never a second event,
// because the audit log promises one event per requested package.
//
// A hold starts unarmed. Only the allow path arms it, so a filter refusal reached any
// other way (report mode relaying a block, a version-scoped verdict's serve) leaves the
// record its own control point already wrote.
type verdictHold struct {
	armed bool
	d     Decision
}

type verdictHoldKey struct{}

// withVerdictHold returns r carrying a fresh, unarmed hold.
func withVerdictHold(r *http.Request) (*http.Request, *verdictHold) {
	h := &verdictHold{}
	return r.WithContext(context.WithValue(r.Context(), verdictHoldKey{}, h)), h
}

// overruleVerdict replaces the held allow with d. It reports whether a held verdict was
// replaced; with no armed hold it does nothing.
func overruleVerdict(r *http.Request, d Decision) bool {
	h, _ := r.Context().Value(verdictHoldKey{}).(*verdictHold)
	if h == nil || !h.armed {
		return false
	}
	h.d = d
	return true
}
