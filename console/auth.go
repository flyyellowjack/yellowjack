package main

import (
	"crypto/subtle"
	"net/http"
)

// basicAuth holds the single shared credential the override console sits behind.
// Per DECISIONS.md D19 (2026-07-15): per-user SSO is the eventual target but
// de-prioritized; near-term the write path ships behind BASIC GATEWAY AUTH — a
// shared username/password — with the loopback bind as the default. This is that
// shared credential, implemented in-process with the standard library (no reverse
// proxy dependency to stand up, no new attack surface).
//
// When no credential is configured, the console runs UNAUTHENTICATED but READ-ONLY:
// the override endpoint is disabled entirely (see server.writesEnabled), so we never
// expose an open state-mutating endpoint — the exact risk D19 flagged.
type basicAuth struct {
	user string
	pass string
}

// newBasicAuth returns a *basicAuth only when BOTH halves are set; otherwise nil,
// which the server reads as "no auth configured => read-only mode".
func newBasicAuth(user, pass string) *basicAuth {
	if user == "" || pass == "" {
		return nil
	}
	return &basicAuth{user: user, pass: pass}
}

// check validates the request's HTTP Basic credentials against the shared secret in
// constant time. subtle.ConstantTimeCompare avoids leaking, via response timing,
// how much of the username/password a guess got right. We compare BOTH fields
// unconditionally (no early return on a username mismatch) for the same reason.
func (a *basicAuth) check(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(a.user)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(a.pass)) == 1
	return userOK && passOK
}

// challenge asks the browser to prompt for credentials (HTTP 401 + WWW-Authenticate).
func challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Yellow Jack console", charset="UTF-8"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}
