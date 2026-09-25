package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// Per-scan capability tokens (issue #13, item 1).
//
// The scan id alone is NOT a secret: register() builds it from a counter and a
// timestamp, so anyone who can reach the scheduler can guess a pending id and POST
// a forged high score to /results/{id} — getting a malicious package allowed. The
// id is a correlation handle (it appears in logs); the token is the authority.
//
// The token is handed to exactly one party — the run-once container we launched,
// via its sink URL — so possession of it *is* the proof that a result came from
// that scan. This is deliberately independent of the wider service-auth mechanism
// (shared secret vs mTLS vs network policy), which is still an open architecture
// question: network policy narrows WHO can reach the sink but never authenticates
// WHAT they send, so this check is needed either way and survives the planned move
// to a Kubernetes Job launcher unchanged.

// tokenBytes is the raw entropy per token. 32 bytes (256 bits) is far beyond
// guessable within a scan's lifetime and costs nothing to carry in a URL.
const tokenBytes = 32

// newCapabilityToken returns a fresh unguessable token, URL-safe so it can be a
// path segment with no escaping. A failure from crypto/rand must be fatal to the
// scan, never silently degraded to a weaker (or empty) token — an empty token
// would make every result acceptable.
func newCapabilityToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating scan capability token: %w", err)
	}
	// RawURLEncoding: no '+', '/', or '=' padding, so the token is exactly one
	// path segment and splitResultPath can rely on that.
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// tokenMatches reports whether the token presented on a result POST is the one we
// issued for that scan.
//
// subtle.ConstantTimeCompare keeps the comparison time independent of how many
// leading bytes a guess got right, so repeated POSTs can't be used to extract the
// token byte by byte (the same reasoning as console/auth.go).
//
// The empty-string guard is load-bearing, not defensive noise:
// ConstantTimeCompare("", "") returns 1 — a MATCH — so without it a scan that
// somehow held an empty token would accept a result bearing no token at all, and
// the check would pass for the wrong reason. TestTokenMatchesRejectsEmpty pins it.
func tokenMatches(issued, presented string) bool {
	if issued == "" || presented == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(issued), []byte(presented)) == 1
}
