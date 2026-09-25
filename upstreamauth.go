package main

import "net/http"

// probeAuthTransport attaches an Authorization header to the firewall's OWN outbound
// probe requests to the upstream registry — and ONLY that host. Authenticating
// ourselves to Maven Central/Sonatype/npm raises the anonymous per-IP rate ceiling
// that a cold resolve's probe fan-out otherwise trips (D25 item e); on shared-IP CI
// runners this is the real fix for the maven 429 flake the probe caches only soften.
//
// The header is scoped to exactly the configured upstream host — a hard security
// requirement. The same http.Client also talks to deps.dev (scoring) and the approval
// service, and an upstream can 3xx to a CDN on another host; sending a registry
// credential to any of those would leak it. The per-request host check attaches the
// header only when req.URL.Host matches, so cross-host redirects silently drop it
// (which is also what net/http's own client does for cross-host redirects).
//
// Mirrors userAgentTransport: clone before mutating (a RoundTripper must not touch the
// caller's request) and only set the header when absent, so a caller that set its own
// Authorization wins.
type probeAuthTransport struct {
	base http.RoundTripper
	host string // upstream registry host (URL.Host, incl. port if any); "" disables
	// auth yields the current Authorization header value, e.g. "Bearer …" or
	// "Basic …"; nil, or a source returning "", disables.
	//
	// CONSULTED PER REQUEST, not captured once (issue #53). An upstream that mints
	// short-lived tokens — AWS CodeArtifact under D177 — rotates the credential
	// during the process's lifetime, and a value read at startup expires with the
	// gate still running. See upstreamcred.go for the sources and for why a failed
	// re-read keeps the last good value rather than blanking it.
	auth credentialSource
}

func (t *probeAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.auth != nil && t.host != "" && req.URL.Host == t.host && req.Header.Get("Authorization") == "" {
		// Ordered so the credential is fetched only after the host has matched: the
		// source can touch the filesystem, and every request to deps.dev or the
		// approval service goes through this same transport.
		if v := t.auth(); v != "" {
			req = req.Clone(req.Context())
			req.Header.Set("Authorization", v)
		}
	}
	return t.base.RoundTrip(req)
}

// withUpstreamAuth wraps base so probe requests to host carry the Authorization value
// yielded by auth. A nil base means http.DefaultTransport. When auth is nil or host is
// empty the wrapper is a transparent pass-through (the feature is simply off), so
// callers need no conditional and tests that omit auth are unaffected.
func withUpstreamAuth(base http.RoundTripper, host string, auth credentialSource) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &probeAuthTransport{base: base, host: host, auth: auth}
}
