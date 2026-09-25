package main

import "net/http"

// userAgent identifies the firewall on every request it makes to an upstream
// registry or scoring source. It MUST be a real, non-default value: Maven Central
// (served by Fastly) throttles Go's default "Go-http-client/1.1" User-Agent with
// HTTP 429, so a firewall that doesn't identify itself literally cannot fetch
// maven-metadata.xml — every evaluate hits 429 -> 503 and no maven package resolves.
// (npm/PyPI/OCI upstreams tolerate the default UA, which is why only maven broke.)
const userAgent = "yellowjack-firewall/0.1 (+https://github.com/flyyellowjack/yellowjack)"

// userAgentTransport is an http.RoundTripper that stamps userAgent onto any
// outbound request that does not already carry one. We wrap the transport instead
// of editing every call site so EVERY fetch the firewall makes — maven-metadata,
// POMs, npm/pypi metadata, OCI manifests — identifies itself, with no way to add a
// new c.Get() that forgets to. Requests the proxy forwards on a client's behalf
// already carry that client's real User-Agent, so the "only if empty" guard leaves
// them untouched.
type userAgentTransport struct {
	base http.RoundTripper
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		// The RoundTripper contract forbids mutating the caller's request, so clone
		// it before adding the header.
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", userAgent)
	}
	return t.base.RoundTrip(req)
}

// withUserAgent wraps base so its requests carry our User-Agent. A nil base means
// http.DefaultTransport (the common case for our simple clients).
func withUserAgent(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &userAgentTransport{base: base}
}
