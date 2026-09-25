package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// TestUpstreamAuthScopedToHost is the security-critical case: the configured
// credential must reach the upstream registry host and NOTHING else. Two servers
// stand in for "the upstream" and "some other host the same client also talks to"
// (deps.dev / the approval service). Auth must appear on the first and be absent on
// the second.
func TestUpstreamAuthScopedToHost(t *testing.T) {
	var upstreamAuth, otherAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth = r.Header.Get("Authorization")
	}))
	defer upstream.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherAuth = r.Header.Get("Authorization")
	}))
	defer other.Close()

	client := &http.Client{Transport: withUpstreamAuth(nil, hostOf(t, upstream.URL), staticCredential("Bearer sekret"))}

	if _, err := client.Get(upstream.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(other.URL); err != nil {
		t.Fatal(err)
	}

	if upstreamAuth != "Bearer sekret" {
		t.Errorf("upstream host: Authorization = %q, want %q", upstreamAuth, "Bearer sekret")
	}
	if otherAuth != "" {
		t.Errorf("non-upstream host: Authorization = %q, want empty — a registry credential must not leak to other hosts", otherAuth)
	}
}

// TestNewFirewallScopesUpstreamAuth checks the wiring end to end: a Firewall built
// with UpstreamAuth set attaches it on its probe client to the configured upstream
// host, and to no other host (deps.dev / approval stand-in).
func TestNewFirewallScopesUpstreamAuth(t *testing.T) {
	var upstreamAuth, otherAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth = r.Header.Get("Authorization")
	}))
	defer upstream.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherAuth = r.Header.Get("Authorization")
	}))
	defer other.Close()

	fw, err := NewFirewall(Config{Ecosystem: "maven", UpstreamRegistry: upstream.URL, UpstreamAuth: "Bearer sekret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.client.Get(upstream.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := fw.client.Get(other.URL); err != nil {
		t.Fatal(err)
	}
	if upstreamAuth != "Bearer sekret" {
		t.Errorf("probe client → upstream: Authorization = %q, want it set", upstreamAuth)
	}
	if otherAuth != "" {
		t.Errorf("probe client → other host: Authorization = %q, want empty (no leak)", otherAuth)
	}
}

// TestUpstreamAuthDisabled verifies the off modes: empty auth (or empty host) makes
// the wrapper a transparent pass-through, so no Authorization is added.
func TestUpstreamAuthDisabled(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
	}))
	defer srv.Close()

	client := &http.Client{Transport: withUpstreamAuth(nil, hostOf(t, srv.URL), staticCredential(""))} // auth off
	if _, err := client.Get(srv.URL); err != nil {
		t.Fatal(err)
	}
	if seen != "" {
		t.Errorf("auth disabled: Authorization = %q, want empty", seen)
	}
}

// TestUpstreamAuthDoesNotOverride verifies a caller's own Authorization is left
// intact (only-if-absent guard), matching userAgentTransport's behaviour.
func TestUpstreamAuthDoesNotOverride(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
	}))
	defer srv.Close()

	client := &http.Client{Transport: withUpstreamAuth(nil, hostOf(t, srv.URL), staticCredential("Bearer ours"))}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer theirs")
	if _, err := client.Do(req); err != nil {
		t.Fatal(err)
	}
	if seen != "Bearer theirs" {
		t.Errorf("Authorization = %q, want the caller's own %q preserved", seen, "Bearer theirs")
	}
}
