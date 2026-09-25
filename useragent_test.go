package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestUserAgentTransportSetsWhenEmpty is the regression guard for the maven 429:
// a firewall-originated fetch with no User-Agent must go out carrying ours (Maven
// Central 429s Go's default "Go-http-client/1.1").
func TestUserAgentTransportSetsWhenEmpty(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	client := &http.Client{Transport: withUserAgent(nil)}
	resp, err := client.Get(srv.URL) // c.Get sets no UA — the transport must add ours
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if got != userAgent {
		t.Errorf("User-Agent = %q, want %q", got, userAgent)
	}
}

// TestUserAgentTransportPreservesExisting guards the proxy-forwarding case: a
// request that already carries a User-Agent (a real client's, forwarded upstream)
// must pass through untouched.
func TestUserAgentTransportPreservesExisting(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	client := &http.Client{Transport: withUserAgent(nil)}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("User-Agent", "caller/9.9")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if got != "caller/9.9" {
		t.Errorf("User-Agent = %q, want the caller's UA preserved", got)
	}
}
