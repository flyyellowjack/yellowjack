package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestClassifyStatusRateLimited pins the D25 taxonomy split: a 429 maps to the
// distinct errUpstreamRateLimited sentinel, while a 5xx stays the generic
// errUpstreamUnavailable. Crucially, the rate-limited sentinel WRAPS the generic
// one, so every existing errors.Is(..., errUpstreamUnavailable) transient check
// still fires — the 429 is still a retryable 503 (D17), only worded differently.
func TestClassifyStatusRateLimited(t *testing.T) {
	rl := classifyStatus(http.StatusTooManyRequests)
	if !errors.Is(rl, errUpstreamRateLimited) {
		t.Errorf("classifyStatus(429) = %v, want errUpstreamRateLimited", rl)
	}
	if !errors.Is(rl, errUpstreamUnavailable) {
		t.Error("errUpstreamRateLimited must still satisfy errors.Is(errUpstreamUnavailable) so the D17 503 routing is unchanged")
	}

	// A 5xx is transient but NOT rate-limited: it must not pick up the 429 wording.
	unavail := classifyStatus(http.StatusBadGateway)
	if !errors.Is(unavail, errUpstreamUnavailable) {
		t.Errorf("classifyStatus(502) = %v, want errUpstreamUnavailable", unavail)
	}
	if errors.Is(unavail, errUpstreamRateLimited) {
		t.Error("a 5xx must not be classified as rate-limited (would misname the outage)")
	}
}

// TestEvaluate429ReasonNamesRateLimit is the end-to-end D25 assertion: when our own
// metadata probe is rate-limited (429), the client-facing Decision is a retryable
// Unavailable (503) whose reason explicitly names the upstream rate limit and HTTP
// 429 — so a developer can tell throttling from a registry outage. A 5xx outage is
// the control: still Unavailable, but WITHOUT the rate-limit wording.
func TestEvaluate429ReasonNamesRateLimit(t *testing.T) {
	newFW := func(status int) *Firewall {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		}))
		t.Cleanup(up.Close)
		f, err := NewFirewall(Config{
			Ecosystem:        "npm",
			UpstreamRegistry: up.URL,
			ScorecardMode:    "stub",
			ScoreThreshold:   5.0,
			UnscorablePolicy: "block",
			ScoreCacheTTL:    time.Minute,
		})
		if err != nil {
			t.Fatalf("NewFirewall: %v", err)
		}
		return f
	}

	// 429: Unavailable, and the reason names the rate limit + HTTP 429.
	d := newFW(http.StatusTooManyRequests).Evaluate("left-pad")
	if !d.Unavailable {
		t.Fatalf("429 metadata: Unavailable=%v, want true (reason: %s)", d.Unavailable, d.Reason)
	}
	if !strings.Contains(d.Reason, "rate limited") || !strings.Contains(d.Reason, "429") {
		t.Errorf("429 reason = %q, want it to name the upstream rate limit and HTTP 429", d.Reason)
	}

	// 503 outage: still Unavailable, but must NOT claim a rate limit.
	d = newFW(http.StatusServiceUnavailable).Evaluate("left-pad")
	if !d.Unavailable {
		t.Fatalf("503 metadata: Unavailable=%v, want true (reason: %s)", d.Unavailable, d.Reason)
	}
	if strings.Contains(d.Reason, "rate limited") || strings.Contains(d.Reason, "429") {
		t.Errorf("503 outage reason = %q, must not misname a generic outage as rate limiting", d.Reason)
	}
}
