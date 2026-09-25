package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---- the token primitive -----------------------------------------------------

func TestCapabilityTokensAreUnguessable(t *testing.T) {
	const n = 200
	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		tok, err := newCapabilityToken()
		if err != nil {
			t.Fatalf("newCapabilityToken: %v", err)
		}
		if seen[tok] {
			t.Fatalf("token %q issued twice — tokens must never repeat", tok)
		}
		seen[tok] = true

		// The entropy is the whole point: a short or truncated token would still
		// "work" in every functional test while being brute-forceable.
		raw, err := base64.RawURLEncoding.DecodeString(tok)
		if err != nil {
			t.Fatalf("token %q is not base64url: %v", tok, err)
		}
		if len(raw) != tokenBytes {
			t.Fatalf("token carries %d bytes of entropy, want %d", len(raw), tokenBytes)
		}
		// Must be a single path segment, since it is used as one.
		if strings.ContainsAny(tok, "/+=") {
			t.Fatalf("token %q is not URL-path-safe", tok)
		}
	}
}

func TestTokenMatches(t *testing.T) {
	issued, err := newCapabilityToken()
	if err != nil {
		t.Fatalf("newCapabilityToken: %v", err)
	}
	other, err := newCapabilityToken()
	if err != nil {
		t.Fatalf("newCapabilityToken: %v", err)
	}

	if !tokenMatches(issued, issued) {
		t.Error("the issued token must match itself")
	}
	if tokenMatches(issued, other) {
		t.Error("a different token must not match")
	}
	if tokenMatches(issued, issued[:len(issued)-1]) {
		t.Error("a truncated token must not match")
	}
	if tokenMatches(issued, issued+"x") {
		t.Error("an extended token must not match")
	}
}

// The guard that makes the empty case safe. subtle.ConstantTimeCompare("", "")
// returns 1 — a MATCH — so without the explicit empty check a scan holding an empty
// token would accept a result bearing no token, and every other test here would
// still pass. This is the "silently passes for the wrong reason" case, pinned.
func TestTokenMatchesRejectsEmpty(t *testing.T) {
	cases := []struct{ issued, presented string }{
		{"", ""},
		{"", "anything"},
		{"real-token", ""},
	}
	for _, c := range cases {
		if tokenMatches(c.issued, c.presented) {
			t.Errorf("tokenMatches(%q, %q) = true, want false", c.issued, c.presented)
		}
	}
}

func TestSplitResultPath(t *testing.T) {
	cases := []struct {
		path, id, token string
		ok              bool
	}{
		{"/results/7-abc/tok123", "7-abc", "tok123", true},
		{"/results/7-abc", "", "", false},  // the pre-token, forgeable shape
		{"/results/7-abc/", "", "", false}, // empty token
		{"/results//tok123", "", "", false},
		{"/results/", "", "", false},
		{"/results/a/b/c", "", "", false}, // tokens are one segment; never lenient
	}
	for _, c := range cases {
		id, token, ok := splitResultPath(c.path)
		if ok != c.ok || id != c.id || token != c.token {
			t.Errorf("splitResultPath(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.path, id, token, ok, c.id, c.token, c.ok)
		}
	}
}

// ---- end-to-end: a forged result must never reach the waiting /scan ----------

// tamperingLauncher plays the attacker: it POSTs a perfect-score report to the
// pending scan's id but with the capability token replaced (or dropped entirely) —
// which is precisely what anyone who can reach the scheduler could do, since the id
// is a counter plus a timestamp. It records the status the sink gave it.
type tamperingLauncher struct {
	dropToken   bool   // POST to /results/{id} with no token segment at all
	wrongToken  string // otherwise, substitute this token
	sinkStatus  chan int
	forgedScore float64
}

func (l *tamperingLauncher) Launch(ctx context.Context, repo, sinkURL string) error {
	slash := strings.LastIndexByte(sinkURL, '/')
	target := sinkURL[:slash+1] + l.wrongToken
	if l.dropToken {
		target = sinkURL[:slash]
	}
	go func() {
		body, _ := json.Marshal(scanReport{
			Repo:   repo,
			Result: &scanResult{Repo: repo, Score: l.forgedScore},
		})
		resp, err := http.Post(target, "application/json", bytes.NewReader(body))
		if err != nil {
			l.sinkStatus <- 0
			return
		}
		resp.Body.Close()
		l.sinkStatus <- resp.StatusCode
	}()
	return nil
}

func TestForgedResultWithWrongTokenIsRejected(t *testing.T) {
	// A wrong token of the same length as a real one, so the rejection can't be
	// attributed to a length check alone.
	sameLengthToken, err := newCapabilityToken()
	if err != nil {
		t.Fatalf("newCapabilityToken: %v", err)
	}
	l := &tamperingLauncher{wrongToken: sameLengthToken, sinkStatus: make(chan int, 1), forgedScore: 10}
	_, ts := newTestScheduler(t, l, 400*time.Millisecond)

	resp := postScan(t, ts, "github.com/evil/pkg")
	defer resp.Body.Close()

	// The forgery is refused at the sink...
	select {
	case status := <-l.sinkStatus:
		if status != http.StatusForbidden {
			t.Errorf("sink accepted a forged result with status %d, want 403", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("forged POST never completed")
	}

	// ...and, the part that actually matters: the score never reached the waiter, so
	// /scan times out instead of returning 10.0 for a malicious package.
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504 — a forged score must not satisfy /scan", resp.StatusCode)
	}
	var got scanResult
	if json.NewDecoder(resp.Body).Decode(&got) == nil && got.Score == 10 {
		t.Fatal("the forged score was served to the firewall")
	}
}

// The pre-token URL shape is not merely unauthenticated — it no longer exists.
func TestForgedResultWithoutTokenIsRejected(t *testing.T) {
	l := &tamperingLauncher{dropToken: true, sinkStatus: make(chan int, 1), forgedScore: 10}
	_, ts := newTestScheduler(t, l, 400*time.Millisecond)

	resp := postScan(t, ts, "github.com/evil/pkg")
	defer resp.Body.Close()

	select {
	case status := <-l.sinkStatus:
		if status != http.StatusBadRequest {
			t.Errorf("tokenless POST got status %d, want 400", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tokenless POST never completed")
	}
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", resp.StatusCode)
	}
}

// The honest path: the token the scheduler put in the sink URL is accepted, and the
// sink URL really does carry a full-entropy token (not, say, a reused id).
func TestSinkURLCarriesTheCapabilityToken(t *testing.T) {
	report := scanReport{Repo: "r", Result: &scanResult{Repo: "r", Score: 8.2}}
	l := &sinkRecordingLauncher{report: report, seen: make(chan string, 1)}
	_, ts := newTestScheduler(t, l, 5*time.Second)

	resp := postScan(t, ts, "r")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 — the real token must be accepted", resp.StatusCode)
	}

	sinkURL := <-l.seen
	path := strings.TrimPrefix(sinkURL, ts.URL)
	id, token, ok := splitResultPath(path)
	if !ok {
		t.Fatalf("sink path %q is not /results/{id}/{token}", path)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != tokenBytes {
		t.Errorf("sink token %q is not a %d-byte random token", token, tokenBytes)
	}
	if token == id {
		t.Error("the sink token must not be the (guessable) scan id")
	}
}

// sinkRecordingLauncher behaves like a well-behaved container — it POSTs to the sink
// URL verbatim — and also hands the URL back to the test.
type sinkRecordingLauncher struct {
	report scanReport
	seen   chan string
}

func (l *sinkRecordingLauncher) Launch(ctx context.Context, repo, sinkURL string) error {
	select {
	case l.seen <- sinkURL:
	default:
	}
	go func() {
		body, _ := json.Marshal(l.report)
		resp, err := http.Post(sinkURL, "application/json", bytes.NewReader(body))
		if err == nil {
			resp.Body.Close()
		}
	}()
	return nil
}
