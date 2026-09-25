package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// Issue #108. The relay's truncation guard compared bytes copied against the upstream
// Content-Length, which is right for a GET and wrong for a HEAD: a HEAD response has no
// body by definition while Content-Length still advertises the size the GET would
// return. Every HEAD therefore looked like a short transfer and the guard aborted the
// handler.
//
// Found by standing up the registry-in-front topology (#98 / D177) for the first time:
// `docker pull` through a registry:2 pull-through cache failed with "not found", and the
// firewall log said "copied 0 of 8077 bytes" for the manifest HEAD.
//
// These drive a REAL server and a REAL client rather than httptest.NewRecorder, because
// the failure is panic(http.ErrAbortHandler), which a recorder does not model. What the
// client sees is a broken connection, and that is the symptom being asserted away.

// bodylessRelayFixture stands a firewall in front of a fake upstream, configured to
// allow everything so the only thing under test is the relay's byte accounting.
func bodylessRelayFixture(t *testing.T, upstream http.Handler) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)

	cfg := Config{
		Ecosystem:        "oci",
		UpstreamRegistry: up.URL,
		FilesUpstream:    up.URL,
		UnscorablePolicy: "allow",
		UnverifiedPolicy: "open-with-visibility",
		ScoreThreshold:   0,
		ScorecardMode:    "stub",
		ScoreCacheTTL:    time.Minute,
		ByteGate:         "off",
	}
	fw, err := NewFirewall(cfg)
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	fwSrv := httptest.NewServer(newProxyServer(cfg, fw))
	t.Cleanup(fwSrv.Close)
	return fwSrv
}

func TestHeadIsNotTreatedAsATruncatedTransfer(t *testing.T) {
	const manifest = `{"schemaVersion":2,"layers":[]}`

	up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Exactly what a registry does for HEAD: advertise the length the GET would
		// return, and send no body. net/http suppresses the body for HEAD itself.
		w.Header().Set("Content-Length", strconv.Itoa(len(manifest)))
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, manifest)
		}
	})
	fw := bodylessRelayFixture(t, up)

	req, err := http.NewRequest(http.MethodHead, fw.URL+"/v2/library/alpine/manifests/3.19", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HEAD through the relay failed at the transport level: %v\n"+
			"That is issue #108: the truncation guard aborted the handler because a "+
			"bodyless response copied 0 bytes against a non-zero Content-Length. A "+
			"pull-through cache reports this to the user as \"not found\".", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("HEAD status = %d, want 200", resp.StatusCode)
	}
	// The Content-Length must survive: a pull-through cache reads it to size the GET it
	// is about to make, so silently zeroing it would trade one bug for a subtler one.
	if got, want := resp.Header.Get("Content-Length"), strconv.Itoa(len(manifest)); got != want {
		t.Errorf("Content-Length = %q, want %q — the header a HEAD exists to deliver", got, want)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("HEAD returned %d body bytes, want 0", len(body))
	}
}

// TestShortGetIsStillTreatedAsTruncated is the negative control, and it is why the fix
// is narrow. Excusing a zero-byte copy for HEAD must not excuse a GET that really was
// cut short — the corrupt-but-2xx artifact the guard was added for. Without this,
// deleting the guard outright would pass the test above.
func TestShortGetIsStillTreatedAsTruncated(t *testing.T) {
	up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "8077")     // promise 8077...
		w.WriteHeader(http.StatusOK)                 //
		_, _ = io.WriteString(w, "only-a-few-bytes") // ...deliver 16
	})
	fw := bodylessRelayFixture(t, up)

	resp, err := http.Get(fw.URL + "/v2/library/alpine/manifests/3.19")
	if err != nil {
		return // the abort surfaced as a transport error, which is the intended outcome
	}
	defer resp.Body.Close()
	if _, rerr := io.ReadAll(resp.Body); rerr == nil {
		t.Fatal("a GET that delivered 16 of a promised 8077 bytes was relayed as a clean " +
			"success. That is the corrupt-but-2xx case the truncation guard exists to " +
			"catch, so the #108 fix has widened past HEAD.")
	}
}

func TestBodylessResponseIsNarrow(t *testing.T) {
	cases := []struct {
		name   string
		method string
		status int
		want   bool
	}{
		{"HEAD is bodyless whatever the status", http.MethodHead, http.StatusOK, true},
		{"204 has no content by definition", http.MethodGet, http.StatusNoContent, true},
		{"304 has no content by definition", http.MethodGet, http.StatusNotModified, true},
		{"a plain GET 200 is NOT excused", http.MethodGet, http.StatusOK, false},
		{"a 302 is NOT excused — redirects may carry a body", http.MethodGet, http.StatusFound, false},
		{"a 403 is NOT excused — block bodies carry the reason", http.MethodGet, http.StatusForbidden, false},
		{"a 206 partial is NOT excused", http.MethodGet, http.StatusPartialContent, false},
	}
	seenTrue, seenFalse := false, false
	for _, tc := range cases {
		got := bodylessResponse(tc.method, tc.status)
		if got != tc.want {
			t.Errorf("%s: bodylessResponse(%q, %d) = %v, want %v",
				tc.name, tc.method, tc.status, got, tc.want)
		}
		if got {
			seenTrue = true
		} else {
			seenFalse = true
		}
	}
	// Anti-vacuity: a predicate that always answered the same way would satisfy half
	// this table silently.
	if !seenTrue || !seenFalse {
		t.Error("the predicate never disagreed across the table, so it is not discriminating")
	}
}
