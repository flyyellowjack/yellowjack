package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Tests for D158's protocol-scraping step: harvesting the registry's own metadata.
//
// The property under test throughout is NOT "does it parse a packument" — it is that
// every way of having no data stays DISTINGUISHABLE. "Never configured", "the registry
// does not have this package" and "we could not reach the registry" are three
// different operational situations, and the endpoint's own contract says an absent
// field reads as "no problem found". Collapsing any pair of them is the bug.

func npmStub(t *testing.T, status int, body string) (*npmUpstream, *int64) {
	t.Helper()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &npmUpstream{base: srv.URL, http: srv.Client()}, &hits
}

const packument = `{
  "dist-tags": {"latest": "4.17.21"},
  "time": {"4.17.20": "2020-08-13T10:00:00.000Z", "4.17.21": "2021-02-20T15:42:16.891Z"},
  "versions": {"4.17.19": {}, "4.17.20": {}, "4.17.21": {}},
  "maintainers": [{}, {}]
}`

func TestHarvestReadsWhatTheRegistryReports(t *testing.T) {
	f, _ := npmStub(t, http.StatusOK, packument)
	h, avail := harvestUpstream(f, "lodash")
	if avail != availPresent {
		t.Fatalf("availability = %q, want %q", avail, availPresent)
	}
	if h.LatestVersion != "4.17.21" {
		t.Errorf("latest = %q, want 4.17.21", h.LatestVersion)
	}
	if h.VersionCount != 3 {
		t.Errorf("versionCount = %d, want 3", h.VersionCount)
	}
	if h.Maintainers != 2 {
		t.Errorf("maintainers = %d, want 2", h.Maintainers)
	}
	// The publish time must be the LATEST version's, not the first entry in the map —
	// Go map iteration is randomised, so keying off anything but dist-tags.latest
	// would pass most runs and fail some.
	want := time.Date(2021, 2, 20, 15, 42, 16, 891000000, time.UTC)
	if !h.PublishedAt.Equal(want) {
		t.Errorf("publishedAt = %v, want %v (the LATEST version's time, not an arbitrary map entry)",
			h.PublishedAt, want)
	}
}

// TestTheThreeNoDataCasesStayDistinct is the one that matters.
func TestTheThreeNoDataCasesStayDistinct(t *testing.T) {
	// 1. never configured — and it must not make a request at all.
	if h, avail := harvestUpstream(nil, "lodash"); avail != availNotCollected || h != nil {
		t.Errorf("unconfigured: got (%v, %q), want (nil, %q)", h, avail, availNotCollected)
	}

	// 2. the registry does not have it. An ANSWER about the package.
	f404, hits404 := npmStub(t, http.StatusNotFound, `{"error":"Not found"}`)
	if h, avail := harvestUpstream(f404, "no-such-pkg"); avail != availNotInRegistry || h != nil {
		t.Errorf("404: got (%v, %q), want (nil, %q)", h, avail, availNotInRegistry)
	}
	if atomic.LoadInt64(hits404) != 1 {
		t.Error("the 404 case did not actually reach the stub, so it proves nothing")
	}

	// 3. we could not ask. A fact about US, not about the package.
	fdead := &npmUpstream{base: "http://127.0.0.1:1", http: &http.Client{Timeout: time.Second}}
	if h, avail := harvestUpstream(fdead, "lodash"); avail != availUpstreamUnreachable || h != nil {
		t.Errorf("unreachable: got (%v, %q), want (nil, %q)", h, avail, availUpstreamUnreachable)
	}

	// The discriminator: all three must differ. Without this, a harvestUpstream that
	// returned one marker for everything would satisfy each assertion that expected
	// that marker.
	seen := map[string]bool{availNotCollected: true, availNotInRegistry: true, availUpstreamUnreachable: true}
	if len(seen) != 3 {
		t.Fatal("the three no-data markers are not three distinct strings")
	}
}

// TestAnUnreachableRegistryIsNotAnEmptyResult — the same point at the level that bites:
// a failed fetch must not produce a harvest at all, because a half-filled struct would
// render as a package with no maintainers and no versions.
func TestAnUnreachableRegistryIsNotAnEmptyResult(t *testing.T) {
	f, _ := npmStub(t, http.StatusInternalServerError, "upstream exploded")
	h, avail := harvestUpstream(f, "lodash")
	if h != nil {
		t.Errorf("a 500 produced a harvest %+v — rendered, that reads as a real package with "+
			"zero versions and zero maintainers", h)
	}
	if avail != availUpstreamUnreachable {
		t.Errorf("availability = %q, want %q", avail, availUpstreamUnreachable)
	}
}

// TestDeprecationSurvivesNpmsLooseTyping.
//
// The registry documents a string and has served a bare `true`. Reading `true` as
// "not deprecated" would hide a first-party warning from the developer — a miss that
// looks exactly like a healthy package.
func TestDeprecationSurvivesNpmsLooseTyping(t *testing.T) {
	cases := []struct {
		name, raw string
		wantEmpty bool
	}{
		{"a real message", `"use lodash-es instead"`, false},
		{"a bare true", `true`, false},
		{"an explicit false", `false`, true},
		{"absent", ``, true},
	}
	for _, c := range cases {
		got := normalizeDeprecated(json.RawMessage(c.raw))
		if (got == "") != c.wantEmpty {
			t.Errorf("%s: normalizeDeprecated(%s) = %q, wantEmpty=%v", c.name, c.raw, got, c.wantEmpty)
		}
	}
	// End to end, so the field is actually reached from a packument rather than only
	// from the helper.
	f, _ := npmStub(t, http.StatusOK, `{"dist-tags":{"latest":"1.0.0"},
		"versions":{"1.0.0":{"deprecated":"do not use"}},"maintainers":[]}`)
	h, _ := harvestUpstream(f, "abandoned")
	if h == nil || !strings.Contains(h.Deprecated, "do not use") {
		t.Errorf("the deprecation message did not survive the parse: %+v", h)
	}
}

// TestScopedNamesReachTheRegistryInNpmsOwnSpelling. npm addresses "@scope/name" as
// "@scope%2fname"; sending the bare slash asks for a path that does not exist, and the
// 404 would render as "not in the registry" — a wrong answer that looks like a real one.
func TestScopedNamesReachTheRegistryInNpmsOwnSpelling(t *testing.T) {
	var asked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.EscapedPath()
		_, _ = w.Write([]byte(packument))
	}))
	t.Cleanup(srv.Close)
	f := &npmUpstream{base: srv.URL, http: srv.Client()}
	if _, _, err := f.Fetch("@babel/core"); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !strings.Contains(strings.ToLower(asked), "%2f") {
		t.Errorf("requested path = %q; the scope separator must be escaped or the registry 404s "+
			"and the page reports a real package as missing", asked)
	}
}

// TestAHostileRegistryResponseCannotExhaustUs — the adversarial tier. Whoever controls
// the registry response controls this document, and a security product must not be
// knocked over by one.
//
// ⚠️ THE OBVIOUS VERSION OF THIS TEST IS DECORATION, and a sabotage run is what proved
// it. The first version asserted only that the fetch RETURNS AN ERROR on an oversized
// body. It does — with or without the cap — because a truncated document and a
// complete-but-huge one both fail to parse for other reasons. Replacing
// io.LimitReader with the raw body turned nothing red.
//
// So this asserts the property that actually matters: HOW MANY BYTES WE CONSUMED. The
// payload below is deliberately VALID JSON all the way down (duplicate keys are legal),
// so a streaming decoder has no syntax error to stop at and will read every byte it is
// offered. With the cap, the client stops near it and the server's remaining writes
// fail on a closed connection.
func TestAHostileRegistryResponseCannotExhaustUs(t *testing.T) {
	const chunkRepeat = 4096 // ~45 KB per write
	const offered = 4096     // writes attempted => ~180 MB offered
	var written int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n, _ := w.Write([]byte(`{"dist-tags":{"latest":"1.0.0"},"versions":{`))
		atomic.AddInt64(&written, int64(n))
		chunk := []byte(strings.Repeat(`"1.0.0":{},`, chunkRepeat))
		for i := 0; i < offered; i++ {
			n, err := w.Write(chunk)
			atomic.AddInt64(&written, int64(n))
			if err != nil {
				return // the client hung up: the cap did its job
			}
		}
	}))
	t.Cleanup(srv.Close)
	f := &npmUpstream{base: srv.URL, http: srv.Client()}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, _, err := f.Fetch("huge"); err == nil {
			t.Error("a truncated document parsed successfully")
		}
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("the fetch did not return")
	}

	got := atomic.LoadInt64(&written)
	// Generous ceiling: socket/proxy buffering lets the server get a few MB ahead of the
	// reader. 64 MB is far below the ~180 MB on offer, so this discriminates between
	// "bounded" and "read everything" without being flaky.
	//
	// The ceiling is UNCHANGED by #152, deliberately. The npm read became a stream with a
	// 256 MB byte budget, which on its own would let this registry send everything it has --
	// but this document is endless `"1.0.0":{},` entries, and the stream also bounds how
	// many versions it will COUNT (npmMaxCountedEntries). That bound stops the read at about
	// 3 MB, so the property this test protects got tighter, not looser.
	const ceiling = 64 << 20
	if got > ceiling {
		t.Errorf("the server got to write %d bytes; the cap is %d, so anything near the %d "+
			"offered means the read is unbounded — a memory-exhaustion lever held by whoever "+
			"controls the registry response", got, upstreamMaxBytes, chunkRepeat*11*offered)
	}
	// ANTI-VACUITY: if the server barely wrote anything the ceiling above is satisfied
	// for the wrong reason (a connection that failed instantly, a stub that never ran).
	//
	// The floor is derived from the mechanism that now ends the read: the reader cannot
	// give up before it has been sent npmMaxCountedEntries entries of 11 bytes each. (It
	// was upstreamMaxBytes/2 while a byte cap ended the read; leaving that number would
	// have failed this test for stopping EARLIER, which is the improvement.)
	const entryBytes = int64(len(`"1.0.0":{},`))
	if floor := npmMaxCountedEntries * entryBytes / 2; got < floor {
		t.Errorf("the server only wrote %d bytes, under the %d the count bound implies — the hostile case "+
			"was never actually exercised, so the ceiling assertion proves nothing", got, floor)
	}
}

// TestTheFetcherIsOffUnlessConfigured pins the shipped default. An existing deployment
// must not acquire a new egress destination by upgrading.
func TestTheFetcherIsOffUnlessConfigured(t *testing.T) {
	t.Setenv("APPROVAL_UPSTREAM_NPM", "")
	if f := newUpstreamFetcher("npm"); f != nil {
		t.Error("a fetcher was built with no registry configured — every existing deployment " +
			"would start making outbound calls it never asked for, against the zero-egress " +
			"posture that is the stated differentiator (D155/D26)")
	}
	t.Setenv("APPROVAL_UPSTREAM_NPM", "https://registry.example.invalid")
	if f := newUpstreamFetcher("npm"); f == nil {
		t.Error("no fetcher was built even though a registry IS configured — the assertion " +
			"above would then pass for the wrong reason")
	}
	// PyPI is implemented now, and carries the SAME off-by-default contract. Its own
	// variable, not a shared one: an operator running an internal npm mirror has not
	// thereby authorised calls to a Python index.
	t.Setenv("APPROVAL_UPSTREAM_PYPI", "")
	if f := newUpstreamFetcher("pypi"); f != nil {
		t.Error("a PyPI fetcher was built with no index configured")
	}
	t.Setenv("APPROVAL_UPSTREAM_PYPI", "https://pypi.example.invalid/pypi")
	if f := newUpstreamFetcher("pypi"); f == nil {
		t.Error("no PyPI fetcher was built even though an index IS configured")
	}
	// Configuring npm must not switch PyPI on, or the per-ecosystem opt-in is a
	// fiction. This is the assertion that would catch a shared env var.
	t.Setenv("APPROVAL_UPSTREAM_PYPI", "")
	if f := newUpstreamFetcher("pypi"); f != nil {
		t.Error("PyPI is on while only npm is configured — the ecosystems share a switch, " +
			"so enabling one silently enables the other's egress")
	}
	// Ecosystems with no implementation must still be nil rather than half-built.
	for _, eco := range []string{"maven", "oci", "cargo"} {
		if f := newUpstreamFetcher(eco); f != nil {
			t.Errorf("%s returned a fetcher, but no harvest is implemented for it", eco)
		}
	}
}
