package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// PyPI's half of D158's protocol-scraping step.
//
// The npm tests pin the shape of the contract; these pin what is DIFFERENT about
// PyPI, because that is where a copy-paste of the npm fetcher would go wrong:
//
//   - the document is a project JSON at /<name>/json, not a packument at /<name>
//   - "deprecated" has no equivalent; the analogue is a per-release YANK (PEP 592)
//   - the publish time lives in urls[], not in a version -> time map
//   - maintainers are free-text prose, not a countable list

func pypiStub(t *testing.T, status int, body string) (*pypiUpstream, *int64, *string) {
	t.Helper()
	var hits int64
	var lastPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		lastPath = r.URL.Path
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &pypiUpstream{base: srv.URL, http: srv.Client()}, &hits, &lastPath
}

const projectJSON = `{
  "info": {"version": "2.31.0", "yanked": false, "yanked_reason": null},
  "releases": {"2.29.0": [], "2.30.0": [], "2.31.0": []},
  "urls": [{"upload_time_iso_8601": "2023-05-22T15:12:42.123456Z"}]
}`

func TestPypiHarvestReadsWhatTheIndexReports(t *testing.T) {
	f, _, path := pypiStub(t, http.StatusOK, projectJSON)
	h, avail := harvestUpstream(f, "requests")
	if avail != availPresent {
		t.Fatalf("availability = %q, want %q", avail, availPresent)
	}
	if h.LatestVersion != "2.31.0" {
		t.Errorf("latest = %q, want 2.31.0", h.LatestVersion)
	}
	if h.VersionCount != 3 {
		t.Errorf("versionCount = %d, want 3 (the releases map's keys)", h.VersionCount)
	}
	want := time.Date(2023, 5, 22, 15, 12, 42, 123456000, time.UTC)
	if !h.PublishedAt.Equal(want) {
		t.Errorf("publishedAt = %v, want %v", h.PublishedAt, want)
	}
	// The JSON API, not /simple/. /simple/ is the installer protocol (PEP 503) and is
	// a bare list of links — none of the fields above exist there, so a fetcher
	// pointed at it would return an empty harvest that renders as a healthy package.
	if !strings.HasSuffix(*path, "/requests/json") {
		t.Errorf("requested %q, want the project JSON document at /<name>/json", *path)
	}
}

// TestAYankedReleaseIsSurfacedAsTheMaintainersWarning.
//
// A yank is PyPI's deprecation signal, and it is the most actionable line the page
// can carry: the maintainer is saying "do not install this". It renders through the
// same Deprecated field so it lands in the console's callout rather than in the
// muted availability style.
func TestAYankedReleaseIsSurfacedAsTheMaintainersWarning(t *testing.T) {
	const yanked = `{
	  "info": {"version": "1.0.1", "yanked": true, "yanked_reason": "ships a backdoor"},
	  "releases": {"1.0.0": [], "1.0.1": []},
	  "urls": []
	}`
	f, _, _ := pypiStub(t, http.StatusOK, yanked)
	h, avail := harvestUpstream(f, "evil")
	if avail != availPresent {
		t.Fatalf("availability = %q, want present", avail)
	}
	if !strings.Contains(h.Deprecated, "ships a backdoor") {
		t.Errorf("the yank reason is absent from the harvest (got %q) — the maintainer's own "+
			"words are the most useful thing on the page", h.Deprecated)
	}
	if !strings.Contains(h.Deprecated, "yanked") {
		t.Errorf("the harvest does not say the release was YANKED (got %q); without the word, "+
			"a reader cannot tell this from an ordinary deprecation note", h.Deprecated)
	}
}

// TestAYankWithNoReasonStillWarns — the silent case. PEP 592 allows a yank with a
// null reason, and reading "no reason given" as "not yanked" would drop the warning
// entirely. Same reasoning as normalizeDeprecated's handling of a bare `true`.
func TestAYankWithNoReasonStillWarns(t *testing.T) {
	const yankedNoReason = `{
	  "info": {"version": "1.0.1", "yanked": true, "yanked_reason": null},
	  "releases": {"1.0.1": []},
	  "urls": []
	}`
	f, _, _ := pypiStub(t, http.StatusOK, yankedNoReason)
	h, _ := harvestUpstream(f, "quiet")
	if h.Deprecated == "" {
		t.Error("a yanked release with a null reason produced no warning at all, so the page " +
			"renders it as a healthy package")
	}
	if !strings.Contains(h.Deprecated, "no reason given") {
		t.Errorf("the harvest does not distinguish 'yanked, reason withheld' from a reason we "+
			"failed to read (got %q)", h.Deprecated)
	}
}

// TestAnUnyankedReleaseCarriesNoWarning is the NEGATIVE CONTROL for the two above.
// Both would pass against a fetcher that stamped a warning on every package.
func TestAnUnyankedReleaseCarriesNoWarning(t *testing.T) {
	f, _, _ := pypiStub(t, http.StatusOK, projectJSON)
	h, _ := harvestUpstream(f, "requests")
	if h.Deprecated != "" {
		t.Errorf("a healthy package carries a maintainer warning (%q) — the yank tests above "+
			"would pass for a fetcher that warns about everything", h.Deprecated)
	}
}

// TestPypiThreeNoDataCasesStayDistinct — the property the whole file exists for,
// re-asserted for this ecosystem rather than assumed to carry over.
func TestPypiThreeNoDataCasesStayDistinct(t *testing.T) {
	if _, avail := harvestUpstream(nil, "requests"); avail != availNotCollected {
		t.Errorf("unconfigured = %q, want %q", avail, availNotCollected)
	}
	f, _, _ := pypiStub(t, http.StatusNotFound, `{"message": "Not Found"}`)
	if h, avail := harvestUpstream(f, "reqeusts"); avail != availNotInRegistry || h != nil {
		t.Errorf("404 = %q/%v, want %q/nil — a typo is an ANSWER, not a failure", avail, h, availNotInRegistry)
	}
	f, _, _ = pypiStub(t, http.StatusInternalServerError, `nope`)
	if h, avail := harvestUpstream(f, "requests"); avail != availUpstreamUnreachable || h != nil {
		t.Errorf("500 = %q/%v, want %q/nil — an index failure must not render like a clean result",
			avail, h, availUpstreamUnreachable)
	}
}

// TestAHostilePypiIndexCannotExhaustUs — the adversarial tier, and the same lever the
// npm fetcher is capped against: whoever controls the index response controls how
// many bytes we read.
func TestAHostilePypiIndexCannotExhaustUs(t *testing.T) {
	const offered = upstreamMaxBytes * 4
	var served int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"info":{"version":"1.0.0"},"releases":{"1.0.0":[]},"urls":[],"junk":"`))
		chunk := make([]byte, 64<<10)
		for i := range chunk {
			chunk[i] = 'A'
		}
		for written := int64(0); written < offered; written += int64(len(chunk)) {
			n, err := w.Write(chunk)
			atomic.AddInt64(&served, int64(n))
			if err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	// Count what WE actually read, by wrapping the response body on its way to the
	// fetcher. This is the invariant the cap states, and it is exact.
	//
	// It replaces an assertion on `served` -- the bytes the SERVER managed to write --
	// which is a different quantity and is what made this test flaky (#111). A peer can
	// push megabytes into socket and transport buffers before our reader stops and the
	// connection closes, so `served` measures the environment's buffer sizes, not our
	// limit. Three CI failures clustered at 2.16-2.21x the cap against a 2x ceiling,
	// while the same code passed on the dev host: that spread is buffering, and tuning
	// the multiplier would just fit a constant to one runner's TCP settings.
	var consumed int64
	client := srv.Client()
	client.Transport = countingTransport{base: client.Transport, n: &consumed}

	f := &pypiUpstream{base: srv.URL, http: client}
	_, _, _ = f.Fetch("huge")

	// THE REAL ASSERTION. io.LimitReader stops at exactly upstreamMaxBytes, so anything
	// above it means the cap is not in the read path at all -- no slack needed, and no
	// environment can move it.
	consumedBytes := atomic.LoadInt64(&consumed)
	if consumedBytes > upstreamMaxBytes {
		t.Errorf("consumed %d bytes of the %d offered; the %d-byte cap is not bounding the read",
			consumedBytes, offered, upstreamMaxBytes)
	}
	// ANTI-VACUITY on the assertion above, and it is not theoretical: "consumed <= cap"
	// is also satisfied by consuming NOTHING, so a connection that failed for an
	// unrelated reason would pass the exact check while proving nothing about the cap.
	// The decoder reads until LimitReader reports EOF, so a healthy run lands ON the cap.
	if consumedBytes < upstreamMaxBytes/2 {
		t.Errorf("consumed only %d bytes, far below the %d-byte cap: the read stopped "+
			"for some reason OTHER than the cap, so this test is not exercising it",
			consumedBytes, upstreamMaxBytes)
	}

	got := atomic.LoadInt64(&served)
	// The server-side count is kept, but ONLY as the coarse "we hung up early" check it
	// actually is -- labelled honestly, and with the generous ceiling the npm twin
	// already uses for the same reason. It discriminates "bounded" from "read
	// everything" without pretending to measure our cap.
	if got >= offered {
		t.Errorf("the server wrote all %d bytes it offered, so nothing ever hung up on it; "+
			"the read was not bounded at any level", offered)
	}
	// Anti-vacuity: if the server never got to write, the ceiling assertion is
	// satisfied by a connection that failed for an unrelated reason.
	if got < 64<<10 {
		t.Errorf("only %d bytes were served, so the cap was never exercised and the "+
			"assertion above proves nothing", got)
	}
}

// countingTransport counts the bytes a client actually READS from a response body.
//
// It exists because "how many bytes did the peer send" and "how many bytes did we read"
// are different numbers, and only the second one is what a read cap bounds (#111). A test
// that asserts the first while claiming the second is measuring the environment.
type countingTransport struct {
	base http.RoundTripper
	n    *int64
}

func (t countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if err != nil || resp == nil || resp.Body == nil {
		return resp, err
	}
	resp.Body = countingBody{ReadCloser: resp.Body, n: t.n}
	return resp, nil
}

type countingBody struct {
	io.ReadCloser
	n *int64
}

func (c countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	atomic.AddInt64(c.n, int64(n))
	return n, err
}
