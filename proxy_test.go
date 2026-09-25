package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestProxy wires a real Firewall + proxyServer against a fake upstream
// registry, in stub scorecard mode — the full request path with no network.
func newTestProxy(t *testing.T, upstream *httptest.Server, mutate func(*Config)) *proxyServer {
	t.Helper()
	cfg := Config{
		Ecosystem:        "npm",
		UpstreamRegistry: upstream.URL,
		UnscorablePolicy: "block",
		ScoreThreshold:   5.0,
		ScorecardMode:    "stub",
		ScoreCacheTTL:    time.Minute,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	fw, err := NewFirewall(cfg)
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	return newProxyServer(cfg, fw)
}

// TestMetadataRewrite verifies the core cooperative-client fix: tarball URLs
// inside relayed npm metadata must point back at the proxy, not the upstream
// registry — otherwise the client's next fetch bypasses the firewall.
func TestMetadataRewrite(t *testing.T) {
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lodash/latest":
			w.Write([]byte(`{"repository":{"url":"git+https://github.com/lodash/lodash.git"}}`))
		case "/lodash":
			w.Write([]byte(`{"versions":{"1.0.0":{"dist":{"tarball":"` + upstream.URL + `/lodash/-/lodash-1.0.0.tgz"}}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest(http.MethodGet, "http://firewall.local:8080/lodash", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, upstream.URL) {
		t.Errorf("metadata still references upstream registry %s: %s", upstream.URL, body)
	}
	// The URL must come back through the proxy AND carry the package identity this
	// metadata request resolved, so the byte fetch can re-gate on it (issue #11).
	// The upstream object path ("/lodash/-/lodash-1.0.0.tgz") rides along after the
	// "/_tarball/<pkg>/" prefix so proxyArtifactBytes can forward it verbatim.
	if !strings.Contains(body, "http://firewall.local:8080/_tarball/lodash/lodash/-/lodash-1.0.0.tgz") {
		t.Errorf("tarball URL not rewritten through /_tarball/<pkg>/: %s", body)
	}
}

// TestTarballNotRewritten verifies tarball (binary) responses stream verbatim —
// rewriting them would corrupt bytes and break npm's integrity check.
func TestTarballNotRewritten(t *testing.T) {
	var upstream *httptest.Server
	payload := "raw-tarball-bytes-mentioning-" // + upstream.URL appended below
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lodash/latest":
			w.Write([]byte(`{"repository":"github.com/lodash/lodash"}`))
		case "/lodash/-/lodash-1.0.0.tgz":
			w.Write([]byte(payload + upstream.URL))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/lodash/-/lodash-1.0.0.tgz", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != payload+upstream.URL {
		t.Errorf("tarball body was altered: %q", rec.Body.String())
	}
}

// TestPypiIndexRewrite is the PyPI analogue of TestMetadataRewrite: the wheel URLs
// in a served /simple/ index point at a DIFFERENT host (files.pythonhosted.org),
// and must be rewritten to come back through the proxy under "/_files/" — else the
// client fetches the artifact bytes straight from the file host, bypassing the gate.
// The "#sha256=" integrity fragment must survive the rewrite untouched.
func TestPypiIndexRewrite(t *testing.T) {
	filesHost := "https://files.example.test"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/six/json": // repo lookup -> scorable (stub score 7.5 >= 5.0 -> allow)
			w.Write([]byte(`{"info":{"project_urls":{"Source":"https://github.com/benjaminp/six"}}}`))
		case "/simple/six/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<a href="` + filesHost + `/packages/aa/six-1.0-py3-none-any.whl#sha256=deadbeef">six-1.0</a>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = filesHost
		c.PublicURL = "http://fw.local:8080"
	})
	req := httptest.NewRequest(http.MethodGet, "http://fw.local:8080/simple/six/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, filesHost) {
		t.Errorf("index still references file host %s: %s", filesHost, body)
	}
	if !strings.Contains(body, "http://fw.local:8080/_files/six/packages/aa/six-1.0-py3-none-any.whl#sha256=deadbeef") {
		t.Errorf("wheel URL not rewritten to proxy /_files/<pkg>/ (sha256 fragment must survive): %s", body)
	}
}

// pypiMetaUpstream serves the /pypi/<pkg>/json metadata the firewall reads to find
// a package's repo, so an Evaluate on the byte-fetch path can resolve a score. The
// repo it declares (six) is scorable, so stub mode scores it 7.5.
func pypiMetaUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pypi/six/json" {
			w.Write([]byte(`{"info":{"project_urls":{"Source":"https://github.com/benjaminp/six"}}}`))
			return
		}
		http.NotFound(w, r)
	}))
}

// TestPypiFilesFetchAllowedStreams verifies the byte-fetch gate's ALLOW branch (D22):
// a wheel under "/_files/<pkg>/…" is Evaluated on <pkg>, and an allowed package's
// bytes are streamed back verbatim (no rewrite — rewriting artifact bytes breaks
// pip's hash check).
func TestPypiFilesFetchAllowedStreams(t *testing.T) {
	files := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/packages/aa/six-1.0-py3-none-any.whl" {
			w.Write([]byte("raw-wheel-bytes"))
			return
		}
		http.NotFound(w, r)
	}))
	defer files.Close()
	upstream := pypiMetaUpstream(t)
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = files.URL // stub scores six 7.5 >= threshold 5.0 -> ALLOW
	})
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/_files/six/packages/aa/six-1.0-py3-none-any.whl", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "raw-wheel-bytes" {
		t.Errorf("relayed wheel bytes altered: %q", rec.Body.String())
	}
}

// TestPypiFilesFetchBlocked is the core D22 fix: a pinned install of a blocked
// package fetches the wheel directly under "/_files/<pkg>/…", and that fetch must
// fail CLOSED — a 403 with our reason — not stream the bytes. It also proves the
// files upstream is never contacted (any request there is a bypass).
func TestPypiFilesFetchBlocked(t *testing.T) {
	files := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("blocked byte fetch reached the files upstream (%s) — the gate was bypassed", r.URL.Path)
		http.Error(w, "should not be reached", http.StatusInternalServerError)
	}))
	defer files.Close()
	upstream := pypiMetaUpstream(t)
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = files.URL
		c.ScoreThreshold = 9.0 // stub scores 7.5 -> below threshold -> BLOCK (no approval)
	})
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/_files/six/packages/aa/six-1.0-py3-none-any.whl", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — a pinned install of a blocked pkg must fail closed (body: %s)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Yellowjack-Reason") == "" {
		t.Error("blocked byte fetch missing X-Yellowjack-Reason header")
	}
	assertReasonSurfaced(t, rec, blockErrMsg)
}

// TestPypiFilesFetchOverrideStreams verifies the deliberate escape hatch for admins:
// a package that would block on score is streamed when a human APPROVED it — the
// override flows through the same Evaluate path, so it works on the byte fetch too.
func TestPypiFilesFetchOverrideStreams(t *testing.T) {
	files := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/packages/aa/six-1.0-py3-none-any.whl" {
			w.Write([]byte("raw-wheel-bytes"))
			return
		}
		http.NotFound(w, r)
	}))
	defer files.Close()
	upstream := pypiMetaUpstream(t)
	defer upstream.Close()
	// Approval service says a human approved "six" despite the low score.
	approval := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/decisions") {
			w.Write([]byte(`{"package":"six","verdict":"approved"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer approval.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = files.URL
		c.ScoreThreshold = 9.0       // would block on score...
		c.ApprovalURL = approval.URL // ...but a human approved it -> ALLOW
	})
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/_files/six/packages/aa/six-1.0-py3-none-any.whl", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — an admin-approved pkg must stream (body: %s)", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "raw-wheel-bytes" {
		t.Errorf("approved wheel bytes altered: %q", rec.Body.String())
	}
}

// TestPypiFilesFetchUnavailable verifies a metadata outage on the byte fetch is
// refused as a 403 carrying the UNAVAILABLE explanation (D102).
//
// This test previously asserted the opposite — a retryable 503 with Retry-After 30,
// on the reasoning that pip retries 5xx and treats 403 as final, so an outage must
// not masquerade as a block. The project overruled the taxonomy: "503 generally means the
// server failed in some way; if these are not failure states, then we should not
// report them as failures... these are both block states, they are permissions
// errors and should be treated as 403s, but they should give different explanations
// of the 403."
//
// The retry does not come back for free, so what is asserted now is the thing that
// replaces it: the developer is told WHICH kind of no this is.
func TestPypiFilesFetchUnavailable(t *testing.T) {
	files := httptest.NewServer(http.NotFoundHandler())
	defer files.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // metadata source down
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = files.URL
	})
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/_files/six/packages/aa/six-1.0-py3-none-any.whl", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, unavailableErrMsg) {
		t.Errorf("body = %s, want the UNAVAILABLE explanation %q — a 403 that does not say "+
			"which kind of no this is leaves the developer with nothing to act on (D102)",
			body, unavailableErrMsg)
	}
	// No Retry-After: nothing honours it on a 403, and shipping a header no client
	// acts on would be decoration dressed as a contract.
	if ra := rec.Header().Get("Retry-After"); ra != "" {
		t.Errorf("Retry-After = %q, want it absent on a 403", ra)
	}
}

// TestPypiFilesFetchPending verifies the async-local-mode cold pull (D18) on the byte
// fetch: an unscored package is quarantined with the PENDING explanation while a
// background scan runs — a different 403 from the unavailable one (D102).
//
// The distinction used to be carried by two different Retry-After values (a longer
// pending hint vs. the 30s outage). Under 403 there is no Retry-After to carry it, so
// the wait moved into the reason text, which is what a developer actually reads. This
// asserts BOTH halves: the right explanation, and the configured wait surfacing in it.
func TestPypiFilesFetchPending(t *testing.T) {
	files := httptest.NewServer(http.NotFoundHandler())
	defer files.Close()
	upstream := pypiMetaUpstream(t)
	defer upstream.Close()
	// A stub scanner so the launched background scan has somewhere to POST; its result
	// is irrelevant to the synchronous "pending" verdict this test asserts.
	scanner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"score":8.0}`))
	}))
	defer scanner.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = files.URL
		c.ScorecardMode = "local" // async: cold repo -> launch bg scan, return pending
		c.ScannerURL = scanner.URL
		c.PendingRetryAfterSeconds = 77
	})
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/_files/six/packages/aa/six-1.0-py3-none-any.whl", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, pendingErrMsg) {
		t.Errorf("body = %s, want the PENDING explanation %q", body, pendingErrMsg)
	}
	// The two non-verdict outcomes must not be confusable: "we're still looking" and
	// "we couldn't look" call for different actions from the developer.
	if strings.Contains(body, unavailableErrMsg) {
		t.Errorf("body = %s, must NOT carry the unavailable explanation — the project's ruling "+
			"requires the two 403s give DIFFERENT explanations (D102)", body)
	}
	// The configured wait has to survive somewhere the developer sees it, now that
	// Retry-After is gone.
	if !strings.Contains(body, "77") {
		t.Errorf("body = %s, want the configured pending wait (77s) in the reason text — "+
			"with no Retry-After, this is the only place it reaches the developer", body)
	}
}

// TestPypiBlockYanksHTMLIndex verifies the PyPI block posture: a blocked package's
// /simple/ page is served as 200 with every release marked PEP 592 yanked-with-reason
// — NOT a 403, which pip reads as "route around this" and answers by backtracking
// OTHER packages to old versions (the silent-downgrade bug). File URLs must still be
// rewritten to /_files/ so an explicit "==" pin (pip's override gesture) routes the
// bytes through us, and the reason must also ride the X-Yellowjack-Reason header.
func TestPypiBlockYanksHTMLIndex(t *testing.T) {
	filesHost := "https://files.example.test"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/six/json":
			w.Write([]byte(`{"info":{"project_urls":{"Source":"https://github.com/benjaminp/six"}}}`))
		case "/simple/six/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<a href="` + filesHost + `/packages/aa/six-1.0-py3-none-any.whl#sha256=deadbeef">six-1.0</a>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = filesHost
		c.PublicURL = "http://fw.local:8080"
		c.ScoreThreshold = 9.0 // stub scores 7.5 -> BLOCK
	})
	req := httptest.NewRequest(http.MethodGet, "http://fw.local:8080/simple/six/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a pypi block must NOT 403 the index (body: %s)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Yellowjack-Reason") == "" {
		t.Errorf("X-Yellowjack-Reason header missing on yanked-index block")
	}
	body := rec.Body.String()
	if !strings.Contains(body, `data-yanked="`) || !strings.Contains(body, "below required 9.0") {
		t.Errorf("index not yanked-with-reason: %s", body)
	}
	if !strings.Contains(body, "http://fw.local:8080/_files/six/packages/aa/six-1.0-py3-none-any.whl#sha256=deadbeef") {
		t.Errorf("blocked index must still rewrite file URLs through /_files/<pkg>/: %s", body)
	}
}

// TestPypiBlockYanksJSONIndex covers the PEP 691 (JSON) shape of the same posture:
// each file entry gains "yanked": "<reason>" while the rest of the document
// (hashes, unknown fields) survives the re-marshal.
func TestPypiBlockYanksJSONIndex(t *testing.T) {
	filesHost := "https://files.example.test"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/six/json":
			w.Write([]byte(`{"info":{"project_urls":{"Source":"https://github.com/benjaminp/six"}}}`))
		case "/simple/six/":
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			w.Write([]byte(`{"name":"six","files":[{"filename":"six-1.0-py3-none-any.whl","url":"` +
				filesHost + `/packages/aa/six-1.0-py3-none-any.whl","hashes":{"sha256":"deadbeef"},"yanked":false}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = filesHost
		c.PublicURL = "http://fw.local:8080"
		c.ScoreThreshold = 9.0 // stub scores 7.5 -> BLOCK
	})
	req := httptest.NewRequest(http.MethodGet, "http://fw.local:8080/simple/six/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var doc struct {
		Files []struct {
			URL    string            `json:"url"`
			Hashes map[string]string `json:"hashes"`
			Yanked any               `json:"yanked"`
		} `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("blocked JSON index is no longer valid JSON: %v", err)
	}
	if len(doc.Files) != 1 {
		t.Fatalf("files count = %d, want 1", len(doc.Files))
	}
	reason, ok := doc.Files[0].Yanked.(string)
	if !ok || !strings.Contains(reason, "below required 9.0") {
		t.Errorf("yanked = %#v, want reason string", doc.Files[0].Yanked)
	}
	if doc.Files[0].Hashes["sha256"] != "deadbeef" {
		t.Errorf("hashes did not survive the yank re-marshal: %#v", doc.Files[0].Hashes)
	}
	if !strings.HasPrefix(doc.Files[0].URL, "http://fw.local:8080/_files/six/") {
		t.Errorf("file URL not rewritten through /_files/<pkg>/: %s", doc.Files[0].URL)
	}
}

// pypiAgeFloorUpstream serves a two-release package — one ancient, one fresh —
// through both the metadata API (the date source) and a /simple/ index in the
// given shape, for the age-floor tests.
func pypiAgeFloorUpstream(t *testing.T, filesHost string, jsonIndex bool) *httptest.Server {
	t.Helper()
	oldTime := time.Now().AddDate(-2, 0, 0).Format(time.RFC3339) // 2 years old
	newTime := time.Now().AddDate(0, 0, -1).Format(time.RFC3339) // yesterday
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/six/json":
			w.Write([]byte(`{"info":{"project_urls":{"Source":"https://github.com/benjaminp/six"}},
				"releases":{
					"0.9.0":[{"filename":"six-0.9.0.tar.gz","upload_time_iso_8601":"` + oldTime + `"}],
					"1.17.0":[{"filename":"six-1.17.0-py3-none-any.whl","upload_time_iso_8601":"` + newTime + `"}]}}`))
		case "/simple/six/":
			if jsonIndex {
				w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
				w.Write([]byte(`{"name":"six","files":[` +
					`{"filename":"six-0.9.0.tar.gz","url":"` + filesHost + `/packages/aa/six-0.9.0.tar.gz","yanked":false},` +
					`{"filename":"six-1.17.0-py3-none-any.whl","url":"` + filesHost + `/packages/bb/six-1.17.0-py3-none-any.whl","yanked":"upstream pulled this build"}]}`))
			} else {
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte(`<a href="` + filesHost + `/packages/aa/six-0.9.0.tar.gz#sha256=aa">six-0.9.0.tar.gz</a>` +
					`<a href="` + filesHost + `/packages/bb/six-1.17.0-py3-none-any.whl#sha256=bb">six-1.17.0-py3-none-any.whl</a>`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
}

// TestPypiAgeFloorHTML verifies the release-age floor on the ALLOW path (D22):
// entries older than FW_MAX_RELEASE_AGE_DAYS are yanked with an age reason —
// so a resolver backtrack can't land on them — while fresh entries pass untouched.
func TestPypiAgeFloorHTML(t *testing.T) {
	filesHost := "https://files.example.test"
	upstream := pypiAgeFloorUpstream(t, filesHost, false)
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = filesHost
		c.PublicURL = "http://fw.local:8080"
		c.MaxReleaseAgeDays = 365 // stub 7.5 >= threshold 5.0 -> ALLOW; floor applies
	})
	req := httptest.NewRequest(http.MethodGet, "http://fw.local:8080/simple/six/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	oldAnchor := body[strings.Index(body, "<a "):strings.Index(body, "</a>")]
	if !strings.Contains(oldAnchor, `data-yanked="release older than`) {
		t.Errorf("2-year-old release not yanked by the age floor: %s", oldAnchor)
	}
	newAnchor := body[strings.LastIndex(body, "<a "):]
	if strings.Contains(newAnchor, "data-yanked") {
		t.Errorf("fresh release wrongly yanked by the age floor: %s", newAnchor)
	}
	if !strings.Contains(body, "http://fw.local:8080/_files/") {
		t.Errorf("age-floor path lost the /_files/ rewrite: %s", body)
	}
}

// TestPypiAgeFloorJSON covers the PEP 691 shape and the precedence rule: an entry
// the UPSTREAM already yanked keeps its original reason — a real security yank
// outranks our policy annotation.
func TestPypiAgeFloorJSON(t *testing.T) {
	filesHost := "https://files.example.test"
	upstream := pypiAgeFloorUpstream(t, filesHost, true)
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = filesHost
		c.PublicURL = "http://fw.local:8080"
		c.MaxReleaseAgeDays = 365
	})
	req := httptest.NewRequest(http.MethodGet, "http://fw.local:8080/simple/six/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var doc struct {
		Files []struct {
			Filename string `json:"filename"`
			Yanked   any    `json:"yanked"`
		} `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("age-floored JSON index is no longer valid JSON: %v", err)
	}
	if len(doc.Files) != 2 {
		t.Fatalf("files count = %d, want 2", len(doc.Files))
	}
	old, fresh := doc.Files[0], doc.Files[1]
	if reason, ok := old.Yanked.(string); !ok || !strings.Contains(reason, "age floor") {
		t.Errorf("old release yanked = %#v, want age-floor reason", old.Yanked)
	}
	if reason, ok := fresh.Yanked.(string); !ok || reason != "upstream pulled this build" {
		t.Errorf("upstream's own yank reason was overwritten: %#v", fresh.Yanked)
	}
}

// pypiAgeFloorBrokenDates serves a working /simple/ index, and a metadata API that
// answers the FIRST call and fails every one after it.
//
// That shape is not arbitrary — it is what makes issue #70 reachable at all. The
// /pypi/<pkg>/json document is read twice per request, by two different callers:
// LookupRepo (to find the repo to score) and then fetchUploadTimes (to apply the age
// floor). Fail it outright and the package simply becomes unevaluable, so we refuse
// long before the floor is consulted and nothing is exposed. The dangerous window is
// the one where evaluation still succeeds — a warm repo cache, or as here a first
// call that lands — and only the DATE fetch fails. That is the steady state in
// production, and it is the state an attacker can drive by degrading one endpoint.
func pypiAgeFloorBrokenDates(t *testing.T, filesHost string) *httptest.Server {
	t.Helper()
	var metaCalls atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/six/json":
			if metaCalls.Add(1) > 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			// Enough to resolve + score the package, so evaluation ALLOWS and we
			// reach the age floor. No "releases" key: dates are the next fetch.
			w.Write([]byte(`{"info":{"project_urls":{"Source":"https://github.com/benjaminp/six"}}}`))
		case "/simple/six/":
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			w.Write([]byte(`{"name":"six","files":[` +
				`{"filename":"six-0.9.0.tar.gz","url":"` + filesHost + `/packages/aa/six-0.9.0.tar.gz","yanked":false},` +
				`{"filename":"six-1.17.0-py3-none-any.whl","url":"` + filesHost + `/packages/bb/six-1.17.0-py3-none-any.whl","yanked":false}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

// TestPypiAgeFloorFailsClosedWhenUploadTimesUnavailable is the issue #70 fix (D100).
//
// The floor is opt-in, and the operators it affects are exactly the ones who asked
// for it — so when we cannot apply it, we must not hand back the unfiltered index
// and hope. Every entry is yanked with a reason that says we could not verify age,
// rather than the index being served as though the floor had passed.
//
// The NEGATIVE CONTROL for this test is TestPypiAgeFloorJSON directly above: same
// index, same config, working metadata endpoint — there the fresh release comes back
// UNyanked. So a bug that yanked everything unconditionally would fail that test,
// and this one cannot pass merely by over-blocking.
func TestPypiAgeFloorFailsClosedWhenUploadTimesUnavailable(t *testing.T) {
	filesHost := "https://files.example.test"
	upstream := pypiAgeFloorBrokenDates(t, filesHost)
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = filesHost
		c.PublicURL = "http://fw.local:8080"
		c.MaxReleaseAgeDays = 365
	})
	req := httptest.NewRequest(http.MethodGet, "http://fw.local:8080/simple/six/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	var doc struct {
		Files []struct {
			Filename string `json:"filename"`
			Yanked   any    `json:"yanked"`
		} `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("index is no longer valid JSON: %v (body: %s)", err, rec.Body.String())
	}
	if len(doc.Files) != 2 {
		t.Fatalf("files count = %d, want 2", len(doc.Files))
	}
	for _, f := range doc.Files {
		reason, ok := f.Yanked.(string)
		if !ok || reason == "" {
			t.Errorf("%s: yanked = %#v — the age floor was ON and could not be applied, "+
				"so serving this entry unyanked is the silent fail-open of issue #70",
				f.Filename, f.Yanked)
			continue
		}
		if !strings.Contains(reason, "cannot verify release age") {
			t.Errorf("%s: yank reason = %q, want it to say the age could not be verified — "+
				"the developer has to be able to tell this from a genuine age block", f.Filename, reason)
		}
	}
}

// TestPypiAgeFloorYanksEntriesWithUnknownUploadTime covers the same fail-open ONE
// LEVEL DOWN (D100). The index and the metadata API are joined on the filename, so
// an attacker who makes that join miss for a single file used to get that file back
// unyanked even while the floor worked perfectly for every other entry.
//
// Unknown age is not evidence of youth.
func TestPypiAgeFloorYanksEntriesWithUnknownUploadTime(t *testing.T) {
	filesHost := "https://files.example.test"
	newTime := time.Now().AddDate(0, 0, -1).Format(time.RFC3339)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/six/json":
			// Dates for the fresh file ONLY: the ancient one has no upload time here.
			w.Write([]byte(`{"info":{"project_urls":{"Source":"https://github.com/benjaminp/six"}},
				"releases":{"1.17.0":[{"filename":"six-1.17.0-py3-none-any.whl","upload_time_iso_8601":"` + newTime + `"}]}}`))
		case "/simple/six/":
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			w.Write([]byte(`{"name":"six","files":[` +
				`{"filename":"six-0.9.0.tar.gz","url":"` + filesHost + `/packages/aa/six-0.9.0.tar.gz","yanked":false},` +
				`{"filename":"six-1.17.0-py3-none-any.whl","url":"` + filesHost + `/packages/bb/six-1.17.0-py3-none-any.whl","yanked":false}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = filesHost
		c.PublicURL = "http://fw.local:8080"
		c.MaxReleaseAgeDays = 365
	})
	req := httptest.NewRequest(http.MethodGet, "http://fw.local:8080/simple/six/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	var doc struct {
		Files []struct {
			Filename string `json:"filename"`
			Yanked   any    `json:"yanked"`
		} `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("index is no longer valid JSON: %v", err)
	}
	if len(doc.Files) != 2 {
		t.Fatalf("files count = %d, want 2", len(doc.Files))
	}
	unknown, fresh := doc.Files[0], doc.Files[1]
	reason, ok := unknown.Yanked.(string)
	if !ok || !strings.Contains(reason, "could not be verified") {
		t.Errorf("the file with no known upload time came back yanked = %#v; want a "+
			"could-not-verify yank. A join miss must not be a way past the floor (#70).", unknown.Yanked)
	}
	// The other half of the claim: this fails closed WITHOUT becoming a blanket block.
	// A file we do have a fresh date for is still served normally.
	if y, isStr := fresh.Yanked.(string); isStr && y != "" {
		t.Errorf("fresh release wrongly yanked (%q) — failing closed on unknown age must "+
			"not turn into yanking everything", y)
	}
}

// TestUpstreamOutageIsForbiddenNotServerError verifies that an upstream we cannot
// reach produces a 403 naming the outage — not a 503, and not a plain block.
//
// This test is the clearest casualty of D102, and the reversal is deliberate rather
// than incidental. It used to assert exactly the opposite ("a flaky/rate-limited
// upstream surfaces as a retryable 503, NOT a 403 block — npm retries 5xx but treats
// 403 as final"), and that reasoning was about CLIENT BEHAVIOUR: a 5xx got a free
// automatic retry, so a transient hiccup healed itself instead of failing a build.
//
// The project ruled on TAXONOMY over that convenience: our failure to reach an upstream is
// not the client's server failing, and reporting it as one is a lie that happens to
// be useful. The automatic retry is genuinely lost — accepted explicitly, with a
// better scan-request mechanism named as the real fix.
//
// What must NOT be lost is the distinction the old 503 was protecting. An outage is
// still not the same event as "we evaluated this and said no", so the response has to
// say so in the one place left: its explanation.
func TestUpstreamOutageIsForbiddenNotServerError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/lodash", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, unavailableErrMsg) {
		t.Errorf("body = %s, want the UNAVAILABLE explanation %q", body, unavailableErrMsg)
	}
	// The whole point of a distinct explanation is that an outage never reads as a
	// verdict. If this ever says "blocked by firewall", we have taught developers that
	// the firewall randomly blocks things — the exact harm the old 503 was avoiding.
	if strings.Contains(body, blockErrMsg) {
		t.Errorf("body = %s, must NOT read as a verdict: nothing was evaluated here", body)
	}
}

// TestUnknownPackagePassesThrough verifies a package the registry has never
// heard of is NOT gated (or queued for approval) — the registry's own 404 is
// the answer. Keeps typo'd installs and scanner probes out of the review queue.
func TestUnknownPackagePassesThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/definitely-not-a-package", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want upstream's 404 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestControlPlanePassesThrough verifies /-/ registry-API requests (audit,
// ping) skip the gate entirely, even under a fail-closed policy.
func TestControlPlanePassesThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/-/npm/v1/security/advisories/bulk" {
			w.Write([]byte(`{}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	req := httptest.NewRequest(http.MethodPost, "http://fw.local/-/npm/v1/security/advisories/bulk", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("audit request gated: status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestScopedPackageEncodedPath verifies the %2f form npm actually sends for
// scoped packages survives the proxy round trip (EscapedPath, not Path).
func TestScopedPackageEncodedPath(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.EscapedPath(), "/latest") {
			w.Write([]byte(`{"repository":"github.com/babel/babel"}`))
			return
		}
		gotPath = r.URL.EscapedPath()
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	u, _ := url.Parse("http://fw.local/@babel%2fcore")
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/", nil)
	req.URL = u
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	if gotPath != "/@babel%2fcore" {
		t.Errorf("upstream saw path %q, want the client's original %q", gotPath, "/@babel%2fcore")
	}
}

// TestBlockSurfacesReasonHeader verifies a blocked npm package carries the reason
// in the X-Yellowjack-Reason header, not only the JSON body. docker (and any
// HEAD-based client) sees no body, so the header is the only channel that always
// survives — without it a blocked pull shows a bare "403 Forbidden".
func TestBlockSurfacesReasonHeader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve a scorable package so the block is a THRESHOLD block (stub score
		// 7.5 < the 9.9 threshold below), not an unscorable one.
		w.Write([]byte(`{"repository":"github.com/lodash/lodash"}`))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) { c.ScoreThreshold = 9.9 })
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/lodash", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Yellowjack-Reason") == "" {
		t.Error("block response missing X-Yellowjack-Reason header (HEAD clients see no body)")
	}
	assertReasonSurfaced(t, rec, blockErrMsg)
}

// TestOciBlockUsesDistributionErrorShape verifies a blocked OCI pull returns the
// distribution-spec error body ({"errors":[{"code":"DENIED",...}]}) that docker/
// containerd/podman actually print, rather than the npm-style body they'd ignore.
// The image here declares no source label, so it blocks via the unscorable path.
func TestOciBlockUsesDistributionErrorShape(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 200 with an empty manifest: no auth challenge (token dance skipped), no
		// config digest and no annotations, so LookupRepo returns "" -> unscorable
		// -> blocked under the fail-closed default.
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) { c.Ecosystem = "oci" })
	req := httptest.NewRequest(http.MethodGet, "http://fw.local/v2/library/alpine/manifests/latest", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"DENIED"`) {
		t.Errorf("oci block body not in distribution-spec shape: %s", rec.Body.String())
	}
}

// TestProxyClientHasNoWholeRequestTimeout guards the streaming fix: the reusable
// client must NOT set http.Client.Timeout, because that caps the ENTIRE body read
// and truncates large artifact downloads (OCI layer blobs, npm tarballs) that
// legitimately stream for minutes. The header-wait bound lives on the transport's
// ResponseHeaderTimeout instead.
func TestProxyClientHasNoWholeRequestTimeout(t *testing.T) {
	p := newProxyServer(Config{Ecosystem: "npm", UpstreamRegistry: "http://x"}, nil)
	if p.client.Timeout != 0 {
		t.Errorf("proxy client has whole-request Timeout=%v; large downloads would truncate", p.client.Timeout)
	}
	tr, ok := p.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("proxy client transport is %T, want *http.Transport with ResponseHeaderTimeout", p.client.Transport)
	}
	if tr.ResponseHeaderTimeout == 0 {
		t.Error("transport ResponseHeaderTimeout unset; a hung upstream could tie up a request forever")
	}
}
