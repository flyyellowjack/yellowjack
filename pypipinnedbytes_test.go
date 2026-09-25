package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The PyPI BYTE path for version-pinned advisories (#103).
//
// The index yank is not enforcement on its own: PEP 592 tells an installer to ignore a
// yanked file UNLESS the requirement pins that exact version, so an exact pin selects it.
// Measured with real pip in e2e/pypi_exactpin_test.go, which installed the named release
// through the gate before this file existed. These are the unit twins.

// pypiPinUpstream serves the two documents the PyPI path needs and COUNTS the metadata
// fetches, so a test can assert what the join costs a package no advisory names.
type pypiPinUpstream struct {
	*httptest.Server
	files    *httptest.Server
	metaHits atomic.Int64
}

func newPypiPinUpstream(t *testing.T, pkg string) *pypiPinUpstream {
	t.Helper()
	u := &pypiPinUpstream{}
	u.files = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ARTIFACT-BYTES")
	}))
	t.Cleanup(u.files.Close)
	uploaded := time.Now().AddDate(0, 0, -100).Format(time.RFC3339)
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/simple/"):
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			fmt.Fprintf(w, `{"files":[
			 {"filename":"%s-1.0.tar.gz","url":"%s/x/%s-1.0.tar.gz"},
			 {"filename":"%s-2.0.tar.gz","url":"%s/x/%s-2.0.tar.gz"}
			]}`, pkg, u.files.URL, pkg, pkg, u.files.URL, pkg)
		case strings.HasPrefix(r.URL.Path, "/pypi/"):
			u.metaHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"info":{"project_urls":{"Source":"https://github.com/acme/%s"}},
			 "releases":{
			  "1.0":[{"filename":"%s-1.0.tar.gz","upload_time_iso_8601":"%s"}],
			  "2.0":[{"filename":"%s-2.0.tar.gz","upload_time_iso_8601":"%s"}]
			 }}`, pkg, pkg, uploaded, pkg, uploaded)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(u.Server.Close)
	return u
}

// pypiPinProxy wires a gate whose ONLY policy is the feed, the shipped-default shape.
func pypiPinProxy(t *testing.T, u *pypiPinUpstream, feed string) *proxyServer {
	t.Helper()
	return newTestProxy(t, u.Server, func(c *Config) {
		c.Ecosystem = "pypi"
		c.MalwareListPath = feed
		c.UnscorablePolicy = "allow"
		c.FilesUpstream = u.files.URL
	})
}

// indexFileURL returns the gate-minted /_files/ path for one filename, taken from the
// index the gate served — the URL a client actually follows, not one the test composes.
func indexFileURL(t *testing.T, p *proxyServer, pkg, filename string) string {
	t.Helper()
	var doc struct {
		Files []struct {
			Filename string `json:"filename"`
			URL      string `json:"url"`
		} `json:"files"`
	}
	body := serveSimpleIndex(t, p, pkg)
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("index is not the JSON shape: %v\n%s", err, body)
	}
	for _, f := range doc.Files {
		if f.Filename == filename {
			if i := strings.Index(f.URL, "/_files/"); i >= 0 {
				return f.URL[i:]
			}
			t.Fatalf("index URL for %s was not rewritten to /_files/: %s", filename, f.URL)
		}
	}
	t.Fatalf("index carries no entry for %s:\n%s", filename, body)
	return ""
}

func getPath(t *testing.T, p *proxyServer, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

func TestPypiExactPinOfAPinnedAdvisoryIsRefusedAtTheFile(t *testing.T) {
	u := newPypiPinUpstream(t, "hijacked")
	feed := writeFeed(t, `{"id":"MAL-2025-PIN","ecosystem":"pypi","name":"hijacked","versions":["2.0"]}`)
	p := pypiPinProxy(t, u, feed)

	bad := indexFileURL(t, p, "hijacked", "hijacked-2.0.tar.gz")
	code, body := getPath(t, p, bad)
	if code == http.StatusOK {
		t.Fatalf("the BYTES of the release a pinned advisory names were served (%d). The index yank does not stop "+
			"an exact pin: PEP 592 selects a yanked file when the requirement pins that version.\n%s", code, body)
	}
	if code != http.StatusForbidden {
		t.Errorf("file refused with %d, want 403 (the shape every other block uses)", code)
	}
	for _, want := range []string{"MAL-2025-PIN", "2.0"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal does not mention %q, so the developer cannot tell which release or which "+
				"advisory refused it: %s", want, body)
		}
	}

	// DISCRIMINATOR: the sibling release must still be served, or this is a package-wide
	// refusal wearing a version-pinned name — the false positive the advisory shape
	// exists to avoid.
	good := indexFileURL(t, p, "hijacked", "hijacked-1.0.tar.gz")
	if code, body := getPath(t, p, good); code != http.StatusOK {
		t.Errorf("the CLEAN sibling release was refused (%d): %s", code, body)
	}
}

func TestTheMetadataFileOfAPinnedReleaseIsAlsoRefused(t *testing.T) {
	// pip fetches the PEP 658 .metadata before the wheel. Refusing only the wheel would
	// still work, but the developer's error would arrive one request later and name the
	// wrong object; and a resolver that trusts the metadata would have read it already.
	u := newPypiPinUpstream(t, "hijacked")
	feed := writeFeed(t, `{"id":"MAL-2025-PIN","ecosystem":"pypi","name":"hijacked","versions":["2.0"]}`)
	p := pypiPinProxy(t, u, feed)
	bad := indexFileURL(t, p, "hijacked", "hijacked-2.0.tar.gz")
	if code, body := getPath(t, p, bad+pep658MetadataSuffix); code != http.StatusForbidden {
		t.Errorf("the .metadata of a pinned release was answered %d, want 403: %s", code, body)
	}
}

func TestAFileWhoseVersionCannotBeJoinedIsRefusedOnlyForAPinnedPackage(t *testing.T) {
	// FAIL CLOSED, but only where there is something to miss — the posture pinnedMalwareVerdict
	// owns. A filename PyPI's releases map does not carry is a join we could not make; if an
	// advisory pins this package, that is exactly the gap an attacker wants.
	u := newPypiPinUpstream(t, "hijacked")
	feed := writeFeed(t, `{"id":"MAL-2025-PIN","ecosystem":"pypi","name":"hijacked","versions":["2.0"]}`)
	p := pypiPinProxy(t, u, feed)
	unknown := "/_files/hijacked/x/hijacked-9.9.tar.gz"
	if code, body := getPath(t, p, unknown); code != http.StatusForbidden {
		t.Errorf("a file whose version could not be determined was answered %d for a package carrying a pinned "+
			"advisory, want 403: %s", code, body)
	}

	// The other half of "only where there is something to miss": for a package NO advisory
	// names, the same unjoinable filename is served, because there is nothing it could hide.
	u2 := newPypiPinUpstream(t, "innocent")
	p2 := pypiPinProxy(t, u2, feed)
	if code, body := getPath(t, p2, "/_files/innocent/x/innocent-9.9.tar.gz"); code != http.StatusOK {
		t.Errorf("a file of a package no advisory names was refused (%d) because its version could not be "+
			"joined; that denies clean packages for no reason: %s", code, body)
	}
}

func TestTheJoinIsNotFetchedForAPackageNoAdvisoryNames(t *testing.T) {
	// COST CONTROL. The join costs one metadata fetch per file request, and it must be
	// paid only by the packages the feed names. Without this, adding the check would put
	// an extra upstream request on every artifact fetch in the deployment.
	u := newPypiPinUpstream(t, "innocent")
	feed := writeFeed(t, `{"id":"MAL-2025-PIN","ecosystem":"pypi","name":"hijacked","versions":["2.0"]}`)
	p := pypiPinProxy(t, u, feed)

	file := indexFileURL(t, p, "innocent", "innocent-1.0.tar.gz")
	before := u.metaHits.Load()
	if code, body := getPath(t, p, file); code != http.StatusOK {
		t.Fatalf("clean package's file refused (%d): %s", code, body)
	}
	if got := u.metaHits.Load() - before; got != 0 {
		t.Errorf("the file fetch made %d metadata request(s) for a package no advisory names; the join must be "+
			"paid only by packages the feed names", got)
	}
}

// TestPypiFileVersionStripsTheMetadataSuffix covers a line the call site cannot reach.
//
// proxyToFiles always passes the suffix-STRIPPED path (metadataOf), so removing the strip
// inside the helper reddens nothing — measured, by sabotage. The strip stays because the
// helper is the join's one entry point and a future caller with a raw path would silently
// get known=false (fail closed, i.e. a clean release refused). This test is what makes
// the line reachable, and it is deliberately a direct call: the three tests above are what
// prove the call site is wired.
func TestPypiFileVersionStripsTheMetadataSuffix(t *testing.T) {
	u := newPypiPinUpstream(t, "hijacked")
	feed := writeFeed(t, `{"id":"MAL-2025-PIN","ecosystem":"pypi","name":"hijacked","versions":["2.0"]}`)
	p := pypiPinProxy(t, u, feed)
	v, known := p.pypiFileVersion("hijacked", "/x/hijacked-2.0.tar.gz"+pep658MetadataSuffix)
	if !known || v != "2.0" {
		t.Errorf("a .metadata path did not join to its release: version=%q known=%v", v, known)
	}
}
