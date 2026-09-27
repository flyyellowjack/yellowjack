package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A PyPI yank must leave a line in the operator's log. Before this, the cooldown, a
// version-pinned advisory and an operator's version deny all refused a PyPI release
// by writing a reason into the index: pip printed it, and the gate's own log showed only
// "served" for the same request. E123b measured it on real trees: 93 cooldown
// downgrades and one tree that could not install at all, and zero cooldown lines in the
// log. npm logs one line per version it removes (npmpackument.go); these tests hold PyPI
// to the same, through the proxy, because the filter's unit tests call it directly and
// cannot see whether anything is logged.

// pypiUpstreamAged serves an index with one sdist of 1.0 and a wheel plus an sdist of
// 2.0, and metadata dating 1.0 at 100 days old and 2.0 at `newAge` days old.
func pypiUpstreamAged(t *testing.T, pkg string, newAge int) *httptest.Server {
	t.Helper()
	old := time.Now().AddDate(0, 0, -100).Format(time.RFC3339)
	fresh := time.Now().AddDate(0, 0, -newAge).Format(time.RFC3339)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/simple/"):
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			fmt.Fprintf(w, `{"files":[
			 {"filename":"%[1]s-1.0.tar.gz","url":"https://files.pythonhosted.org/x/%[1]s-1.0.tar.gz"},
			 {"filename":"%[1]s-2.0-py3-none-any.whl","url":"https://files.pythonhosted.org/x/%[1]s-2.0-py3-none-any.whl"},
			 {"filename":"%[1]s-2.0.tar.gz","url":"https://files.pythonhosted.org/x/%[1]s-2.0.tar.gz"}
			]}`, pkg)
		case strings.HasPrefix(r.URL.Path, "/pypi/"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"info":{"project_urls":{"Source":"https://github.com/acme/%[1]s"}},
			 "releases":{
			  "1.0":[{"filename":"%[1]s-1.0.tar.gz","upload_time_iso_8601":"%[2]s"}],
			  "2.0":[{"filename":"%[1]s-2.0-py3-none-any.whl","upload_time_iso_8601":"%[3]s"},
			         {"filename":"%[1]s-2.0.tar.gz","upload_time_iso_8601":"%[3]s"}]
			 }}`, pkg, old, fresh)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// indexLog serves /simple/<pkg>/ and returns what the gate logged while doing it.
func indexLog(t *testing.T, p *proxyServer, pkg string) (body, logged string) {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	body = serveSimpleIndex(t, p, pkg)
	return body, buf.String()
}

func yankLines(logged string) []string {
	var out []string
	for _, l := range strings.Split(logged, "\n") {
		if strings.Contains(l, "yanked in the index") {
			out = append(out, l)
		}
	}
	return out
}

func TestPypiCooldownYankIsLoggedOncePerRelease(t *testing.T) {
	up := pypiUpstreamAged(t, "fresh", 2)
	defer up.Close()
	p := newTestProxy(t, up, func(c *Config) {
		c.Ecosystem = "pypi"
		c.MinReleaseAgeDays = 14
		c.UnscorablePolicy = "allow" // isolate: the only refusal under test is the cooldown
	})

	body, logged := indexLog(t, p, "fresh")
	if !strings.Contains(body, "cooldown") {
		t.Fatalf("precondition: the 2-day-old release was not yanked by the cooldown:\n%s", body)
	}
	lines := yankLines(logged)
	if len(lines) != 1 {
		t.Fatalf("want exactly one yank line (one release, two files), got %d:\n%s", len(lines), logged)
	}
	for _, want := range []string{"GET [release-window] fresh -> version 2.0 yanked in the index (", "cooldown", "; 2 file(s)"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("yank line lacks %q:\n%s", want, lines[0])
		}
	}
}

// The discriminator: an index the cooldown does not touch logs no yank. Without it the
// test above passes on a logger that writes a line for every index it serves.
func TestPypiIndexWithNothingHeldLogsNoYank(t *testing.T) {
	up := pypiUpstreamAged(t, "settled", 60)
	defer up.Close()
	p := newTestProxy(t, up, func(c *Config) {
		c.Ecosystem = "pypi"
		c.MinReleaseAgeDays = 14
		c.UnscorablePolicy = "allow"
	})

	body, logged := indexLog(t, p, "settled")
	if strings.Contains(body, "yanked") {
		t.Fatalf("precondition: nothing should be held at 60 days:\n%s", body)
	}
	if lines := yankLines(logged); len(lines) != 0 {
		t.Errorf("an index with nothing yanked logged a yank:\n%s", strings.Join(lines, "\n"))
	}
}

// An advisory's yank carries the advisory's token, not the cooldown's, so an operator
// can tell a malware refusal from a policy hold in the log alone.
func TestPypiAdvisoryYankIsLoggedWithItsOwnToken(t *testing.T) {
	up := pypiUpstreamAged(t, "hijacked", 60)
	defer up.Close()
	feed := writeFeed(t, `{"id":"MAL-2026-LOG","ecosystem":"pypi","name":"hijacked","versions":["2.0"]}`)
	p := newTestProxy(t, up, func(c *Config) {
		c.Ecosystem = "pypi"
		c.MalwareListPath = feed
		c.UnscorablePolicy = "allow"
	})

	_, logged := indexLog(t, p, "hijacked")
	lines := yankLines(logged)
	if len(lines) != 1 {
		t.Fatalf("want exactly one yank line, got %d:\n%s", len(lines), logged)
	}
	want := "GET [known-malware] hijacked -> version 2.0 yanked in the index (known malware: MAL-2026-LOG); 2 file(s)"
	if !strings.Contains(lines[0], want) {
		t.Errorf("yank line:\n%s\nwant it to contain:\n%s", lines[0], want)
	}
}
