package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D337: an upstream serving packuments with no `time` map has every version refused while
// the release window is active (D100). The operator must be told ONCE which upstream, why,
// and which setting -- and must not be told when the window is off or the document is dated.
func TestUndatedUpstreamIsNamedOnceWhileTheWindowIsOn(t *testing.T) {
	undated := []byte(`{"name":"left-pad","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"version":"1.0.0"}}}`)
	dated := []byte(`{"name":"left-pad","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"version":"1.0.0"}},` +
		`"time":{"1.0.0":"2016-01-01T00:00:00.000Z"}}`)
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()

	capture := func(p *proxyServer, bodies ...[]byte) string {
		var buf bytes.Buffer
		prev := log.Writer()
		log.SetOutput(&buf)
		defer log.SetOutput(prev)
		r := httptest.NewRequest(http.MethodGet, "/left-pad", nil)
		for _, b := range bodies {
			p.npmFilterPackumentForRelay(r, b, "left-pad")
		}
		return buf.String()
	}

	on := newTestProxy(t, upstream, func(c *Config) { c.MinReleaseAgeDays = 14 })
	out := capture(on, undated, undated, undated)
	if n := strings.Count(out, "NO publish dates"); n != 1 {
		t.Fatalf("an undated upstream was named %d times across three packuments, want exactly once:\n%s", n, out)
	}
	for _, want := range []string{upstream.URL, "FW_MIN_RELEASE_AGE_DAYS=14", "set FW_MIN_RELEASE_AGE_DAYS=0", "D100"} {
		if !strings.Contains(out, want) {
			t.Errorf("the warning does not name %q, so it does not tell the operator what to do:\n%s", want, out)
		}
	}

	// Controls: silent with the window off, and silent for a dated packument.
	off := newTestProxy(t, upstream, func(c *Config) { c.MinReleaseAgeDays = 0 })
	if out := capture(off, undated); strings.Contains(out, "NO publish dates") {
		t.Errorf("warned with the window OFF, where an undated packument costs nothing:\n%s", out)
	}
	datedGate := newTestProxy(t, upstream, func(c *Config) { c.MinReleaseAgeDays = 14 })
	if out := capture(datedGate, dated); strings.Contains(out, "NO publish dates") {
		t.Errorf("warned about a packument that DOES carry dates:\n%s", out)
	}
}
