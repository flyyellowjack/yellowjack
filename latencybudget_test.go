package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

// THE ADDED-LATENCY BUDGET (#21 box 3).
//
// docs/FOOTPRINT.md measured what we cost a developer — about -1 to -2 ms at p50 through
// p99 against a real registry, i.e. nothing measurable. This is the assertion that keeps
// it true, and the shape of the measurement is the whole design:
//
// ── WE ASSERT THE DELTA, NOT THE ABSOLUTE ────────────────────────────────────
//
// An absolute latency ceiling on a shared CI runner measures the runner, not us: it
// flakes when a neighbour is busy, and a gate that cries wolf gets re-run rather than
// read. So both paths are measured in the SAME run, INTERLEAVED, against the SAME
// upstream, and only the difference is asserted. Whatever slows the machine slows both
// halves and cancels.
//
// ── AND AGAINST A LOCAL UPSTREAM, NOT A REGISTRY ─────────────────────────────
//
// The published figure was measured against registry.npmjs.org because the question was
// "what does a developer experience". The question HERE is "did our own handling get
// slower", so the upstream is an in-process httptest server: no internet, no CDN
// variance, no rate limit, and nothing to be unavailable at 3am. What remains in the
// delta is our work — parse, evaluate, rewrite every tarball URL, relay.
//
// ── BOTH PATHS ARE REAL HTTP ─────────────────────────────────────────────────
//
// The proxy is served through httptest too, deliberately. Calling p.ServeHTTP directly
// would skip the socket, the transport and the response write, and would flatter us with
// a number no client can observe.
//
// ── THE CEILINGS ARE SET FROM A SAMPLE, NOT FROM ONE RUN ────────────────────
//
// The first version of this test asserted p99 < 25 ms on the strength of a single run that
// measured 2.6 ms. Six runs on one idle-ish laptop then produced:
//
//	p50 0.934  p95  2.425  p99  3.667
//	p50 1.149  p95  4.825  p99  7.807
//	p50 0.550  p95  1.678  p99  2.541
//	p50 1.024  p95 11.499  p99 28.735   <- would have FAILED that ceiling
//	p50 0.636  p95  2.666  p99  6.230
//	p50 0.567  p95  1.634  p99  2.086
//
// One run in six over the bound, on a quieter machine than a shared CI runner. The p99 of
// a 200-sample timing run is two data points from the top: it measures whatever the
// scheduler, the GC and the neighbours did during those two requests. A bound tight enough
// to mean anything flakes, and a flaky gate gets re-run rather than read.
//
// The MEDIAN is the stable one — 0.550 to 1.149 across the same six runs, a spread of 2x
// against a 5 ms bound — and it is what catches the regression worth catching: an added
// round trip, a body buffered where it used to stream, an allocation storm. Those move
// every request, so they move the median.
//
// p99 keeps a bound anyway, but a deliberately LOOSE one: ~9x the worst noise observed.
// It exists for the one failure the median cannot see — a TAIL-only regression, say a lock
// that makes 1% of requests take seconds — and for nothing else. Do not tighten it without
// re-running the sample above; the temptation to make it "meaningful" is how this becomes
// the flaky gate it was written to avoid.
const (
	maxMedianAddedMS = 5.0
	maxP99AddedMS    = 250.0

	latencySamples = 200
	latencyWarmup  = 20
)

// packumentWith builds an npm packument with n versions, each carrying a tarball URL the
// firewall has to rewrite. Size and version count both matter: the rewrite walks every
// version, so a one-version document would measure nothing that scales.
func packumentWith(upstreamURL string, n int) string {
	var b strings.Builder
	b.WriteString(`{"name":"yj-latency","dist-tags":{"latest":"1.0.0"},"versions":{`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"1.0.%d":{"name":"yj-latency","version":"1.0.%d","dist":{"tarball":"%s/yj-latency/-/yj-latency-1.0.%d.tgz","integrity":"sha512-%060d"}}`,
			i, i, upstreamURL, i, i)
	}
	b.WriteString(`}}`)
	return b.String()
}

// timeGet performs one GET and returns how long the whole exchange took, body included.
// The body is drained rather than discarded unread, so the measurement covers the
// response the client actually receives.
func timeGet(t *testing.T, c *http.Client, url string) time.Duration {
	t.Helper()
	start := time.Now()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	d := time.Since(start)
	if err != nil {
		t.Fatalf("draining %s: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", url, resp.StatusCode)
	}
	if n < 1000 {
		t.Fatalf("GET %s returned only %d bytes — too small to be the packument, so the "+
			"measurement would not exercise the rewrite", url, n)
	}
	return d
}

func pct(v []float64, p float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	i := int(p / 100 * float64(len(s)))
	if i >= len(s) {
		i = len(s) - 1
	}
	return s[i]
}

// measureAdded interleaves the two paths and returns the per-pair added milliseconds.
// Interleaved, not one block after the other: a machine that gets busy halfway through
// would otherwise load all of its noise onto whichever path ran second.
func measureAdded(t *testing.T, c *http.Client, directURL, throughURL string) []float64 {
	t.Helper()
	for i := 0; i < latencyWarmup; i++ {
		timeGet(t, c, directURL)
		timeGet(t, c, throughURL)
	}
	added := make([]float64, 0, latencySamples)
	for i := 0; i < latencySamples; i++ {
		d := timeGet(t, c, directURL)
		th := timeGet(t, c, throughURL)
		added = append(added, float64(th-d)/float64(time.Millisecond))
	}
	return added
}

func TestAddedLatencyStaysWithinBudget(t *testing.T) {
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/yj-latency/latest":
			w.Write([]byte(`{"repository":{"url":"git+https://github.com/yj/latency.git"}}`))
		case r.URL.Path == "/yj-latency":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(packumentWith(upstream.URL, 60)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	through := httptest.NewServer(p)
	defer through.Close()

	// One client, one transport, keep-alive on both paths — otherwise the comparison
	// measures connection setup rather than handling. (The published figure was inverted
	// by exactly this: a client that did not request gzip moved 4x the bytes on one side.)
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 4}, Timeout: 30 * time.Second}

	added := measureAdded(t, client, upstream.URL+"/yj-latency", through.URL+"/yj-latency")
	median, p95, p99 := pct(added, 50), pct(added, 95), pct(added, 99)
	// t.Logf, and its output is visible only under `-v` or on failure — `go test` buffers a
	// passing package's output either way, so writing to os.Stderr instead does NOT surface
	// it in CI (measured; that was this file's second wrong assumption). The numbers are a
	// local tool: `go test . -run TestAddedLatency -v`. Watching the budget drift over time
	// is a separate measurement.
	t.Logf("added latency over %d interleaved pairs: p50=%.3fms p95=%.3fms p99=%.3fms "+
		"(ceilings: median %.1fms, p99 %.1fms)",
		len(added), median, p95, p99, maxMedianAddedMS, maxP99AddedMS)

	if median > maxMedianAddedMS {
		t.Errorf("median added latency %.3fms exceeds the %.1fms budget (#21). This is the "+
			"sensitive bound: it moves when the request path gains a round trip, buffers a "+
			"body it used to stream, or allocates per request. p95=%.3f p99=%.3f",
			median, maxMedianAddedMS, p95, p99)
	}
	if p99 > maxP99AddedMS {
		t.Errorf("p99 added latency %.3fms exceeds the %.1fms backstop (#21). That bound sits "+
			"~9x above the worst noise measured over six sample runs (28.7ms), so this is not a "+
			"noisy neighbour: it is a TAIL-only regression the median cannot see — a lock, a "+
			"retry storm, a rare slow path. p50=%.3f p95=%.3f", p99, maxP99AddedMS, median, p95)
	}
}

// TestAddedLatencyMeasurementDetectsASlowdown is the negative control, and it is the
// reason the test above can be believed.
//
// Every assertion above says a number stayed SMALL, which is exactly what a broken
// measurement also reports. So: inject a known delay into the proxy path only — not into
// the upstream, which both paths share and which would therefore cancel — and require the
// harness to see it. If this test passes while the budget test's numbers are near zero,
// the instrument works.
func TestAddedLatencyMeasurementDetectsASlowdown(t *testing.T) {
	const injected = 40 * time.Millisecond

	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/yj-latency/latest":
			w.Write([]byte(`{"repository":{"url":"git+https://github.com/yj/latency.git"}}`))
		case r.URL.Path == "/yj-latency":
			w.Write([]byte(packumentWith(upstream.URL, 60)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(injected)
		p.ServeHTTP(w, r)
	}))
	defer slow.Close()

	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 4}, Timeout: 30 * time.Second}

	// Far fewer samples: each one pays the injected delay, and the point is detection,
	// not a distribution.
	added := make([]float64, 0, 20)
	for i := 0; i < 5; i++ {
		timeGet(t, client, upstream.URL+"/yj-latency")
		timeGet(t, client, slow.URL+"/yj-latency")
	}
	for i := 0; i < 20; i++ {
		d := timeGet(t, client, upstream.URL+"/yj-latency")
		th := timeGet(t, client, slow.URL+"/yj-latency")
		added = append(added, float64(th-d)/float64(time.Millisecond))
	}
	median := pct(added, 50)
	t.Logf("with %v injected into the proxy path only, the harness measured p50=%.1fms added", injected, median)

	floor := float64(injected/time.Millisecond) * 0.75
	if median < floor {
		t.Errorf("injected %v into the proxy path and the harness reported only %.1fms added "+
			"(expected at least %.1f). The measurement cannot see added latency, so the budget "+
			"test above proves nothing.", injected, median, floor)
	}
}
