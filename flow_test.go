package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// find returns the snapshot row for a package+kind, or a zero row.
func find(rows []flowRow, pkg string, kind flowKind) flowRow {
	for _, r := range rows {
		if r.Package == pkg && r.Kind == kind {
			return r
		}
	}
	return flowRow{}
}

// totalBytes sums the client-side bytes across every row — the number a dashboard's
// "total throughput" tile would show.
func totalBytes(rows []flowRow) int64 {
	var n int64
	for _, r := range rows {
		n += r.BytesClient
	}
	return n
}

// A relayed artifact is counted against its package, with the bytes that actually moved.
func TestFlowRecordsArtifactBytes(t *testing.T) {
	payload := strings.Repeat("x", 4096)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(payload))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) { c.ByteGate = "off" })
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/lodash/-/lodash-4.17.21.tgz", nil))

	row := find(p.flow.Snapshot(), "lodash", flowArtifact)
	if row.Requests != 1 {
		t.Errorf("Requests = %d, want 1 (the tarball fetch)", row.Requests)
	}
	if row.BytesClient != int64(len(payload)) || row.BytesUpstream != int64(len(payload)) {
		t.Errorf("bytes = up %d / client %d, want %d for both (streamed verbatim)",
			row.BytesUpstream, row.BytesClient, len(payload))
	}
	if row.Ecosystem != "npm" {
		t.Errorf("Ecosystem = %q, want npm — the row must say which firewall produced it", row.Ecosystem)
	}
}

// NEGATIVE CONTROL for the unattributed bucket. Registry-infrastructure requests carry
// no package name but do carry bytes; if they are dropped instead of bucketed, the
// per-package rows stop summing to the instance total and the dashboard silently
// disagrees with itself.
func TestFlowCountsUnattributedTraffic(t *testing.T) {
	body := strings.Repeat("y", 512)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer upstream.Close()

	// An OCI /v2/ handshake: real bytes, no package identity.
	p := newTestProxy(t, upstream, func(c *Config) { c.Ecosystem = "oci" })
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/", nil))

	rows := p.flow.Snapshot()
	infra := find(rows, "", flowInfra)
	if infra.Requests != 1 || infra.BytesClient != int64(len(body)) {
		t.Errorf("unattributed row = %+v, want 1 request and %d bytes — infrastructure traffic must be bucketed, not dropped",
			infra, len(body))
	}
	if got := totalBytes(rows); got != int64(len(body)) {
		t.Errorf("instance total = %d, want %d — per-package rows must sum to the real total", got, len(body))
	}
}

// NEGATIVE CONTROL for the Content-Length trap. Upstream promises more than it sends;
// we must count what arrived. Counting the header would inflate traffic precisely during
// the failure the dashboard exists to explain.
func TestFlowCountsTransferredBytesNotPromised(t *testing.T) {
	const promised, sent = 10000, 100
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(promised))
		w.Write([]byte(strings.Repeat("z", sent)))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) { c.ByteGate = "off" })
	rec := httptest.NewRecorder()
	// A short body makes relay panic(http.ErrAbortHandler) by design — that is how a
	// truncated transfer is surfaced to the client. Recover so the test can inspect
	// the counters afterwards.
	func() {
		defer func() { recover() }()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/lodash/-/lodash-4.17.21.tgz", nil))
	}()

	row := find(p.flow.Snapshot(), "lodash", flowArtifact)
	if row.BytesClient != sent {
		t.Errorf("BytesClient = %d, want %d — must count bytes transferred, not the %d Content-Length promised",
			row.BytesClient, sent, promised)
	}
	if row.Truncated != 1 {
		t.Errorf("Truncated = %d, want 1 (upstream delivered less than it promised)", row.Truncated)
	}
}

// Upstream statuses: only real failures count. A 404 is routine probing — package
// managers ask for optional artifacts constantly — and counting those would show
// thousands of "failures" on a healthy instance and train operators to ignore the metric.
func TestFlowStatusCountsFailuresNotProbes(t *testing.T) {
	cases := []struct {
		status int
		want   int64
		why    string
	}{
		{http.StatusNotFound, 0, "a 404 is routine probing for an optional artifact, not a failure"},
		{http.StatusTooManyRequests, 1, "429 is upstream throttling us — an operational problem (D25)"},
		{http.StatusBadGateway, 1, "5xx is upstream genuinely broken"},
		{http.StatusOK, 0, "success is not a failure"},
	}
	for _, c := range cases {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
		}))
		p := newTestProxy(t, upstream, func(cfg *Config) { cfg.ByteGate = "off" })
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/lodash/-/lodash-4.17.21.tgz", nil))
		upstream.Close()

		if got := find(p.flow.Snapshot(), "lodash", flowArtifact).UpstreamStatus; got != c.want {
			t.Errorf("status %d counted %d, want %d — %s", c.status, got, c.want, c.why)
		}
	}
}

// Metadata is rewritten on the way through, so the upstream and client byte counts
// legitimately DIFFER. Collapsing them into one number would misreport egress — the
// figure an egress-metered site actually pays for.
func TestFlowRecordsMetadataBothSides(t *testing.T) {
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lodash/latest":
			// Declares a source repo, so the stub scorer allows it and the relay
			// actually happens — an unscorable package is blocked and never relays.
			w.Write([]byte(`{"repository":{"url":"git+https://github.com/lodash/lodash.git"}}`))
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"name":"lodash","versions":{"1.0.0":{"dist":{"tarball":"%s/lodash/-/lodash-1.0.0.tgz"}}}}`, upstream.URL)
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/lodash", nil))

	row := find(p.flow.Snapshot(), "lodash", flowMetadata)
	if row.Requests != 1 {
		t.Fatalf("metadata Requests = %d, want 1", row.Requests)
	}
	if row.BytesUpstream == 0 || row.BytesClient == 0 {
		t.Fatalf("metadata bytes not recorded: %+v", row)
	}
	// The rewrite repoints the tarball URL at us, changing the body's size — so the two
	// sides must not be equal here. If they are, one of them is being derived from the
	// other rather than measured.
	if row.BytesUpstream == row.BytesClient {
		t.Errorf("upstream (%d) == client (%d) bytes on a REWRITTEN body; the two sides must be measured separately",
			row.BytesUpstream, row.BytesClient)
	}
}

// The recorder is written from every per-request goroutine. Run under -race.
func TestFlowRecorderConcurrent(t *testing.T) {
	f := newFlowRecorder("npm")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := flowID{Package: fmt.Sprintf("pkg-%d", i%5), Kind: flowArtifact}
			f.recordRequest(id)
			f.recordBytes(id, 10, 10)
			f.recordRetry(id)
			f.Snapshot()
		}(i)
	}
	wg.Wait()

	var reqs, bytes int64
	for _, r := range f.Snapshot() {
		reqs += r.Requests
		bytes += r.BytesClient
	}
	if reqs != 50 || bytes != 500 {
		t.Errorf("got %d requests / %d bytes, want 50 / 500 — a lost update means the counters are not safe under concurrency", reqs, bytes)
	}
}

// A nil recorder is a working no-op, so any construction path that wires no accounting
// still serves traffic rather than panicking on the request path.
func TestFlowNilRecorderIsSafe(t *testing.T) {
	var f *flowRecorder
	id := flowID{Package: "x", Kind: flowArtifact}
	f.recordRequest(id)
	f.recordBytes(id, 1, 1)
	f.recordTruncated(id)
	f.recordRelayError(id)
	f.recordTransportError(id)
	f.recordMetaError(id)
	f.recordRetry(id)
	f.recordStatus(id, 500)
	if got := f.Snapshot(); got != nil {
		t.Errorf("nil recorder Snapshot = %+v, want nil", got)
	}
}

// NEGATIVE CONTROL, and the one that matters most operationally: a CLIENT hang-up is
// not upstream corruption.
//
// A developer pressing Ctrl-C mid-install produces a short read that is byte-for-byte
// indistinguishable from upstream truncation at the io.Copy call site. If the counter
// ignores the context check and counts it, the failure metric tracks developer
// impatience instead of upstream health — and the design's zero-threshold alert
// ("Truncated > 0 is always wrong") fires constantly from day one, which is how an
// alert gets muted and stops being an alert at all.
func TestFlowClientCancelIsNotCorruption(t *testing.T) {
	// The upstream promises far more than it will send and dribbles the body out, so the
	// client can hang up mid-transfer. It ends itself when its own request context is
	// cancelled (which happens when we cancel, since the relay ties the two together) —
	// deliberately NOT on a channel the test closes, because that version deadlocks: the
	// test would have to be past the wait it is about to perform in order to release it.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100000")
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 200; i++ {
			if _, err := w.Write([]byte(strings.Repeat("q", 256))); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) { c.ByteGate = "off" })
	done := make(chan struct{})
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		p.ServeHTTP(w, r)
	}))
	defer front.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, front.URL+"/lodash/-/lodash-4.17.21.tgz", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := io.ReadFull(resp.Body, make([]byte, 128)); err != nil {
		t.Fatalf("read partial body: %v", err)
	}
	cancel() // the developer hits Ctrl-C
	resp.Body.Close()

	// Bounded: if the handler never returns, fail with a diagnosis instead of hanging
	// until the whole suite times out with no clue which test wedged.
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("proxy handler did not return after the client cancelled")
	}

	row := find(p.flow.Snapshot(), "lodash", flowArtifact)
	if row.Truncated != 0 {
		t.Errorf("Truncated = %d, want 0 — a client hang-up is the developer abandoning their own transfer, not upstream corruption", row.Truncated)
	}
	if row.RelayErrors != 0 {
		t.Errorf("RelayErrors = %d, want 0 — a client hang-up is not a relay failure", row.RelayErrors)
	}
	// The traffic that did move is still counted: those bytes really were served.
	if row.BytesClient == 0 {
		t.Error("BytesClient = 0, want the partial transfer to still be counted")
	}
}
