package main

import (
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// burstConnCount fires n concurrent GETs at a fresh httptest server through client
// and returns how many distinct TCP connections the server ever accepted. The
// ConnState hook is the honest oracle here: it counts connections the SERVER saw, so
// it cannot be fooled by anything we believe about the client's pool.
func burstConnCount(t *testing.T, client *http.Client, n int) int64 {
	t.Helper()

	var conns int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt64(&conns, 1)
		}
	}
	srv.Start()
	defer srv.Close()

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(srv.URL)
			if err != nil {
				return // a refused/failed dial is exactly what we're measuring against
			}
			// Drain and close: a body left unread is never returned to the idle pool,
			// which would make even a correctly-pooled client re-dial every time.
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
	wg.Wait()
	return atomic.LoadInt64(&conns)
}

// TestPooledTransportBoundsConnectionsPerHost is the deterministic assertion behind
// issue #1. The flake it replaces was platform-dependent (Windows only) and only
// showed up as a downstream symptom — repos re-scanned because their L2 lookup was
// refused. This asserts the actual property instead: a burst far wider than the cap
// must never open more connections than the cap allows.
//
// It carries its OWN negative control (the DefaultTransport leg below), because a
// bound-checking test that can only pass is worthless — it would still "pass" if
// pooledTransport were deleted tomorrow.
func TestPooledTransportBoundsConnectionsPerHost(t *testing.T) {
	const (
		burst = 240 // the same fan-out width as the stress tests
		cap_  = 16  // deliberately far below burst, so the bound is unmistakable
	)

	pooled := &http.Client{Timeout: 30 * time.Second, Transport: pooledTransport(cap_, nil)}
	got := burstConnCount(t, pooled, burst)
	if got > int64(cap_) {
		t.Errorf("pooled transport opened %d connections for a %d-wide burst, want at most %d "+
			"(MaxConnsPerHost is not bounding the pool — issue #1 regression)", got, burst, cap_)
	}
	t.Logf("pooled(cap=%d): %d connections for %d requests", cap_, got, burst)

	// NEGATIVE CONTROL: the stdlib default this replaces. It keeps only 2 idle
	// connections per host and has no ceiling, so the same burst must churn through
	// far more connections. If this leg ever stops exceeding the cap, the assertion
	// above has stopped proving anything and this test is lying.
	unpooled := &http.Client{Timeout: 30 * time.Second, Transport: http.DefaultTransport.(*http.Transport).Clone()}
	base := burstConnCount(t, unpooled, burst)
	if base <= int64(cap_) {
		t.Errorf("negative control: DefaultTransport opened only %d connections for a %d-wide burst "+
			"(want > %d) — the bound assertion above is no longer proving anything", base, burst, cap_)
	}
	t.Logf("negative control DefaultTransport: %d connections for %d requests", base, burst)
}

// TestPooledTransportUnboundedEscapeHatch pins the documented meaning of a negative
// cap: no ceiling, but still a real idle pool. Without this, someone "simplifying"
// the <=0 branch could turn the escape hatch into a 0-sized idle pool and quietly
// reintroduce the churn for anyone who set it.
func TestPooledTransportUnboundedEscapeHatch(t *testing.T) {
	tr := pooledTransport(-1, nil)
	if tr.MaxConnsPerHost > 0 {
		t.Errorf("MaxConnsPerHost = %d, want <= 0 (unbounded)", tr.MaxConnsPerHost)
	}
	if tr.MaxIdleConnsPerHost < defaultMaxConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost = %d, want >= %d — unbounded must still pool, not churn",
			tr.MaxIdleConnsPerHost, defaultMaxConnsPerHost)
	}
}

// TestNewFirewallUsesPooledTransport is the wiring assertion. The bound above is
// worth nothing if the firewall's clients don't actually use it — and both were
// previously on http.DefaultTransport via withUserAgent(nil), which is precisely the
// mistake that is easy to reintroduce when adding a new transport wrapper.
//
// It also pins the zero-value contract: a Config literal that never mentions
// MaxConnsPerHost (i.e. nearly every test in this package) must still come out
// pooled at the default.
func TestNewFirewallUsesPooledTransport(t *testing.T) {
	f, err := NewFirewall(Config{
		Ecosystem:        "npm",
		UpstreamRegistry: "http://unused.invalid",
		ScorecardMode:    "stub",
		ScoreThreshold:   5.0,
		UnscorablePolicy: "block",
		// MaxConnsPerHost deliberately unset.
	})
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}

	for _, tc := range []struct {
		name   string
		client *http.Client
	}{
		{"client", f.client},
		{"scannerClient", f.scannerClient},
	} {
		tr := unwrapTransport(tc.client.Transport)
		if tr == nil {
			t.Errorf("%s: transport chain does not end in an *http.Transport "+
				"(still on http.DefaultTransport? — issue #1 regression)", tc.name)
			continue
		}
		if tr.MaxConnsPerHost != defaultMaxConnsPerHost {
			t.Errorf("%s: MaxConnsPerHost = %d, want %d", tc.name, tr.MaxConnsPerHost, defaultMaxConnsPerHost)
		}
		if tr.MaxIdleConnsPerHost != defaultMaxConnsPerHost {
			t.Errorf("%s: MaxIdleConnsPerHost = %d, want %d", tc.name, tr.MaxIdleConnsPerHost, defaultMaxConnsPerHost)
		}
	}

	// Both clients must share ONE transport, so the per-host budget is per host and
	// not doubled by having two pools.
	if unwrapTransport(f.client.Transport) != unwrapTransport(f.scannerClient.Transport) {
		t.Error("client and scannerClient use different transports, want one shared pool")
	}
}

// unwrapTransport walks our RoundTripper decorators (User-Agent, upstream auth) down
// to the underlying *http.Transport. It returns nil if the chain bottoms out in
// anything else — notably http.DefaultTransport, which is a *different* *http.Transport
// instance and is caught by the settings assertions above rather than here.
func unwrapTransport(rt http.RoundTripper) *http.Transport {
	for range 8 { // bounded: our chains are 1-2 deep; never loop on a cycle
		switch v := rt.(type) {
		case *userAgentTransport:
			rt = v.base
		case *probeAuthTransport:
			rt = v.base
		case *http.Transport:
			return v
		default:
			return nil
		}
	}
	return nil
}

// waveConnCount fires `waves` successive bursts of n concurrent GETs at ONE server
// through the same client, and returns how many TCP connections the server accepted in
// total. Where burstConnCount measures the ceiling, this measures REUSE: with a real
// idle pool the later waves should ride on the connections the first wave opened.
func waveConnCount(t *testing.T, client *http.Client, n, waves int) int64 {
	t.Helper()

	var conns int64

	// THE HANDLER HOLDS EVERY REQUEST OF A WAVE UNTIL THE WHOLE WAVE HAS ARRIVED.
	//
	// Without this the measurement does not mean what it says, and issue #125 is what
	// that looks like: the negative control reported exactly `perWave` and the test
	// correctly refused to adjudicate.
	//
	// The arrangement assumes n requests are in flight AT ONCE, so an unpooled client
	// -- holding two idle connections -- must dial the other n-2. That assumption is
	// false against a local server. Each request completes in microseconds, so a pool
	// of two connections can serve all 32 sequentially, and if dialing is slow relative
	// to that (a contended runner) NO new connection is ever opened. Instrumented, with
	// 20ms dials and no barrier:
	//
	//	wave 0 done: conns=30 open=3     <- wave 1 never needed 32 either
	//	wave 1 done: conns=32 open=2     <- wave 2 opened NOTHING; 2 conns served 32
	//
	// A barrier makes the concurrency real instead of hoped for, which makes the
	// measurement independent of how fast this machine dials or serves.
	var (
		mu      sync.Mutex
		arrived int
		gate    = make(chan struct{})
	)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		arrived++
		if arrived == n {
			close(gate)
		}
		g := gate
		mu.Unlock()
		select {
		case <-g:
		case <-time.After(20 * time.Second):
			// Never on a healthy run. Releasing rather than hanging means a broken
			// arrangement is reported by the assertions, not by a test timeout.
		}
		io.WriteString(w, "ok")
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt64(&conns, 1)
		}
	}
	srv.Start()
	defer srv.Close()

	for w := 0; w < waves; w++ {
		mu.Lock()
		arrived, gate = 0, make(chan struct{})
		mu.Unlock()

		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := client.Get(srv.URL)
				if err != nil {
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}()
		}
		wg.Wait()
	}
	return atomic.LoadInt64(&conns)
}

// TestProxyRelayTransportPoolsWithoutCapping pins BOTH halves of the issue #54
// decision, because each half is separately easy to get wrong:
//
//	POOLS  — the relay is the highest-volume path in the product, and on
//	         http.DefaultTransport's 2-idle-conns-per-host it re-dialed and
//	         re-handshook against a remote TLS registry under any real parallelism.
//	NO CAP — a MaxConnsPerHost ceiling would make excess requests wait for a free
//	         connection, and this client has NO http.Client.Timeout on purpose (a
//	         whole-request timeout truncated large artifact blobs). A cap without a
//	         deadline could stall a download indefinitely behind other downloads.
//
// A test that only checked "is pooled" would happily pass if someone added a ceiling
// and quietly introduced that stall, so the absence of the cap is asserted too.
func TestProxyRelayTransportPoolsWithoutCapping(t *testing.T) {
	p := newProxyServer(Config{Ecosystem: "npm", UpstreamRegistry: "http://x"}, nil)

	tr := unwrapTransport(p.client.Transport)
	if tr == nil {
		t.Fatal("relay transport chain does not end in an *http.Transport")
	}
	if tr.MaxIdleConnsPerHost < defaultMaxConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost = %d, want >= %d — the relay path is back on the "+
			"stdlib's 2-idle-conns default and will churn connections (issue #54)",
			tr.MaxIdleConnsPerHost, defaultMaxConnsPerHost)
	}
	if tr.MaxConnsPerHost != 0 {
		t.Errorf("MaxConnsPerHost = %d, want 0 (no ceiling): capping the client-facing "+
			"relay would queue artifact downloads behind each other, and this client has "+
			"no Client.Timeout to bound the wait", tr.MaxConnsPerHost)
	}
	// The pooling change must not have disturbed the blob-truncation fix that shares
	// this transport — a 30s header timeout with no whole-request timeout.
	if tr.ResponseHeaderTimeout != 30*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want 30s", tr.ResponseHeaderTimeout)
	}
	if p.client.Timeout != 0 {
		t.Errorf("relay client Timeout = %v, want 0 — a whole-request timeout truncates "+
			"large artifact downloads mid-stream", p.client.Timeout)
	}
}

// reuseTolerance is the slack on the pooled connection count, and it exists for a
// specific mechanical reason rather than to quiet a noisy test (issue #62).
//
// waveConnCount starts wave 2 as soon as wg.Wait() returns — i.e. as soon as every
// wave-1 goroutine has called resp.Body.Close(). But Go's transport returns a
// connection to the idle pool ASYNCHRONOUSLY, from its read loop, after the body is
// drained; closing the body does not guarantee the connection is back in the pool yet.
// So a handful of wave-2 requests can legitimately find the pool not yet replenished
// and dial, even though pooling is working perfectly.
//
// The original assertion was `pooled <= perWave` — exactly 32, zero slack — and it
// failed intermittently on CI at 33 while the negative control sat at 54-62, i.e. while
// pooling was demonstrably working. It failed on `main` (a02a1939) as well as on
// feature branches, and 30 consecutive local runs could not reproduce it, which is
// exactly the signature of a race whose window widens on a loaded runner.
//
// A tolerance chosen only to make CI quiet would be how a real regression gets absorbed
// later, so it is deliberately SMALL and it is not the only guard: the ratio assertion
// below is what actually distinguishes pooled from unpooled, and no tolerance can
// satisfy it.
// Kept, but no longer load-bearing: the handler barrier in waveConnCount makes every
// request of a wave genuinely concurrent, so the async-return race described above no
// longer has a window and the pooled count is now exactly perWave on every run measured
// (6/6 with normal dials, 6/6 with 20ms dials). The slack stays as slack rather than
// being removed on the strength of one machine (#125).
const reuseTolerance = 4

// TestProxyRelayTransportReusesConnections is the behavioral half: the settings above
// are only worth asserting if they actually change what goes on the wire. Two waves
// through one pooled client must ride on the first wave's connections.
//
// The property is asserted TWO ways, because neither alone is sound:
//
//  1. an absolute bound with a small, mechanically-justified tolerance, and
//  2. a RATIO against a bare DefaultTransport measured in the same run.
//
// (2) is the load-bearing one and the reason (1) can afford any slack at all: a client
// that dialed every single request lands near the control, not near perWave, and no
// tolerance short of absurd would let it through. Measuring the control in the same run
// also means a slower or busier machine moves both numbers together.
func TestProxyRelayTransportReusesConnections(t *testing.T) {
	const (
		perWave = 32
		waves   = 2
	)

	// NEGATIVE CONTROL first, so the pooled assertion can be expressed relative to it.
	// The stdlib default this replaces keeps 2 idle conns per host, so wave 2 must
	// re-dial nearly everything.
	unpooled := &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}
	base := waveConnCount(t, unpooled, perWave, waves)
	t.Logf("negative control DefaultTransport: %d connections for %d x %d requests", base, waves, perWave)

	p := newProxyServer(Config{Ecosystem: "npm", UpstreamRegistry: "http://x"}, nil)
	pooled := waveConnCount(t, p.client, perWave, waves)
	t.Logf("relay client: %d connections for %d x %d requests", pooled, waves, perWave)

	if base <= perWave {
		t.Fatalf("negative control: DefaultTransport opened only %d connections for %d waves "+
			"of %d (want > %d) — the reuse assertions below are no longer proving anything",
			base, waves, perWave, perWave)
	}

	// (1) Absolute: essentially one wave's worth of connections, plus the few racing
	// dials explained on reuseTolerance.
	if pooled > perWave+reuseTolerance {
		t.Errorf("relay client opened %d connections for %d waves of %d, want <= %d "+
			"(%d + %d tolerance) — the second wave should ride on the first's connections (issue #54)",
			pooled, waves, perWave, perWave+reuseTolerance, perWave, reuseTolerance)
	}

	// (2) Relative: the pooled client must sit in the bottom quarter of the range
	// between "perfect reuse" (perWave) and "no reuse" (base). This is the assertion
	// that cannot be satisfied by a regression — an unpooled client lands at base, and
	// a partially-pooled one lands in the middle.
	ceiling := perWave + (base-perWave)/4
	if pooled > ceiling {
		t.Errorf("relay client opened %d connections; with perfect reuse that is %d and with "+
			"NO reuse it is %d (measured this run), so anything above %d means the pool is not "+
			"being used as intended (issue #54)", pooled, perWave, base, ceiling)
	}
}

// TestPooledTransportHonoursTheProxyEnvironment pins the OTHER half of class 7 (#137).
//
// An enterprise forward proxy needs two things from us: trust its CA (FW_UPSTREAM_CA_BUNDLE)
// and route through it. We ship NO knob for the route, deliberately — the clone of
// http.DefaultTransport already carries http.ProxyFromEnvironment, so HTTPS_PROXY routes us
// and NO_PROXY keeps internal hosts direct, and re-implementing that would cost the config
// budget (#51) two more values for behaviour the standard library already has.
//
// The cost of "we get it for free" is that nothing in the tree would notice if it went away.
// Setting Proxy to nil here — a plausible line in any future tidy-up of this constructor —
// silently strips every deployment behind a corporate proxy of its route, and the symptom
// lands on the customer as a connection timeout, not on us as a failing test.
//
// The assertion is on function IDENTITY rather than on behaviour, and that is deliberate:
// net/http resolves the proxy environment ONCE per process (envProxyOnce), so a test that
// set HTTPS_PROXY and called tr.Proxy would pass or fail depending on whether some earlier
// test in the binary had already triggered that sync.Once. The behavioural half is the e2e
// leg, where a real firewall container reaches a real corporate proxy through the
// environment and nothing else (P15-2).
func TestPooledTransportHonoursTheProxyEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name string
		tr   *http.Transport
	}{
		{"the firewall's probe pool", pooledTransport(defaultMaxConnsPerHost, nil)},
		{"the proxy's relay pool", pooledTransport(-1, nil)},
		{"with an operator CA bundle attached", pooledTransport(0, x509.NewCertPool())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.tr.Proxy == nil {
				t.Fatal("this transport ignores the proxy environment entirely: a deployment behind a " +
					"corporate forward proxy has no way to route through it, and we ship no knob for it")
			}
			got := runtime.FuncForPC(reflect.ValueOf(tc.tr.Proxy).Pointer()).Name()
			want := runtime.FuncForPC(reflect.ValueOf(http.ProxyFromEnvironment).Pointer()).Name()
			if got != want {
				t.Errorf("the proxy resolver is %s, not the standard library's %s. HTTPS_PROXY/NO_PROXY "+
					"are the documented interface for this (docs/CONFIGURATION.md); anything else is a "+
					"second, undocumented one", got, want)
			}
		})
	}
}
