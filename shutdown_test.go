package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// On a stop signal the gate keeps SERVING through the lameduck while /readyz says it is
// draining, and only then stops accepting. The first real-cluster drain dropped a request
// because the gate had no signal handling at all (e2e/helm_install.sh, leg 4); this pins the
// sequence without a cluster.
func TestAStopSignalDrainsBeforeTheListenerCloses(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()
	p := newTestProxy(t, upstream, func(c *Config) { c.ScorecardMode = "off" })

	prev := shutdownLameduck
	shutdownLameduck = 400 * time.Millisecond
	defer func() { shutdownLameduck = prev }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	sigs := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() { done <- serveUntilSignal(p, cooperativeServer(ln.Addr().String(), p), ln, sigs) }()

	get := func(path string) (int, string) {
		resp, err := http.Get(base + path)
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// CONTROL: before the signal the gate is ready. Without this, a 503 below could be any
	// unreadiness, not the drain.
	if code, body := get("/readyz"); code != http.StatusOK {
		t.Fatalf("before the signal /readyz = %d %q; want 200 ready, or the drain assertion proves nothing", code, body)
	}

	sigs <- syscall.SIGTERM
	time.Sleep(100 * time.Millisecond)

	// Inside the lameduck: not ready, but still answering.
	if code, body := get("/readyz"); code != http.StatusServiceUnavailable || !strings.Contains(body, "draining") {
		t.Errorf("during the drain /readyz = %d %q; want 503 naming the drain", code, body)
	}
	if code, _ := get("/healthz"); code != http.StatusOK {
		t.Errorf("during the drain /healthz = %d; the gate must still SERVE until routes are withdrawn", code)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveUntilSignal returned %v after a drain; want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the gate did not stop after the lameduck")
	}
	// After the drain the listener is closed: a new connection is refused.
	if c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
		c.Close()
		t.Error("the listener still accepts after the drain completed")
	}
}
