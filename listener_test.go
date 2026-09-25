package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// #130 -- the cooperative listener's connection lifetimes, measured the way the
// interception listener's were (intercept_class6_test.go): a client misbehaves in one
// specific way, the connection it held is released by a BOUND rather than by the
// client's goodwill, and a well-behaved client is served afterwards. Before #130 the
// listener was http.ListenAndServe with no timeouts, and every release test here hung.
//
// The bounds are the same package variables the interception listener copies at
// construction, so `shorten` works here exactly as it does there.

// startCooperative serves a test proxy on a real TCP listener through cooperativeServer.
// httptest's server would carry its OWN http.Server, with none of the bounds under test.
func startCooperative(t *testing.T, up *httptest.Server) string {
	t.Helper()
	p := newTestProxy(t, up, func(c *Config) { c.ScoreThreshold = 0; c.UnscorablePolicy = "allow" })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := cooperativeServer(ln.Addr().String(), p)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// stalledPut sends complete headers, promises 100000 body bytes, sends three, and
// returns the connection. Whatever the gate does next waits on a body that never comes.
func stalledPut(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "PUT /lodash HTTP/1.1\r\nHost: %s\r\nContent-Length: 100000\r\nContent-Type: application/octet-stream\r\n\r\nabc", addr)
	return c
}

func servedCooperatively(t *testing.T, addr, what string) {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/lodash")
	if err != nil {
		t.Fatalf("after %s, a client was not served: %v", what, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"lodash"`) {
		t.Fatalf("after %s, a client got %d (%d bytes), want 200 with the packument", what, resp.StatusCode, len(b))
	}
}

// TestCooperativeStalledRequestBodyIsReleasedByTheReadTimeout is the issue's own
// reproduction: headers complete, body promised and never sent. The gate must answer
// or close within the read window, and serve the next client.
func TestCooperativeStalledRequestBodyIsReleasedByTheReadTimeout(t *testing.T) {
	shorten(t, &interceptRequestReadTimeout, 500*time.Millisecond)
	addr := startCooperative(t, npmUpstream(t))
	c := stalledPut(t, addr)
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil && err != io.EOF {
		t.Fatalf("the stalled PUT was neither answered nor closed within 3s (read window %s): %v -- the body wait is unbounded, which is #130", interceptRequestReadTimeout, err)
	}
	t.Logf("stalled PUT released once the read window expired: %q (err %v)", strings.TrimSpace(line), err)
	servedCooperatively(t, addr, "a stalled request body")
}

// TestCooperativeSilentClientIsReleasedByTheHeaderTimeout: a connection that never
// sends a request line is closed by the header bound, not held until the client leaves.
func TestCooperativeSilentClientIsReleasedByTheHeaderTimeout(t *testing.T) {
	shorten(t, &interceptReadHeaderTimeout, 300*time.Millisecond)
	addr := startCooperative(t, npmUpstream(t))
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = c.Read(make([]byte, 1))
	if err == nil || strings.Contains(err.Error(), "i/o timeout") {
		t.Fatalf("a client that never sent a request was still connected after 3s (header window %s): %v", interceptReadHeaderTimeout, err)
	}
	servedCooperatively(t, addr, "a silent client")
}

// uploadCountingUpstream serves lodash's packument for the gate's own lookup and, on PUT,
// reads the whole body and answers with the byte count -- so the upload test can see
// that every trickled byte crossed the relay, not merely that something answered.
func uploadCountingUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			n, err := io.Copy(io.Discard, r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			fmt.Fprintf(w, "%d", n)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"name":"lodash","dist-tags":{"latest":"1.0.0"},"repository":{"type":"git","url":"https://github.com/lodash/lodash"},`+
			`"versions":{"1.0.0":{"name":"lodash","version":"1.0.0","repository":{"url":"https://github.com/lodash/lodash"},"dist":{"tarball":"`+srv.URL+`/lodash/-/lodash-1.0.0.tgz"}}}}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestCooperativeTrickledUploadIsNotCutByTheReadTimeout pins the other half of the
// bound: an upload that keeps ARRIVING, slower than the window is long, must complete.
// A plain ReadTimeout would cut it at the window's edge, which is exactly the "proxy
// stopped responding" shape moved from stalled clients to legitimate slow ones.
func TestCooperativeTrickledUploadIsNotCutByTheReadTimeout(t *testing.T) {
	shorten(t, &interceptRequestReadTimeout, 500*time.Millisecond)
	addr := startCooperative(t, uploadCountingUpstream(t))
	const chunks, chunk = 20, 100 // 2000 bytes over ~2s: four read windows long
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "PUT /lodash HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nContent-Type: application/octet-stream\r\n\r\n", addr, chunks*chunk)
	for i := 0; i < chunks; i++ {
		if _, err := c.Write(bytes.Repeat([]byte{'x'}, chunk)); err != nil {
			t.Fatalf("chunk %d refused after %s: %v -- the upload was cut", i, time.Duration(i)*100*time.Millisecond, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("no response to a ~2s upload under a 500ms read window: %v -- the window is bounding the upload, not the stall", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != fmt.Sprint(chunks*chunk) {
		t.Fatalf("upload answered %d %q, want 200 %q (every byte across the relay)", resp.StatusCode, string(b), fmt.Sprint(chunks*chunk))
	}
}

// TestCooperativeBoundsAreTheInstrument is the negative control: with the bounds
// disabled the stalled PUT is NOT released, so the releases above are the bounds'
// doing and not some other path that happens to answer stalled writes.
func TestCooperativeBoundsAreTheInstrument(t *testing.T) {
	shorten(t, &interceptRequestReadTimeout, 0)
	shorten(t, &interceptReadHeaderTimeout, 0)
	addr := startCooperative(t, npmUpstream(t))
	c := stalledPut(t, addr)
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	_, err := bufio.NewReader(c).ReadString('\n')
	if err == nil || !strings.Contains(err.Error(), "i/o timeout") {
		t.Fatalf("with no read bound the stalled PUT was released anyway (%v), so the releases above may not be the bound's doing", err)
	}
}
