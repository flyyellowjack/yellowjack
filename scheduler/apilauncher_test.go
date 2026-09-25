package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeDaemon is a stand-in Docker daemon served over a real unix socket, so the
// apiLauncher's socket-dialing client and its create/start HTTP round-trip are
// exercised end-to-end without a real Docker daemon. It records what it received so
// tests can assert on the request bodies the launcher built.
type fakeDaemon struct {
	mu         sync.Mutex
	createBody containerCreateRequest
	createRaw  string   // raw JSON, to assert on wire shape (e.g. omitempty)
	startedID  string   // id passed to /containers/{id}/start
	calls      []string // ordered list of paths hit, to assert create-before-start

	// canned responses (defaults: 201 + id "c123" on create, 204 on start)
	createStatus int
	createReply  string
	startStatus  int
}

func (d *fakeDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, r.URL.Path)

	switch {
	case r.URL.Path == "/containers/create":
		raw, _ := io.ReadAll(r.Body)
		d.createRaw = string(raw)
		_ = json.Unmarshal(raw, &d.createBody)
		status := d.createStatus
		if status == 0 {
			status = http.StatusCreated
		}
		reply := d.createReply
		if reply == "" {
			reply = `{"Id":"c123"}`
		}
		w.WriteHeader(status)
		io.WriteString(w, reply)
	case strings.HasPrefix(r.URL.Path, "/containers/") && strings.HasSuffix(r.URL.Path, "/start"):
		d.startedID = strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/containers/"), "/start")
		status := d.startStatus
		if status == 0 {
			status = http.StatusNoContent
		}
		w.WriteHeader(status)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// startFakeDaemon serves d over a unix socket and returns the socket path. A short
// temp dir is used deliberately: AF_UNIX socket paths are capped (108 bytes), and
// the default per-test temp dir names can be long enough to overflow it on Windows.
func startFakeDaemon(t *testing.T, d *fakeDaemon) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "yjd")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	sock := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable here (%v) — apiLauncher wire test needs one", err)
	}
	srv := &http.Server{Handler: d}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func TestAPILauncherCreatesAndStarts(t *testing.T) {
	d := &fakeDaemon{}
	sock := startFakeDaemon(t, d)

	l := newAPILauncher(sock, "yellowjack-scanner:dev", "tok-123", "yellowjack", "90")
	if err := l.Launch(context.Background(), "github.com/example/pkg", "http://scheduler:8096/results/42"); err != nil {
		t.Fatalf("Launch: %v", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// create happened, then start — in that order.
	if len(d.calls) != 2 || d.calls[0] != "/containers/create" || !strings.HasSuffix(d.calls[1], "/start") {
		t.Fatalf("call order = %v, want [create, .../start]", d.calls)
	}
	// start targeted the id the create call returned.
	if d.startedID != "c123" {
		t.Errorf("started id = %q, want c123", d.startedID)
	}

	// The create body carried the right image, env, and cleanup/network wiring.
	if d.createBody.Image != "yellowjack-scanner:dev" {
		t.Errorf("image = %q", d.createBody.Image)
	}
	if !d.createBody.HostConfig.AutoRemove {
		t.Errorf("AutoRemove = false, want true (the API form of --rm)")
	}
	if d.createBody.HostConfig.NetworkMode != "yellowjack" {
		t.Errorf("NetworkMode = %q, want yellowjack", d.createBody.HostConfig.NetworkMode)
	}
	wantEnv := map[string]string{
		"SCANNER_REPO":              "github.com/example/pkg",
		"SCANNER_SINK_URL":          "http://scheduler:8096/results/42",
		"GITHUB_TOKEN":              "tok-123",
		"SCANNER_SCAN_TIMEOUT_SECS": "90",
	}
	gotEnv := envMap(d.createBody.Env)
	for k, want := range wantEnv {
		if gotEnv[k] != want {
			t.Errorf("env %s = %q, want %q (all env: %v)", k, gotEnv[k], want, d.createBody.Env)
		}
	}
}

// With no token and no timeout configured, those env vars must be omitted entirely
// (not sent empty) — matching dockerRunLauncher, which only adds -e when set. And
// with no network, NetworkMode must be omitted from the JSON (omitempty), so the
// daemon falls back to its default bridge.
func TestAPILauncherOmitsUnsetOptionals(t *testing.T) {
	d := &fakeDaemon{}
	sock := startFakeDaemon(t, d)

	l := newAPILauncher(sock, "img", "", "", "")
	if err := l.Launch(context.Background(), "r", "http://s/results/1"); err != nil {
		t.Fatalf("Launch: %v", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	gotEnv := envMap(d.createBody.Env)
	if _, ok := gotEnv["GITHUB_TOKEN"]; ok {
		t.Errorf("GITHUB_TOKEN present with no token configured: %v", d.createBody.Env)
	}
	if _, ok := gotEnv["SCANNER_SCAN_TIMEOUT_SECS"]; ok {
		t.Errorf("SCANNER_SCAN_TIMEOUT_SECS present with no timeout configured: %v", d.createBody.Env)
	}
	if strings.Contains(d.createRaw, "NetworkMode") {
		t.Errorf("NetworkMode present in JSON with no network configured: %s", d.createRaw)
	}
}

// A create failure (e.g. image not found) surfaces the daemon's message and the
// container is never started.
func TestAPILauncherCreateFailureSurfaced(t *testing.T) {
	d := &fakeDaemon{createStatus: http.StatusNotFound, createReply: `{"message":"No such image: nope:latest"}`}
	sock := startFakeDaemon(t, d)

	l := newAPILauncher(sock, "nope:latest", "", "", "")
	err := l.Launch(context.Background(), "r", "http://s/results/1")
	if err == nil {
		t.Fatal("expected error on create 404, got nil")
	}
	if !strings.Contains(err.Error(), "No such image") {
		t.Errorf("error = %q, want it to carry the daemon message", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.startedID != "" {
		t.Errorf("start was called (%q) despite create failing", d.startedID)
	}
}

// A start failure surfaces the daemon's message too.
func TestAPILauncherStartFailureSurfaced(t *testing.T) {
	d := &fakeDaemon{startStatus: http.StatusInternalServerError, createReply: `{"Id":"c9"}`}
	sock := startFakeDaemon(t, d)

	l := newAPILauncher(sock, "img", "", "", "")
	err := l.Launch(context.Background(), "r", "http://s/results/1")
	if err == nil {
		t.Fatal("expected error on start 500, got nil")
	}
	if !strings.Contains(err.Error(), "start container") {
		t.Errorf("error = %q, want it to mention start", err)
	}
}

// The launcher respects the context deadline (the scheduler bounds each scan).
func TestAPILauncherHonorsContext(t *testing.T) {
	d := &fakeDaemon{}
	sock := startFakeDaemon(t, d)

	l := newAPILauncher(sock, "img", "", "", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before any request goes out
	if err := l.Launch(ctx, "r", "http://s/results/1"); err == nil {
		t.Error("expected error from a cancelled context")
	}
}

// envMap turns ["K=V", ...] into a map for assertions.
func envMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, e := range env {
		if i := strings.IndexByte(e, '='); i >= 0 {
			m[e[:i]] = e[i+1:]
		}
	}
	return m
}
