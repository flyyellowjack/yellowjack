package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Zero-egress, measured (issue #27).
//
// The claim this file defends is NOT "the firewall makes no outbound connections" — it
// makes several, and saying otherwise would be the overclaim D65 warns about. It is:
//
//	every address the firewall dials is one the OPERATOR configured.
//
// Nothing phones home, because there is no home to phone: no host literal exists in the
// binary's egress path at all. That is the difference between us and the alternatives we examined
// studied (2026-07-26), each of which needs its own cloud in the request path — and it is
// why we can default fail-closed where they must fail open.
//
// Three assertions, because the property has three independent ways to break:
//
//  1. TestFirewallDialsOnlyConfiguredDestinations — the behaviour itself.
//  2. TestEveryOutboundClientIsObservable — an outbound client that skips pooledTransport
//     would be invisible to (1), making it green for the wrong reason.
//  3. TestFirewallBinaryLinksOnlyStdlib — a third-party dependency can dial on its own,
//     bypassing the seam entirely. This is the known weakness of dialler-level egress
//     checks, so it is measured rather than assumed away.
//
// (1) is the fast leg. The container-level leg in e2e is the honest one — it watches the
// process from outside, where DNS and any rogue dialer are visible. Neither replaces the
// other; see egress.go for exactly what this layer can and cannot see.

// egressRecorder collects every address dialled while it is installed.
type egressRecorder struct {
	mu    sync.Mutex
	addrs map[string]int
}

func newEgressRecorder() *egressRecorder {
	return &egressRecorder{addrs: map[string]int{}}
}

func (r *egressRecorder) observe(network, addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addrs[addr]++
}

func (r *egressRecorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.addrs))
	for a := range r.addrs {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// unexpected returns everything dialled that the configuration does not permit. This is
// the assertion in one line: the set difference must be empty.
func (r *egressRecorder) unexpected(allowed []string) []string {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	var bad []string
	for _, a := range r.seen() {
		if !ok[a] {
			bad = append(bad, a)
		}
	}
	return bad
}

// TestFirewallDialsOnlyConfiguredDestinations drives the full request path against
// stand-ins for every configured destination and asserts nothing else was dialled.
//
// Deliberately run against STAND-INS, not the live registry. A real registry redirects
// artifact fetches to a CDN on a different host, which this assertion would (correctly)
// report as an unconfigured destination — a true observation about the internet, but a
// useless test, because the result would depend on npm's CDN topology rather than on our
// code. The container-level leg is where following a real redirect is meaningful.
func TestFirewallDialsOnlyConfiguredDestinations(t *testing.T) {
	// Every configured destination gets its own listener, so "which host was dialled"
	// is unambiguous — one shared server would make the subset assertion trivially true.
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/lodash/latest":
			w.Write([]byte(`{"repository":{"url":"git+https://github.com/lodash/lodash.git"}}`))
		case r.URL.Path == "/lodash":
			w.Write([]byte(`{"versions":{"1.0.0":{"dist":{"tarball":"` + upstream.URL + `/lodash/-/lodash-1.0.0.tgz"}}}}`))
		default:
			// Artifact bytes: a gzip magic number is enough to be recognisable.
			w.Write([]byte{0x1f, 0x8b, 0x08, 0x00})
		}
	}))
	defer upstream.Close()

	depsDev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Shape matters less than the fact that it is a DIFFERENT host being dialled.
		w.Write([]byte(`{"version":{"projects":[{"projectKey":{"id":"github.com/lodash/lodash"}}]}}`))
	}))
	defer depsDev.Close()

	approval := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"verdict":"denied"}`))
	}))
	defer approval.Close()

	cfg := Config{
		Ecosystem:        "npm",
		UpstreamRegistry: upstream.URL,
		FilesUpstream:    upstream.URL,
		DepsDevBase:      depsDev.URL,
		ApprovalURL:      approval.URL,
		UnscorablePolicy: "allow",
		ScoreThreshold:   0,
		ScorecardMode:    "api", // exercises the deps.dev leg rather than the stub
		ScoreCacheTTL:    time.Minute,
		ByteGate:         "enforce",
	}

	rec := newEgressRecorder()
	restore := setEgressObserver(rec.observe)
	defer restore()

	fw, err := NewFirewall(cfg)
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	p := newProxyServer(cfg, fw)

	// Walk the paths a real client walks: metadata, then artifact bytes.
	for _, path := range []string{"/lodash", "/lodash/-/lodash-1.0.0.tgz"} {
		req := httptest.NewRequest(http.MethodGet, "http://fw.local"+path, nil)
		p.ServeHTTP(httptest.NewRecorder(), req)
	}
	// And the telemetry path, which is the one most deserving of scrutiny here: if
	// anything ever reports home, this is the code it would live in.
	p.flowEmit.heartbeat()

	allowed := cfg.egressDestinations()

	// Anti-vacuity FIRST. Every assertion below is satisfied by a firewall that dialled
	// nothing at all — a broken build, a handler that 500s before any upstream call — so
	// the test must prove it actually exercised the egress path before it can claim the
	// egress path is clean.
	seen := rec.seen()
	if len(seen) == 0 {
		t.Fatal("no outbound connection was observed at all — the request path did not run, " +
			"so 'nothing unexpected was dialled' proves nothing")
	}
	if len(seen) < 2 {
		t.Errorf("only one distinct destination (%v) was dialled; the scenario is meant to reach the "+
			"registry, deps.dev AND the approval service, so the subset assertion is weaker than intended", seen)
	}

	if bad := rec.unexpected(allowed); len(bad) > 0 {
		t.Errorf("EGRESS VIOLATION: the firewall dialled %v, which no Config field names.\n"+
			"configured destinations: %v\nall observed: %v\n"+
			"Every outbound address must come from operator-supplied config — a literal host in the "+
			"binary is exactly the 'phones home' property #27 exists to prevent.",
			bad, allowed, seen)
	}
	t.Logf("observed %d destinations, all configured: %v", len(seen), seen)

	// ── Negative control (required by #27's acceptance): prove this check CAN go red.
	//
	// An egress check that has only ever printed green is worse than no check — it
	// converts an unknown into false confidence. So: make exactly the kind of call the
	// assertion exists to catch — an unrelated host, reached through the same transport
	// every firewall client uses — and prove it is both observed and flagged.
	t.Run("negative control: an unrelated host is caught", func(t *testing.T) {
		rogue := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer rogue.Close()

		client := &http.Client{Transport: pooledTransport(0, nil)}
		resp, err := client.Get(rogue.URL + "/telemetry")
		if err != nil {
			t.Fatalf("control: the rogue call itself failed (%v) — it must SUCCEED, or this "+
				"proves only that unreachable hosts are unreachable", err)
		}
		resp.Body.Close()

		want := hostPort(rogue.URL)
		bad := rec.unexpected(allowed)
		found := false
		for _, a := range bad {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("NEGATIVE CONTROL FAILED: a call to %s was not reported as unexpected (reported: %v).\n"+
				"The assertion above cannot fail, so its green result means nothing.", want, bad)
		}
		t.Logf("negative control: rogue call to %s correctly flagged", want)
	})
}

// TestEveryOutboundClientIsObservable is the assertion that keeps the test above honest.
//
// The egress hook lives in pooledTransport. An http.Client built WITHOUT it — a bare
// &http.Client{} falls back to http.DefaultTransport — dials without ever being seen, so
// the behavioural test would stay green while real egress went unobserved. That is not a
// hypothetical: the flow/health emitter was exactly this shape until #27, which means the
// one path that would carry telemetry was the one path the check could not see.
//
// Structural rather than behavioural on purpose: the failure mode is "someone adds a new
// client next year", and only reading the source catches that before it ships.
func TestEveryOutboundClientIsObservable(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}

	var offenders []string
	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				sel, ok := lit.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Client" {
					return true
				}
				if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "http" {
					return true
				}
				for _, elt := range lit.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Transport" {
							return true // explicitly transported — fine
						}
					}
				}
				offenders = append(offenders,
					fmt.Sprintf("%s:%d", path, fset.Position(lit.Pos()).Line))
				return true
			})
		}
	}
	if len(offenders) > 0 {
		t.Errorf("these http.Client values set no Transport, so they use http.DefaultTransport and are "+
			"INVISIBLE to the egress observer: %v\n"+
			"Give each one the pooled transport (pooledTransport / the existing `tr`). Otherwise "+
			"TestFirewallDialsOnlyConfiguredDestinations stays green while this client's traffic goes "+
			"unmeasured — which is how the zero-egress claim would become false without any test noticing.",
			offenders)
	}
}

// TestFirewallBinaryLinksOnlyStdlib closes the dialler-level check's known blind spot.
//
// A dialler hook can only see connections made through OUR transports. A third-party
// package that builds its own net.Dialer — an SDK, a telemetry library, a database driver
// — is invisible to it. The usual answer is "so dialler-level checking is unsound", and it
// is, UNLESS the binary has no third-party code in it at all.
//
// It currently has none, which is what makes the fast leg trustworthy. That is a strong
// property worth keeping deliberately rather than discovering it was lost: CLAUDE.md
// already says every dependency is part of our own attack surface, and this is the test
// that makes the firewall binary's zero-dependency status a gate instead of a habit.
//
// Note the scope: the firewall BINARY. The approval service links pgx (a database driver),
// which is fine — it is a different binary with a different job.
func TestFirewallBinaryLinksOnlyStdlib(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	var external []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "yellowjack") {
			continue // our own packages
		}
		// A stdlib import path's first element never contains a dot; every module path
		// does (github.com/..., golang.org/x/...). This is the same rule the go command
		// itself uses to tell the two apart.
		if first, _, _ := strings.Cut(line, "/"); strings.Contains(first, ".") {
			external = append(external, line)
		}
	}
	if len(external) > 0 {
		t.Errorf("the firewall binary now links %d third-party package(s): %v\n"+
			"Each one can open its own connections without passing through pooledTransport, which "+
			"makes the dialler-level egress assertion unsound — and each is part of our attack "+
			"surface (CLAUDE.md). If this dependency is genuinely needed, the container-level egress "+
			"leg must become the primary gate and this test updated deliberately, not deleted.",
			len(external), external)
	}
}

// TestEgressDestinationsNamesEveryConfiguredHost pins the LIST itself — the thing #27 calls
// the real deliverable ("the exact list is the deliverable, not the slogan").
//
// Without this, a new destination could be added to Config and dialled in production while
// egressDestinations quietly omitted it — which would make the behavioural test green by
// widening nothing and observing nothing. The list is the specification an operator uses to
// configure their own firewall, so it has to be wrong loudly rather than silently.
func TestEgressDestinationsNamesEveryConfiguredHost(t *testing.T) {
	cfg := Config{
		UpstreamRegistry: "https://registry.npmjs.org",
		FilesUpstream:    "https://files.pythonhosted.org",
		DepsDevBase:      "https://api.deps.dev",
		ScannerURL:       "http://scheduler.internal:9000",
		ApprovalURL:      "http://approval.internal:8081",
	}
	want := []string{
		"api.deps.dev:443",
		"approval.internal:8081",
		"files.pythonhosted.org:443",
		"registry.npmjs.org:443",
		"scheduler.internal:9000",
	}
	got := cfg.egressDestinations()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("egressDestinations() = %v, want %v", got, want)
	}

	// The default-port fill-in is load-bearing: a dialer is always handed an explicit
	// port, so a list built from bare hostnames would match nothing and the subset
	// assertion would report every real connection as a violation.
	if got := hostPort("https://example.com"); got != "example.com:443" {
		t.Errorf("hostPort(https, no port) = %q, want example.com:443", got)
	}
	if got := hostPort("http://example.com"); got != "example.com:80" {
		t.Errorf("hostPort(http, no port) = %q, want example.com:80", got)
	}

	// An empty field must contribute nothing rather than a bare ":443" — optional
	// services (scanner in api mode, approval when unset) are the common case.
	if got := hostPort(""); got != "" {
		t.Errorf("hostPort(empty) = %q, want empty", got)
	}
	if _, err := url.Parse("://bad"); err == nil {
		t.Skip("url.Parse accepted a malformed URL; the guard below is not meaningful here")
	}
	if got := hostPort("://bad"); got != "" {
		t.Errorf("hostPort(malformed) = %q, want empty", got)
	}
}
