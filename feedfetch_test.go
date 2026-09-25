package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// PULLING THE SNAPSHOT (#157). Every refusal here is indistinguishable from a fetcher
// that does nothing, so the control comes first: a good, newer snapshot must be
// INSTALLED and then ENFORCED.

// feedServer serves a snapshot and its signature from mutable state, and records the
// Authorization header of every request it receives.
type feedServer struct {
	mu     sync.Mutex
	body   []byte
	sig    []byte
	status int    // 0 = 200
	ctype  string // "" = text/plain
	auths  []string
}

func (s *feedServer) set(body, sig []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body, s.sig, s.status, s.ctype = body, sig, 0, ""
}

func (s *feedServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.auths = append(s.auths, r.Header.Get("Authorization"))
		if s.status != 0 {
			w.WriteHeader(s.status)
			return
		}
		if s.ctype != "" {
			w.Header().Set("Content-Type", s.ctype)
		}
		if strings.HasSuffix(r.URL.Path, feedSigSuffix) {
			if s.sig == nil {
				http.NotFound(w, r)
				return
			}
			w.Write(s.sig)
			return
		}
		w.Write(s.body)
	})
}

func signB64(priv ed25519.PrivateKey, b []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b)))
}

// feedWith is goodFeed plus extra advisories, with the declared row count kept honest.
func feedWith(serial int64, extra ...string) []byte {
	body := goodFeed(serial, time.Now())
	body = strings.Replace(body, "rows=2", fmt.Sprintf("rows=%d", 2+len(extra)), 1)
	for _, e := range extra {
		body += e + "\n"
	}
	return []byte(body)
}

// fetchRig is a feed on disk at serial 5, a reloading source over it, a feed server,
// and a fetcher pointed at that server and installing over the same file.
type fetchRig struct {
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	path    string
	srv     *feedServer
	src     *reloadingFeed
	fetcher *feedFetcher
	logMu   sync.Mutex
	logged  []string
}

func (r *fetchRig) logf(f string, a ...any) {
	r.logMu.Lock()
	defer r.logMu.Unlock()
	r.logged = append(r.logged, fmt.Sprintf(f, a...))
}

func (r *fetchRig) logs() string {
	r.logMu.Lock()
	defer r.logMu.Unlock()
	return strings.Join(r.logged, "\n")
}

func newFetchRig(t *testing.T) *fetchRig {
	t.Helper()
	shortFeedIntervals(t)
	r := &fetchRig{srv: &feedServer{}}
	r.priv, r.pub, _ = feedKeys(t)
	r.path = writeSignedFeed(t, t.TempDir(), r.priv, goodFeed(5, time.Now()), nil)
	first, err := loadMalwareList(r.path, r.pub)
	if err != nil {
		t.Fatal(err)
	}
	r.src = newReloadingFeed(r.path, "npm", r.logf, first, r.pub)
	ts := httptest.NewServer(r.srv.handler())
	t.Cleanup(ts.Close)
	r.fetcher = &feedFetcher{
		url: ts.URL + "/feed.ndjson", path: r.path, key: r.pub,
		client: ts.Client(), logf: r.logf, inForce: r.src.current,
	}
	return r
}

// onDisk returns the snapshot bytes currently at the path.
func (r *fetchRig) onDisk(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// reread forces the reloading source's next interval, as the 60 s stat would.
func (r *fetchRig) reread() *malwareList {
	r.src.checked = time.Time{}
	return r.src.current()
}

// THE CONTROL: a newer signed snapshot is installed, then enforced by the re-read.
func TestAPulledNewerSnapshotIsInstalledAndEnforced(t *testing.T) {
	r := newFetchRig(t)
	body := feedWith(6, `{"id":"MAL-NEW","ecosystem":"npm","name":"fresh-evil"}`)
	r.srv.set(body, signB64(r.priv, body))

	out, err := r.fetcher.fetchOnce()
	if err != nil {
		t.Fatalf("a good, newer snapshot was refused, so every refusal below proves nothing: %v", err)
	}
	if !strings.Contains(out, "installed serial 6") {
		t.Errorf("outcome = %q", out)
	}
	if !bytes.Equal(r.onDisk(t), body) {
		t.Error("the snapshot on disk is not the one served")
	}
	got := r.reread()
	if got.header.Serial != 6 {
		t.Fatalf("serial %d in force after the pull; the re-read did not install it", got.header.Serial)
	}
	if _, ok := got.lookupAll("npm", "fresh-evil"); !ok {
		t.Error("the pulled advisory is not enforced")
	}
}

// Everything the fetcher must refuse, each leaving the snapshot on disk byte-for-byte
// unchanged. The shapes are the #157 tier-3 list: tampered, replayed, an HTML page
// served with 200, plus an outage, a missing signature and another key's signature.
func TestAPulledSnapshotThatFailsNeverReachesTheMount(t *testing.T) {
	good := feedWith(6)
	cases := []struct {
		name  string
		setup func(r *fetchRig)
		want  string
	}{
		{"tampered", func(r *fetchRig) {
			bad := feedWith(6, `{"id":"MAL-X","ecosystem":"npm","name":"x"}`)
			r.srv.set(bad, signB64(r.priv, good))
		}, "does not verify"},
		{"another key", func(r *fetchRig) {
			other, _, _ := feedKeys(t)
			r.srv.set(good, signB64(other, good))
		}, "does not verify"},
		{"replayed older serial", func(r *fetchRig) {
			old := feedWith(4)
			r.srv.set(old, signB64(r.priv, old))
		}, "OLDER than"},
		{"html with 200", func(r *fetchRig) {
			page := []byte("<html><body>Welcome to nginx</body></html>")
			r.srv.set(page, signB64(r.priv, good))
			r.srv.ctype = "text/html"
		}, "does not verify"},
		{"outage", func(r *fetchRig) { r.srv.status = http.StatusBadGateway }, "status 502"},
		{"missing signature", func(r *fetchRig) { r.srv.set(good, nil) }, "status 404"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newFetchRig(t)
			before := r.onDisk(t)
			c.setup(r)
			_, err := r.fetcher.fetchOnce()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one naming %q", err, c.want)
			}
			if !bytes.Equal(r.onDisk(t), before) {
				t.Error("a refused snapshot changed the file on the mount")
			}
			if r.fetcher.writeCount() != 0 {
				t.Error("a refused snapshot was written")
			}
			if got := r.reread(); got.header.Serial != 5 {
				t.Errorf("serial %d in force; want the original 5", got.header.Serial)
			}
			if err := r.src.stale(); err != nil {
				t.Errorf("a failed pull made readiness fail (every replica shares one endpoint): %v", err)
			}
			// No temp file may be left behind in the directory.
			ents, _ := os.ReadDir(filepath.Dir(r.path))
			for _, e := range ents {
				if strings.HasSuffix(e.Name(), ".tmp") {
					t.Errorf("temp file left behind: %s", e.Name())
				}
			}
		})
	}
}

// The same serial is not rewritten, so an hourly pull of an unchanged feed does not
// force an hourly re-parse of a large file.
func TestTheSameSnapshotIsNotRewritten(t *testing.T) {
	r := newFetchRig(t)
	same := []byte(r.onDisk(t))
	r.srv.set(same, signB64(r.priv, same))
	fi1, _ := os.Stat(r.path)
	out, err := r.fetcher.fetchOnce()
	if err != nil || !strings.Contains(out, "unchanged") {
		t.Fatalf("out=%q err=%v", out, err)
	}
	fi2, _ := os.Stat(r.path)
	if r.fetcher.writeCount() != 0 || !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Error("an unchanged snapshot was rewritten")
	}
}

// A failure is logged when the outcome CHANGES, not every interval.
func TestAPullOutcomeIsLoggedOncePerChange(t *testing.T) {
	r := newFetchRig(t)
	r.srv.status = http.StatusServiceUnavailable
	for i := 0; i < 3; i++ {
		out, err := r.fetcher.fetchOnce()
		r.fetcher.report(out, err)
	}
	if n := strings.Count(r.logs(), "refused or failed"); n != 1 {
		t.Errorf("an unchanged failure was logged %d times; want 1", n)
	}
	body := feedWith(6)
	r.srv.set(body, signB64(r.priv, body))
	out, err := r.fetcher.fetchOnce()
	r.fetcher.report(out, err)
	if !strings.Contains(r.logs(), "installed serial 6") {
		t.Error("recovery was not logged")
	}
	r.srv.status = http.StatusServiceUnavailable
	out, err = r.fetcher.fetchOnce()
	r.fetcher.report(out, err)
	if n := strings.Count(r.logs(), "refused or failed"); n != 2 {
		t.Errorf("a failure after a recovery was not logged again (count %d)", n)
	}
}

func fetchConfig(up, feedURL, list, key string) Config {
	return Config{
		Ecosystem: "npm", UpstreamRegistry: up, DepsDevBase: up, ScorecardMode: "stub",
		ScoreThreshold: 5.0, MalwareListPath: list, MalwareFeedKey: key, MalwareFeedURL: feedURL,
		UpstreamAuth: "Bearer registry-secret",
	}
}

// Startup refuses the configurations that would pull something it cannot verify or has
// nowhere to put.
//
// The feed server is REACHABLE and serves a correctly signed snapshot, and each case's
// error must name the knob at fault. The first version pointed at an unreachable host,
// so startup failed on the failed pull whether or not the key was checked -- a sabotage
// removing the key check reddened nothing. Now the only possible reason to refuse is
// the one under test.
func TestAFeedURLIsRefusedWithoutAKeyOrAPlace(t *testing.T) {
	priv, _, key := feedKeys(t)
	srv := &feedServer{}
	body := feedWith(3)
	srv.set(body, signB64(priv, body))
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no key", fetchConfig(ts.URL, ts.URL+"/f", filepath.Join(t.TempDir(), "f.ndjson"), ""), "FW_MALWARE_FEED_KEY"},
		{"no list", fetchConfig(ts.URL, ts.URL+"/f", "", key), "FW_MALWARE_LIST"},
		{"not http(s)", fetchConfig(ts.URL, "file:///etc/passwd", filepath.Join(t.TempDir(), "f.ndjson"), key), "not an http(s) URL"},
	}
	for _, c := range cases {
		_, err := NewFirewall(c.cfg)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one naming %q", c.name, err, c.want)
		}
	}
}

// A replica with an EMPTY mount seeds itself from the endpoint; if the endpoint is down
// it refuses to start and names the fix. The registry credential never reaches the feed
// host on either path.
func TestAnEmptyMountIsSeededOrStartupNamesTheFix(t *testing.T) {
	priv, _, key := feedKeys(t)
	srv := &feedServer{}
	body := feedWith(3)
	srv.set(body, signB64(priv, body))
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	list := filepath.Join(t.TempDir(), "feed.ndjson")
	if _, err := NewFirewall(fetchConfig(ts.URL, ts.URL+"/f.ndjson", list, key)); err != nil {
		t.Fatalf("an empty mount with a reachable endpoint should seed and start: %v", err)
	}
	if b, err := os.ReadFile(list); err != nil || !bytes.Equal(b, body) {
		t.Fatalf("the seed was not written: %v", err)
	}
	srv.mu.Lock()
	for _, a := range srv.auths {
		if a != "" {
			t.Errorf("the feed host received an Authorization header %q; the registry credential leaked", a)
		}
	}
	srv.mu.Unlock()

	srv.mu.Lock()
	srv.status = http.StatusBadGateway
	srv.mu.Unlock()
	list2 := filepath.Join(t.TempDir(), "feed.ndjson")
	_, err := NewFirewall(fetchConfig(ts.URL, ts.URL+"/f.ndjson", list2, key))
	if err == nil || !strings.Contains(err.Error(), "Seed that directory") {
		t.Fatalf("an unseeded replica with the endpoint down must refuse to start and name the fix: %v", err)
	}
}

// The feed host is on the enumerated egress list exactly when it is configured.
func TestTheFeedHostIsAConfiguredDestinationOnlyWhenSet(t *testing.T) {
	with := Config{MalwareFeedURL: "https://feed.example:8443/snapshot"}
	if !strings.Contains(strings.Join(with.egressDestinations(), " "), "feed.example:8443") {
		t.Error("a configured feed URL is missing from the egress list")
	}
	if strings.Contains(strings.Join(Config{}.egressDestinations(), " "), "feed") {
		t.Error("the egress list names a feed host nobody configured")
	}
}

// A missing or malformed key is a refusal, never a panic, even if a caller forgets the
// startup check.
func TestAVerifierWithNoKeyRefusesInsteadOfPanicking(t *testing.T) {
	err := verifySignatureBytes("x.sig", []byte("data"), []byte("c2ln"), nil)
	if err == nil || !strings.Contains(err.Error(), "cannot be checked") {
		t.Fatalf("err = %v", err)
	}
}

// The committed e2e fixture must verify with the committed public key. A checkout that
// converted its line endings would break the signature and turn the e2e leg into a
// false failure; this catches that on every platform before the rig runs.
func TestTheCommittedPullFixtureVerifies(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash("e2e/feed-fetch-fixture/pubkey.txt"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := parseFeedKey(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs(filepath.FromSlash("e2e/feed-fetch-fixture/snapshot.ndjson"))
	l, err := loadMalwareList(abs, key)
	if err != nil {
		t.Fatalf("the committed fixture does not verify (line endings converted?): %v", err)
	}
	if _, ok := l.lookupAll("npm", "yj-harden-pulled"); !ok {
		t.Error("the fixture does not name the package the e2e leg asserts on")
	}
}
