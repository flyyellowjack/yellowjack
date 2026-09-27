package main

import (
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// D366: the curated feed is a subscription, reached with a key. These pin what the key
// may do (authenticate the feed pull), where it may go (the feed host only), and what an
// operator reads when it is missing or refused.

const feedKeyValue = "Bearer yj-feed-subscription-k3y"

// keyedFeed serves a signed snapshot only to a request carrying the right key: none -> 401,
// wrong -> 403, the way a subscription endpoint answers.
func keyedFeed(t *testing.T, srv *feedServer, want string) *httptest.Server {
	t.Helper()
	inner := srv.handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch got := r.Header.Get("Authorization"); {
		case got == "":
			srv.mu.Lock()
			srv.auths = append(srv.auths, "")
			srv.mu.Unlock()
			w.WriteHeader(http.StatusUnauthorized)
		case got != want:
			srv.mu.Lock()
			srv.auths = append(srv.auths, got)
			srv.mu.Unlock()
			w.WriteHeader(http.StatusForbidden)
		default:
			inner.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func keyFile(t *testing.T, v string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "feed.key")
	if err := os.WriteFile(p, []byte(v+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The three answers a subscription endpoint gives, and what the fetcher makes of each.
// The CONTROL is the right key installing a snapshot; without it the two refusals prove
// nothing about the key.
func TestTheFeedAccessKeyIsSentAndARefusalIsNamed(t *testing.T) {
	r := newFetchRig(t)
	body := feedWith(6)
	r.srv.set(body, signB64(r.priv, body))
	ts := keyedFeed(t, r.srv, feedKeyValue)
	r.fetcher.url, r.fetcher.client = ts.URL+"/feed.ndjson", ts.Client()

	// No key configured -> 401, named as a MISSING key.
	_, err := r.fetcher.fetchOnce()
	var access *feedAccessError
	if !errors.As(err, &access) || access.status != http.StatusUnauthorized || access.keySent {
		t.Fatalf("no key: err = %v, want a feedAccessError 401 with no key sent", err)
	}
	if !strings.Contains(err.Error(), "NO access key was sent") || !strings.Contains(err.Error(), "FW_MALWARE_FEED_AUTH_FILE") {
		t.Errorf("no key: the message does not name the missing key and the setting: %v", err)
	}

	// A wrong key -> 403, named as a REFUSED key.
	r.fetcher.cred = func() string { return "Bearer not-the-key" }
	_, err = r.fetcher.fetchOnce()
	if !errors.As(err, &access) || access.status != http.StatusForbidden || !access.keySent {
		t.Fatalf("wrong key: err = %v, want a feedAccessError 403 with the key sent", err)
	}
	if !strings.Contains(err.Error(), "REFUSED the access key") {
		t.Errorf("wrong key: the message does not say the key was refused: %v", err)
	}
	r.fetcher.report("", err)
	if strings.Contains(r.logs(), "SECURITY") {
		t.Errorf("a refused subscription key was logged as a SECURITY event; nothing was tampered with:\n%s", r.logs())
	}

	// The CONTROL: the right key installs the snapshot.
	r.fetcher.cred = func() string { return feedKeyValue }
	out, err := r.fetcher.fetchOnce()
	if err != nil || !strings.Contains(out, "installed serial 6") {
		t.Fatalf("the right key did not install the snapshot: out=%q err=%v", out, err)
	}
	r.fetcher.report(out, nil)
	if strings.Contains(r.logs(), "subscription-k3y") {
		t.Errorf("the access key appears in a log line:\n%s", r.logs())
	}
}

// The key goes to the feed host and NOWHERE else: not to the registry on a package pull,
// and not to another host a redirect points at. The registry credential, in turn, still
// never reaches the feed host.
func TestTheFeedKeyNeverLeavesTheFeedHost(t *testing.T) {
	priv, _, pub := feedKeys(t)
	srv := &feedServer{}
	body := feedWith(3)
	srv.set(body, signB64(priv, body))
	feed := keyedFeed(t, srv, feedKeyValue)

	var mu sync.Mutex
	var registrySaw []string
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		registrySaw = append(registrySaw, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name":"left-pad","versions":{},"dist-tags":{}}`))
	}))
	defer registry.Close()

	list := filepath.Join(t.TempDir(), "feed.ndjson")
	p := newTestProxy(t, registry, func(c *Config) {
		c.DepsDevBase = registry.URL
		c.MalwareListPath, c.MalwareFeedKey, c.MalwareFeedURL = list, pub, feed.URL+"/f.ndjson"
		c.MalwareFeedAuthFile = keyFile(t, feedKeyValue)
		c.UpstreamAuth = "Bearer registry-secret"
	})
	// Startup seeded the empty mount through the KEYED endpoint: the key reached the feed.
	if b, err := os.ReadFile(list); err != nil || string(b) != string(body) {
		t.Fatalf("the keyed feed did not seed the mount, so the key was not sent: %v", err)
	}
	p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/left-pad", nil))

	mu.Lock()
	defer mu.Unlock()
	if len(registrySaw) == 0 {
		t.Fatal("the registry was never asked, so this proves nothing about where the key goes")
	}
	for _, a := range registrySaw {
		if strings.Contains(a, "subscription-k3y") {
			t.Errorf("the registry received the FEED key: %q", a)
		}
	}
	srv.mu.Lock()
	for _, a := range srv.auths {
		if strings.Contains(a, "registry-secret") {
			t.Errorf("the feed host received the REGISTRY credential: %q", a)
		}
	}
	srv.mu.Unlock()
}

// A redirect off the feed host does not carry the key along. net/http strips Authorization
// on a cross-host redirect; pinned here rather than trusted, because the day it does not,
// a compromised feed host could hand our customers' keys to anyone.
func TestTheFeedKeyDoesNotFollowARedirectToAnotherHost(t *testing.T) {
	var elsewhere string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer other.Close()
	// "localhost" vs 127.0.0.1: a different HOST to the client, so the redirect is cross-host.
	otherURL := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	var sawKey string
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawKey = r.Header.Get("Authorization")
		http.Redirect(w, r, otherURL+"/elsewhere", http.StatusFound)
	}))
	defer feed.Close()

	f := &feedFetcher{client: feed.Client(), cred: func() string { return feedKeyValue }}
	f.get(feed.URL+"/f.ndjson", 1<<20)
	if sawKey != feedKeyValue {
		t.Fatalf("the feed host did not receive the key (%q), so the redirect half proves nothing", sawKey)
	}
	if elsewhere != "" {
		t.Errorf("the key followed a redirect to another host: %q", elsewhere)
	}
}

// A rotated key is used without a restart; an empty or missing file keeps the last key
// (a refresher mid-write must not drop the pull to anonymous).
func TestARotatedFeedKeyIsPickedUpWithoutARestart(t *testing.T) {
	p := keyFile(t, "Bearer one")
	var logged []string
	cred := fileCredentialFor("feed-auth", "feed pulls", p, func(f string, a ...any) {
		logged = append(logged, f)
	}, time.Millisecond)
	if got := cred(); got != "Bearer one" {
		t.Fatalf("first read = %q", got)
	}
	os.WriteFile(p, []byte("Bearer two\n"), 0o600)
	time.Sleep(5 * time.Millisecond)
	if got := cred(); got != "Bearer two" {
		t.Errorf("after rotation = %q, want the new key", got)
	}
	os.WriteFile(p, nil, 0o600)
	time.Sleep(5 * time.Millisecond)
	if got := cred(); got != "Bearer two" {
		t.Errorf("an empty file blanked the key (%q); it must keep the last good one", got)
	}
	for _, l := range logged {
		if strings.HasPrefix(l, "upstream-auth") {
			t.Errorf("a feed-key log line is labelled as the registry's: %q", l)
		}
	}
}

// Startup refuses a key that could not be used safely or at all.
func TestAFeedKeyIsRefusedWhereItWouldLeakOrDoNothing(t *testing.T) {
	priv, _, pub := feedKeys(t)
	srv := &feedServer{}
	body := feedWith(3)
	srv.set(body, signB64(priv, body))
	feed := httptest.NewServer(srv.handler())
	defer feed.Close()
	list := filepath.Join(t.TempDir(), "feed.ndjson")

	// Plain http to a NON-loopback host would carry the key in cleartext.
	cfg := fetchConfig(feed.URL, "http://feeds.example.invalid/f.ndjson", list, pub)
	cfg.MalwareFeedAuthFile = keyFile(t, feedKeyValue)
	if _, err := NewFirewall(cfg); err == nil || !strings.Contains(err.Error(), "cleartext") {
		t.Errorf("a key over plain http to a remote host was not refused: %v", err)
	}
	// CONTROL: the same key over http to LOOPBACK is allowed (a local mirror, the tests).
	cfg = fetchConfig(feed.URL, feed.URL+"/f.ndjson", list, pub)
	cfg.MalwareFeedAuthFile = keyFile(t, feedKeyValue)
	if _, err := NewFirewall(cfg); err != nil && strings.Contains(err.Error(), "cleartext") {
		t.Errorf("a loopback feed was refused as cleartext: %v", err)
	}

	for _, c := range []struct {
		name, env, want string
	}{
		{"relative path", "FW_MALWARE_FEED_URL=https://feed.example/f\nFW_MALWARE_FEED_AUTH_FILE=feed.key", "must be an absolute path"},
		{"key without a feed", "FW_MALWARE_FEED_AUTH_FILE=/etc/yellowjack/feed.key", "FW_MALWARE_FEED_URL is not"},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, kv := range strings.Split(c.env, "\n") {
				k, v, _ := strings.Cut(kv, "=")
				t.Setenv(k, v)
			}
			_, err := loadConfig()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want one containing %q", err, c.want)
			}
		})
	}
}

// feedCredential itself labels its log lines as the FEED's. The rotation test above calls
// the reader directly with its own label, so it could not see feedCredential choose the
// wrong one -- found by sabotaging the label, which that test survived.
func TestTheFeedCredentialLogsAsTheFeed(t *testing.T) {
	var buf strings.Builder
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	feedCredential(filepath.Join(t.TempDir(), "absent.key"))()
	got := buf.String()
	if !strings.Contains(got, "feed-auth:") || !strings.Contains(got, "feed pulls are going out unauthenticated") {
		t.Errorf("an unreadable feed key file is not reported as the feed's: %q", got)
	}
	if strings.Contains(got, "upstream") {
		t.Errorf("the feed key's log line names the upstream registry: %q", got)
	}
}
