package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// D165's readiness endpoint, asserted. /readyz is distinct from /healthz: it answers 503
// while the policy in force is not the file on the deployment mount -- an operator list
// that failed to re-read, so the gate is enforcing the last good list rather than the
// deployed one -- and 200 otherwise. It shares D163's locality with liveness: it never
// varies with, and never contacts, anything external. A registry outage must not pull a
// gate out of rotation; every replica shares the registry, and an outage that empties the
// rotation is a route around the firewall.

// listedProxy is a gate with a deny list on disk that re-reads every ttl.
func listedProxy(t *testing.T, ttl time.Duration) (*proxyServer, string, *upstreamStates) {
	t.Helper()
	prev := listReloadTTL
	listReloadTTL = ttl
	t.Cleanup(func() { listReloadTTL = prev })
	path := filepath.Join(t.TempDir(), "deny.txt")
	writeDenyFile(t, path, "left-pad\n")
	u := newUpstreamStates(t)
	p := newTestProxy(t, u.srv, func(c *Config) {
		c.DenyListPath = path
		c.ScoreThreshold = 0
		c.UnscorablePolicy = "allow"
		// Scoring OFF, not the `stub` default. These tests measure LIST STALENESS, and
		// D273 makes `stub` a not-ready configuration in its own right -- leaving it
		// here would mean every assertion below passed or failed for a reason that has
		// nothing to do with the list. `off` is the supported no-scorer posture (D280's
		// launch shape), so the only thing that can move /readyz here is the list.
		c.ScorecardMode = scorecardModeOff
	})
	return p, path, u
}

func writeDenyFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

// waitProbe polls path until its status is want or the deadline passes, returning the
// last probe either way.
func waitProbe(t *testing.T, h http.Handler, path string, want int, within time.Duration) healthzProbe {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		last := probePath(t, h, path)
		if last.status == want || time.Now().After(deadline) {
			return last
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestReadyzIsRedWhileAListIsUnreadableAndGreenWhenItIsFixed walks the transition D165
// is about: ready on the deployed list; NOT ready once the file on the mount can no
// longer be loaded (a version-pinned line, the shape a hand edit produces) while the gate
// keeps enforcing the last good list; ready again when the file is fixed. Liveness never
// moves -- that is the whole point of having two endpoints.
func TestReadyzIsRedWhileAListIsUnreadableAndGreenWhenItIsFixed(t *testing.T) {
	p, path, _ := listedProxy(t, 20*time.Millisecond)

	if got := probePath(t, p, "/readyz"); got.status != http.StatusOK || !strings.Contains(got.body, "ready") {
		t.Fatalf("/readyz on the deployed list = %s, want 200 ready", got)
	}
	// The REASON is asserted, not the status: this fake upstream serves nothing parseable,
	// so a package the deny list did NOT catch is also a 403 (D102's could-not-verify) --
	// an impostor that masked a sabotage until the body was checked.
	if got := probePath(t, p, "/left-pad"); got.status != http.StatusForbidden || !strings.Contains(got.body, "deny list") {
		t.Fatalf("control: the denied package = %s, want 403 on the DENY LIST -- the list is not in force, so nothing below measures it", got)
	}

	// The mount now holds a list the gate cannot load. It was "left-pad@1.0.0" until #155
	// made a version-scoped DENY entry a VALID line; whitespace is still malformed in every
	// list, and the point of this test is the unreadable-list path, not which line broke it.
	writeDenyFile(t, path, "left pad 1.0.0\n")
	got := waitProbe(t, p, "/readyz", http.StatusServiceUnavailable, 2*time.Second)
	if got.status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz with an unreadable deny list = %s, want 503 -- the gate reports ready on a policy that is not the deployed one (D165)", got)
	}
	for _, want := range []string{"not ready", "deny-list", filepath.Base(path), "still enforcing the last good list (1 entries)"} {
		if !strings.Contains(got.body, want) {
			t.Errorf("/readyz body lacks %q: %s", want, got)
		}
	}
	if got := probePath(t, p, "/left-pad"); got.status != http.StatusForbidden || !strings.Contains(got.body, "deny list") {
		t.Errorf("the denied package = %s while the list is unreadable, want 403 on the DENY LIST -- the last good list must stay in force (a blanked deny list fails OPEN)", got)
	}
	if got := probePath(t, p, "/healthz"); got.status != http.StatusOK {
		t.Errorf("/healthz = %s while NOT ready, want 200 -- liveness and readiness are different questions (D165)", got)
	}

	writeDenyFile(t, path, "left-pad\n")
	if got := waitProbe(t, p, "/readyz", http.StatusOK, 2*time.Second); got.status != http.StatusOK {
		t.Fatalf("/readyz after the list was fixed = %s, want 200", got)
	}
}

// TestReadyzDoesNotVaryWithUpstreamReachability is D163's assertion extended to readiness,
// as D165 asks: a registry outage must not make a gate unready.
func TestReadyzDoesNotVaryWithUpstreamReachability(t *testing.T) {
	p, _, u := listedProxy(t, time.Hour)
	probes, varied := varianceAcrossUpstreamStates(t, u, p, "/readyz")
	if varied {
		t.Errorf("/readyz VARIED with upstream reachability: healthy=%s, erroring=%s, unreachable=%s. "+
			"Readiness must reflect only whether the deployed config is loaded (D165), never anything external (D163).",
			probes[0], probes[1], probes[2])
	}
	if probes[0].status != http.StatusOK {
		t.Errorf("/readyz = %s with a healthy upstream, want 200 (anti-vacuity)", probes[0])
	}
}

// TestReadyzNeverContactsUpstream: the re-read a probe drives is a FILE read, never a dial.
func TestReadyzNeverContactsUpstream(t *testing.T) {
	p, _, u := listedProxy(t, 0) // re-read on every probe, so a dial hidden in the reload would show
	for i := 0; i < 5; i++ {
		if got := probePath(t, p, "/readyz"); got.status != http.StatusOK {
			t.Fatalf("/readyz = %s on probe %d, want 200", got, i+1)
		}
	}
	if n := u.hits.Load(); n != 0 {
		t.Errorf("/readyz reached upstream %d time(s) across 5 probes -- readiness must not depend on a network call", n)
	}
}

// TestReadyzLocalityCheckCanFail: the measurement is the one TestHealthzLocalityCheckCanFail
// proves capable of failing; this pins that it fails for /readyz too, against a handler
// that checks upstream on that path.
func TestReadyzLocalityCheckCanFail(t *testing.T) {
	u := newUpstreamStates(t)
	probes, varied := varianceAcrossUpstreamStates(t, u, dependencyCheckingHealthz(u.srv.URL), "/readyz")
	if !varied {
		t.Errorf("the negative control did NOT detect a readiness handler that fails on upstream state: %s %s %s",
			probes[0], probes[1], probes[2])
	}
}

// TestReloadingListIsSeededWithTheStartupLoad: the reloading source used to start EMPTY
// and re-read on first use, so what it enforced before its first successful read depended
// on who called it first (in practice the constructor's policy digest, which is why the
// window never opened). Seeded with the startup load, it enforces that list until a
// re-read succeeds whoever calls, and readiness says so.
func TestReloadingListIsSeededWithTheStartupLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deny.txt")
	writeDenyFile(t, path, "left-pad\n")
	first, err := loadOperatorList("deny", "npm", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	src := newReloadingList("deny", "npm", path, func(string, ...any) {}, 0, first)
	if l := src.current(); l == nil || !l.has("npm", "left-pad") {
		t.Fatalf("a reloading list seeded with the startup load enforces nothing after the file vanished; got %v", l)
	}
	if err := src.stale(); err == nil || !strings.Contains(err.Error(), "still enforcing the last good list (1 entries)") {
		t.Errorf("stale() = %v, want the vanished file named with the list still in force", err)
	}
	// And the unseeded shape the older tests exercise is unchanged: nothing loaded, nothing
	// enforced, and readiness says THAT.
	bare := newReloadingList("deny", "npm", path, func(string, ...any) {}, 0, nil)
	if l := bare.current(); l != nil {
		t.Fatalf("an unseeded source with no file returned a list: %v", l)
	}
	if err := bare.stale(); err == nil || !strings.Contains(err.Error(), "nothing was ever loaded") {
		t.Errorf("unseeded stale() = %v, want the enforcing-nothing reason", err)
	}
}

// TestFirewallSeedsItsReloadingListsWithTheStartupLoad pins the PROPERTY through
// NewFirewall: the deny list startup loaded is enforced after its file vanishes before the
// first request, and readiness names the vanished file with that list in force. It cannot
// tell the seed from the other mechanism that provides it -- the constructor's policy
// digest reads both lists at construction -- which the sabotage ledger records: removing
// the seed reddened nothing here, and that is why the seed is belt-and-braces, not a fix.
func TestFirewallSeedsItsReloadingListsWithTheStartupLoad(t *testing.T) {
	p, path, _ := listedProxy(t, 0)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := probePath(t, p, "/left-pad"); got.status != http.StatusForbidden || !strings.Contains(got.body, "deny list") {
		t.Fatalf("the denied package = %s after the list file vanished before the first request, want 403 on the DENY LIST -- "+
			"the reloading source was not seeded with the startup load, so the gate enforced NOTHING (fail-open)", got)
	}
	if got := probePath(t, p, "/readyz"); got.status != http.StatusServiceUnavailable || !strings.Contains(got.body, "still enforcing the last good list (1 entries)") {
		t.Errorf("/readyz = %s, want 503 naming the last good list still in force", got)
	}
}
