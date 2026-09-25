//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file closes the one honest gap left by issue #16 (request coalescing): the
// N-concurrent-lookups-become-1 guarantee was proven only IN-PROCESS, by unit tests
// that call Evaluate directly. The e2e suite ran the coalescing code for real, but
// measured nothing about it — a regression that removed the flight groups entirely
// would have left every existing e2e assertion green.
//
// What was missing was not a test but a SEAM: an e2e firewall is a container, and its
// only interface is the environment, so there was no way to put a counter between it
// and deps.dev. FW_DEPSDEV_BASE (this MR) is that seam.
//
// The load is REAL npm clients rather than a synthetic burst, because the shape of the
// herd is the thing under test and a hand-rolled burst would be us assuming it. The one
// thing this file did have to learn by experiment is WHERE the herd comes from: not
// from a single install (npm fetches each packument exactly once), but from several
// clients pulling overlapping trees through one shared firewall — which is how the
// firewall is deployed. See concurrentInstalls.

// depsDevFake is a stand-in deps.dev API running as a container, which COUNTS what the
// firewall asks it and how much of that arrived concurrently.
type depsDevFake struct {
	url  string // reachable from the firewall CONTAINER (host.docker.internal)
	port int    // published on the docker host; the test reads /stats here
}

// depsDevStats is the fake's view of the run. The two "max concurrent" figures are
// the point of the whole file: coalescing is not "fewer calls" (a cache does that
// too), it is "never two AT THE SAME TIME for the same key".
type depsDevStats struct {
	Hits          map[string]int `json:"hits"`           // path -> total requests
	Distinct      int            `json:"distinct"`       // distinct paths seen
	Total         int            `json:"total"`          // total requests served
	MaxSamePath   int            `json:"max_same_path"`  // most simultaneous requests for ONE path
	MaxConcurrent int            `json:"max_concurrent"` // most simultaneous requests overall
	BusiestPath   string         `json:"busiest_path"`   // path that hit MaxSamePath
}

// startDepsDevFake runs the counting deps.dev stand-in and returns a handle. It
// answers the two endpoints api mode uses, and holds each one open for `delay` so
// that requests which the firewall issues in parallel genuinely OVERLAP at the
// server — without that window a fast fake could serialize by luck and report
// max-concurrency 1 for a firewall that does no coalescing at all.
//
//   - GET /v3/systems/<sys>/packages/<pkg>  -> 404. A durable "deps.dev has no
//     source-repo mapping", which under FW_UNVERIFIED_POLICY=open-with-visibility
//     proceeds on the self-declared repo. Chosen over a 200 because the fake cannot
//     know what repo each of express's ~70 dependencies declares, and answering with
//     the wrong one would be a MISMATCH — the borrow-a-score tripwire — which would
//     block the install for a reason that has nothing to do with this test.
//   - GET /v3/projects/<repo>               -> 200, score 9.0, so everything passes
//     the threshold and the install completes like a customer's would.
//
// Both are counted; /stats is not (it is the measurement channel, not traffic).
//
// The server is THREADING on purpose. A single-threaded http.server would serialize
// every request and report max_concurrent == 1 no matter what the firewall did,
// turning the central assertion into a tautology that passes forever.
func startDepsDevFake(t *testing.T, delay time.Duration) *depsDevFake {
	t.Helper()
	port := freePort(t)
	name := fmt.Sprintf("yj-e2e-depsdev-%d", port)

	prog := fmt.Sprintf(`import json, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DELAY = %v
lock = threading.Lock()
hits = {}
live = {}
state = {"inflight": 0, "max_same": 0, "max_all": 0, "busiest": ""}
SCORE = json.dumps({"scorecard": {"overallScore": 9.0}}).encode()

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = self.path
        if path == "/stats":
            with lock:
                out = json.dumps({
                    "hits": dict(hits),
                    "distinct": len(hits),
                    "total": sum(hits.values()),
                    "max_same_path": state["max_same"],
                    "max_concurrent": state["max_all"],
                    "busiest_path": state["busiest"],
                }).encode()
            self.reply(200, out)
            return

        with lock:
            hits[path] = hits.get(path, 0) + 1
            live[path] = live.get(path, 0) + 1
            state["inflight"] += 1
            if live[path] > state["max_same"]:
                state["max_same"] = live[path]
                state["busiest"] = path
            if state["inflight"] > state["max_all"]:
                state["max_all"] = state["inflight"]
        try:
            time.sleep(DELAY)
            if path.startswith("/v3/projects/"):
                self.reply(200, SCORE)
            else:
                self.reply(404, b"{}")
        finally:
            with lock:
                live[path] -= 1
                state["inflight"] -= 1

    def log_message(self, *a):
        pass

srv = ThreadingHTTPServer(("", 80), H)
srv.daemon_threads = True
srv.serve_forever()`, delay.Seconds())

	args := []string{"run", "-d", "--name", name, "-p", fmt.Sprintf("%d:80", port),
		"python:3.12-slim", "python3", "-c", prog}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("start deps.dev fake: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	dd := &depsDevFake{url: fmt.Sprintf("http://host.docker.internal:%d", port), port: port}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(dd.statsURL()); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return dd
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("deps.dev fake never became ready at %s", dd.statsURL())
	return nil
}

func (d *depsDevFake) statsURL() string {
	return fmt.Sprintf("http://%s:%d/stats", fwHost(), d.port)
}

func (d *depsDevFake) stats(t *testing.T) depsDevStats {
	t.Helper()
	resp, err := http.Get(d.statsURL())
	if err != nil {
		t.Fatalf("read deps.dev fake stats: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read deps.dev fake stats body: %v", err)
	}
	var s depsDevStats
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatalf("decode deps.dev fake stats: %v\n%s", err, body)
	}
	return s
}

// concurrentInstalls is how many `npm install express` clients hit ONE firewall at
// once. Three, because the herd this guards against is not a property of a single
// install — it is a property of a SHARED gateway, which is how the firewall is
// actually deployed (one instance, a team or a CI fleet behind it).
//
// This number is load-bearing and was measured, not guessed. The first version of
// this test ran ONE install and its own anti-vacuity guard failed it: npm fetches
// each packument exactly once, so a lone install produced 132 upstream calls across
// 132 distinct paths — no two same-key lookups ever competed, and the coalescing
// assertion would have been true of a firewall with no coalescing at all. Concurrent
// clients requesting overlapping trees are what create same-key contention.
const concurrentInstalls = 3

// TestNpmCoalescesUpstreamScoringCalls measures issue #16's guarantee end to end:
// when several real clients pull the same dependency tree through one firewall at the
// same time, lookups of the SAME key must collapse into ONE upstream call instead of
// fanning out into the burst that gets us rate-limited.
//
// THE L1 CACHES ARE TURNED OFF for this run (FW_SCORE_CACHE_TTL=0). That is what makes
// the result mean something. With caching on, "one upstream call per package" is
// exactly what a cache produces on its own, and the test would pass identically with
// the flight groups deleted — measuring the wrong mechanism and reporting it as proof
// of this one. With caching off, every request re-does the work, so the only thing
// that can collapse two same-key calls is coalescing.
//
// Two assertions, plus guards that stop this test from passing — or failing —
// vacuously. "No same-key overlap was observed" is also what a test that observed
// nothing at all reports, so the guards are what make the assertions mean something:
//
//  1. score calls < decisions   — the N-to-1 reduction, measured: the firewall served
//     strictly more client requests than it made upstream score calls, with caching
//     off. Delete the flight groups and these two numbers converge. With caching off
//     this doubles as the proof that same-key requests really did overlap, since an
//     absorbed request is by definition one that met a flight already in progress.
//  2. max_same_path == 1        — the invariant: never two concurrent upstream calls
//     for one key. This is what "coalesced" means; a cache cannot produce it.
//  3. total > 0                 — (guard) FW_DEPSDEV_BASE actually took effect and we
//     measured this firewall rather than an empty counter.
//  4. clientOverlap >= 2        — (guard) the installs really ran at the same time.
//     This does NOT gate the assertions; it decides how to READ a run with no
//     coalescing in it, so a runner that serialized the clients is reported as an
//     unusable run rather than as a broken firewall.
//
// ISSUE #44. Guard 4 replaced an earlier one that required the FAKE to have seen two
// upstream calls in flight at once (max_concurrent > 1). That is a different quantity
// from the one this test depends on: it measures overlap between calls the firewall
// had already decided to make, across UNRELATED keys, whereas coalescing is about
// several clients converging on the SAME key. A real run failed it while collapsing
// 198 client requests into 66 upstream calls — a textbook 3:1 coalesce — because the
// firewall's lookups happened to be issued one at a time. The guarantee was intact and
// the test said otherwise. Client-side overlap is the precondition that actually
// underwrites the claim, so that is what is measured now.
func TestNpmCoalescesUpstreamScoringCalls(t *testing.T) {
	bin := buildFirewall(t)
	// 250ms is a deliberate widening of the overlap window, not a realistic latency:
	// it makes "these two requests were in flight together" observable rather than a
	// race against the fake's own speed, and it holds each flight open long enough for
	// the other clients to arrive at the same package and be coalesced into it.
	dd := startDepsDevFake(t, 250*time.Millisecond)

	fw := startFirewall(t, bin, coalesceEnv(dd.url))

	// All clients start together and pull the same tree, so they contend for the same
	// keys. Each runs in its own container with its own npm cache, so none of them can
	// satisfy a request from another's cache — every client genuinely asks the firewall.
	//
	// Each client's start/end is recorded because whether they REALLY ran at the same
	// time is not something this test may assume — on a loaded shared runner they can
	// serialize, and issue #44 is exactly the failure of reading a serialized run as a
	// broken firewall. See maxOverlap.
	type result struct {
		out        string
		err        error
		start, end time.Time
	}
	results := make([]result, concurrentInstalls)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start := time.Now()
			out, err := npmInstallCmd(fw.port, "express").CombinedOutput()
			results[i] = result{out: string(out), err: err, start: start, end: time.Now()}
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		if r.err != nil {
			t.Fatalf("concurrent `npm install express` #%d failed: %v\n%s\n--- firewall ---\n%s",
				i, r.err, tail(r.out, 15), logAround(fw.log.String(), 20))
		}
	}

	s := dd.stats(t)
	// Client-side demand: one decision line per gated request, from the proxy's single
	// control point. This is the "N" that coalescing is supposed to reduce.
	decisions := fw.allowedCount() + fw.blockedCount()
	scoreCalls := 0
	for path, n := range s.Hits {
		if strings.HasPrefix(path, "/v3/projects/") {
			scoreCalls += n
		}
	}
	// absorbed is the number of client requests that did NOT produce an upstream score
	// call. With the L1 caches off there is only one way for that to happen: the request
	// arrived while a lookup for the SAME key was already in flight and was folded into
	// it. So `absorbed` is direct evidence of same-key CONTENTION — the precondition
	// this test needs — measured at the firewall rather than inferred from how busy the
	// fake happened to look.
	absorbed := decisions - scoreCalls

	// clientOverlap is the largest number of installs that were running at the same
	// instant. It is what separates the two ways `absorbed <= 0` can come about: a
	// firewall that stopped coalescing, or a runner that never let the clients meet.
	intervals := make([][2]time.Time, len(results))
	for i, r := range results {
		intervals[i] = [2]time.Time{r.start, r.end}
	}
	clientOverlap := maxOverlap(intervals)

	t.Logf("%d concurrent installs (max %d running at once) -> %d firewall decisions, %d absorbed by coalescing; deps.dev fake saw %d requests over %d distinct paths (%d score calls); max concurrent overall=%d, max concurrent for one path=%d (%s)",
		concurrentInstalls, clientOverlap, decisions, absorbed, s.Total, s.Distinct, scoreCalls, s.MaxConcurrent, s.MaxSamePath, s.BusiestPath)

	// Anti-vacuity first: if the run measured nothing, say THAT, rather than reporting
	// the guarantee as verified on the strength of an empty measurement.
	if s.Total == 0 {
		t.Fatalf("the firewall never called the fake deps.dev — FW_DEPSDEV_BASE did not take effect, so this test measured nothing\n--- firewall ---\n%s",
			logAround(fw.log.String(), 30))
	}
	if decisions == 0 {
		t.Fatalf("no decision lines in the firewall log — cannot compare upstream calls against client demand\n--- firewall ---\n%s",
			logAround(fw.log.String(), 30))
	}

	// (1) The N-to-1 reduction, measured — and, when it is absent, a diagnosis rather
	// than a guess. `absorbed <= 0` means every client request went upstream on its own,
	// which is what an uncoalesced firewall does AND what a run whose clients never met
	// looks like. Those two are not the same finding, so we do not report them as one:
	// only a run where the clients demonstrably overlapped is allowed to accuse the
	// firewall. This is issue #44 — a shared runner serialized the installs and the test
	// read that as a broken guarantee.
	switch {
	case absorbed > 0:
		// Same-key contention happened and coalescing absorbed it. The run is real;
		// assertion (2) below now has something to be true ABOUT.
	case clientOverlap < 2:
		t.Skipf("the runner never ran two installs at the same time (max %d concurrent, %d in total), so no two clients could contend for a key and this run proves nothing either way; the invariant itself is still enforced unconditionally by TestNpmCoalescesConcurrentSameKeyLookups",
			clientOverlap, concurrentInstalls)
	default:
		t.Errorf("no measurable coalescing: %d upstream score calls for %d client requests with caching off, and the clients DID overlap (%d ran at once), so this is the firewall, not the runner — expected strictly fewer calls than requests\nbusiest keys:\n%s",
			scoreCalls, decisions, clientOverlap, topHits(s.Hits, 10))
	}

	// (2) The invariant. A cache cannot produce this: it is about simultaneity, not
	// about totals.
	if s.MaxSamePath != 1 {
		t.Errorf("thundering herd: %d concurrent upstream lookups for the same key %q (want exactly 1 — see issue #16)\nbusiest keys:\n%s",
			s.MaxSamePath, s.BusiestPath, topHits(s.Hits, 10))
	}
}

// maxOverlap returns the largest number of the given [start, end) intervals that were
// open at the same instant. It is the test's own measurement of whether the clients
// really ran concurrently — the question issue #44 turned on, which the fake's
// max_concurrent could not answer because that counts overlap between calls the
// firewall had ALREADY decided to make, not overlap between the clients asking.
func maxOverlap(intervals [][2]time.Time) int {
	// A sweep over the endpoints: +1 at each start, -1 at each end, and the running
	// total is how many were open. Ends sort before starts at an equal instant, so two
	// intervals that merely touch are not counted as overlapping.
	type event struct {
		at    time.Time
		delta int
	}
	events := make([]event, 0, 2*len(intervals))
	for _, iv := range intervals {
		events = append(events, event{iv[0], +1}, event{iv[1], -1})
	}
	sort.Slice(events, func(i, j int) bool {
		if !events[i].at.Equal(events[j].at) {
			return events[i].at.Before(events[j].at)
		}
		return events[i].delta < events[j].delta
	})
	open, max := 0, 0
	for _, e := range events {
		open += e.delta
		if open > max {
			max = open
		}
	}
	return max
}

// TestMaxOverlap pins the helper that decides how a coalescing-free run is READ —
// firewall regression or unusable run. Getting it wrong in the "serialized" direction
// would re-file issue #44 as a code defect; getting it wrong in the other direction
// would let a real regression be waved through as a busy runner. It needs no Docker,
// so it also gives the e2e package one assertion that runs in milliseconds.
func TestMaxOverlap(t *testing.T) {
	base := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	at := func(sec int) time.Time { return base.Add(time.Duration(sec) * time.Second) }

	cases := []struct {
		name      string
		intervals [][2]time.Time
		want      int
	}{
		{"none", nil, 0},
		{"one alone", [][2]time.Time{{at(0), at(10)}}, 1},
		// The issue #44 shape: three installs that ran back to back. Whatever the fake
		// saw, no two clients could have contended for a key.
		{"serialized", [][2]time.Time{{at(0), at(10)}, {at(10), at(20)}, {at(20), at(30)}}, 1},
		{"all three together", [][2]time.Time{{at(0), at(30)}, {at(1), at(29)}, {at(2), at(28)}}, 3},
		// Partial overlap must report 2, not 3: the run is usable but only two clients
		// were ever able to meet.
		{"two of three", [][2]time.Time{{at(0), at(10)}, {at(5), at(15)}, {at(20), at(30)}}, 2},
		// Touching is not overlapping — one ends exactly as the next begins, so they
		// never coexisted and must not be counted as contention.
		{"touching", [][2]time.Time{{at(0), at(10)}, {at(10), at(20)}}, 1},
		// Order of the input must not matter; the sweep sorts.
		{"unsorted input", [][2]time.Time{{at(20), at(30)}, {at(0), at(10)}, {at(5), at(25)}}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := maxOverlap(tc.intervals); got != tc.want {
				t.Errorf("maxOverlap = %d, want %d", got, tc.want)
			}
		})
	}
}

// coalesceEnv is the firewall configuration both legs of this file run under: api
// mode, pointed at the counting fake, with everything that could quietly satisfy a
// request WITHOUT an upstream call turned off. Shared so the two legs cannot drift
// into measuring differently-configured firewalls and reporting one conclusion.
func coalesceEnv(depsDevURL string) map[string]string {
	return map[string]string{
		"FW_ECOSYSTEM":      "npm",
		"FW_SCORECARD_MODE": "api",
		// The seam: point the whole api-mode path (scoring AND the D33 repo
		// cross-check) at something that counts.
		"FW_DEPSDEV_BASE":    depsDevURL,
		"FW_SCORE_THRESHOLD": "0",
		// The load-bearing setting — see the doc comment on the npm leg. Also disables
		// the repo cache (both are constructed from this TTL), so package->repo
		// resolution re-runs per request too, which is what puts concurrent load on the
		// verification endpoint.
		"FW_SCORE_CACHE_TTL": "0",
		// D25's 429 circuit breaker would short-circuit requests without consulting the
		// fake, silently removing the very concurrency we are trying to observe. The
		// fake never returns 429, so this is belt-and-braces against a confusing result.
		"FW_RATELIMIT_BACKOFF_TTL": "0",
		"FW_UNSCORABLE_POLICY":     "allow",
		// The fake answers "no source-repo mapping" for every package (see
		// startDepsDevFake); under the D36 default that is a durable negative and would
		// block the whole tree. These legs are about call counts, not posture — the
		// fail-closed default is exercised by the unit matrix and verify_repo_local.sh.
		"FW_UNVERIFIED_POLICY": "open-with-visibility",
	}
}

// sameKeyClients is how many requests for ONE package the deterministic leg puts in
// flight at the same time. Twelve is arbitrary except that it is comfortably more than
// two, so "one upstream call" is a visible collapse rather than a coin flip.
const sameKeyClients = 12

// sameKeyHold is how long the fake sits on each deps.dev call. It is the entire
// determinism budget of the leg below: every client must arrive while the first one's
// lookup is still open, and this is the window in which they have to do it. Five
// seconds is absurd as a latency and deliberately so — the clients are goroutines in
// ONE process whose starts are microseconds apart, and a leader's Evaluate makes two
// of these calls in series, so the window is ~10s against a skew four orders of
// magnitude smaller. That margin is what makes this leg immune to the runner load that
// broke the npm leg (issue #44).
const sameKeyHold = 5 * time.Second

// TestNpmCoalescesConcurrentSameKeyLookups proves issue #16's guarantee through the
// deployed CONTAINER without depending on how a loaded CI runner schedules anything.
//
// The npm leg above is the honest end-to-end shape — real clients, real trees — but it
// buys that realism by letting the runner decide whether its clients ever meet, and
// issue #44 is what that costs: a green firewall reported red because three installs
// serialized. This leg gives up the realism and takes the determinism. It drives the
// firewall directly, from goroutines in the test process, all asking for the SAME
// package. Same-key contention is then a property of the code, not of the runner.
//
// It is not a duplicate of the in-process tests (TestEvaluateCoalescesColdLookups,
// TestFlightGroupCoalesces). Those call Evaluate in the same process as the flight
// group. This one crosses the real boundaries — HTTP into a container, HTTP out to an
// upstream — and so is the only place that can catch coalescing being lost to how the
// binary is BUILT or CONFIGURED rather than how it is written.
//
// The measurement is a subtraction that admits no other explanation: with the L1 caches
// off, N simultaneous requests for one key produce exactly ONE upstream score call.
// Delete the flight groups and the fake sees N.
func TestNpmCoalescesConcurrentSameKeyLookups(t *testing.T) {
	bin := buildFirewall(t)
	dd := startDepsDevFake(t, sameKeyHold)
	fw := startFirewall(t, bin, coalesceEnv(dd.url))

	// One package, requested by everyone. `express` because the npm leg already proves
	// this suite can score it — a package whose npm metadata declares no repo would
	// produce no score call at all and fail this test for an unrelated reason.
	const pkg = "express"
	url := fmt.Sprintf("http://%s:%d/%s", fwHost(), fw.port, pkg)

	type call struct {
		status     int
		err        error
		start, end time.Time
	}
	calls := make([]call, sameKeyClients)
	var wg sync.WaitGroup
	for i := range calls {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start := time.Now()
			// A generous timeout: the leader deliberately waits ~2*sameKeyHold and every
			// follower waits with it. Too short a client timeout here would cancel the
			// followers and destroy the very contention being measured.
			c := &http.Client{Timeout: 4 * sameKeyHold}
			resp, err := c.Get(url)
			if err == nil {
				// Drain before close, so "this request finished" means the response
				// really arrived rather than merely that headers did.
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			calls[i] = call{err: err, start: start, end: time.Now()}
			if resp != nil {
				calls[i].status = resp.StatusCode
			}
		}(i)
	}
	wg.Wait()

	for i, c := range calls {
		if c.err != nil {
			t.Fatalf("concurrent GET %s #%d failed: %v\n--- firewall ---\n%s",
				url, i, c.err, logAround(fw.log.String(), 20))
		}
		if c.status != http.StatusOK {
			t.Fatalf("concurrent GET %s #%d returned %d, want 200 — the package must be ALLOWED for this leg to exercise the scoring path\n--- firewall ---\n%s",
				url, i, c.status, logAround(fw.log.String(), 20))
		}
	}

	s := dd.stats(t)
	decisions := fw.allowedCount() + fw.blockedCount()
	scoreCalls := 0
	for path, n := range s.Hits {
		if strings.HasPrefix(path, "/v3/projects/") {
			scoreCalls += n
		}
	}
	intervals := make([][2]time.Time, len(calls))
	for i, c := range calls {
		intervals[i] = [2]time.Time{c.start, c.end}
	}
	overlap := maxOverlap(intervals)

	t.Logf("%d simultaneous requests for %q (max %d in flight at once) -> %d firewall decisions, %d upstream score calls; deps.dev fake saw %d requests over %d distinct paths; max concurrent for one path=%d (%s)",
		sameKeyClients, pkg, overlap, decisions, scoreCalls, s.Total, s.Distinct, s.MaxSamePath, s.BusiestPath)

	// The precondition, MEASURED rather than assumed. This is the whole reason the leg
	// exists: it does not ask the fake how busy it looked, it asks whether all N clients
	// were genuinely waiting at the same instant. If they were not, the subtraction
	// below would be meaningless, and we say so instead of reporting a verdict.
	if overlap != sameKeyClients {
		t.Fatalf("only %d of %d requests were ever in flight at once, so this run did not create the same-key contention it is built to create; with a %s hold per upstream call that should be impossible — suspect the test setup, not the firewall",
			overlap, sameKeyClients, sameKeyHold)
	}
	if decisions != sameKeyClients {
		t.Fatalf("firewall logged %d decisions for %d requests — every request must reach the gate for the call count below to mean anything\n--- firewall ---\n%s",
			decisions, sameKeyClients, logAround(fw.log.String(), 30))
	}

	// The claim. N clients were provably waiting together, so the fake must have been
	// asked once. Not "fewer than N" — exactly one, because with caching off there is
	// nothing else that could have answered the other eleven.
	if scoreCalls != 1 {
		t.Errorf("thundering herd: %d simultaneous lookups of %q produced %d upstream score calls, want exactly 1 (see issue #16)\nbusiest keys:\n%s",
			sameKeyClients, pkg, scoreCalls, topHits(s.Hits, 10))
	}
	if s.MaxSamePath != 1 {
		t.Errorf("thundering herd: %d concurrent upstream lookups for the same key %q (want exactly 1 — see issue #16)\nbusiest keys:\n%s",
			s.MaxSamePath, s.BusiestPath, topHits(s.Hits, 10))
	}
}

// topHits renders the n most-requested paths. The raw map is ~130 entries — dumping
// it in full buries the failure in a wall of text that no one reads in a CI log, and
// the counts that matter on a failure are the highest ones anyway.
func topHits(hits map[string]int, n int) string {
	paths := make([]string, 0, len(hits))
	for p := range hits {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool {
		if hits[paths[i]] != hits[paths[j]] {
			return hits[paths[i]] > hits[paths[j]]
		}
		return paths[i] < paths[j] // stable, so a failure message is reproducible
	})
	if len(paths) > n {
		paths = paths[:n]
	}
	var b strings.Builder
	for _, p := range paths {
		fmt.Fprintf(&b, "  %4d  %s\n", hits[p], p)
	}
	fmt.Fprintf(&b, "  (%d distinct paths in total)", len(hits))
	return b.String()
}
