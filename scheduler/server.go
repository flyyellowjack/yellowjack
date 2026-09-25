package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The scheduler is our product. It receives a scan request from the firewall,
// launches ONE run-once scorecard container per scan (handing it the repo, a
// GitHub token, and a sink URL that points back here), waits for that container to
// POST its result, and returns the score to the firewall. It holds no durable
// state and no scorecard code of its own — the heavy, third-party, token-bearing
// work happens in the ephemeral container, not here (DECISIONS.md D16).

// scanResult mirrors the scanner's ScanResult across the HTTP boundary. The two
// services are separate packages and each owns its own DTO (same rule as the
// firewall<->approval boundary) — so they can evolve independently.
type scanResult struct {
	Repo   string        `json:"repo"`
	Score  float64       `json:"score"`
	Commit string        `json:"commit,omitempty"`
	Date   string        `json:"date,omitempty"`
	Checks []checkResult `json:"checks"`

	// Coverage (#133), copied through unchanged. The scheduler does NOT recompute
	// these from Checks even though it could: the scanner decides what "scored"
	// means, and a second component deriving the same ratio its own way is how the
	// two quietly come to disagree. The scheduler's job here is transport.
	//
	// They are also not interpreted here. Whether a partial report may be compared to
	// a threshold is a POLICY question and the scheduler holds no policy (D16) — the
	// firewall decides, and today refuses.
	ScoredChecks int `json:"scoredChecks"`
	TotalChecks  int `json:"totalChecks"`
}

type checkResult struct {
	Name   string `json:"name"`
	Score  int    `json:"score"`
	Reason string `json:"reason"`
}

// scanReport is the envelope the run-once container POSTs to /results/{id}.
// Exactly one of Result / Error is meaningful.
type scanReport struct {
	Repo   string      `json:"repo"`
	Result *scanResult `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// launcher starts a run-once scanner container that will POST its scanReport to
// sinkURL. It's an interface so the launch mechanism can vary — docker-run
// shell-out first, raw Docker Engine API later, Kubernetes Job later still — with
// the server logic unchanged. The GitHub token is launcher config, not a per-call
// argument, so it stays out of the request path entirely.
type launcher interface {
	Launch(ctx context.Context, repo, sinkURL string) error
}

// pendingScan is one in-flight scan: the channel the waiting /scan handler is
// listening on, plus the capability token that authorizes a result for it. The
// token is generated per scan and handed only to the container we launched, so a
// result POST that carries it must have come from that container (capability.go).
type pendingScan struct {
	ch    chan scanReport
	token string
}

// scheduler wires the HTTP surface to a launcher and correlates each launched
// container's result back to the request that is waiting for it.
type scheduler struct {
	launcher launcher
	selfURL  string        // base URL a launched container uses to reach /results
	timeout  time.Duration // how long /scan waits for a container's result

	// launchSlots bounds how many scans are in flight at once — one permit per
	// running scan (issue #13, item 3). Each permit stands for a real container
	// holding real memory and CPU, so without a bound a burst of /scan calls
	// launches a container per call and can take the host down. nil = uncapped.
	launchSlots chan struct{}

	mu      sync.Mutex
	pending map[string]*pendingScan // scan id -> waiter + its capability token
	nextID  uint64
}

// newScheduler builds the service. maxConcurrentScans <= 0 means uncapped (the
// pre-cap behavior, kept available for an operator who is bounding launches some
// other way — e.g. at a Kubernetes ResourceQuota once the Job launcher lands).
func newScheduler(l launcher, selfURL string, timeout time.Duration, maxConcurrentScans int) *scheduler {
	s := &scheduler{
		launcher: l,
		selfURL:  strings.TrimRight(selfURL, "/"),
		timeout:  timeout,
		pending:  make(map[string]*pendingScan),
	}
	if maxConcurrentScans > 0 {
		s.launchSlots = make(chan struct{}, maxConcurrentScans)
	}
	return s
}

// acquireSlot takes a launch permit, waiting for one if all are busy, and returns
// the release func. It reports false only when ctx expired while queueing.
//
// Queueing rather than rejecting is the important design point. A rejected scan
// reaches the firewall as a non-200, which it reads as "couldn't get a score" — and
// under the default fail-closed unscorable policy that BLOCKS the package. Failing
// a legitimate package because we were momentarily busy would be a worse bug than
// the one this cap fixes, so a burst is smoothed instead: callers wait inside the
// deadline they already set (s.timeout), and only a caller that never gets a slot
// within it is turned away.
func (s *scheduler) acquireSlot(ctx context.Context, repo string) (func(), bool) {
	if s.launchSlots == nil {
		return func() {}, true
	}
	release := func() { <-s.launchSlots }
	select {
	case s.launchSlots <- struct{}{}:
		return release, true // a slot was free: no waiting, no log noise
	default:
	}
	log.Printf("scan %s: all %d launch slots busy, queueing", repo, cap(s.launchSlots))
	select {
	case s.launchSlots <- struct{}{}:
		return release, true
	case <-ctx.Done():
		return nil, false
	}
}

func (s *scheduler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/healthz":
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok\n")
	case r.URL.Path == "/scan":
		s.handleScan(w, r)
	case strings.HasPrefix(r.URL.Path, "/results/"):
		s.handleResult(w, r)
	default:
		writeError(w, http.StatusNotFound, "unknown path")
	}
}

// scanRequest is the firewall's request body.
type scanRequest struct {
	Repo string `json:"repo"`
}

func (s *scheduler) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use POST /scan")
		return
	}
	var req scanRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Repo == "" {
		writeError(w, http.StatusBadRequest, "missing 'repo'")
		return
	}

	// Bound the whole wait: queueing for a launch slot + launch + scan + report
	// delivery. The deadline is the caller's budget for all of it.
	ctx, cancel := context.WithTimeout(r.Context(), s.timeout)
	defer cancel()

	// Take a launch permit before launching anything. Held until this handler
	// returns, i.e. for as long as we are waiting on that container.
	release, ok := s.acquireSlot(ctx, req.Repo)
	if !ok {
		// Saturated for the caller's whole deadline. 503 (not 502/504) is deliberate:
		// the firewall maps a scheduler 503 to a RETRYABLE transient failure, while
		// 502/504 mean "this repo couldn't be scored" and feed the unscorable policy.
		// Being busy is not a verdict on the package.
		log.Printf("scan %s: no launch slot within %s, shedding", req.Repo, s.timeout)
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, "scheduler at scan capacity, retry")
		return
	}
	defer release()

	// Register a waiter before launching, so a fast container can't POST its result
	// before we're listening. Buffered (size 1) so handleResult never blocks even
	// if we've already given up waiting.
	id, token, ch, err := s.register()
	if err != nil {
		// Only crypto/rand failing gets us here. Refuse the scan rather than run one
		// whose result we couldn't authenticate.
		log.Printf("scan %s: %v", req.Repo, err)
		writeError(w, http.StatusInternalServerError, "failed to prepare scan")
		return
	}
	defer s.forget(id)

	// The token rides in the sink URL, which is the ONLY place it is ever written and
	// is handed to exactly one launched container. Both launchers pass sinkURL
	// through verbatim as SCANNER_SINK_URL, and the scanner POSTs to it unmodified,
	// so no other service needed a change for this.
	sinkURL := s.selfURL + "/results/" + id + "/" + token

	if err := s.launcher.Launch(ctx, req.Repo, sinkURL); err != nil {
		// 503, NOT 502 (issue #69). We never reached the repo — the container did not
		// start, because Docker is unreachable, the image is missing, or the daemon is
		// wedged. That is OUR infrastructure, and it is the same kind of statement as
		// the capacity shed above, so it must reach the firewall as TRANSIENT.
		//
		// As a 502 it was indistinguishable from "the scan ran and the repo could not
		// be scored", which the firewall must treat as unscorable — and under its
		// default byte gate a soft deny SERVES the artifact. So a launcher that could
		// not reach Docker quietly degraded into "serve the bytes".
		log.Printf("scan %s: launch failed: %v", req.Repo, err)
		writeError(w, http.StatusServiceUnavailable, "failed to launch scanner: "+err.Error())
		return
	}

	select {
	case report := <-ch:
		if report.Error != "" {
			// The scan itself failed. Return non-2xx so the firewall treats it as
			// "couldn't get a score" (unscorable), exactly as the old scanner's
			// non-200 did — the approval/policy path is unchanged.
			//
			// 502 is now RESERVED for exactly this meaning (issue #69): the scan ran
			// and the repo could not be scored. It is the one case here that is a
			// statement about the package rather than about us, and retrying cannot
			// help — the approval queue is where it belongs.
			log.Printf("scan %s: reported failure: %s", req.Repo, report.Error)
			writeError(w, http.StatusBadGateway, "scan failed: "+report.Error)
			return
		}
		if report.Result == nil {
			// A report should carry exactly one of Result / Error, but that's the
			// container's contract, not a guarantee — a buggy or truncated report
			// with NEITHER would nil-panic below. Treat it as a failed scan.
			// Also 503 (issue #69): a report carrying NEITHER a result nor an error
			// violates the container's own contract. That is our plumbing being broken
			// or truncated, not a finding about the repo, so it must not land on the
			// unscorable policy. If it is systematic rather than transient it will 503
			// persistently — which is the right failure for a bug of ours: loud and
			// attributable, instead of silently marking every package unscorable.
			log.Printf("scan %s: malformed report (neither result nor error)", req.Repo)
			writeError(w, http.StatusServiceUnavailable, "scan returned no result")
			return
		}
		// Coverage in the line an operator greps for: a 4.8 over 11 of 18 checks and a
		// 4.8 over 18 are different measurements, and until this said so the log could
		// not tell them apart (#133).
		log.Printf("scan %s -> score %.1f (%d of %d checks scored)", req.Repo,
			report.Result.Score, report.Result.ScoredChecks, report.Result.TotalChecks)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(report.Result)
	case <-ctx.Done():
		// 504 deliberately KEPT as a non-transient outcome (issue #69). A timeout is
		// genuinely ambiguous — our load, or a pathological repo — but a repo that
		// always exceeds the deadline must eventually reach the approval path rather
		// than 503 forever. Revisit if timeouts turn out to track our load instead.
		log.Printf("scan %s: timed out waiting for result", req.Repo)
		writeError(w, http.StatusGatewayTimeout, "scan timed out")
	}
}

func (s *scheduler) handleResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use POST /results/{id}")
		return
	}
	id, token, ok := splitResultPath(r.URL.Path)
	if !ok {
		// Includes the pre-token URL shape (/results/{id} with no token segment):
		// that form is exactly the forgeable one, so it is refused outright.
		writeError(w, http.StatusBadRequest, "use POST /results/{id}/{token}")
		return
	}

	// Look the scan up and check the token BEFORE decoding the body, so an
	// unauthorized POST costs us a map lookup rather than up to 1 MiB of JSON.
	s.mu.Lock()
	p, known := s.pending[id]
	s.mu.Unlock()

	// No waiter: it timed out, or this is a duplicate/late POST. Accept and drop —
	// the container did its job; there is simply no one to hand the report to, and
	// answering 2xx keeps a late-reporting container from exiting non-zero.
	//
	// This does mean a 200 here vs. a 403 below tells a prober whether an id is
	// live. That leaks nothing worth having: ids are enumerable by construction
	// (counter + timestamp), and knowing one is live buys nothing without the
	// 256-bit token.
	if !known {
		log.Printf("result for unknown/expired scan id %q, ignoring", id)
		w.WriteHeader(http.StatusOK)
		return
	}

	if !tokenMatches(p.token, token) {
		// Not a routine client error — the only way to be here is to have found a
		// live scan id and presented the wrong authority for it. Log it loudly
		// enough for an operator to see an attempt at score forgery.
		log.Printf("SECURITY: rejected result for scan id %q from %s: invalid capability token", id, r.RemoteAddr)
		writeError(w, http.StatusForbidden, "invalid capability token")
		return
	}

	var report scanReport
	// Scan reports are small; cap the body generously but firmly.
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&report); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	p.ch <- report // non-blocking: the channel is buffered size 1
	w.WriteHeader(http.StatusOK)
}

// splitResultPath parses "/results/{id}/{token}" into its two segments. Both must
// be non-empty, and the token must be a single segment — capability tokens are
// base64url, which never contains '/', so anything else is malformed rather than
// something to be lenient about.
func splitResultPath(path string) (id, token string, ok bool) {
	rest := strings.TrimPrefix(path, "/results/")
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return "", "", false
	}
	id, token = rest[:slash], rest[slash+1:]
	if token == "" || strings.Contains(token, "/") {
		return "", "", false
	}
	return id, token, true
}

// register creates a waiter and returns its id, its capability token, and the
// channel the result will arrive on. The id stays a readable counter+timestamp — it
// is a log-safe correlation handle, NOT an authenticator; the token is what
// authorizes a result (capability.go).
func (s *scheduler) register() (string, string, chan scanReport, error) {
	token, err := newCapabilityToken()
	if err != nil {
		return "", "", nil, err
	}
	ch := make(chan scanReport, 1)
	s.mu.Lock()
	s.nextID++
	id := strconv.FormatUint(s.nextID, 10) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	s.pending[id] = &pendingScan{ch: ch, token: token}
	s.mu.Unlock()
	return id, token, ch, nil
}

func (s *scheduler) forget(id string) {
	s.mu.Lock()
	delete(s.pending, id)
	s.mu.Unlock()
}

// writeError returns a JSON error body with the given status.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
