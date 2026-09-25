//go:build e2e

// Package e2e drives the firewall the way a company actually uses it: a real
// package client (npm/pip/docker/mvn), running in a throwaway container, pointed
// at a live firewall, asserting the allow/block behavior end to end. These tests
// are gated behind the `e2e` build tag (run with `go test -tags e2e ./e2e/...`) so
// the normal `go test ./...` stays fast and offline. They require Docker and
// network access to the real public registries.
//
// The firewall runs as a CONTAINER (built from the repo Dockerfile) with a
// published port, not as a host process. That is what lets the suite run on
// GitLab's shared docker:dind runners as well as a dev laptop: a dind daemon can't
// route a client container to a firewall PROCESS in the job container, but it can
// route it to a firewall CONTAINER's published port via host.docker.internal. See
// the e2e job in .gitlab-ci.yml and docs/E2E_TESTING.md.
package e2e

import (
	"crypto/sha256"
	"fmt"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fwImageTag derives the firewall image tag from the absolute path of the tree being
// tested, so concurrent checkouts cannot clobber each other's image.
//
// THIS WAS A CONSTANT (`yj-e2e-firewall:latest`), shared by every worktree on the host. A
// sibling session running e2e from a DIFFERENT checkout rebuilds the same tag; whichever
// build lands last wins, and the other session's containers then run the other tree's
// binary. The failure is maximally confusing because it looks like a product regression: a
// fix present in the source, green in the unit tests and in a hand-built image, absent from
// the e2e run -- because the code under test was never the code on disk. This host carries
// 13 worktrees, so it is the normal case, not a corner. Cost to diagnose: about an hour.
//
// The tag stays STABLE per tree, which preserves the original intent: the four ecosystem
// tests still share one build and a re-run in the same tree still hits docker's layer cache.
// Only cross-tree collision is removed -- layer caching is content-addressed and unaffected
// by the tag, so different trees sharing unchanged layers still reuse them.
func fwImageTag(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..") // repo root; this package lives in ./e2e
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	// The build variant is part of the key: an image built without interception must never
	// be reused by a run that needs it, or the other way round.
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(root)) + "|" + firewallBuildTags))
	return fmt.Sprintf("yj-e2e-firewall:%x", sum[:6])
}

// buildFirewall builds the firewall Docker image from the repo root. On dind the
// build context is shipped to the daemon; docker's layer cache makes the repeat
// builds across the four ecosystem tests cheap (only go.mod/source-change layers
// rebuild). Returns the image tag, which the caller threads into startFirewall.
func buildFirewall(t *testing.T) string {
	t.Helper()
	img := fwImageTag(t)
	cmd := exec.Command("docker", "build", "--build-arg", "GO_TAGS="+firewallBuildTags, "-t", img, ".")
	cmd.Dir = ".." // repo root (this package lives in ./e2e; the Dockerfile is there)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build firewall image: %v\n%s", err, out)
	}
	return img
}

// Published container ports are drawn from a band BELOW the kernel's ephemeral range,
// which on every image this suite runs is 32768-60999 (`/proc/sys/net/ipv4/ip_local_port_range`).
//
// That choice is the whole point of freePort, so it is worth stating why. A rig publishes
// its port on the DOCKER DAEMON's host, which under `docker:dind` is a different container
// from the one the test binary runs in -- the job container reaches it as `docker:<port>`
// (see fwHost). So asking the OS here for a free port answers a question about the wrong
// machine: it says the port is free in the JOB container, and says nothing about the dind
// container where the bind actually happens.
//
// In dind that port space is busy. Every client container's outbound connection takes an
// ephemeral source port there, and these rigs dial hard enough to have exhausted the pool
// once already (#96: 7,511 dials against a 16,384-port range). A published port asked for
// out of the same 32768-60999 band therefore collides with an ordinary outbound socket
// sooner or later, and the daemon refuses the container:
//
//	docker: Error response from daemon: driver failed programming external connectivity
//	on endpoint yj-mitm-38933: Bind for 0.0.0.0:38933 failed: port is already allocated
//
// That is what turned `main` red on 0206554 (#123) while the identical code passed on the MR and
// on the next commit: a probabilistic collision, not a code change. Staying below 32768
// removes the mechanism rather than retrying against it.
const (
	e2ePortBandLo = 20000
	e2ePortBandHi = 32767
)

var (
	portMu     sync.Mutex
	portIssued = map[int]bool{}
	portNext   int
)

// freePort returns a TCP port to publish a container port on. Ports are handed out
// sequentially from a random start inside the band: sequential so two rigs in one run
// cannot draw the same number, random-start so two suites sharing a dev machine do not
// march in lockstep from the same place.
//
// The local listen is kept as a courtesy check for a DEV LAPTOP, where the daemon and the
// test binary really do share a host and the probe means something. It is deliberately not
// load-bearing: in CI it cannot see the namespace that matters, which is precisely the bug
// this function exists to avoid.
func freePort(t *testing.T) int {
	t.Helper()
	portMu.Lock()
	defer portMu.Unlock()

	if portNext == 0 {
		portNext = e2ePortBandLo + mrand.Intn(e2ePortBandHi-e2ePortBandLo+1)
	}
	for tries := 0; tries <= e2ePortBandHi-e2ePortBandLo; tries++ {
		port := portNext
		portNext++
		if portNext > e2ePortBandHi {
			portNext = e2ePortBandLo
		}
		if portIssued[port] {
			continue
		}
		if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			l.Close()
		} else if !portProbeUninformative() {
			continue // free here and here is the daemon's host too: believe it
		}
		portIssued[port] = true
		return port
	}
	t.Fatalf("no free port left in %d-%d after %d issued", e2ePortBandLo, e2ePortBandHi, len(portIssued))
	return 0
}

// portProbeUninformative reports whether the local listen above says nothing useful,
// because the docker daemon lives somewhere else (E2E_FW_HOST is set on dind).
func portProbeUninformative() bool { return os.Getenv("E2E_FW_HOST") != "" }

// fwHost is where the harness itself (the test binary, running in the CI job
// container or on a dev laptop) reaches the firewall's PUBLISHED port. Locally the
// docker host is 127.0.0.1; on GitLab dind the daemon is a linked service reachable
// by hostname `docker`, so the CI job sets E2E_FW_HOST=docker. Client CONTAINERS,
// by contrast, always reach the firewall via host.docker.internal:<port>
// (host-gateway), which resolves to the docker host in both environments — so the
// client test files need no per-environment logic.
func fwHost() string {
	if h := os.Getenv("E2E_FW_HOST"); h != "" {
		return h
	}
	return "127.0.0.1"
}

// firewall is one running firewall container for a single scenario. Its published
// port is what clients dial; its container logs are the decision log tests assert
// on.
type firewall struct {
	port int
	name string
	log  fwLog // decision log, fetched from `docker logs <name>` on demand
}

// fwLog is a lazy handle on a firewall container's logs. It exposes String() so the
// ecosystem tests keep asserting on fw.log.String() unchanged — whether the firewall
// is a host process (old) or a container (now).
type fwLog struct{ name string }

func (l fwLog) String() string {
	out, _ := exec.Command("docker", "logs", l.name).CombinedOutput()
	return string(out)
}

// startFirewall runs the firewall image with the given env overrides, publishing a
// free host port to the container's :8080, and blocks until /healthz is green. It's
// torn down (docker rm -f) automatically at test end.
func startFirewall(t *testing.T, image string, env map[string]string) *firewall {
	t.Helper()
	return startFirewallOnPort(t, image, freePort(t), env)
}

// startFirewallWithMounts is startFirewall plus docker -v arguments.
//
// It exists for the credential-rotation leg (#53), which needs a file the firewall
// re-reads while running AND a way to rewrite that file from outside the container.
// The firewall image is distroless, so nothing inside it can write the file; a mount is
// also how a refresher (Vault agent, a cron running the AWS CLI, a Kubernetes projected
// token) delivers a rotated credential in production, so it is the faithful shape too.
//
// mounts are passed verbatim, so a caller should use a NAMED VOLUME rather than a host
// path: under docker:dind in CI the daemon is a different container from the test
// process, so a host path resolves on the DAEMON's filesystem and the file the test
// wrote is simply not there. A named volume lives on the daemon and both sides agree.
func startFirewallWithMounts(t *testing.T, image string, env map[string]string, mounts []string) *firewall {
	t.Helper()
	return startFirewallOnPortWithMounts(t, image, freePort(t), env, mounts)
}

// startFirewallOnPort is startFirewall with the published port chosen by the caller.
// It exists for the lockfile scenario (issue #11): a lockfile records the firewall's
// ADDRESS in each dependency's "resolved" URL, so replaying that lockfile against a
// differently-configured firewall — the real-world "policy tightened after the
// lockfile was committed" case — means restarting on the SAME port. Everything else
// is identical to startFirewall.
func startFirewallOnPort(t *testing.T, image string, port int, env map[string]string) *firewall {
	t.Helper()
	return startFirewallOnPortWithMounts(t, image, port, env, nil)
}

// startFirewallOnPortWithMounts is the one implementation the wrappers above share.
// mounts may be nil, which is every pre-existing caller.
func startFirewallOnPortWithMounts(t *testing.T, image string, port int, env map[string]string, mounts []string) *firewall {
	t.Helper()
	name := fmt.Sprintf("yj-e2e-%d", port)
	fw := &firewall{port: port, name: name, log: fwLog{name: name}}

	// The container always listens on :8080 (the Dockerfile's EXPOSEd port); we
	// publish it on the free host port clients dial.
	// A previous scenario may have held this port (the lockfile legs deliberately
	// reuse one); make sure its container is gone before rebinding.
	_ = exec.Command("docker", "rm", "-f", name).Run()
	args := []string{"run", "-d", "--name", fw.name,
		"-p", fmt.Sprintf("%d:8080", fw.port),
		// So the firewall CONTAINER can reach host-side/sibling services published on
		// the docker host — e.g. the approval stub in the override test (startApprovalStub).
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "FW_LISTEN_ADDR=:8080"}
	for k, v := range env {
		args = append(args, "-e", k+"="+v)
	}
	for _, m := range mounts {
		args = append(args, "-v", m)
	}
	args = append(args, image)
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("start firewall container: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", fw.name).Run() })

	url := fmt.Sprintf("http://%s:%d/healthz", fwHost(), fw.port)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(url); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return fw
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("firewall never became healthy at %s\n%s", url, fw.log.String())
	return nil
}

// stop tears the container down early, freeing its published port for the next
// firewall in the same scenario. Its logs go with it, so callers that still need
// them must read fw.log.String() first. The t.Cleanup teardown stays registered and
// is harmless once the container is already gone.
func (f *firewall) stop() { _ = exec.Command("docker", "rm", "-f", f.name).Run() }

// blockedCount / allowedCount count decision lines of each kind in the firewall log.
func (f *firewall) blockedCount() int { return strings.Count(f.log.String(), "allowed=false") }
func (f *firewall) allowedCount() int { return strings.Count(f.log.String(), "allowed=true") }

// decision is one parsed firewall verdict. Counting decision lines proves only that the
// gate ran; it does not say WHICH package was judged or WHY. A test asserting
// "blockedCount() > 0" passes when the firewall blocks something unrelated while the
// install fails for its own reasons -- two independent facts that read as cause and
// effect. Parsing gives the ecosystem tests the package and the reason, so they can
// assert the failure is attributable to the block they meant to provoke.
type decision struct {
	method  string
	pkg     string
	allowed bool
	reason  string
	// bytes is true when the gate judged the artifact fetch itself rather than the
	// metadata request. Tests that care about WHERE a package was refused need this: an
	// install can fail at the index for its own reasons while the byte gate was never
	// consulted.
	//
	// Three emitters set it, one per ecosystem's byte path, and they look nothing alike:
	// PyPI's `GET _files pkg -> …`, npm's `artifact [known-malware] pkg -> …` from
	// proxyArtifactBytes, and npm's `byte gate (enforce|allow-but-log) pkg -> …`. Keying
	// on the `_files ` token alone — which is what this field did until the log-contract
	// guard went in — reports the two npm shapes as METADATA verdicts, so an npm test
	// asking "was this refused at the bytes?" silently gets false.
	bytes bool
}

// Matches both decision shapes emitted by proxy.go: the main one
// (`GET [verdict-blocked] express -> allowed=false score=3.2 hasScore=true (reason)`) and
// the byte-relay one (`GET _files [verdict-blocked] pkg -> allowed=false (reason)`), which
// carries no score. The optional groups are what let one regexp serve both, rather than
// silently matching only the shape that happens to be tested.
//
// The `[outcome-token]` group is optional because it postdates these lines (#76 added it
// so an upstream outage reads the same on every ecosystem). It is ALSO the reason this
// regexp is covered by TestHarnessParsesEveryDecisionLogShape: this parser and
// modematrix_test.go's classifyLog are two independent readers of the same log line, and
// #76 updated only one of them — the mode matrix stayed green while every parse here
// silently returned nothing, which surfaced as "no verdict was rendered" in an e2e leg
// ten minutes downstream.
var decisionRe = regexp.MustCompile(
	`(\w+) (_files )?(?:\[[a-z-]+\] )?(\S+) -> allowed=(true|false)(?: score=\S+ hasScore=\S+)? \((.*)\)`)

// byteGateRe matches npm's byte-gate verdicts, which decisionRe structurally cannot:
// they open with a two-word prefix carrying a parenthesised MODE (`byte gate (enforce) `)
// where decisionRe expects a single method word, and they interleave `pending=`,
// `unavailable=`, `deny=` and `rule=` between `allowed=` and the parenthesised reason.
//
// They were invisible to decisions() while blockedCount() counted them by substring, so
// the two readers disagreed on real logs by construction — the #76 divergence again, on
// three shapes the hand-written corpus in harness_parse_test.go never contained. Found by
// rendering each emitter in proxy.go and feeding it to the live regexp, not by reading it.
//
// `[^(]*` is the load-bearing part of the middle: it cannot cross a `(`, so it stops at
// the reason's opening paren however many `key=value` pairs precede it, and a new field
// added between them needs no change here. The reason capture stays GREEDY to the last
// `)` for the same reason decisionRe's does — a reason containing parentheses must not be
// truncated — which also correctly ignores the trailing ` — SERVING BYTES ANYWAY…` prose.
var byteGateRe = regexp.MustCompile(
	`byte gate \((?:enforce|allow-but-log)\) (?:\[[a-z-]+\] )?(\S+) -> allowed=(true|false)[^(]*\((.*)\)`)

func (f *firewall) decisions() []decision { return parseDecisions(f.log.String()) }

// parseDecisions is split out from decisions() so the parser can be tested against
// literal log lines without a container: fwLog.String() shells out to `docker logs`,
// which would make a parser test cost a docker runner and hide it behind the e2e legs.
func parseDecisions(logText string) []decision {
	var out []decision
	for _, line := range strings.Split(logText, "\n") {
		if m := decisionRe.FindStringSubmatch(line); m != nil {
			out = append(out, decision{
				method: m[1],
				// `_files ` is PyPI's byte path; `artifact ` is the method word npm's
				// proxyArtifactBytes writes literally. Both judge bytes, so both set it.
				bytes:   m[2] != "" || m[1] == "artifact",
				pkg:     m[3],
				allowed: m[4] == "true",
				reason:  m[5],
			})
			continue
		}
		if m := byteGateRe.FindStringSubmatch(line); m != nil {
			out = append(out, decision{
				method:  "byte gate",
				bytes:   true,
				pkg:     m[1],
				allowed: m[2] == "true",
				reason:  m[3],
			})
		}
	}
	return out
}

// decisionsFor returns every verdict rendered for one package, so a test can assert the
// gate actually judged the package under test rather than merely judging something.
func (f *firewall) decisionsFor(pkg string) []decision {
	var out []decision
	for _, d := range f.decisions() {
		if d.pkg == pkg {
			out = append(out, d)
		}
	}
	return out
}

// blocked maps each blocked package to the reason given. The reason is half the product:
// a block a developer cannot diagnose is a support ticket, so tests assert on it.
func (f *firewall) blocked() map[string]string {
	out := map[string]string{}
	for _, d := range f.decisions() {
		if !d.allowed {
			out[d.pkg] = d.reason
		}
	}
	return out
}

// blockSurfacedAtClient inspects the real client's own error output and reports which
// blocked packages it attributes the failure to, and which of those arrived without our
// reason attached.
//
// MATCHING IS PER LINE, and that is the whole point. Two looser versions were written
// first and both were wrong:
//
//   - Package name anywhere in the output. The express tree blocks on `debug`, and "debug"
//     occurs in npm's own noise (`...-debug-0.log`, cache paths), so this passes with the
//     gate switched off.
//   - Name anywhere AND "403" anywhere. Still wrong, and it produced a confusing failure:
//     `blocked()` is a map, so iteration order is random, and the helper "attributed" the
//     failure to `debug` (matched on the log filename) while the 403 belonged to
//     `cookie-signature` on a completely different line.
//
// Requiring both on the SAME line ties the refusal to the package the client actually
// failed on. Every attributed package is checked, rather than the first one the map
// yields, so the result does not depend on iteration order.
func (f *firewall) blockSurfacedAtClient(clientOut string) (attributed, missingReason []string) {
	lines := strings.Split(clientOut, "\n")
	for pkg, reason := range f.blocked() {
		for _, line := range lines {
			if !strings.Contains(line, "403") || !strings.Contains(line, pkg) {
				continue
			}
			attributed = append(attributed, pkg)
			if !strings.Contains(line, reason) {
				missingReason = append(missingReason, pkg)
			}
			break
		}
	}
	sort.Strings(attributed)
	sort.Strings(missingReason)
	return attributed, missingReason
}

// startApprovalStub runs a minimal HTTP approval service as a CONTAINER on a
// published port and returns a URL the firewall container can reach it at
// (host.docker.internal:<port>). The override e2e test needs the firewall to consult
// an approval service; now that the firewall is itself a container, that service must
// be container-reachable — a host httptest server on 127.0.0.1 is only reachable from
// the test host's loopback, not from the firewall container (and, on dind, not from
// the separate daemon the firewall runs in).
//
// ⚠️ IT ANSWERS ONLY FOR pkg, AND THAT IS THE FIX, NOT A LIMITATION. Until 2026-09-07 it
// replied with one fixed body to EVERY /v1/decisions query, so a leg needing one package
// allowed and another blocked got both approved and passed while testing nothing. That is
// also what a real service can never do — both stores key on an exact-match TEXT PRIMARY
// KEY — so the old stub was not a simplification of the service, it was a different and
// more permissive thing. A 404 for any other package is what the real one returns, and it
// is what keeps a leg honest.
//
// The firewall now refuses a record whose `package` is not the one it asked about (see
// lookupApproval), so the old fixed-body stub would surface as a stream of "refusing to
// apply another package's ruling" lines and a fall-back to policy, rather than as a silent
// pass. Keeping the stub selective means the e2e legs exercise the same identity contract
// the product enforces.
//
// For a leg that needs several packages with DIFFERENT verdicts, use
// startSelectiveApprovalStub (e2e/adversarial_pypi_test.go). Torn down at test end.
func startApprovalStub(t *testing.T, pkg, verdict string) string {
	t.Helper()
	port := freePort(t)
	name := fmt.Sprintf("yj-e2e-approval-%d", port)
	prog := fmt.Sprintf(`import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
PKG = %q
body = json.dumps({"package": PKG, "verdict": %q}).encode()
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path)
        # Answer ONLY for the package this stub was started for. Any other name gets the
        # 404 the real service returns for "no decision recorded" -- see the comment on
        # startApprovalStub for why a fixed body made legs vacuous.
        if u.path == "/v1/decisions" and parse_qs(u.query).get("package", [""])[0] == PKG:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, *a):
        pass
# Threading, not HTTPServer: since D272 the firewall consults this stub on the ALLOW
# path too, so a leg installing several packages makes several lookups a
# single-threaded server would serialise behind each other.
ThreadingHTTPServer(("", 80), H).serve_forever()`, pkg, verdict)

	args := []string{"run", "-d", "--name", name, "-p", fmt.Sprintf("%d:80", port),
		"python:3.12-slim", "python3", "-c", prog}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("start approval stub: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	// Wait until it answers, so the firewall never races an unready stub (which would
	// look like a connection-refused fall-back to policy). Reached from the test host
	// the same way the firewall's health check is (E2E_FW_HOST).
	url := fmt.Sprintf("http://%s:%d/v1/decisions?package=%s", fwHost(), port, pkg)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(url); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return fmt.Sprintf("http://host.docker.internal:%d", port)
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("approval stub never became ready at %s", url)
	return ""
}

// tail returns the last n lines of s, for readable failure messages.
//
// Prefer logAround for FIREWALL LOGS. A bare tail cannot show the moment of failure
// unless the failure happened at the very end of the run, and it does not say so — see
// logAround's comment for what that cost us (#75).
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// logAround returns at most n lines of s centred on the LAST line matching any anchor,
// with a header saying which window you are looking at.
//
// WHY THIS EXISTS (#75). Failure dumps used to be a bare `tail(log, 25)`. During #68 a
// Maven leg failed on two artifacts and neither appeared in the 25 lines printed — they
// had scrolled off. That left two very different explanations indistinguishable:
//
//   - the proxy refused those artifacts (a real gate bug), or
//   - the proxy never saw them at all (an upstream/network problem).
//
// Both are consistent with "not in the last 25 lines". The absence was absence of
// evidence inside a truncated window, not evidence the proxy behaved — but the output
// looked like a failure dump, so it read as one. That is the same false-confidence shape
// this project keeps digging out: a report that can only say one thing convincingly.
//
// So the header is not decoration. It is the part that makes absence interpretable:
// an anchored window says "here is the failure context", while the fallback says the
// window may simply not contain the failure, and a reader must never have to guess which
// they were handed.
func logAround(s string, n int, anchors ...string) string {
	if n < 1 {
		n = 1
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return "--- log is EMPTY (the firewall wrote nothing) ---"
	}
	// Short enough to show whole: truncation is a readability tool, and a log that fits
	// needs none of it. Saying "full log" removes the ambiguity outright.
	if len(lines) <= n {
		return fmt.Sprintf("--- full log (%d lines) ---\n%s", len(lines), strings.Join(lines, "\n"))
	}

	// Last match, not first: when a package is fetched repeatedly, the interesting event
	// is the one nearest the failure.
	hit, matched := -1, ""
	for i, line := range lines {
		for _, a := range anchors {
			if a != "" && strings.Contains(line, a) {
				hit, matched = i, a
			}
		}
	}
	if hit < 0 {
		why := "no anchor was given"
		if d := describeAnchors(anchors); d != "" {
			why = "no line matched " + d
		}
		return fmt.Sprintf(
			"--- LAST %d of %d lines (%s), so THE FAILURE MAY BE OUTSIDE THIS WINDOW; "+
				"absence here is not evidence ---\n%s",
			n, len(lines), why, strings.Join(lines[len(lines)-n:], "\n"))
	}

	start := hit - n/2
	if start < 0 {
		start = 0
	}
	end := start + n
	if end > len(lines) {
		end = len(lines)
		if start = end - n; start < 0 {
			start = 0
		}
	}
	return fmt.Sprintf("--- %d lines around %q (log line %d of %d) ---\n%s",
		end-start, matched, hit+1, len(lines), strings.Join(lines[start:end], "\n"))
}

func describeAnchors(anchors []string) string {
	var kept []string
	for _, a := range anchors {
		if a != "" {
			kept = append(kept, strconv.Quote(a))
		}
	}
	return strings.Join(kept, " or ")
}

// mavenImage carries mvn, a JDK and keytool -- everything an operator would use.
const mavenImage = "maven:3.9-eclipse-temurin-21"

// lastLine returns the last line containing needle, for a tidy log message.
func lastLine(s, needle string) string {
	found := ""
	for _, ln := range strings.Split(s, "\n") {
		if strings.Contains(ln, needle) {
			found = ln
		}
	}
	return found
}

// craneImage is the debug variant deliberately: the default crane image is DISTROLESS
// (no shell), so under docker-in-docker a leg cannot write the CA into it from an env
// var the way the Go leg does, and a host bind mount does not survive dind. The debug
// image carries a busybox shell; the crane binary is on PATH at /ko-app/crane.
const craneImage = "gcr.io/go-containerregistry/crane:debug"
