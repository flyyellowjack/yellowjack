//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Zero-egress, observed from OUTSIDE the process (issue #27).
//
// WHY THIS FILE EXISTS. The in-process check (egress_test.go in package main) wraps our own
// dialer, so it can only see connections made through pooledTransport. Two things are
// structurally invisible there, and both are exactly what a phone-home would use: DNS
// itself, and anything that dials without going through our transport — a future
// dependency, cgo, or the Go runtime. That check is the fast leg; this one is the honest
// leg, and the issue is explicit that the honest one is what makes the claim defensible.
//
// THE MECHANISM. Every legitimate destination is configured as an explicit IP, so a
// correct run needs NO name resolution at all. The firewall's --dns is pointed at a
// sinkhole that records every query. A clean run therefore produces an EMPTY query log,
// and any entry in it is a name the firewall wanted that nobody configured.
//
// WHAT IT DOES NOT CATCH: egress to a hard-coded IP literal, which needs no DNS. That
// spelling is what the in-process dialler check DOES see. The two legs are complementary
// by design; neither alone is sufficient, and this is written down here so a future reader
// does not retire one believing the other covers it.

// dockerIP returns a container's address on the default bridge, which is how the firewall
// container reaches the sinkhole and the upstream stand-in without any lookup.
func dockerIP(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("docker", "inspect", "-f",
		"{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).CombinedOutput()
	if err != nil {
		t.Fatalf("inspect %s: %v\n%s", name, err, out)
	}
	ip := strings.TrimSpace(string(out))
	if ip == "" {
		t.Fatalf("container %s has no IP address", name)
	}
	return ip
}

// startDNSSinkhole builds and runs the recorder, returning its IP and a log reader.
func startDNSSinkhole(t *testing.T) (ip string, queries func() []string) {
	t.Helper()
	build := exec.Command("docker", "build", "-f", "e2e/fakedns/Dockerfile", "-t", "yellowjack-fakedns:e2e", ".")
	build.Dir = ".." // repo root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fakedns: %v\n%s", err, out)
	}
	name := fmt.Sprintf("yj-e2e-fakedns-%d", time.Now().UnixNano())
	if out, err := exec.Command("docker", "run", "-d", "--name", name, "yellowjack-fakedns:e2e").CombinedOutput(); err != nil {
		t.Fatalf("start fakedns: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	return dockerIP(t, name), func() []string {
		out, _ := exec.Command("docker", "logs", name).CombinedOutput()
		var names []string
		for _, line := range strings.Split(string(out), "\n") {
			if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "QUERY "); ok {
				names = append(names, rest)
			}
		}
		return names
	}
}

// startUpstreamStub serves the one npm package this scenario pulls. Inline rather than a
// committed fixture because the point here is the NETWORK, not the registry's content.
func startUpstreamStub(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("yj-e2e-egress-upstream-%d", time.Now().UnixNano())
	prog := `import json
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/lodash/latest":
            body = json.dumps({"repository": {"url": "git+https://github.com/lodash/lodash.git"}}).encode()
        elif self.path == "/lodash":
            body = json.dumps({"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {"dist": {"tarball": "http://UPSTREAM/lodash/-/lodash-1.0.0.tgz"}}}}).encode()
        else:
            body = b"\x1f\x8b\x08\x00fake-tarball"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
HTTPServer(("", 80), H).serve_forever()`
	if out, err := exec.Command("docker", "run", "-d", "--name", name,
		"python:3.12-slim", "python3", "-c", prog).CombinedOutput(); err != nil {
		t.Fatalf("start upstream stub: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	return dockerIP(t, name)
}

// startFirewallWithDNS is startFirewallOnPort with the container's resolver pointed at the
// sinkhole. A separate function rather than a parameter on the shared harness helper: only
// this scenario wants a hijacked resolver, and threading a rarely-used knob through the
// helper every other test depends on is how a shared rig acquires footguns.
func startFirewallWithDNS(t *testing.T, image, dnsIP string, env map[string]string) *firewall {
	t.Helper()
	port := freePort(t)
	name := fmt.Sprintf("yj-e2e-egress-%d", port)
	fw := &firewall{port: port, name: name, log: fwLog{name: name}}
	_ = exec.Command("docker", "rm", "-f", name).Run()

	args := []string{"run", "-d", "--name", name,
		"-p", fmt.Sprintf("%d:8080", port),
		"--dns", dnsIP,
		"-e", "FW_LISTEN_ADDR=:8080"}
	for k, v := range env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, image)
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("start firewall: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(fmt.Sprintf("http://%s:%d/healthz", fwHost(), port)); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return fw
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("firewall never became healthy\n%s", fw.log.String())
	return nil
}

// TestFirewallMakesNoUnconfiguredEgress drives a real install path through a firewall whose
// only resolver is a recorder, and asserts it never asked for a name.
func TestFirewallMakesNoUnconfiguredEgress(t *testing.T) {
	bin := buildFirewall(t)
	dnsIP, queries := startDNSSinkhole(t)
	upstreamIP := startUpstreamStub(t)
	upstream := "http://" + upstreamIP + ":80"

	// Every destination is an IP. FW_VERIFY_REPO=false and stub scoring keep deps.dev out
	// of the path entirely — not because a deps.dev lookup would be illegitimate (it is a
	// configured destination), but because it would be a NAME, and this leg's whole
	// discriminator is that a correct run resolves nothing at all. A scenario needing a
	// legitimate lookup would have to allowlist it, which is exactly the kind of exception
	// that later swallows a real finding.
	// The stand-in upstream's packument carries no publish times, so the default cooldown
	// would refuse it before any egress happened (D335). The second gate below keeps the
	// default window: it is the one proving that "on by default" adds no destination.
	fw := startFirewallWithDNS(t, bin, dnsIP, syntheticRegistryDates(map[string]string{
		"FW_ECOSYSTEM":         "npm",
		"FW_UPSTREAM":          upstream,
		"FW_SCORECARD_MODE":    "stub",
		"FW_SCORE_THRESHOLD":   "0",
		"FW_VERIFY_REPO":       "false",
		"FW_UNSCORABLE_POLICY": "allow",
		"FW_UNVERIFIED_POLICY": "open-with-visibility",
		"FW_BYTE_GATE":         "enforce",
	}))

	// Anti-vacuity: the request path must really work. A firewall that 500s before
	// contacting anything also resolves no names, and would pass every assertion below
	// while proving nothing.
	code, body := rawGet(t, fwHost(), fw.port, "/lodash")
	if code != http.StatusOK || !strings.Contains(string(body), "dist-tags") {
		t.Fatalf("control: the metadata request did not succeed (%d, %d bytes) — the scenario never "+
			"exercised the egress path, so 'no lookups' proves nothing\n--- firewall ---\n%s",
			code, len(body), logAround(fw.log.String(), 30, "lodash"))
	}
	if code, _ := rawGet(t, fwHost(), fw.port, "/lodash/-/lodash-1.0.0.tgz"); code != http.StatusOK {
		t.Fatalf("control: the artifact byte path did not succeed (%d)\n--- firewall ---\n%s",
			code, logAround(fw.log.String(), 30, "lodash"))
	}

	// Give any fire-and-forget emission a chance to happen. A telemetry POST would be
	// best-effort and off the request's critical path, so asserting immediately after the
	// response would be the one timing at which it is guaranteed invisible.
	time.Sleep(3 * time.Second)

	if names := queries(); len(names) > 0 {
		t.Errorf("EGRESS VIOLATION: the firewall tried to resolve %v.\n"+
			"Every configured destination in this scenario is an explicit IP, so a correct run "+
			"resolves NOTHING. A name lookup here means the binary wanted to reach a host nobody "+
			"configured — which is the phone-home property #27 exists to rule out.", names)
	} else {
		t.Logf("no DNS queries observed across metadata + artifact + telemetry paths")
	}

	// ── Negative control (required by #27's acceptance).
	//
	// A sinkhole that has only ever reported "no queries" is indistinguishable from one
	// that is broken, misconfigured, or never consulted — and an egress check that cannot
	// go red converts an unknown into false confidence. So run the same scenario with the
	// upstream named rather than addressed: that single change must make the recorder
	// report, proving both that the firewall's resolver really is ours and that the
	// assertion above can fail.
	t.Run("negative control: a named destination IS recorded", func(t *testing.T) {
		fw2 := startFirewallWithDNS(t, bin, dnsIP, map[string]string{
			"FW_ECOSYSTEM":         "npm",
			"FW_UPSTREAM":          "http://upstream-not-configured.test",
			"FW_SCORECARD_MODE":    "stub",
			"FW_SCORE_THRESHOLD":   "0",
			"FW_VERIFY_REPO":       "false",
			"FW_UNSCORABLE_POLICY": "allow",
			"FW_UNVERIFIED_POLICY": "open-with-visibility",
		})
		rawGet(t, fwHost(), fw2.port, "/lodash")
		time.Sleep(2 * time.Second)

		// The same recorder: both firewalls point at it, and it is the thing under test.
		found := false
		for _, n := range queries() {
			if strings.Contains(n, "upstream-not-configured.test") {
				found = true
			}
		}
		if !found {
			t.Fatalf("NEGATIVE CONTROL FAILED: the firewall was configured to reach a HOSTNAME and the "+
				"sinkhole recorded %v — it did not see the lookup. The resolver is not ours, so the "+
				"main assertion's clean result means nothing.", queries())
		}
		t.Logf("negative control: the named destination was recorded, so the sinkhole can fail the test")
	})
}
