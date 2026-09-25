//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"os/exec"
	"testing"
	"time"
)

// Every block must be self-serve clearable, and the CLIENT must see the clear (#20).
//
// WHY THIS IS THE PROPERTY THAT MATTERS. Field research (r/devops, "Does anyone actually
// check npm packages before installing them?", 67 comments) found high tolerance for false
// positives — the author's own scanner false-positived on `torch` and `tensorflow`, and his
// entire reaction was "but whatever just whitelist those". Three other operators in the same
// thread describe maintaining their own allowlist and call it "simple, and works well".
//
// So what gets a blocking product ripped out is not the false positive. It is being STUCK
// behind one with no way to clear it without contacting the vendor. That reframes the
// requirement from "never false-positive" — unachievable, and not what operators are asking
// for — to "every block is clearable by the operator, without us."
//
// # The failure this actually hunts
//
// A clear that succeeds SERVER-SIDE while the client stays broken. The gate caches: an L1
// score cache, a verdict resolved per request, and package managers that memoise 4xx
// responses. Any of those can keep a package blocked after the operator has approved it,
// and the operator's next move is to conclude the override does not work.
//
// That is invisible to an API-level test — the approval record is right, the decision
// endpoint returns "approved", every server-side assertion passes — and only a REAL CLIENT
// pulling again can see it. Hence e2e.
//
// # Scope
//
// This asserts the FIREWALL honours a cleared verdict on the next pull. It deliberately does
// NOT test the console UI that writes the record: #20 says the override *mechanism* is out of
// scope (console per D19b, config, or the Phase-3 workflow), only that whatever path exists
// actually unblocks the client. The write path is `console/server.go handleOverride`; the
// read path is what runs here.

// startFlippableApprovalStub is startApprovalStub with a verdict that can be CHANGED while
// the firewall is running — which is the whole experiment. A fixed-verdict stub can show a
// package blocked, or approved, but never the TRANSITION, and the transition is where a
// stale cached verdict would hide.
//
// Returns the URL the firewall should use, plus a flip function.
func startFlippableApprovalStub(t *testing.T, initial string) (string, func(t *testing.T, verdict string)) {
	t.Helper()
	port := freePort(t)
	name := fmt.Sprintf("yj-e2e-flipapproval-%d", port)

	// The verdict lives in a one-element list so the handler can rebind it. "/_set?v=..."
	// is the control channel; it is deliberately NOT under /v1/ so it cannot be confused
	// with the decision API the firewall reads.
	prog := fmt.Sprintf(`import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
verdict = [%q]
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/_set":
            verdict[0] = (parse_qs(u.query).get("v") or ["denied"])[0]
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok"); return
        if u.path.startswith("/v1/decisions"):
            q = (parse_qs(u.query).get("package") or [""])[0]
            body = json.dumps({"package": q, "verdict": verdict[0]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body); return
        self.send_response(404); self.end_headers()
    def log_message(self, *a):
        pass
HTTPServer(("", 80), H).serve_forever()`, initial)

	args := []string{"run", "-d", "--name", name, "-p", fmt.Sprintf("%d:80", port),
		"python:3.12-slim", "python3", "-c", prog}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("start flippable approval stub: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	probe := fmt.Sprintf("http://%s:%d/v1/decisions?package=probe", fwHost(), port)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(probe); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return fmt.Sprintf("http://host.docker.internal:%d", port),
					func(t *testing.T, verdict string) {
						t.Helper()
						url := fmt.Sprintf("http://%s:%d/_set?v=%s", fwHost(), port, verdict)
						resp, err := http.Get(url)
						if err != nil {
							t.Fatalf("flip approval stub to %q: %v", verdict, err)
						}
						resp.Body.Close()
					}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("flippable approval stub never became ready at %s", probe)
	return "", nil
}

// TestBlockedPackageIsClearableAndTheClientSeesIt drives each real client twice: once while
// the package is denied, once after the operator has cleared it.
func TestBlockedPackageIsClearableAndTheClientSeesIt(t *testing.T) {
	bin := buildFirewall(t)

	for _, leg := range blockReasonLegs() {
		t.Run(leg.name, func(t *testing.T) {
			approvalURL, flip := startFlippableApprovalStub(t, "denied")

			env := map[string]string{}
			for k, v := range leg.env {
				env[k] = v
			}
			// The approval service is the ONLY thing that can open a package here: the
			// threshold is above the flat stub score, so nothing passes on its merits and
			// a success after the flip cannot be a scoring coincidence.
			env["FW_APPROVAL_URL"] = approvalURL

			fw := startFirewall(t, bin, env)

			// BEFORE: the negative control, and it must run first. Without it, a success
			// after the flip proves nothing — the package might never have been blocked.
			if code, out := leg.run(t, fw.port); code == 0 {
				t.Fatalf("%s installed BEFORE the operator cleared anything — the package was never "+
					"blocked, so this test cannot observe a clear\n%s\n--- firewall ---\n%s",
					leg.name, tail(out, 20), logAround(fw.log.String(), 25, "denied", "blocked"))
			}
			t.Logf("%s: blocked before the clear, as required", leg.name)

			// The operator clears it. In production this is console/handleOverride writing an
			// approval record; here it is the same record arriving by the same read path.
			flip(t, "approved")

			// AFTER: the assertion #20 exists for. A server-side clear that the client never
			// sees is indistinguishable, from the operator's chair, from an override that
			// does not work.
			code, out := leg.run(t, fw.port)
			if code != 0 {
				t.Errorf("CLEAR DID NOT REACH THE CLIENT: %s still fails (exit %d) after the package "+
					"was approved. The operator did everything right and the developer is still "+
					"blocked — a cached verdict, a memoised 4xx, or a score cache is holding the "+
					"old decision (#20).\n--- what the developer saw ---\n%s\n--- firewall ---\n%s",
					leg.name, code, tail(out, 25), logAround(fw.log.String(), 30, "approved", "denied"))
				return
			}
			t.Logf("%s: cleared — the next pull succeeded", leg.name)
		})
	}
}
