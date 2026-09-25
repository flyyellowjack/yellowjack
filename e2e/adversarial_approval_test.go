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

// Adversarial: a FORGING approval service must not open the gate.
//
// THE THREAT. The firewall asks the approval service "has a human ruled on X?" and, until
// 2026-09-07, applied whatever record came back without checking it was about X. Anything
// that can answer that request — a compromised or misconfigured control plane, a mis-keyed
// cache or proxy in front of it, a replaced implementation — could therefore hand back one
// approval and have it apply to EVERY package the firewall asked about. The query string
// said what was asked; nothing said what came back. That is the confused-deputy shape of
// issue #67 one layer up, and it is the same class of defect as borrow-a-score (#10/D33),
// arriving through our own control plane rather than through publisher metadata.
//
// WHY THIS IS A CREDIBLE FIXTURE AND NOT A STRAW MAN: the forging stub below is a verbatim
// copy of what `startApprovalStub` in e2e/harness.go DID until this change — one fixed body
// for every query. The helper we shipped as a test fixture was, behaviourally, the attack.
// That is also why the defect survived: every leg using it passed.
//
// Both legs are required. The first alone is satisfied by a firewall whose approval service
// is simply unreachable — "blocked" is the default here — so the second proves an HONEST
// approval for the SAME package still opens the gate, and therefore that leg one's refusal
// is the identity check and nothing else.

// startForgingApprovalStub answers EVERY /v1/decisions query with an approval recorded
// against `claim`, whatever was actually asked for.
func startForgingApprovalStub(t *testing.T, claim string) string {
	t.Helper()
	port := freePort(t)
	name := fmt.Sprintf("yj-e2e-forgeapproval-%d", port)
	prog := fmt.Sprintf(`import json
from http.server import BaseHTTPRequestHandler, HTTPServer
body = json.dumps({"package": %q, "verdict": "approved"}).encode()
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/v1/decisions"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, *a):
        pass
HTTPServer(("", 80), H).serve_forever()`, claim)

	args := []string{"run", "-d", "--name", name, "-p", fmt.Sprintf("%d:80", port),
		"python:3.12-slim", "python3", "-c", prog}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("start forging approval stub: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	url := fmt.Sprintf("http://%s:%d/v1/decisions?package=anything", fwHost(), port)
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
	t.Fatalf("forging approval stub never became ready at %s", url)
	return ""
}

func TestAdversarialForgedApprovalCannotOpenTheGate(t *testing.T) {
	bin := buildFirewall(t)

	// A posture where policy blocks EVERYTHING deterministically: the stub scorer returns
	// a flat 7.5 and the threshold is above it. So the ONLY thing that could produce a 200
	// is a human override — which is exactly the lever the forged record is reaching for.
	blockEverything := func(approvalURL string) map[string]string {
		return map[string]string{
			"FW_ECOSYSTEM":         "npm",
			"FW_SCORECARD_MODE":    "stub",
			"FW_SCORE_THRESHOLD":   "8.0",
			"FW_UNSCORABLE_POLICY": "block",
			"FW_APPROVAL_URL":      approvalURL,
		}
	}

	t.Run("forged_approval_is_refused", func(t *testing.T) {
		fw := startFirewall(t, bin, blockEverything(startForgingApprovalStub(t, "some-other-package")))

		code, body := rawGet(t, fwHost(), fw.port, "/lodash")
		if code == http.StatusOK {
			t.Fatalf("FORGED APPROVAL OPENED THE GATE: GET /lodash returned 200 (%d bytes) because the approval "+
				"service answered with a record for \"some-other-package\". One forged record would unblock every "+
				"package the firewall asks about.\n--- firewall ---\n%s",
				len(body), logAround(fw.log.String(), 25, "approval"))
		}
		if code != http.StatusForbidden {
			t.Errorf("GET /lodash returned %d, want 403 — a refusal for some other reason does not demonstrate the identity check", code)
		}

		// The operator has to be able to SEE that the control plane is misbehaving.
		// A silently-discarded forged record is indistinguishable from "no ruling recorded".
		if !strings.Contains(fw.log.String(), "another package's ruling") {
			t.Errorf("the firewall never logged that it refused a foreign approval record, so a compromised or "+
				"mis-keyed control plane is invisible to whoever operates this\n--- firewall ---\n%s",
				logAround(fw.log.String(), 25, "approval"))
		}
	})

	t.Run("honest_approval_still_opens_it", func(t *testing.T) {
		// THE DISCRIMINATOR. Everything asserted above is also true of a firewall that
		// cannot reach its approval service at all, or that ignores approvals entirely.
		// The same package, the same posture, the same stub shape — only the identity is
		// honest — must be ALLOWED.
		fw := startFirewall(t, bin, blockEverything(startApprovalStub(t, "lodash", "approved")))

		code, _ := rawGet(t, fwHost(), fw.port, "/lodash")
		if code != http.StatusOK {
			t.Fatalf("control: an HONEST approval for lodash returned %d, want 200. The override path is not "+
				"working in this configuration, so the refusal in the leg above proves nothing about identity "+
				"checking.\n--- firewall ---\n%s", code, logAround(fw.log.String(), 25, "approval"))
		}
	})
}
