//go:build e2e

package e2e

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// D165 through the container: readiness follows the deployed list on a real mount. The
// list rides the credential volume -- a DIRECTORY mount, so a temp-file-and-rename write
// is visible to the gate (a file bind mount would hide the new inode; see
// credVolume.write) -- because the firewall image is distroless and cannot write its
// own files. The orchestrator's view is the status; the operator's is the body.
func TestReadinessTracksTheDeployedList(t *testing.T) {
	bin := buildFirewall(t)
	vol := newCredVolume(t, buildCredWriter(t))
	vol.write(t, "left-pad\n")
	fw := startFirewallWithMounts(t, bin, map[string]string{
		"FW_ECOSYSTEM": "npm",
		// `off`, not `stub`: this leg measures whether readiness tracks the DEPLOYED
		// LIST, and D273 makes `stub` unready in its own right -- leaving it here would
		// mean every probe answered 503 for a reason unrelated to the list it is named for.
		"FW_SCORECARD_MODE":    "off",
		"FW_SCORE_THRESHOLD":   "0",
		"FW_UNSCORABLE_POLICY": "allow",
		"FW_UNVERIFIED_POLICY": "open-with-visibility",
		"FW_VERIFY_REPO":       "false",
		"FW_DENY_LIST":         credMountDir + "/token", // the volume's one file, used as the deny list
	}, []string{vol.mount()})

	get := func(path string) (int, string) {
		t.Helper()
		resp, err := http.Get(fmt.Sprintf("http://%s:%d%s", fwHost(), fw.port, path))
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, strings.TrimSpace(string(b))
	}
	waitFor := func(path string, want int, within time.Duration) (int, string) {
		t.Helper()
		deadline := time.Now().Add(within)
		for {
			st, body := get(path)
			if st == want || time.Now().After(deadline) {
				return st, body
			}
			time.Sleep(250 * time.Millisecond)
		}
	}

	if st, body := get("/readyz"); st != http.StatusOK {
		t.Fatalf("/readyz on the deployed list = %d %q, want 200", st, body)
	}
	if st, body := get("/left-pad"); st != http.StatusForbidden || !strings.Contains(body, "deny list") {
		t.Fatalf("control: the denied package = %d %q, want 403 on the DENY LIST -- the list is not in force", st, body)
	}

	// The mount now holds a list the gate cannot load. Readiness goes red within the
	// re-read interval; the last good list stays in force; liveness stays green.
	//
	// The line was "left-pad@1.0.0" until #155 made a version-scoped DENY entry VALID —
	// at which point this fixture loaded cleanly and the gate stayed ready, which is how
	// CI caught the e2e twin of the unit fixture. Whitespace is malformed in every list,
	// and what this test is about is the unreadable-list path, not which line broke it.
	vol.write(t, "left pad 1.0.0\n")
	st, redBody := waitFor("/readyz", http.StatusServiceUnavailable, 20*time.Second)
	if st != http.StatusServiceUnavailable {
		t.Fatalf("/readyz with an unreadable deny list on the mount = %d %q, want 503 (D165)\n--- firewall ---\n%s",
			st, redBody, tail(fw.log.String(), 20))
	}
	if !strings.Contains(redBody, "deny-list") || !strings.Contains(redBody, "still enforcing the last good list") {
		t.Errorf("/readyz body does not say what is wrong and what is in force: %q", redBody)
	}
	if st, body := get("/left-pad"); st != http.StatusForbidden || !strings.Contains(body, "deny list") {
		t.Errorf("the denied package = %d %q while the list is unreadable, want 403 on the DENY LIST -- the last good list stays in force", st, body)
	}
	if st, _ := get("/healthz"); st != http.StatusOK {
		t.Errorf("/healthz = %d while NOT ready, want 200 -- liveness must not follow readiness", st)
	}

	vol.write(t, "left-pad\n")
	if st, body := waitFor("/readyz", http.StatusOK, 20*time.Second); st != http.StatusOK {
		t.Fatalf("/readyz after the list was fixed = %d %q, want 200", st, body)
	}
	logs := fw.log.String()
	for _, want := range []string{"became unreadable", "readable again"} {
		if !strings.Contains(logs, want) {
			t.Errorf("the transition was not logged (%q):\n%s", want, tail(logs, 20))
		}
	}
	t.Logf("readiness followed the deployed list: 200 -> 503 (%s) -> 200", redBody)
}
