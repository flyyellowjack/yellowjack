//go:build e2e

package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// runCranePull pulls an image through the firewall using crane (a scriptable OCI
// client — no dockerd-in-dockerd needed). The firewall speaks plain HTTP, so we
// pass --insecure to make crane use http and skip TLS. We rewrite the reference
// to point registry + repository at the firewall host; crane hits
// "/v2/<name>/manifests/<ref>", which is the single OCI control point the gate
// inspects. Returns crane's exit code and combined output.
func runCranePull(t *testing.T, port int, image string) (int, string) {
	t.Helper()
	ref := fmt.Sprintf("host.docker.internal:%d/%s", port, image)
	cmd := exec.Command("docker", "run", "--rm",
		"--add-host", "host.docker.internal:host-gateway",
		"gcr.io/go-containerregistry/crane:latest",
		"pull", "--insecure", ref, "/tmp/img.tar",
	)
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatalf("could not run docker (is it installed/running?): %v\n%s", err, out)
	}
	return 0, string(out)
}

// TestOciEndToEnd pulls a real image (library/alpine) through the firewall.
//
// OCI is the ecosystem that most exercises the UNSCORABLE branch: deps.dev has no
// container index, so no image ever has a score, and the decision hinges on
// FW_UNSCORABLE_POLICY. That makes the two policies the clean way to isolate behavior:
//   - unscorable=allow: the pull SUCCEEDS (fail-open on a repo we can't score).
//   - unscorable=block: the pull is BLOCKED at the manifest — the gate refusing
//     what it cannot vet.
//
// Both legs run with FW_UNVERIFIED_POLICY=open-with-visibility, and that is
// load-bearing since #33 (D48). alpine DOES declare a source repo
// (github.com/alpinelinux/docker-alpine) — an earlier version of this comment said
// it did not, and the #33 pipeline disproved it — and under the closed default an
// unverifiable claim is refused BEFORE the unscorable policy is consulted. Without
// the override the permissive leg fails, and the fail-closed leg passes for the
// wrong reason (refused as unverified, never reaching unscorable). The closed
// default itself is what oci_unverified_test.go measures; this test isolates the
// unscorable policy, so it lifts the claim and asserts the claim was logged.
func TestOciEndToEnd(t *testing.T) {
	bin := buildFirewall(t)

	t.Run("permissive_allows_unscorable_image", func(t *testing.T) {
		fw := startFirewall(t, bin, map[string]string{
			"FW_ECOSYSTEM":         "oci",
			"FW_SCORECARD_MODE":    "api",
			"FW_SCORE_THRESHOLD":   "0",
			"FW_UNSCORABLE_POLICY": "allow",
			"FW_UNVERIFIED_POLICY": "open-with-visibility",
		})
		code, out := runCranePull(t, fw.port, "library/alpine:3.20")
		if code != 0 {
			t.Fatalf("permissive `crane pull alpine` failed (exit %d)\n%s\n--- firewall ---\n%s",
				code, tail(out, 15), logAround(fw.log.String(), 20))
		}
		if fw.allowedCount() == 0 {
			t.Errorf("expected an allow decision at the manifest, saw none\n%s", fw.log.String())
		}
		// The override is visibility, not silence: the unverifiable claim must be in
		// the log, or this leg is green because verification never ran.
		if !strings.Contains(fw.log.String(), "not indexed by deps.dev (policy=open-with-visibility, proceeding on self-declared repo)") {
			t.Errorf("expected the unverifiable self-declared repo to be logged under open-with-visibility, saw no such line\n%s", fw.log.String())
		}
	})

	t.Run("failclosed_blocks_unscorable_image", func(t *testing.T) {
		fw := startFirewall(t, bin, map[string]string{
			"FW_ECOSYSTEM":         "oci",
			"FW_SCORECARD_MODE":    "api",
			"FW_SCORE_THRESHOLD":   "0",
			"FW_UNSCORABLE_POLICY": "block",
			"FW_UNVERIFIED_POLICY": "open-with-visibility",
		})
		code, _ := runCranePull(t, fw.port, "library/alpine:3.20")
		if code == 0 {
			t.Fatalf("fail-closed `crane pull alpine` unexpectedly succeeded\n--- firewall ---\n%s",
				logAround(fw.log.String(), 30))
		}
		if fw.blockedCount() == 0 {
			t.Errorf("expected a block decision at the manifest, saw none\n%s", fw.log.String())
		}
	})
}
