//go:build e2e

package e2e

import (
	"os/exec"
	"strings"
	"testing"
)

// Helpers shared by several legs, kept apart from any one rig so a leg can be
// removed without taking helpers other legs use.

// countOciBlobs reports how many blob requests crossed the interception point. A blob may
// be served by a redirect target (Docker Hub 302s layers to a CDN), which the rig also
// terminates, so the path -- not the host -- is what identifies it.
func countOciBlobs(seen []string) int {
	n := 0
	for _, s := range seen {
		if strings.Contains(s, "/blobs/") {
			n++
		}
	}
	return n
}

func craneOK(out string) bool { return strings.Contains(out, "CRANE_EXIT=0") }

func countOciManifests(seen []string) int {
	n := 0
	for _, s := range seen {
		if strings.Contains(s, "/manifests/") {
			n++
		}
	}
	return n
}

// craneThroughMitm runs one crane pull in a throwaway container with the interception
// proxy in the path, optionally trusting the rig's CA via SSL_CERT_FILE. Mirrors
// goThroughMitm: crane is Go, so the trust mechanism is the same variable.
func craneThroughMitm(t *testing.T, proxyURL string, caPEM []byte, trustCA bool, ref string) (int, string) {
	t.Helper()
	script := "crane pull " + ref + " /tmp/img.tar 2>&1; echo \"CRANE_EXIT=$?\""
	if trustCA {
		script = "printf '%s' \"$YJ_CA_PEM\" > /tmp/ca.pem && export SSL_CERT_FILE=/tmp/ca.pem && " + script
	}
	args := []string{"run", "--rm",
		"--add-host", "host.docker.internal:host-gateway",
		"--entrypoint", "sh",
		"-e", "HTTPS_PROXY=" + proxyURL,
		"-e", "https_proxy=" + proxyURL,
		"-e", "YJ_CA_PEM=" + string(caPEM),
		craneImage, "-c", script,
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatalf("could not run docker (is it installed/running?): %v\n%s", err, out)
	}
	return 0, string(out)
}

// ociImageRepo is a real Docker Hub repository. Both digests below live under it, so a
// manifest swap between them keeps every blob request resolvable (blobs are namespaced
// by repository, content-addressed within it).
const ociImageRepo = "registry-1.docker.io/library/alpine"

// ociReal320Amd64 is alpine 3.20's amd64 manifest digest -- what an operator pins.
// ociSub319Amd64 is alpine 3.19.9's amd64 manifest digest -- the substitute the rig
// serves in its place. Neither is a tag, so neither drifts.
const ociReal320Amd64 = "sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e"

// reasonLine returns the first line naming needle, trimmed. The point of recording it
// is the standing lesson that an exit code is shared by the success case and an
// impostor: what makes a control a control is that the REASON is the expected one, and
// a reason worth asserting is worth printing so a human can read it in the log.
func reasonLine(s, needle string) string {
	for _, ln := range strings.Split(s, "\n") {
		if strings.Contains(strings.ToLower(ln), needle) {
			return strings.TrimSpace(ln)
		}
	}
	return "(none found)"
}

// uvImage carries both clients: it is a python image with uv preinstalled, so pip and uv
// are exercised on the SAME base and any difference between them is the tool rather than
// the distro's certificate layout.
const uvImage = "ghcr.io/astral-sh/uv:python3.12-alpine"
