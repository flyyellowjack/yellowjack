//go:build e2e

package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// #93 question 1 / D164, customer-shaped: a real OCI client pulls a TAG through the gate,
// the tag is moved underneath it on the registry to an image the gate must refuse, and
// the next pull of the same tag must be refused on its FIRST request. The unit tier
// (oci_tagdrift_test.go at the root) measured the gap and the fix against an httptest
// registry; this drives crane against a real registry:2, which answers HEAD with
// Docker-Content-Digest the way the fix relies on.
//
// Before the fix this leg would have PASSED its first pull and then served the moved
// tag on the old approval for the whole FW_SCORE_CACHE_TTL -- the second pull below would
// have exited 0.

// driftRegistryImage is the registry:2 digest docker-compose.registryfront.yml already
// pins, so this file adds no new image to mirror or audit.
const driftRegistryImage = "registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"

// startDriftRegistry runs an empty registry:2 on a free host port, reachable by client
// and gate containers alike as host.docker.internal:<port>.
func startDriftRegistry(t *testing.T) (port int, name string) {
	t.Helper()
	port = freePort(t)
	name = fmt.Sprintf("yj-drift-registry-%d", port)
	_ = exec.Command("docker", "rm", "-f", name).Run()
	out, err := exec.Command("docker", "run", "-d", "--name", name, "-p", fmt.Sprintf("%d:5000", port), driftRegistryImage).CombinedOutput()
	if err != nil {
		t.Fatalf("could not start registry:2: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if code, _ := runClient(t, "docker", "run", "--rm", "--add-host", "host.docker.internal:host-gateway",
			craneImage, "catalog", "--insecure", fmt.Sprintf("host.docker.internal:%d", port)); code == 0 {
			return port, name
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("registry:2 on :%d never answered", port)
	return
}

// crane runs one crane command in a throwaway container against host.docker.internal.
func crane(t *testing.T, args ...string) (int, string) {
	t.Helper()
	full := append([]string{"docker", "run", "--rm", "--add-host", "host.docker.internal:host-gateway", craneImage}, args...)
	return runClient(t, full...)
}

// pushDriftImage builds a from-scratch image with one tiny layer, optionally labelled
// with a source repo, and pushes it to ref DIRECTLY on the registry (not through the
// gate). Returns the digest the registry recorded for it.
func pushDriftImage(t *testing.T, ref, sourceLabel string) string {
	t.Helper()
	// crane append with no --base starts from the empty image; the layer is a tar of
	// one file, built inside the container so nothing is mounted from the host.
	script := `set -e; mkdir -p /w/root && echo drift > /w/root/hello && tar -C /w/root -cf /w/layer.tar hello && ` +
		`crane append --insecure --new_layer /w/layer.tar -t ` + ref
	if sourceLabel != "" {
		script += ` && crane mutate --insecure --label org.opencontainers.image.source=` + sourceLabel + ` -t ` + ref + ` ` + ref
	}
	code, out := runClient(t, "docker", "run", "--rm", "--add-host", "host.docker.internal:host-gateway",
		"--entrypoint", "sh", craneImage, "-c", script)
	if code != 0 {
		t.Fatalf("could not push the drift image %s (exit %d):\n%s", ref, code, out)
	}
	code, out = crane(t, "digest", "--insecure", ref)
	if code != 0 {
		t.Fatalf("crane digest %s failed (exit %d):\n%s", ref, code, out)
	}
	return strings.TrimSpace(out)
}

func TestAMovedTagIsRefusedOnTheFirstPullByARealClient(t *testing.T) {
	bin := buildFirewall(t)
	regPort, _ := startDriftRegistry(t)
	const image = "acme/drifter"
	direct := fmt.Sprintf("host.docker.internal:%d/%s:latest", regPort, image)

	// 1. The tag points at an image that declares a source repo: stub-scored 7.5, allowed
	//    at a 5.0 threshold.
	goodDigest := pushDriftImage(t, direct, "https://github.com/acme/drifter")

	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":         "oci",
		"FW_UPSTREAM":          fmt.Sprintf("http://host.docker.internal:%d", regPort),
		"FW_SCORECARD_MODE":    "stub",
		"FW_SCORE_THRESHOLD":   "5",
		"FW_UNSCORABLE_POLICY": "block",
		"FW_UNVERIFIED_POLICY": "open-with-visibility",
		// The shipped default cache TTL, one hour: the window #93 measured. Left at the
		// default on purpose, because a shortened TTL is exactly the wrong repair.
	})
	defer fw.stop()

	// 2. ANTI-VACUITY: the good image pulls through the gate.
	code, out := runCranePull(t, fw.port, image+":latest")
	if code != 0 {
		t.Fatalf("pre-drift pull of %s:latest failed (exit %d); the allowed state must be real or this leg measures nothing.\n%s\n--- gate ---\n%s",
			image, code, tail(out, 15), tail(fw.log.String(), 15))
	}
	if !strings.Contains(fw.log.String(), "allowed=true") {
		t.Fatalf("crane exited 0 but the gate logged no allow: the pull did not go through the gate.\n%s", tail(fw.log.String(), 15))
	}

	// 3. THE TAG MOVES, directly on the registry, to an image with NO source label
	//    (unscorable, and the policy is block).
	badDigest := pushDriftImage(t, direct, "")
	if badDigest == goodDigest {
		t.Fatalf("the second push produced the same digest as the first (%s); the tag did not move", badDigest)
	}

	// 4. THE MEASUREMENT: the same tag, same warm gate, first pull after the move.
	code, out = runCranePull(t, fw.port, image+":latest")
	t.Logf("first pull after the tag moved: crane exit=%d", code)
	if code == 0 {
		t.Fatalf("the moved tag was SERVED on the first pull after the move: a cached verdict for %s is "+
			"answering for an image it never judged (the #93 gap).\n%s\n--- gate ---\n%s", goodDigest, tail(out, 15), tail(fw.log.String(), 20))
	}
	// crane prints the distribution-spec error BODY, which carries our reason (that is
	// what makes crane legible on #79); the status number itself is not printed.
	if !strings.Contains(out, "blocked by firewall") || !strings.Contains(out, "unscorable") {
		t.Errorf("crane failed, but not with our refusal naming the moved tag unscorable; this is not the "+
			"refusal the leg is about.\n%s", tail(out, 15))
	}
	if !strings.Contains(fw.log.String(), "unscorable") {
		t.Errorf("the gate's log does not show the moved tag refused as unscorable.\n%s", tail(fw.log.String(), 20))
	}

	// 5. DISCRIMINATOR: the OLD image, pulled by its DIGEST, is still allowed. The tag
	//    moved; the bytes it used to name did not. If this fails, the gate is refusing
	//    everything rather than revalidating the tag.
	code, out = runCranePull(t, fw.port, image+"@"+goodDigest)
	if code != 0 {
		t.Errorf("the old image by digest (%s) was refused (exit %d) after the tag moved; the gate is not "+
			"discriminating the moved tag from its former content.\n%s", goodDigest, code, tail(out, 15))
	}
}
