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

// Issue #22 part 1, as an assertion instead of a claim.
//
// The Dockerfile already does the right things — distroless/static:nonroot, a static
// binary, USER nonroot, no shell — and the README describes the image as
// "read-only-rootfs-friendly, requires no writable host directory". That description is
// the kind of thing that is true until someone adds a cache file, a scratch directory or
// a temp download and nobody notices, because nothing in CI ever ran the container the
// hardened way.
//
// This runs it the hardened way. It is the deployment posture #22 cites incumbents
// failing at repeatedly: JFrog's charts could not start under OpenShift's restricted SCC
// across four separate issues, and the 2018-era "directory is not writable" reports were
// the same defect five years earlier. D133 puts the customer's deployment security on the
// customer — but it also keeps the DOCKERFILE and how the image behaves on us, so
// "deployable inside a restricted environment" is ours to prove.

// hardened starts the firewall image with extra docker flags and reports whether it
// became healthy. Deliberately NOT a change to startFirewallOnPort: the shared harness is
// used by every other e2e leg, and this needs to vary exactly the flags that harness
// fixes.
func hardened(t *testing.T, image string, extra []string, env map[string]string) (healthy bool, logs string) {
	t.Helper()
	port := freePort(t)
	name := fmt.Sprintf("yj-harden-%d", port)
	_ = exec.Command("docker", "rm", "-f", name).Run()

	args := []string{"run", "-d", "--name", name,
		"-p", fmt.Sprintf("%d:8080", port),
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "FW_LISTEN_ADDR=:8080"}
	args = append(args, extra...)
	for k, v := range env {
		args = append(args, "-e", k+"="+v)
	}
	args = append(args, image)

	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		// A refusal to CREATE the container is a legitimate failure of this test, not an
		// infrastructure error: it means the image cannot run in this posture at all.
		return false, fmt.Sprintf("docker run failed: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	url := fmt.Sprintf("http://%s:%d/healthz", fwHost(), port)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(url); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true, ""
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	out, _ := exec.Command("docker", "logs", name).CombinedOutput()
	return false, string(out)
}

// TestContainerRunsUnderHardenedDeployment is the assertion.
//
// Each posture is one a real operator (or a platform) imposes, and each has a named
// incumbent failure behind it rather than being hardening theatre.
func TestContainerRunsUnderHardenedDeployment(t *testing.T) {
	image := buildFirewall(t)
	env := map[string]string{
		"FW_ECOSYSTEM":      "npm",
		"FW_SCORECARD_MODE": "stub",
	}

	for _, tc := range []struct {
		name  string
		extra []string
		why   string
	}{
		{
			"read-only root filesystem",
			[]string{"--read-only"},
			"the image must need no writable location anywhere in its own filesystem",
		},
		{
			"read-only, all capabilities dropped, no new privileges",
			[]string{"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges"},
			"a gate that needs Linux capabilities to serve HTTP is holding something it should not",
		},
		{
			"OpenShift-style arbitrary UID with GID 0",
			[]string{"--read-only", "--user", "12345:0", "--cap-drop", "ALL"},
			"OpenShift's restricted SCC assigns an arbitrary UID with group 0. This is the exact " +
				"posture that broke JFrog's charts in issues 1910 and 1938 — an image that only " +
				"works as ITS OWN baked-in user does not deploy there",
		},
		{
			"no writable host directory mounted",
			[]string{"--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m"},
			"if /tmp is the only writable place and it is tiny, noexec and ephemeral, nothing " +
				"durable is being written — the stateless claim in CLAUDE.md, tested rather than asserted",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, logs := hardened(t, image, tc.extra, env)
			if !ok {
				t.Errorf("the firewall did not become healthy under %v.\nWHY THIS MATTERS: %s\n--- container ---\n%s",
					tc.extra, tc.why, logs)
			}
		})
	}
}

// TestImageDoesNotRunAsRoot pins the property separately from the postures above,
// because a container can be perfectly healthy AND running as uid 0.
func TestImageDoesNotRunAsRoot(t *testing.T) {
	image := buildFirewall(t)
	out, err := exec.Command("docker", "inspect", "-f", "{{.Config.User}}", image).CombinedOutput()
	if err != nil {
		t.Fatalf("docker inspect: %v\n%s", err, out)
	}
	user := strings.TrimSpace(string(out))
	if user == "" || user == "root" || strings.HasPrefix(user, "0:") || user == "0" {
		t.Errorf("image runs as %q — the base image's :nonroot tag or the USER line was lost. "+
			"Every incumbent failure cited in #22 starts here.", user)
	}
	t.Logf("image user: %q", user)
}

// TestReadOnlyFlagIsActuallyApplied is the NEGATIVE CONTROL, and without it the test
// above is worth very little.
//
// Everything in TestContainerRunsUnderHardenedDeployment passes if `--read-only` is
// silently doing nothing — a flag dropped while editing the args slice, a docker version
// that ignores it, a dind daemon configured oddly. The observable result is identical: a
// healthy container. So the constraint itself is verified against a container that MUST
// fail under it.
//
// busybox is used rather than our own image because our image has no shell to attempt a
// write with — which is a virtue of the image and an obstacle to testing the flag.
func TestReadOnlyFlagIsActuallyApplied(t *testing.T) {
	// Sanity first: the same write must SUCCEED without the flag, or "it failed" proves
	// nothing about read-only — the image could simply be broken or the path unwritable.
	out, err := exec.Command("docker", "run", "--rm", "busybox:1.36",
		"sh", "-c", "echo x > /control-probe").CombinedOutput()
	if err != nil {
		t.Fatalf("control: writing to / FAILED even without --read-only (%v)\n%s\n"+
			"The negative control cannot distinguish 'read-only works' from 'writes never work here'.",
			err, out)
	}

	// Now the same command WITH the flag must fail.
	out, err = exec.Command("docker", "run", "--rm", "--read-only", "busybox:1.36",
		"sh", "-c", "echo x > /readonly-probe").CombinedOutput()
	if err == nil {
		t.Errorf("--read-only did NOT prevent a write to /. The flag is not being enforced by this "+
			"docker daemon, so TestContainerRunsUnderHardenedDeployment is passing without "+
			"testing anything.\n%s", out)
	}
}
