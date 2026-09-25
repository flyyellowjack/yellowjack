//go:build e2e

package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A version-pinned known-malware advisory for PyPI, against an EXACT pin from real pip.
//
// PyPI's per-version enforcement was an index YANK (PEP 592): the named release is marked
// yanked with the advisory as its reason. That steers an ordinary `pip install six` away
// from it. It does not stop `pip install six==<that version>`: PEP 592 tells installers
// to ignore a yanked file UNLESS the requirement pins that exact version, and pip does
// exactly that. So the bytes have to be refused at the file fetch, where the version is
// known -- the rule npm's tarball path and Maven's request path already apply.
//
// npm has had this leg ("an explicit request for the refused version does not install
// it", npm_versionfilter_test.go) since #35. PyPI never did, which is how the gap stayed
// open: the index test passed, and nothing asked what an exact pin fetched.

const (
	pinPkg      = "six"
	pinBad      = "1.16.0" // named by the advisory below
	pinGood     = "1.17.0" // its sibling release: must still install
	pinAdvisory = "MAL-E2E-PYPI-EXACT-PIN"
	pinFeedDir  = "/etc/yellowjack/feed"
)

// pinFeedVolume writes a one-line feed naming six==1.16.0 into a docker volume the
// firewall mounts read-only (a volume, not a file bind mount: see feedVolume).
func pinFeedVolume(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("yj-e2e-pinfeed-%d", time.Now().UnixNano())
	if out, err := exec.Command("docker", "volume", "create", name).CombinedOutput(); err != nil {
		t.Fatalf("create feed volume: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "volume", "rm", "-f", name).Run() })
	line := fmt.Sprintf(`{"id":%q,"ecosystem":"pypi","name":%q,"versions":[%q]}`, pinAdvisory, pinPkg, pinBad)
	script := "printf '%s\\n' " + shellQuote(line) + " > " + pinFeedDir + "/malware.jsonl"
	if out, err := exec.Command("docker", "run", "--rm", "-v", name+":"+pinFeedDir, "busybox", "sh", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("write feed: %v\n%s", err, out)
	}
	return name
}

// pipInstallExact installs one requirement through the gate and reports which version
// landed, so the test asserts what the DEVELOPER got.
func pipInstallExact(t *testing.T, port int, requirement string) (int, string) {
	t.Helper()
	script := "pip install --no-cache-dir --disable-pip-version-check --target /tmp/s '" + requirement + "' && " +
		"echo RESOLVED=$(ls /tmp/s | sed -n 's/^six-\\(.*\\)\\.dist-info$/\\1/p')"
	return runClient(t, "docker", "run", "--rm",
		"--add-host", "host.docker.internal:host-gateway",
		"-e", fmt.Sprintf("PIP_INDEX_URL=http://host.docker.internal:%d/simple/", port),
		"-e", "PIP_TRUSTED_HOST=host.docker.internal",
		"python:3.12-slim", "sh", "-c", script)
}

func TestPypiExactPinOfAnAdvisoryVersionIsRefused(t *testing.T) {
	bin := buildFirewall(t)

	// CONTROL: no feed, same exact pin. It must INSTALL, or the refusal below could be
	// the rig (a missing trusted-host, an unreachable index) rather than the advisory.
	t.Run("control: without the feed, the exact pin installs", func(t *testing.T) {
		fw := startFirewall(t, bin, permissiveEnv("pypi", nil))
		defer fw.stop()
		code, out := pipInstallExact(t, fw.port, pinPkg+"=="+pinBad)
		if code != 0 || !strings.Contains(out, "RESOLVED="+pinBad) {
			t.Fatalf("control: pip could not install %s==%s through a gate with NO feed (exit %d); the rig is "+
				"broken and the legs below would prove nothing\n%s\n--- gate ---\n%s", pinPkg, pinBad, code, tail(out, 20), tail(fw.log.String(), 20))
		}
		mustHaveReachedTheGate(t, fw, pinPkg, "pip")
	})

	vol := pinFeedVolume(t)
	env := permissiveEnv("pypi", map[string]string{"FW_MALWARE_LIST": pinFeedDir + "/malware.jsonl"})
	fw := startFirewallWithMounts(t, bin, env, []string{vol + ":" + pinFeedDir + ":ro"})
	defer fw.stop()

	t.Run("the exact pin of the advisory's version does not install", func(t *testing.T) {
		code, out := pipInstallExact(t, fw.port, pinPkg+"=="+pinBad)
		mustHaveReachedTheGate(t, fw, pinPkg, "pip")
		if code == 0 {
			t.Fatalf("pip INSTALLED %s==%s past a version-pinned known-malware advisory (%s). The index marked it "+
				"yanked, and an exact pin selects a yanked file anyway (PEP 592), so the bytes must be refused at the "+
				"file fetch.\n%s\n--- gate ---\n%s", pinPkg, pinBad, pinAdvisory, tail(out, 20), logAround(fw.log.String(), 30, "_files", pinAdvisory))
		}
		// The REASON: the refusal must be ours, at the file, naming the advisory. Without
		// this a failure for any other cause (network, a pip change) would read as a pass.
		if !strings.Contains(fw.log.String(), "_files [known-malware] "+pinPkg) || !strings.Contains(fw.log.String(), pinAdvisory) {
			t.Errorf("pip failed, but the gate's log does not show the FILE refused as known malware naming %s; this "+
				"is not the refusal the leg is about.\n--- pip ---\n%s\n--- gate ---\n%s", pinAdvisory, tail(out, 15), tail(fw.log.String(), 30))
		}
		if !strings.Contains(out, "403") {
			t.Errorf("pip failed without reporting a 403 from the gate:\n%s", tail(out, 15))
		}
	})

	// DISCRIMINATOR: the sibling release of the same package still installs, so the leg
	// above is the advisory refusing ONE release and not the gate refusing six.
	t.Run("the sibling release still installs", func(t *testing.T) {
		code, out := pipInstallExact(t, fw.port, pinPkg+"=="+pinGood)
		if code != 0 || !strings.Contains(out, "RESOLVED="+pinGood) {
			t.Fatalf("pip could not install the CLEAN sibling %s==%s (exit %d): the advisory is refusing more than "+
				"the release it names\n%s\n--- gate ---\n%s", pinPkg, pinGood, code, tail(out, 20), tail(fw.log.String(), 20))
		}
	})
}
