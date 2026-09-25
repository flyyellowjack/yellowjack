//go:build e2e

package e2e

import (
	"fmt"
	"os/exec"
	"testing"
)

// runUvInstall drives uv against the same PEP 503 index pip gets, so any difference
// between the two legs is the TOOL and not the rig.
//
// uvImage (declared in tls_trust_python_test.go) is already this suite's uv client, which
// is deliberate: adding a second uv image would make a divergence between the two legs
// ambiguous between the tool and the base image.
//
// --index-url rather than PIP_INDEX_URL: uv reads its own env, and passing the flag keeps
// the leg from silently resolving against PyPI if that name ever changes. --system because
// the image has no venv, and no --index-strategy: that flag SUPPRESSES uv's 403 hint, and
// a leg measuring what a developer sees must not be run under a flag that edits the output
// (found while measuring #79 — the first sweep carried it and read the 403 case wrong).
func runUvInstall(t *testing.T, port int, pkg string) (int, string) {
	t.Helper()
	index := fmt.Sprintf("http://host.docker.internal:%d/simple/", port)
	cmd := exec.Command("docker", "run", "--rm",
		"--add-host", "host.docker.internal:host-gateway",
		uvImage,
		"uv", "pip", "install", "--system", "--no-cache", "--index-url", index, pkg,
	)
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatalf("could not run docker (is it installed/running?): %v\n%s", err, out)
	}
	return 0, string(out)
}

// runPipInstall runs `pip install <pkg>` inside a throwaway python container,
// pointed (via PIP_* env, so no mounted files) at the firewall on the host as its
// PEP 503 "simple" index. We use python:3.12-slim (glibc) rather than -alpine so
// pip can install the manylinux wheels real packages ship; an alpine (musl) image
// would force source builds and muddy the signal. PIP_TRUSTED_HOST is required
// because the proxy speaks plain HTTP and pip refuses an http index otherwise.
// --target installs into a throwaway dir so we need neither a venv nor root, and
// --no-cache-dir guarantees every metadata + wheel request actually traverses the
// proxy instead of being served from a warm cache.
func runPipInstall(t *testing.T, port int, pkg string) (int, string) {
	t.Helper()
	index := fmt.Sprintf("http://host.docker.internal:%d/simple/", port)
	cmd := exec.Command("docker", "run", "--rm",
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "PIP_INDEX_URL="+index,
		"-e", "PIP_TRUSTED_HOST=host.docker.internal",
		"-e", "PIP_DISABLE_PIP_VERSION_CHECK=1",
		"python:3.12-slim",
		"pip", "install", "--no-cache-dir", "--target", "/tmp/site", pkg,
	)
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatalf("could not run docker (is it installed/running?): %v\n%s", err, out)
	}
	return 0, string(out)
}

// TestPypiEndToEnd pulls a real package (requests, with its transitive tree)
// through the firewall under two policies, isolating the policy effect:
//   - permissive (threshold 0, fail-open): the install SUCCEEDS through the gate.
//   - fail-closed (threshold 9.9, block): with an unreachable threshold EVERY
//     scorable package is blocked, so pip fails — the gate doing its job. We use
//     9.9 rather than betting a specific dependency scores low, so the assertion
//     doesn't drift as scores change over time.
func TestPypiEndToEnd(t *testing.T) {
	bin := buildFirewall(t)

	t.Run("permissive_allows_real_install", func(t *testing.T) {
		fw := startFirewall(t, bin, map[string]string{
			"FW_ECOSYSTEM":       "pypi",
			"FW_SCORECARD_MODE":  "api",
			"FW_SCORE_THRESHOLD": "0",
			// Both fail-open knobs: as of D36 the unverified posture is a second,
			// independent fail-closed default, so "permissive" must relax it too or
			// this leg starts depending on deps.dev's repo-mapping coverage for
			// requests' tree rather than on the policy under test.
			"FW_UNSCORABLE_POLICY": "allow",
			"FW_UNVERIFIED_POLICY": "open-with-visibility",
		})
		code, out := runPipInstall(t, fw.port, "requests")
		if code != 0 {
			t.Fatalf("permissive `pip install requests` failed (exit %d)\n%s\n--- firewall ---\n%s",
				code, tail(out, 15), logAround(fw.log.String(), 20))
		}
		if fw.allowedCount() == 0 {
			t.Errorf("expected allow decisions through the gate, saw none\n%s", fw.log.String())
		}
	})

	t.Run("failclosed_blocks_scored_pkg", func(t *testing.T) {
		fw := startFirewall(t, bin, map[string]string{
			"FW_ECOSYSTEM":         "pypi",
			"FW_SCORECARD_MODE":    "api",
			"FW_SCORE_THRESHOLD":   "9.9",
			"FW_UNSCORABLE_POLICY": "block",
		})
		code, _ := runPipInstall(t, fw.port, "requests")
		if code == 0 {
			t.Fatalf("fail-closed `pip install requests` unexpectedly succeeded\n--- firewall ---\n%s",
				logAround(fw.log.String(), 30))
		}
		if fw.blockedCount() == 0 {
			t.Errorf("expected at least one block decision, saw none\n%s", fw.log.String())
		}
	})
}

// TestPypiPinnedBlockByteFetch is the D22 fix end to end: the yanked-index posture
// leaves ONE escape hatch — an exact pin (pip install foo==1.2.3) installs a yanked
// release anyway — but the wheel bytes route back through the firewall under
// "/_files/<pkg>/…", so a blocked package must fail CLOSED there, and only an admin
// override may open it. We pin six==1.16.0 (a pure-python package with no runtime
// deps, so the install reaches six's own wheel fetch rather than failing on a
// dependency) and run it under an unreachable threshold so six is always blocked.
func TestPypiPinnedBlockByteFetch(t *testing.T) {
	bin := buildFirewall(t)
	const pinned = "six==1.16.0"

	t.Run("pinned_blocked_install_denied_at_byte_fetch", func(t *testing.T) {
		fw := startFirewall(t, bin, map[string]string{
			"FW_ECOSYSTEM":         "pypi",
			"FW_SCORECARD_MODE":    "api",
			"FW_SCORE_THRESHOLD":   "9.9", // nothing scores this high -> six is blocked
			"FW_UNSCORABLE_POLICY": "block",
		})
		code, out := runPipInstall(t, fw.port, pinned)
		if code == 0 {
			t.Fatalf("pinned install of a blocked package SUCCEEDED — the byte fetch was not gated\n%s\n--- firewall ---\n%s",
				tail(out, 20), logAround(fw.log.String(), 30))
		}
		// The install failing isn't enough — it must fail AT THE BYTE FETCH (the D22
		// gap), not merely because pip declined the yanked index. Ask the parser for a
		// byte-relay verdict on six rather than substring-matching the log text: the
		// old literal ("_files six") was adjacency-coupled and #76 broke it by inserting
		// an outcome token between the two words, with no change in behaviour.
		gatedBytes := false
		for _, d := range fw.decisionsFor("six") {
			gatedBytes = gatedBytes || d.bytes
		}
		if !gatedBytes {
			t.Errorf("firewall never gated a /_files/ byte fetch for six — the pin failed elsewhere, not at the gate\n%s",
				fw.log.String())
		}
	})

	t.Run("admin_approved_pinned_install_succeeds", func(t *testing.T) {
		// A stub approval service that reports six as human-APPROVED. Now that the
		// firewall runs as a CONTAINER, the stub runs as one too (startApprovalStub),
		// reachable at host.docker.internal like the firewall itself — a 127.0.0.1
		// httptest server would be unreachable from the firewall container. This
		// exercises the real override -> allow -> stream path (index AND byte fetch)
		// with real pip; the approval store's own persistence is unit-tested separately.
		approvalURL := startApprovalStub(t, "six", "approved")

		fw := startFirewall(t, bin, map[string]string{
			"FW_ECOSYSTEM":         "pypi",
			"FW_SCORECARD_MODE":    "api",
			"FW_SCORE_THRESHOLD":   "9.9",
			"FW_UNSCORABLE_POLICY": "block",
			"FW_APPROVAL_URL":      approvalURL,
		})
		code, out := runPipInstall(t, fw.port, pinned)
		if code != 0 {
			t.Fatalf("admin-approved pinned install FAILED (exit %d) — override did not open the byte fetch\n%s\n--- firewall ---\n%s",
				code, tail(out, 20), logAround(fw.log.String(), 30))
		}
	})
}
