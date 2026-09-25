//go:build e2e

package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// runNpmInstall runs `npm install <pkg>` inside a throwaway node container,
// configured (via npm_config_* env, so no mounted files) to use the firewall on
// the host as its registry with an isolated empty cache — so every metadata and
// tarball request traverses the proxy. Returns the npm exit code and combined
// output. `--add-host host.docker.internal:host-gateway` makes the host reachable
// on Linux/CI Docker too, not just Docker Desktop.
func runNpmInstall(t *testing.T, port int, pkg string) (int, string) {
	t.Helper()
	out, err := npmInstallCmd(port, pkg).CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatalf("could not run docker (is it installed/running?): %v\n%s", err, out)
	}
	return 0, string(out)
}

// npmInstallCmd builds (but does not run) that same command. Split out so a test can
// run SEVERAL installs concurrently: runNpmInstall calls t.Fatalf, which must not be
// called from a non-test goroutine, so the concurrent coalescing leg drives the
// *exec.Cmd itself and reports failures from the main goroutine.
func npmInstallCmd(port int, pkg string) *exec.Cmd {
	reg := fmt.Sprintf("http://host.docker.internal:%d/", port)
	return exec.Command("docker", "run", "--rm",
		"-w", "/work", // npm errors with "idealTree already exists" if run in / (root)
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "npm_config_registry="+reg,
		"-e", "npm_config_cache=/tmp/npmcache",
		"-e", "npm_config_fund=false",
		"-e", "npm_config_audit=false",
		"node:22-alpine",
		"npm", "install", "--no-save", pkg,
	)
}

// npmLockWorkspace creates a named docker volume to hold one scenario's working
// directory. A named volume, not a host bind mount: on GitLab's dind runners the
// docker daemon is a SEPARATE service, so a host path from the job container means
// nothing to it — a bind mount would silently produce an empty directory there while
// working fine on a laptop. Removed at test end.
func npmLockWorkspace(t *testing.T, port int) string {
	t.Helper()
	vol := fmt.Sprintf("yj-e2e-lock-%d", port)
	_ = exec.Command("docker", "volume", "rm", "-f", vol).Run()
	if out, err := exec.Command("docker", "volume", "create", vol).CombinedOutput(); err != nil {
		t.Fatalf("create volume: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "volume", "rm", "-f", vol).Run() })
	return vol
}

// npmInWorkspace runs a shell command in a node container with `vol` mounted at
// /work and npm pointed at the firewall on `port`, with an EMPTY cache each time —
// a warm cache would let `npm ci` satisfy itself locally and never exercise the byte
// path this test exists to check.
func npmInWorkspace(t *testing.T, vol string, port int, script string) (int, string) {
	t.Helper()
	reg := fmt.Sprintf("http://host.docker.internal:%d/", port)
	cmd := exec.Command("docker", "run", "--rm",
		"-v", vol+":/work", "-w", "/work",
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "npm_config_registry="+reg,
		"-e", "npm_config_cache=/tmp/npmcache",
		"-e", "npm_config_fund=false",
		"-e", "npm_config_audit=false",
		"node:22-alpine", "sh", "-c", script,
	)
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatalf("could not run docker (is it installed/running?): %v\n%s", err, out)
	}
	return 0, string(out)
}

// TestNpmLockfileByteGate is the end-to-end proof for issue #11 — the side-door where
// a package the firewall BLOCKS is still installable byte-for-byte, because `npm ci`
// installs from a lockfile: it fetches each tarball directly by its recorded
// "resolved" URL and never re-requests the metadata the gate was watching. (Reported
// in the field, not theorised: an operator was hit by the March-31 axios compromise
// running only `npm ci`.)
//
// The scenario is the realistic one — the lockfile is generated while the package
// passes, then the policy tightens, exactly as it would when a package's score drops
// or a threshold is raised after the lockfile was committed. The firewall is restarted
// on the SAME port because the lockfile hard-codes that address.
//
// Four legs. Leg 3 is the commercially important one — the DEFAULT configuration, what
// a deployment gets without reading the manual — and since D72 it must block, because a
// package denied on a positive finding is refused on every path. Leg 4 is a NEGATIVE
// CONTROL that demonstrates the vulnerability is real: with the gate off, the same
// `npm ci` succeeds. Without that control, legs 2 and 3 could both go red for an
// unrelated reason (a typo'd package, a broken volume, npm failing on its own) and we
// would believe we had closed a hole we had not.
func TestNpmLockfileByteGate(t *testing.T) {
	bin := buildFirewall(t)
	port := freePort(t)
	vol := npmLockWorkspace(t, port)

	// stub mode scores every package 7.5, offline and deterministic, so "passes" vs
	// "blocked" is purely the threshold — no dependence on a live score that drifts.
	// `ms` is tiny and has ZERO dependencies, so the lockfile has exactly one tarball
	// to reason about.
	const pkg = "ms"
	permissive := map[string]string{
		"FW_ECOSYSTEM": "npm", "FW_SCORECARD_MODE": "stub", "FW_SCORE_THRESHOLD": "0",
	}
	blocking := map[string]string{
		"FW_ECOSYSTEM": "npm", "FW_SCORECARD_MODE": "stub", "FW_SCORE_THRESHOLD": "10",
	}

	// ── Leg 1: generate a lockfile through a firewall that allows the package. The
	// byte gate is left at its DEFAULT here, so the artifact URLs written into the
	// lockfile are the ones a real deployment mints.
	fw := startFirewallOnPort(t, bin, port, permissive)
	code, out := npmInWorkspace(t, vol, port, "npm init -y >/dev/null && npm install "+pkg+" && cat package-lock.json")
	if code != 0 {
		t.Fatalf("lockfile generation failed (exit %d)\n%s\n--- firewall ---\n%s",
			code, tail(out, 20), logAround(fw.log.String(), 20))
	}
	// If the lockfile does not point back at the firewall, `npm ci` below would fetch
	// from the public registry and every remaining assertion would be vacuous —
	// including the "blocked" one, which would then be green for the wrong reason.
	resolved := fmt.Sprintf("host.docker.internal:%d", port)
	if !strings.Contains(out, resolved) {
		t.Fatalf("lockfile does not resolve through the firewall (%s) — the scenario would be vacuous:\n%s",
			resolved, tail(out, 30))
	}
	fw.stop()

	// ── Leg 2: the fix. Same lockfile, same address, a firewall that now blocks the
	// package, byte gate ENFORCING: `npm ci` must fail at the tarball fetch.
	enforceEnv := map[string]string{"FW_BYTE_GATE": "enforce"}
	for k, v := range blocking {
		enforceEnv[k] = v
	}
	fw = startFirewallOnPort(t, bin, port, enforceEnv)
	code, out = npmInWorkspace(t, vol, port, "rm -rf node_modules && npm ci")
	fwLogEnforce := fw.log.String()
	if code == 0 {
		t.Errorf("SIDE-DOOR OPEN: `npm ci` installed a blocked package with FW_BYTE_GATE=enforce\n%s\n--- firewall ---\n%s",
			tail(out, 20), tail(fwLogEnforce, 30))
	}
	if !strings.Contains(fwLogEnforce, "byte gate (enforce)") {
		t.Errorf("no byte-gate decision in the firewall log — the tarball fetch was not gated at all\n%s",
			tail(fwLogEnforce, 30))
	}
	fw.stop()

	// ── Leg 3: the DEFAULT configuration — no FW_BYTE_GATE at all. Since D72 this must
	// ALSO fail: the package is denied on a positive finding (it scored below the
	// threshold), and a hard deny blocks bytes in every BYTE-GATE mode. This is the leg
	// that matters commercially — what a deployment gets without reading the
	// manual. "BYTE-GATE mode" is the precise claim: FW_MODE=report suppresses this
	// refusal like any other policy verdict, which is why the word was added.
	fw = startFirewallOnPort(t, bin, port, blocking)
	code, out = npmInWorkspace(t, vol, port, "rm -rf node_modules && npm ci")
	fwLogDefault := fw.log.String()
	if code == 0 {
		t.Errorf("SIDE-DOOR OPEN IN THE DEFAULT CONFIG: `npm ci` installed a hard-denied package with no FW_BYTE_GATE set\n%s\n--- firewall ---\n%s",
			tail(out, 20), tail(fwLogDefault, 30))
	}
	if !strings.Contains(fwLogDefault, "a hard deny blocks bytes in every BYTE-GATE mode") {
		t.Errorf("default mode blocked without saying why — the operator-facing reason is the point\n%s",
			tail(fwLogDefault, 30))
	}
	fw.stop()

	// ── Leg 4 (negative control): identical run with the gate turned OFF. This one must
	// SUCCEED. It is what demonstrates the vulnerability is real and that the GATE is
	// what closes it — without it, legs 2 and 3 could both be failing for some unrelated
	// reason (a broken volume, a typo'd package, npm failing on its own) and we would
	// believe we had closed a hole we had not.
	offEnv := map[string]string{"FW_BYTE_GATE": "off"}
	for k, v := range blocking {
		offEnv[k] = v
	}
	fw = startFirewallOnPort(t, bin, port, offEnv)
	code, out = npmInWorkspace(t, vol, port, "rm -rf node_modules && npm ci")
	if code != 0 {
		t.Errorf("gate-off control failed (exit %d) — legs 2/3 may be blocking for an unrelated reason\n%s\n--- firewall ---\n%s",
			code, tail(out, 20), logAround(fw.log.String(), 30))
	}
}

// TestNpmEndToEnd simulates a company pulling a real package (express, with its
// ~60-package transitive tree) through the firewall under two policies:
//   - permissive (threshold 0, fail-open): the install SUCCEEDS through the gate.
//   - fail-closed (threshold 5.0, block): a low-scored dependency is BLOCKED and
//     npm fails — the gate doing its job.
//
// The same package under two policies isolates the policy effect. Assertions are
// deliberately drift-robust (exit code + presence of allow/block decisions)
// rather than pinning a specific dependency's score, which changes over time.
func TestNpmEndToEnd(t *testing.T) {
	bin := buildFirewall(t)

	t.Run("permissive_allows_real_install", func(t *testing.T) {
		fw := startFirewall(t, bin, map[string]string{
			"FW_ECOSYSTEM":       "npm",
			"FW_SCORECARD_MODE":  "api",
			"FW_SCORE_THRESHOLD": "0",
			// As of D36 there are TWO independent fail-closed postures, so a
			// "permissive" leg has to relax both. This one passes without the second
			// knob today (express's whole 70-package tree verifies against deps.dev —
			// measured 2026-07-26), but only by luck of deps.dev's coverage: a single
			// dropped mapping would otherwise turn this leg red for a reason that has
			// nothing to do with what it tests. The fail-closed default is exercised
			// deliberately by the unit matrix and by leg G of verify_repo_local.sh.
			"FW_UNSCORABLE_POLICY": "allow",
			"FW_UNVERIFIED_POLICY": "open-with-visibility",
		})
		code, out := runNpmInstall(t, fw.port, "express")
		if code != 0 {
			t.Fatalf("permissive `npm install express` failed (exit %d)\n%s\n--- firewall ---\n%s",
				code, tail(out, 15), logAround(fw.log.String(), 20))
		}
		if fw.allowedCount() == 0 {
			t.Errorf("expected allow decisions through the gate, saw none\n%s", fw.log.String())
		}
	})

	t.Run("failclosed_blocks_low_scored_dep", func(t *testing.T) {
		fw := startFirewall(t, bin, map[string]string{
			"FW_ECOSYSTEM":         "npm",
			"FW_SCORECARD_MODE":    "api",
			"FW_SCORE_THRESHOLD":   "5.0",
			"FW_UNSCORABLE_POLICY": "block",
		})
		code, out := runNpmInstall(t, fw.port, "express")

		// THE LADDER. Each rung is a strictly stronger claim than the one below, and each is
		// asserted separately so a failure says WHICH property broke. Asserting only the
		// bottom rungs -- "npm failed" plus "some block was logged" -- passes when the
		// firewall blocks something unrelated while the install fails for its own reasons:
		// two independent facts that read as cause and effect, with the suite green.
		//
		//   5  the request completed at all          (docker/npm ran)
		//   4  a verdict was rendered for the package under test
		//   3  the verdict is correct                (something was blocked)
		//   2  the block carries a usable reason
		//   1  the reason reaches the real client's own error output
		//
		// Rungs 4, 2 and 1 were previously unasserted. Rung 1 failed on its first run and
		// found a real scope violation: the reason was in the body's "reason" field, which
		// npm does not print, so the developer saw a refusal with no cause. See
		// writeForbidden in proxy.go.
		if code == 0 {
			t.Fatalf("fail-closed `npm install express` unexpectedly succeeded\n--- firewall ---\n%s",
				logAround(fw.log.String(), 30))
		}
		// 4 -- the gate judged express itself, not merely something during the install.
		if len(fw.decisionsFor("express")) == 0 {
			t.Errorf("no verdict was rendered for `express`; the gate judged other packages "+
				"but never the one under test\n%s", logAround(fw.log.String(), 30))
		}
		// 3 -- a block happened.
		blocked := fw.blocked()
		if len(blocked) == 0 {
			t.Errorf("expected at least one block decision, saw none\n%s", fw.log.String())
		}
		// 2 -- every block explains itself. An empty reason is a support ticket: the
		// developer sees a failed install and cannot tell policy from outage.
		for pkg, reason := range blocked {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("package %q was blocked with an empty reason", pkg)
			}
		}
		// 1 -- the block is attributable at the client, and carries our reason.
		attributed, missingReason := fw.blockSurfacedAtClient(out)
		if len(attributed) == 0 {
			t.Errorf("npm's output attributes the failure to none of the %d blocked packages, "+
				"so the developer cannot tell which dependency was refused\n"+
				"--- npm ---\n%s\n--- firewall ---\n%s",
				len(blocked), tail(out, 20), logAround(fw.log.String(), 30))
		}
		for _, pkg := range missingReason {
			t.Errorf("npm attributed the failure to %q but did not surface our reason %q; "+
				"the developer sees a refusal with no cause\n--- npm ---\n%s",
				pkg, blocked[pkg], tail(out, 20))
		}
	})
}
