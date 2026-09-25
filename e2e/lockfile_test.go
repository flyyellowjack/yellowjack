//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// What lands in package-lock.json, and whether it is stable (issue #20, increment 2).
//
// WHY THIS MATTERS. We rewrite npm's `dist.tarball` to point at ourselves — the correct
// call, because preserving upstream URLs would let clients fetch tarballs straight from npm
// and bypass the gate entirely. But that rewrite lands in `package-lock.json` as `resolved`,
// and a lockfile is COMMITTED and shared across machines and CI.
//
// So the rewrite has an operator-visible consequence the security reasoning does not cover:
// if `resolved` encodes the address a particular developer happened to reach us on, then the
// lockfile is not portable, and `FW_PUBLIC_URL` defaulting to empty — falling back to the
// request `Host` — makes exactly that happen. The same dependency then resolves differently
// per environment, and a lockfile committed from a laptop can be unusable in CI.
//
// Two properties are asserted here:
//
//  1. `resolved` follows FW_PUBLIC_URL, and is IDENTICAL across two firewalls that share one
//     FW_PUBLIC_URL but listen on different ports. That is what "stable" has to mean; a test
//     using one firewall could not distinguish stability from the Host fallback agreeing with
//     itself.
//  2. `integrity` is byte-identical to what the real npm registry publishes. We must never
//     touch it: it is the client's own end-to-end check on the tarball, and rewriting it
//     would either break every install or, worse, launder a modified artifact.
//
// The control leg drives the failure the issue names — no FW_PUBLIC_URL, so `resolved`
// follows whatever address the client used — proving the stability assertion above is not
// vacuous.

// lockResolvedRe pulls the `resolved` URL for the installed package out of package-lock.json.
// Read from the lockfile text rather than by parsing the whole schema: the schema differs
// across lockfile versions, and the string that gets COMMITTED is what this test is about.
var lockResolvedRe = regexp.MustCompile(`"resolved"\s*:\s*"([^"]+)"`)
var lockIntegrityRe = regexp.MustCompile(`"integrity"\s*:\s*"([^"]+)"`)
var lockVersionRe = regexp.MustCompile(`"version"\s*:\s*"(\d+\.\d+\.\d+[^"]*)"`)

// upstreamIntegrity asks the REAL npm registry what integrity it publishes for a version.
// Discovered rather than hardcoded: a literal would be an undocumented magic value that rots
// the day the package is republished, and the whole point is to compare against upstream's
// current truth.
func upstreamIntegrity(t *testing.T, pkg, version string) string {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("https://registry.npmjs.org/%s/%s", pkg, version))
	if err != nil {
		t.Skipf("cannot reach the public registry to cross-check integrity: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Skipf("public registry returned %d; skipping the integrity cross-check", resp.StatusCode)
	}
	var doc struct {
		Dist struct {
			Integrity string `json:"integrity"`
		} `json:"dist"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Dist.Integrity == "" {
		t.Skipf("could not read dist.integrity from the public registry for %s@%s", pkg, version)
	}
	return doc.Dist.Integrity
}

// installAndReadLock runs a fresh `npm install <pkg>` in its own workspace and returns the
// lockfile text.
func installAndReadLock(t *testing.T, port int, pkg string) string {
	t.Helper()
	vol := npmLockWorkspace(t, port)
	code, out := npmInWorkspace(t, vol, port,
		"npm init -y >/dev/null && npm install "+pkg+" >/dev/null 2>&1 && cat package-lock.json")
	if code != 0 {
		t.Fatalf("`npm install %s` failed (exit %d) — the lockfile cannot be inspected\n%s",
			pkg, code, tail(out, 25))
	}
	return out
}

// TestNpmLockfileResolvedIsStableAndIntegrityUntouched is increment 2 of #20.
//
// `ms` is used throughout: it has ZERO dependencies, so the lockfile holds exactly one
// `resolved`/`integrity` pair and there is no ambiguity about which entry is being asserted.
func TestNpmLockfileResolvedIsStableAndIntegrityUntouched(t *testing.T) {
	bin := buildFirewall(t)
	const pkg = "ms"

	base := map[string]string{
		"FW_ECOSYSTEM": "npm", "FW_SCORECARD_MODE": "stub", "FW_SCORE_THRESHOLD": "0",
		"FW_UNSCORABLE_POLICY": "allow",
		"FW_UNVERIFIED_POLICY": "open-with-visibility",
	}
	env := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// Firewall A is the one FW_PUBLIC_URL names. It must stay up for the whole test: the
	// URL it publishes is the one npm will fetch tarballs from in BOTH legs, so tearing it
	// down would make leg B fail for a reason that has nothing to do with stability.
	portA := freePort(t)
	publicA := fmt.Sprintf("http://host.docker.internal:%d", portA)
	fwA := startFirewallOnPort(t, bin, portA, env(map[string]string{"FW_PUBLIC_URL": publicA}))

	lockA := installAndReadLock(t, portA, pkg)

	resolvedA := lockResolvedRe.FindStringSubmatch(lockA)
	if resolvedA == nil {
		t.Fatalf("no \"resolved\" in the lockfile — nothing to assert about\n%s", tail(lockA, 30))
	}
	// Anti-vacuity: the lockfile must resolve through the FIREWALL. If npm recorded a
	// registry.npmjs.org URL, the install bypassed us and every assertion below is about
	// the wrong thing.
	if !strings.Contains(resolvedA[1], publicA) {
		t.Fatalf("resolved = %q, which does not point at the configured FW_PUBLIC_URL (%s). Either the "+
			"rewrite is not happening or the install bypassed the firewall; either way the lockfile "+
			"assertions below would be meaningless.\n--- firewall ---\n%s",
			resolvedA[1], publicA, logAround(fwA.log.String(), 25, pkg))
	}
	t.Logf("resolved (firewall A, port %d) = %s", portA, resolvedA[1])

	// ── Property 1: STABILITY. A second firewall, different port, same FW_PUBLIC_URL. The
	// lockfile it produces must be byte-identical in `resolved` — that is what makes a
	// committed lockfile portable across deployments.
	portB := freePort(t)
	fwB := startFirewallOnPort(t, bin, portB, env(map[string]string{"FW_PUBLIC_URL": publicA}))
	defer fwB.stop()

	lockB := installAndReadLock(t, portB, pkg)
	resolvedB := lockResolvedRe.FindStringSubmatch(lockB)
	if resolvedB == nil {
		t.Fatalf("no \"resolved\" in the second lockfile\n%s", tail(lockB, 30))
	}
	if resolvedA[1] != resolvedB[1] {
		t.Errorf("LOCKFILE IS NOT PORTABLE: two firewalls sharing one FW_PUBLIC_URL produced different "+
			"`resolved` values:\n  port %d -> %s\n  port %d -> %s\n"+
			"A committed lockfile therefore depends on which deployment wrote it, and `npm ci` in CI "+
			"would fetch from an address that may not exist there (#20).",
			portA, resolvedA[1], portB, resolvedB[1])
	} else {
		t.Logf("stable: firewall B (port %d) produced the same resolved URL", portB)
	}

	// ── Property 2: INTEGRITY IS UNTOUCHED. Compared against the live registry, because
	// the value only means anything if it still matches what npm itself publishes.
	gotIntegrity := lockIntegrityRe.FindStringSubmatch(lockA)
	gotVersion := lockVersionRe.FindAllStringSubmatch(lockA, -1)
	if gotIntegrity == nil || len(gotVersion) == 0 {
		t.Fatalf("lockfile carries no integrity/version to cross-check\n%s", tail(lockA, 30))
	}
	// The last version match is the dependency's; the first is the throwaway project's.
	version := gotVersion[len(gotVersion)-1][1]
	if want := upstreamIntegrity(t, pkg, version); gotIntegrity[1] != want {
		t.Errorf("INTEGRITY WAS MODIFIED: lockfile has %q for %s@%s but the public registry publishes %q.\n"+
			"dist.integrity is the client's own end-to-end check on the tarball. Rewriting it either "+
			"breaks every install or launders a modified artifact — neither is acceptable.",
			gotIntegrity[1], pkg, version, want)
	} else {
		t.Logf("integrity untouched for %s@%s (matches the public registry)", pkg, version)
	}

	// ── Control: the failure #20 names. With FW_PUBLIC_URL unset, `resolved` follows the
	// address the client happened to use — so the same dependency resolves differently per
	// environment. This is what makes the stability assertion above non-vacuous: without it,
	// "the two agreed" could just as well mean the firewall ignores FW_PUBLIC_URL entirely.
	portC := freePort(t)
	fwC := startFirewallOnPort(t, bin, portC, env(nil)) // no FW_PUBLIC_URL
	defer fwC.stop()

	lockC := installAndReadLock(t, portC, pkg)
	resolvedC := lockResolvedRe.FindStringSubmatch(lockC)
	if resolvedC == nil {
		t.Fatalf("no \"resolved\" in the control lockfile\n%s", tail(lockC, 30))
	}
	if resolvedC[1] == resolvedA[1] {
		t.Errorf("control: a firewall with NO FW_PUBLIC_URL on port %d produced the same resolved URL "+
			"as the configured one (%s). Then FW_PUBLIC_URL is doing nothing, and the stability "+
			"assertion above passed for the wrong reason.", portC, resolvedC[1])
	} else {
		t.Logf("control: without FW_PUBLIC_URL, resolved follows the request host (%s) — this is the "+
			"per-environment drift FW_PUBLIC_URL exists to prevent", resolvedC[1])
	}

	fwA.stop()
}
