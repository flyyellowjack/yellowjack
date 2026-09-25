//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
)

// Customer-shaped e2e for signed artifact URLs (#72), plus the attacker leg.
//
// WHY THIS FILE EXISTS. #72 shipped with unit tests and an adversarial test
// (TestAdversarialNpmTarballPathCannotBeConfused), but NO real client had ever installed
// through a signing-enabled firewall. That is the wrong half to be missing, because the
// entire no-expiry argument rests on a claim about a real client's behaviour: that a
// signed URL survives into package-lock.json and is replayed by `npm ci` days later.
// Nothing in the unit tests can establish that — only npm can.
//
// It also tests a design choice that could quietly be wrong. The signature rides in a
// QUERY PARAMETER. If npm normalised or dropped the query when writing "resolved", every
// lockfile in the field would replay an unsigned URL and `npm ci` would fail for
// everyone the moment an operator enabled the feature. This suite is what turns that
// from an assumption into a measurement.

const (
	// 32 bytes, fixed rather than random so a failure is reproducible from the log
	// alone. It signs nothing that outlives the test.
	e2eSigningKey    = "yellowjack-e2e-url-signing-key-0"
	e2eSigningKeyAlt = "yellowjack-e2e-url-signing-key-1"
)

// TestNpmSignedUrlsSurviveLockfileReplay is the load-bearing customer scenario: an
// ordinary developer runs `npm install`, and weeks later CI runs `npm ci` from the
// lockfile that produced. Four legs, in the order a real deployment meets them.
func TestNpmSignedUrlsSurviveLockfileReplay(t *testing.T) {
	bin := buildFirewall(t)
	port := freePort(t)
	vol := npmLockWorkspace(t, port)

	// stub mode scores every package 7.5; threshold 0 allows it. `ms` has ZERO
	// dependencies, so the lockfile holds exactly one tarball to reason about.
	const pkg = "ms"
	base := func(extra map[string]string) map[string]string {
		env := map[string]string{
			"FW_ECOSYSTEM": "npm", "FW_SCORECARD_MODE": "stub", "FW_SCORE_THRESHOLD": "0",
			"FW_BYTE_GATE":       "enforce", // strictest posture we ship
			"FW_URL_SIGNING_KEY": e2eSigningKey,
		}
		for k, v := range extra {
			env[k] = v
		}
		return env
	}

	// ── Leg 1: signing must not break an honest install. This is the one that would
	// catch "the feature works but nobody can install anything".
	fw := startFirewallOnPort(t, bin, port, base(nil))
	code, out := npmInWorkspace(t, vol, port,
		"npm init -y >/dev/null && npm install "+pkg+" && cat package-lock.json")
	if code != 0 {
		t.Fatalf("`npm install` FAILED against a signing-enabled firewall (exit %d) — signing broke "+
			"the ordinary path\n%s\n--- firewall ---\n%s",
			code, tail(out, 25), logAround(fw.log.String(), 40, pkg, "signature"))
	}

	// Anti-vacuity: the lockfile must actually resolve through the firewall, or `npm ci`
	// below would fetch from the public registry and every later assertion — including
	// the attacker leg — would be green for the wrong reason.
	resolved := fmt.Sprintf("host.docker.internal:%d", port)
	if !strings.Contains(out, resolved) {
		t.Fatalf("lockfile does not resolve through the firewall (%s); the scenario is vacuous:\n%s",
			resolved, tail(out, 30))
	}
	// THE measurement this file exists for: npm preserved the query string, so the
	// signature really is in the lockfile. If this fails, the query-parameter design is
	// wrong and the signature must move into the path instead.
	if !strings.Contains(out, "_yjsig=") {
		t.Fatalf("the lockfile carries NO signature — npm dropped or normalised the query string, so "+
			"every replayed install would arrive unsigned. The signature cannot ride in a query "+
			"parameter; it has to move into the path.\n%s", tail(out, 30))
	}
	fw.stop()

	// ── Leg 2: the replay claim. Same key, fresh container, install strictly from the
	// lockfile. This is `npm ci` in CI, weeks later — the case the no-expiry decision
	// (D108) is built on.
	fw = startFirewallOnPort(t, bin, port, base(nil))
	code, out = npmInWorkspace(t, vol, port, "rm -rf node_modules && npm ci")
	if code != 0 {
		t.Fatalf("`npm ci` FAILED replaying a signed lockfile (exit %d) — the lockfile-replay claim "+
			"behind D108's no-expiry decision does not hold\n%s\n--- firewall ---\n%s",
			code, tail(out, 25), logAround(fw.log.String(), 40, pkg, "signature"))
	}
	fw.stop()

	// ── Leg 3: rotation. The operator rotates to a new key and keeps the old one as
	// PREVIOUS. Lockfiles already in the field must keep working — that is the entire
	// reason the previous key exists.
	fw = startFirewallOnPort(t, bin, port, base(map[string]string{
		"FW_URL_SIGNING_KEY":          e2eSigningKeyAlt,
		"FW_URL_SIGNING_KEY_PREVIOUS": e2eSigningKey,
	}))
	code, out = npmInWorkspace(t, vol, port, "rm -rf node_modules && npm ci")
	if code != 0 {
		t.Fatalf("`npm ci` FAILED after key rotation with the previous key still accepted (exit %d) — "+
			"rotation would break every lockfile in flight\n%s\n--- firewall ---\n%s",
			code, tail(out, 25), logAround(fw.log.String(), 40, pkg, "signature"))
	}
	fw.stop()

	// ── Leg 4: the attacker leg, and the negative control for all three above. The key
	// is rotated with NO previous key, so the lockfile's signatures are now foreign.
	// `npm ci` MUST fail. If it succeeds, the signature is decorative: it is being
	// minted and written into lockfiles but never actually enforced, and legs 1–3 were
	// only ever proving that a URL is reachable.
	fw = startFirewallOnPort(t, bin, port, base(map[string]string{
		"FW_URL_SIGNING_KEY": e2eSigningKeyAlt,
	}))
	code, out = npmInWorkspace(t, vol, port, "rm -rf node_modules && npm ci")
	if code == 0 {
		t.Errorf("SIGNATURE NOT ENFORCED: `npm ci` succeeded using a lockfile signed with a key this "+
			"firewall no longer accepts. The signature is being minted but not checked, which means "+
			"the #67 confused-deputy defence is not actually in force.\n%s\n--- firewall ---\n%s",
			tail(out, 25), logAround(fw.log.String(), 40, pkg, "signature"))
	}
	fw.stop()
}

// TestPypiSignedUrlsHonestInstall is the PyPI half of the customer shape.
//
// PyPI is the more fragile of the two: pip validates the "#sha256=" fragment on every
// artifact URL, and signing appends a query BEFORE that fragment. If the ordering were
// wrong — or if pip re-encoded the URL — the hash check would fail and every install
// would break. Unit tests assert the ordering; only pip can prove pip accepts it.
func TestPypiSignedUrlsHonestInstall(t *testing.T) {
	bin := buildFirewall(t)
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM": "pypi", "FW_SCORECARD_MODE": "stub", "FW_SCORE_THRESHOLD": "0",
		"FW_UNSCORABLE_POLICY": "allow",
		"FW_UNVERIFIED_POLICY": "open-with-visibility",
		"FW_URL_SIGNING_KEY":   e2eSigningKey,
	})

	const pkg = "six" // small, pure-python, no build step
	code, out := runPipInstall(t, fw.port, pkg)
	if code != 0 {
		t.Fatalf("`pip install %s` FAILED against a signing-enabled firewall (exit %d) — signing broke "+
			"the ordinary PyPI path, most likely the '#sha256=' fragment or URL re-encoding\n%s\n"+
			"--- firewall ---\n%s", pkg, code, tail(out, 25), logAround(fw.log.String(), 40, pkg, "signature"))
	}
	// Anti-vacuity: prove the byte fetch actually went through our signed relay, rather
	// than pip having reached files.pythonhosted.org directly.
	if !strings.Contains(fw.log.String(), "_files") {
		t.Errorf("no /_files/ byte fetch was gated — pip did not install through the signed relay, so "+
			"this leg proves nothing\n--- firewall ---\n%s", logAround(fw.log.String(), 30, pkg))
	}
}
