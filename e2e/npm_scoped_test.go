//go:build e2e

package e2e

// Scoped npm packages traverse more special cases than any other request shape, and
// until now no real client exercised one.
//
// MEASURED 2026-09-12, by pointing a real `npm install` at a recording server: npm asks
// for a scoped package as
//
//	GET /@babel%2fcore
//
// with the separator PERCENT-ENCODED, while an unscoped package is plain (`GET /lodash`).
// That single encoded byte is load-bearing in at least four places:
//
//   - pathguard.go refuses percent-encoded separators as a confused-deputy vector (#59),
//     and carves out an exemption for exactly this shape. If the exemption broke, every
//     scoped install would be refused; if it were too wide, "@foo%2f..%2fbar" would smuggle
//     a dot segment through.
//   - the package name must decode back to "@babel/core" before any verdict is rendered,
//     or the gate judges something that is not the package being installed.
//   - the tarball is served from "/@babel%2fcore/-/core-7.0.0.tgz" — note the filename
//     carries the BASE name only, so npmTarballVersionFromPath has to strip the scope to
//     recover the version (#52, #122).
//   - the byte gate has to bind those tarball bytes to the scoped package (#67).
//
// Each of those has unit tests. None had a real client behind it, which is the gap this
// file closes: unit tests agreeing with each other is not evidence they agree with npm.
//
// The two legs are each other's control. The open-gate leg proves npm can install this
// shape through us at all — without it, the refusal below could be npm failing for its own
// reasons. The closed-gate leg proves the request is actually JUDGED rather than falling
// through to the ungated relay, which is the failure mode #11 and #59 both rode in on: a
// path our parsers do not recognise is not refused, it is forwarded.

import (
	"strings"
	"testing"
)

// scopedPkg has no runtime dependencies, so a failure is about the scoped path and not
// about some transitive package's availability.
const scopedPkg = "@types/node"

func TestNpmScopedPackageIsJudgedUnderItsDecodedName(t *testing.T) {
	bin := buildFirewall(t)

	t.Run("control: the open gate installs it, and the verdict names the decoded scope", func(t *testing.T) {
		fw := startFirewall(t, bin, permissiveEnv("npm", nil))
		defer fw.stop()

		code, out := runNpmInstall(t, fw.port, scopedPkg)
		if code != 0 {
			t.Fatalf("npm could not install %s through the firewall with the gate OPEN (exit %d) — "+
				"either the path guard is refusing the encoded separator npm really sends, or the "+
				"scoped name is not being decoded\n%s\n--- firewall ---\n%s",
				scopedPkg, code, tail(out, 25), tail(fw.log.String(), 40))
		}

		// The install succeeding is necessary but not sufficient: a request our parsers
		// failed to recognise is RELAYED, not refused, so it would also succeed. The
		// verdict is what distinguishes "gated and allowed" from "never judged".
		decisions := fw.decisionsFor(scopedPkg)
		if len(decisions) == 0 {
			t.Fatalf("npm installed %s but the firewall rendered NO verdict for that name — the "+
				"request was relayed ungated, which is the #11/#59 shape. Verdicts seen: %v",
				scopedPkg, allDecisionNames(fw))
		}
		for _, d := range decisions {
			if !d.allowed {
				t.Errorf("the open gate refused %s (%s)", scopedPkg, d.reason)
			}
		}

		// The tarball half: the scope has to be stripped to recover the version from the
		// filename. This is the line npmversion.go emits when it read the artifact.
		if !strings.Contains(fw.log.String(), "artifact "+scopedPkg) {
			t.Errorf("no artifact line for %s — the tarball fetch did not reach the version "+
				"check, so the scope-stripping path (#52/#122) is untested by this run\n%s",
				scopedPkg, tail(fw.log.String(), 40))
		}
	})

	t.Run("the closed gate refuses it under the same name, rather than relaying it", func(t *testing.T) {
		fw := startFirewall(t, bin, strictEnv("npm", map[string]string{"FW_UNVERIFIED_POLICY": "closed"}))
		defer fw.stop()

		code, out := runNpmInstall(t, fw.port, scopedPkg)
		if code == 0 {
			t.Fatalf("npm INSTALLED %s with the gate shut — a scoped request is reaching the "+
				"upstream without a verdict\n%s\n--- firewall ---\n%s",
				scopedPkg, tail(out, 25), tail(fw.log.String(), 40))
		}
		if !strings.Contains(out, blockedMarker) {
			t.Errorf("npm failed (exit %d) but its output carries no block marker, so this could be "+
				"any failure rather than our refusal (#20)\n%s", code, tail(out, 30))
		}

		// The refusal must be ABOUT the scoped package. A 404, a path-guard rejection, or a
		// verdict rendered for some other name would all fail npm too, and none of them
		// would prove the gate understood the request.
		decisions := fw.decisionsFor(scopedPkg)
		if len(decisions) == 0 {
			t.Fatalf("npm was refused, but no verdict was rendered for %s — the refusal came from "+
				"somewhere other than the gate judging this package. Verdicts seen: %v",
				scopedPkg, allDecisionNames(fw))
		}
		refused := false
		for _, d := range decisions {
			if !d.allowed {
				refused = true
			}
		}
		if !refused {
			t.Errorf("every verdict for %s was ALLOW, yet npm failed — the failure is not ours, "+
				"so this leg proves nothing about the gate", scopedPkg)
		}
	})
}

// allDecisionNames lists the package names the gate actually rendered verdicts for, so a
// failure message can distinguish "judged nothing" from "judged the wrong name" — the
// difference between a request that was relayed and one that was decoded incorrectly.
func allDecisionNames(fw *firewall) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range fw.decisions() {
		if !seen[d.pkg] {
			seen[d.pkg] = true
			out = append(out, d.pkg)
		}
	}
	return out
}
