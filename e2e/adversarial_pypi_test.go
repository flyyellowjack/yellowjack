//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Adversarial e2e for PyPI's artifact byte gate — the "/_files/<pkg>/<object path>"
// relay added by D22.
//
// WHY THIS FILE EXISTS: until now the adversarial tier covered npm request paths
// (issue #59) and OCI blob paths (issue #57). PyPI had NO adversarial coverage at all,
// while carrying a byte gate of exactly the shape those two issues were about. Every
// PyPI leg in this suite drives real pip doing an honest install, and tier 2
// structurally cannot find a bypass: pip only ever requests the URLs our own rewritten
// index handed it, so the prefix always matches the artifact by construction.
//
// The specific property under test is the one proxyToFiles rests on. It peels <pkg>
// off the front of the path, Evaluates THAT, and then relays the REMAINDER verbatim to
// the files upstream. Nothing checks that the remainder is an object belonging to
// <pkg>. So the question an attacker asks is: can the two halves be made to disagree —
// gate on a package that is allowed, fetch the bytes of one that is blocked?
//
// This is the "confused deputy" row of the attack catalogue (docs/TEST_TIERS.md),
// applied to the ecosystem that had never been asked. Per the threat model, "you would
// have to craft that URL by hand" is not a mitigation: a postinstall script, a poisoned
// transitive dependency, or an insider all craft URLs, and the firewall's promise is
// that a blocked package's bytes do not cross it by ANY route.

// wheelBytes reports whether a body is a real Python wheel or sdist rather than an
// error page. Checked by CONTENT, not status: a bypass returns an ordinary 200, so
// trusting the status is the mistake that lets it through.
//
// A wheel is a zip (PK\x03\x04); an sdist is gzip (\x1f\x8b).
func wheelBytes(body []byte) string {
	if len(body) >= 4 && body[0] == 'P' && body[1] == 'K' && body[2] == 0x03 && body[3] == 0x04 {
		return "wheel (zip)"
	}
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		return "sdist (gzip)"
	}
	return ""
}

// startSelectiveApprovalStub is startApprovalStub's discriminating cousin: it approves
// ONE package and denies every other, keyed on the ?package= query.
//
// This test needs one package ALLOWED and another BLOCKED at the same time, and it must
// not get that split from scores. Driving the verdicts from the approval service instead
// makes the experiment independent of deps.dev entirely, so it cannot drift the way issue
// #44 did.
//
// It echoes the QUERIED name back, which is what a real service does and what the firewall
// now requires: since 2026-09-07 a record whose `package` is not the one asked about is
// refused (lookupApproval). The shared harness stub used to return a fixed body for any
// query — approving the whole world — and this comment used to say the firewall did not
// check. It does now; see startApprovalStub and TestAdversarialForgedApprovalCannotOpenTheGate.
func startSelectiveApprovalStub(t *testing.T, approved string) string {
	t.Helper()
	port := freePort(t)
	name := fmt.Sprintf("yj-e2e-selapproval-%d", port)
	prog := fmt.Sprintf(`import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
APPROVED = %q
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path)
        if not u.path.startswith("/v1/decisions"):
            self.send_response(404); self.end_headers(); return
        q = (parse_qs(u.query).get("package") or [""])[0]
        verdict = "approved" if q == APPROVED else "denied"
        body = json.dumps({"package": q, "verdict": verdict}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
HTTPServer(("", 80), H).serve_forever()`, approved)

	args := []string{"run", "-d", "--name", name, "-p", fmt.Sprintf("%d:80", port),
		"python:3.12-slim", "python3", "-c", prog}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("start selective approval stub: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	url := fmt.Sprintf("http://%s:%d/v1/decisions?package=%s", fwHost(), port, approved)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(url); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return fmt.Sprintf("http://host.docker.internal:%d", port)
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("selective approval stub never became ready at %s", url)
	return ""
}

// filesObjectPath discovers the REAL upstream object path for a package's artifact by
// reading it out of the firewall's own rewritten /simple/ index.
//
// Deliberately discovered rather than hardcoded. A files.pythonhosted.org path embeds a
// content hash ("/packages/71/39/<64 hex>/six-1.16.0-py2.py3-none-any.whl"), and a
// literal one in the test would be an undocumented magic value that rots silently the
// day the artifact is re-uploaded. Reading it from the index also proves the path is one
// the firewall itself just minted — so when the attack leg reuses it, there is no
// question of the request having been unrealistic.
var filesHrefRe = regexp.MustCompile(`/_files/([^/"]+)(/[^"#]+)`)

// npmMintedTarballRe pulls the tarball URL the firewall minted out of a relayed
// packument, capturing it from "/_tarball/" onward so the captured value is a path the
// test can request directly — including the signature query #72 appends.
var npmMintedTarballRe = regexp.MustCompile(`"tarball"\s*:\s*"[^"]*(/_tarball/express/[^"]*)"`)

func filesObjectPath(t *testing.T, port int, pkg string) string {
	t.Helper()
	code, body := rawGet(t, fwHost(), port, "/simple/"+pkg+"/")
	if code != http.StatusOK {
		t.Fatalf("permissive GET /simple/%s/ returned %d, want 200 — cannot discover the object path", pkg, code)
	}
	for _, m := range filesHrefRe.FindAllStringSubmatch(string(body), -1) {
		if m[1] == pkg {
			return m[2]
		}
	}
	t.Fatalf("no /_files/%s/... link in the rewritten index; the relay shape changed\nbody: %s", pkg, tail(string(body), 5))
	return ""
}

// TestAdversarialPypiFilesPathCannotBeConfused is the confused-deputy leg.
//
// Verdicts come from a selective approval stub, not from scores: "requests" is
// APPROVED, everything else (including "six") is DENIED. That makes the split a
// property of the configuration rather than of whatever deps.dev says this week.
//
// The attack: take six's real object path — six is blocked — and request it under the
// APPROVED package's prefix. The firewall Evaluates "requests", which is allowed, and
// then relays six's object path. If six's wheel comes back, a blocked package's bytes
// crossed the firewall.
func TestAdversarialPypiFilesPathCannotBeConfused(t *testing.T) {
	bin := buildFirewall(t)

	// Phase 1 — discover both real object paths through a permissive firewall, and
	// prove the honest route actually carries artifact bytes. This is the
	// discriminator: without it, every "no bytes came back" assertion below is also
	// satisfied by a firewall that can't reach files.pythonhosted.org at all.
	var sixObject, requestsObject string
	func() {
		fw := startFirewall(t, bin, map[string]string{
			"FW_ECOSYSTEM":         "pypi",
			"FW_SCORECARD_MODE":    "stub",
			"FW_SCORE_THRESHOLD":   "0", // allow everything
			"FW_UNSCORABLE_POLICY": "allow",
			"FW_UNVERIFIED_POLICY": "open-with-visibility",
		})
		defer fw.stop()

		sixObject = filesObjectPath(t, fw.port, "six")
		requestsObject = filesObjectPath(t, fw.port, "requests")

		code, body := rawGet(t, fwHost(), fw.port, "/_files/six"+sixObject)
		if code != http.StatusOK || wheelBytes(body) == "" {
			t.Fatalf("control: permissive GET /_files/six%s returned %d with no artifact bytes (%d bytes) — "+
				"the honest route does not serve artifacts here, so a refusal in the attack leg would prove nothing",
				sixObject, code, len(body))
		}
		t.Logf("control: honest permissive fetch served %d bytes of %s", len(body), wheelBytes(body))
	}()

	// Phase 2 — the strict posture, with exactly one package approved.
	approvalURL := startSelectiveApprovalStub(t, "requests")
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":      "pypi",
		"FW_SCORECARD_MODE": "stub", // flat 7.5 for everything — no score drift
		// Above the stub score, so nothing is allowed on its merits; the approval
		// stub is the ONLY thing that can open a package.
		"FW_SCORE_THRESHOLD":   "8.0",
		"FW_UNSCORABLE_POLICY": "block",
		"FW_UNVERIFIED_POLICY": "closed",
		"FW_APPROVAL_URL":      approvalURL,
	})

	// Anti-vacuity 1: the blocked package must really be refused on its own path.
	if code, body := rawGet(t, fwHost(), fw.port, "/_files/six"+sixObject); code == http.StatusOK && wheelBytes(body) != "" {
		t.Fatalf("control: six is NOT blocked (honest fetch returned %d with %s) — the whole test is vacuous\n--- firewall ---\n%s",
			code, wheelBytes(body), logAround(fw.log.String(), 20))
	}

	// Anti-vacuity 2: the decoy must really be allowed AND serve real bytes, or the
	// attack below could not possibly work for reasons unrelated to the gate.
	code, body := rawGet(t, fwHost(), fw.port, "/_files/requests"+requestsObject)
	if code != http.StatusOK || wheelBytes(body) == "" {
		t.Fatalf("control: the approved decoy 'requests' did not serve artifact bytes (%d, %d bytes) — "+
			"the confused-deputy attack cannot be evaluated\n--- firewall ---\n%s",
			code, len(body), logAround(fw.log.String(), 20))
	}
	t.Logf("control: approved decoy served %d bytes of %s", len(body), wheelBytes(body))

	// THE ATTACK: an allowed prefix carrying a blocked package's object path.
	attack := "/_files/requests" + sixObject
	code, hdr, body := rawGetHeaders(t, fwHost(), fw.port, attack)
	if what := wheelBytes(body); what != "" {
		t.Errorf("GATE BYPASS (confused deputy): GET %s returned %d with %d bytes of %s.\n"+
			"The firewall evaluated the ALLOWED package in the prefix and relayed the BLOCKED package's object path verbatim.\n"+
			"proxyToFiles peels <pkg> off the front and never checks that the remainder belongs to it.",
			attack, code, len(body), what)
		return
	}
	// A 2xx with nothing recognizable is not a pass — it means the request reached
	// upstream and we merely failed to recognize the response. And a refusal must be
	// OURS: an upstream 404 for a path it dislikes is not the gate working.
	if code >= 200 && code < 300 {
		t.Errorf("GET %s returned %d and was RELAYED (%d bytes) — it must be refused before reaching upstream",
			attack, code, len(body))
	}
	if reason := hdr.Get("X-Yellowjack-Reason"); reason == "" && code != http.StatusOK {
		t.Logf("NOTE: %s was refused with %d but carries no X-Yellowjack-Reason — "+
			"confirm the refusal is ours and not the upstream's", attack, code)
	}
}

// TestAdversarialNpmTarballPathCannotBeConfused is the same experiment against npm's
// "/_tarball/<pkg>/<object path>" relay, which is the SAME CODE SHAPE: npmArtifactPath
// peels <pkg> off the prefix, proxyArtifactBytes Evaluates it and then forwards the
// remaining object path verbatim to the registry. If PyPI's relay can be confused, this
// one is built the same way and must be measured rather than assumed.
func TestAdversarialNpmTarballPathCannotBeConfused(t *testing.T) {
	// Unskipped by #72. The premise this test was written to disprove — "identity rides
	// in the prefix rather than the shape" — was indeed wrong, but the fix is not the
	// filename check the skip anticipated (D101 declined to guess npm's grammar). It is a
	// SIGNATURE over the (ecosystem, package, object path) tuple: the prefix and the
	// object path are now something we asserted belong together, so there is no shape to
	// infer and no odd-path registry to break.
	//
	// The signing key is what makes this leg meaningful; without FW_URL_SIGNING_KEY the
	// bypass below still succeeds by design, because D103 made the feature opt-in.
	bin := buildFirewall(t)

	// lodash's tarball path in the registry's own convention — the shape a lockfile
	// records, and what /_tarball/<pkg>/ wraps.
	const target = "/lodash/-/lodash-4.17.21.tgz"

	approvalURL := startSelectiveApprovalStub(t, "express")
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":         "npm",
		"FW_SCORECARD_MODE":    "stub",
		"FW_SCORE_THRESHOLD":   "8.0", // above the flat stub score: nothing passes on merit
		"FW_UNSCORABLE_POLICY": "block",
		"FW_UNVERIFIED_POLICY": "closed",
		"FW_BYTE_GATE":         "enforce", // the strictest posture we ship
		"FW_APPROVAL_URL":      approvalURL,
		// Opt-in per D103. 32 bytes, fixed rather than random so a failure is
		// reproducible from the log alone; it signs nothing that outlives the test.
		"FW_URL_SIGNING_KEY": "yellowjack-e2e-url-signing-key-0",
	})

	// Anti-vacuity 1: the target really is blocked on its own route.
	if code, body := rawGet(t, fwHost(), fw.port, target); code == http.StatusOK && leaked(body) != "" {
		t.Fatalf("control: lodash is NOT blocked (%d, %s) — the test is vacuous\n--- firewall ---\n%s",
			code, leaked(body), logAround(fw.log.String(), 20))
	}

	// Anti-vacuity 2: the approved decoy really serves tarball bytes — fetched through
	// the URL the FIREWALL ITSELF MINTED, signature and all. Taking the URL from the
	// packument rather than hand-building one means this control also proves the whole
	// mint-then-verify round trip works against the real binary; a signing bug that
	// refused everything would fail here rather than masquerading as a successful defence
	// in the attack below.
	code, packument := rawGet(t, fwHost(), fw.port, "/express")
	if code != http.StatusOK {
		t.Fatalf("control: could not read the decoy packument (%d)\n--- firewall ---\n%s",
			code, logAround(fw.log.String(), 20))
	}
	m := npmMintedTarballRe.FindSubmatch(packument)
	if m == nil {
		t.Fatalf("control: no minted /_tarball/express/... URL in the packument; the relay shape changed")
	}
	minted := string(m[1])
	if !strings.Contains(minted, "_yjsig=") {
		t.Fatalf("control: the minted URL carries no signature (%q) — FW_URL_SIGNING_KEY did not take "+
			"effect, so this leg would 'pass' while testing nothing\n--- firewall ---\n%s",
			minted, logAround(fw.log.String(), 20))
	}
	code, body := rawGet(t, fwHost(), fw.port, minted)
	if code != http.StatusOK || leaked(body) == "" {
		t.Fatalf("control: approved decoy 'express' served no tarball from its own minted URL "+
			"(%d, %d bytes) — the confused-deputy attack cannot be evaluated\n--- firewall ---\n%s",
			code, len(body), logAround(fw.log.String(), 20))
	}
	t.Logf("control: approved decoy served %d bytes of %s from its minted signed URL", len(body), leaked(body))

	// The attack, in both forms an attacker actually has available: reuse the decoy's
	// REAL signature against a different object path, and omit the signature entirely.
	// Neither may deliver the blocked package's bytes.
	decoySig := minted[strings.Index(minted, "?"):]
	for _, tc := range []struct{ name, attack string }{
		{"decoy's real signature, blocked package's object path", "/_tarball/express" + target + decoySig},
		{"no signature at all", "/_tarball/express" + target},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := rawGet(t, fwHost(), fw.port, tc.attack)
			if what := leaked(body); what != "" {
				t.Errorf("GATE BYPASS (confused deputy): GET %s returned %d with %d bytes of %s.\n"+
					"The byte gate evaluated the ALLOWED package named in the prefix and forwarded the BLOCKED package's object path verbatim.",
					tc.attack, code, len(body), what)
				return
			}
			if code >= 200 && code < 300 {
				t.Errorf("GET %s returned %d and was RELAYED (%d bytes) — it must be refused before reaching upstream",
					tc.attack, code, len(body))
			}
		})
	}
}
