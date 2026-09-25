//go:build e2e

package e2e

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// Adversarial e2e for PyPI's SIGNED artifact binding (#72) and, specifically, for the
// PEP 658 relaxation !114 added to it (#77).
//
// WHY THIS FILE EXISTS. Signed artifact URLs cover both minted byte routes, but the
// adversarial tier covered only one of them against the real binary:
//
//   - npm's "/_tarball/" has TestAdversarialNpmTarballPathCannotBeConfused, which runs
//     the real firewall with FW_URL_SIGNING_KEY set and attacks the signature;
//   - PyPI's "/_files/" has TestAdversarialPypiFilesPathCannotBeConfused, which runs the
//     real firewall with signing OFF. It therefore exercises the FILENAME GRAMMAR
//     (pypiFilenameBindsToPackage), not the signature.
//
// So no adversarial leg had ever attacked PyPI's signature against the real binary.
//
// # Why the gap mattered more than a missing-symmetry complaint
//
// !114 put a DELIBERATE RELAXATION in the binding. pip fetches a wheel's METADATA
// without the wheel by appending ".metadata" to the distribution's URL — appended to the
// WHOLE URL, query and all — so on a signed link the suffix lands on OUR SIGNATURE
// ("?_yjsig=abc.metadata") rather than on the path. proxyToFiles repairs that: it takes
// the suffix off the signature, verifies against the BASE artifact, and puts the suffix
// back on the object when it fetches. One signature now admits two object paths, X and
// X.metadata.
//
// That relaxation had unit coverage (TestSignedPypiMetadataDerivativeCannotBeConfused)
// and nothing else. Unit tests build the request the way we IMAGINE a client builds it —
// which is precisely the assumption real pip falsified when it produced this shape in the
// first place. Any loosening of a security binding earns an attacker leg against the real
// binary, not just the leg that proves the honest path still works.
//
// # What is being asked
//
// Can the three things the signature is supposed to bind together — the package prefix,
// the object path, and the ".metadata" derivation — be made to disagree, in a way that
// delivers a BLOCKED package's bytes or an object we never authorised?

// signedFilesAnchorRe pulls a minted, SIGNED artifact link out of the firewall's own
// rewritten /simple/ index, capturing (package, object path, signature) as three separate
// pieces because every attack below works by recombining them.
//
// Two things about it are load-bearing:
//
//   - It only matches anchors carrying data-core-metadata. That attribute is PyPI saying
//     a ".metadata" sibling exists for this file; it is absent on most older uploads. An
//     honest-metadata control built on a file without it would fail with an upstream 404
//     and be misread as the binding working.
//   - It reads the signature out of the index rather than recomputing it. A signature this
//     test computed itself would prove only that the test and the firewall share an HMAC;
//     one the firewall MINTED proves the round trip, and means the attack legs recombine
//     material an attacker could really have obtained.
//
// Deliberately discovered, not hardcoded: a files.pythonhosted.org path embeds a content
// hash, so a literal here would be an undocumented magic value that rots the day the
// artifact is re-uploaded.
var signedFilesAnchorRe = regexp.MustCompile(
	`href="[^"]*?/_files/([^/"]+)(/[^"?#]+)\?_yjsig=([^"&#]+)[^"]*"[^>]*data-core-metadata=`)

// signedArtifact is one artifact link the firewall minted, taken apart.
type signedArtifact struct{ pkg, objectPath, sig string }

// pypiMetadataURL builds the request PIP ITSELF WOULD SEND for an artifact's PEP 658
// metadata: ".metadata" appended to the whole URL, after the query, which is exactly why
// the suffix lands on the signature.
//
// Every leg below goes through this constructor with the three fields supplied
// separately, so an attack is written as "which package, whose object, whose signature"
// rather than as a hand-spliced string — the recombination is the experiment.
func pypiMetadataURL(pkg, objectPath, sig string) string {
	return "/_files/" + pkg + objectPath + "?_yjsig=" + sig + pep658Suffix
}

// pep658Suffix mirrors the constant in urlsign.go. Spelled out here rather than imported
// (the e2e package builds against the real binary, not the source) so that a change to the
// suffix upstream shows up as this test failing rather than as this test quietly attacking
// a shape the firewall no longer recognises.
const pep658Suffix = ".metadata"

// coreMetadataName returns the package a Python core-metadata document describes, or "".
//
// The Name field, not just "does it look like metadata", because the cross-package legs
// need to say WHOSE metadata came back: a leak that returned the blocked package's
// METADATA is the finding, and reporting it by name makes the failure self-explaining.
var metadataNameRe = regexp.MustCompile(`(?m)^Name:[ \t]*(\S+)`)

func coreMetadataName(body []byte) string {
	// The header block is at the top; a long Description must not push Name out of range.
	if len(body) > 8192 {
		body = body[:8192]
	}
	s := string(body)
	if !strings.Contains(s, "Metadata-Version:") {
		return ""
	}
	if m := metadataNameRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return "an unnamed distribution"
}

// pypiLeak reports whether a response carries real package content — an artifact or a
// metadata document.
//
// Checked by CONTENT, not by status: the failure this guards against returns an ordinary
// 200, so trusting the status code is the mistake that lets it through.
func pypiLeak(body []byte) string {
	if what := wheelBytes(body); what != "" {
		return what
	}
	if name := coreMetadataName(body); name != "" {
		return "core metadata for " + name
	}
	return ""
}

// discoverSignedMetadataArtifact reads one signed, metadata-bearing artifact link for pkg
// out of a permissive firewall's rewritten index.
func discoverSignedMetadataArtifact(t *testing.T, port int, pkg string) signedArtifact {
	t.Helper()
	code, body := rawGet(t, fwHost(), port, "/simple/"+pkg+"/")
	if code != http.StatusOK {
		t.Fatalf("permissive GET /simple/%s/ returned %d, want 200 — cannot discover a signed artifact link", pkg, code)
	}
	for _, m := range signedFilesAnchorRe.FindAllStringSubmatch(string(body), -1) {
		if m[1] == pkg {
			return signedArtifact{pkg: m[1], objectPath: m[2], sig: m[3]}
		}
	}
	t.Fatalf("no SIGNED /_files/%s/... link advertising data-core-metadata in the rewritten index.\n"+
		"Either FW_URL_SIGNING_KEY did not take effect — in which case every leg of this test would "+
		"'pass' while testing nothing — or the index/relay shape changed, or upstream stopped "+
		"advertising PEP 658 metadata for this package.\nbody: %s", pkg, tail(string(body), 5))
	return signedArtifact{}
}

// refuseCase is one attack, named by the disagreement it tries to create.
type refuseCase struct {
	name string
	path string
	// why states what the firewall would have had to get wrong for this to succeed. It
	// goes into the failure message so a red run reports a DEFECT, not just a URL.
	why string
}

// sigRefusal is the reason artifactURLAuthentic writes when the signed binding is what
// refused a request. Every leg below asserts on it — and that assertion is not
// decoration, it is the thing that makes this an adversarial test OF THE SIGNATURE.
//
// MEASURED, not assumed (this is why it is here). With signature verification stubbed out
// entirely, five of the seven legs below go red — but the two cross-package ones stay
// GREEN, because PyPI has a second, independent defence behind the signature:
// pypiFilenameBindsToPackage refuses "requests" carrying a file named "six-…​.whl" on
// grammar alone. That is real defence in depth and worth having. It is also exactly how an
// adversarial test comes to certify a defence that never ran: the leg passes, the signature
// is broken, and nothing says so.
//
// Asserting the REASON closes that. The signature check runs before the grammar check, so
// on a correct build every leg here is refused by the signature; if one is ever refused by
// the grammar instead, the signature silently stopped covering that case and this test says
// so instead of hiding behind the backstop.
const sigRefusal = "signature"

// TestAdversarialPypiSignedMetadataBindingCannotBeConfused attacks the signed binding on
// the real firewall binary, with signing ON, through the PEP 658 shape.
//
// Verdicts come from the selective approval stub rather than from scores: "requests" is
// APPROVED and everything else — including "six" — is DENIED. That makes the allowed /
// blocked split a property of the configuration, so the experiment cannot drift with
// whatever deps.dev says this week (the way issue #44 did).
//
// Note which package each leg attacks. The confused-deputy legs need a BLOCKED target, so
// they carry six's object path. The relaxation legs deliberately attack the APPROVED
// package instead: if "requests" is allowed and its filename grammar checks out, the
// SIGNATURE is the only thing left that can refuse the request — which is the only way to
// prove the signature, and not some other check standing behind it, is what holds.
func TestAdversarialPypiSignedMetadataBindingCannotBeConfused(t *testing.T) {
	bin := buildFirewall(t)

	// ── Phase 1: discovery, through a permissive firewall using the SAME signing key.
	//
	// The signature covers (ecosystem, package, object path) and nothing else — no expiry,
	// no verdict (see urlsign.go: it is a binding, not an authorisation) — so links minted
	// here verify in phase 2 under the strict posture. That is what lets us hold a real,
	// firewall-minted signature for a package that is about to be blocked, which is exactly
	// the material an attacker has: a lockfile or an index fetched before policy tightened.
	var six, requests signedArtifact
	func() {
		fw := startFirewall(t, bin, map[string]string{
			"FW_ECOSYSTEM":         "pypi",
			"FW_SCORECARD_MODE":    "stub",
			"FW_SCORE_THRESHOLD":   "0", // allow everything
			"FW_UNSCORABLE_POLICY": "allow",
			"FW_UNVERIFIED_POLICY": "open-with-visibility",
			"FW_URL_SIGNING_KEY":   e2eSigningKey,
		})
		defer fw.stop()

		six = discoverSignedMetadataArtifact(t, fw.port, "six")
		requests = discoverSignedMetadataArtifact(t, fw.port, "requests")

		// The discriminator for the whole file. Without it, every "no bytes came back"
		// assertion below is equally satisfied by a firewall that cannot serve PEP 658
		// metadata at all — because the repair is broken, because upstream 404s, or
		// because it refuses everything.
		code, body := rawGet(t, fwHost(), fw.port, pypiMetadataURL(six.pkg, six.objectPath, six.sig))
		if name := coreMetadataName(body); code != http.StatusOK || name != "six" {
			t.Fatalf("control: the HONEST PEP 658 fetch does not work on a permissive signing firewall "+
				"(status %d, %d bytes, name %q). The !114 repair is not serving metadata here, so a refusal "+
				"in any attack leg below would prove nothing.\npath: %s\n--- firewall ---\n%s",
				code, len(body), name, pypiMetadataURL(six.pkg, six.objectPath, six.sig),
				logAround(fw.log.String(), 30, "_files", "signature"))
		}
		t.Logf("control: honest permissive metadata fetch served %d bytes of core metadata for six", len(body))
	}()

	// ── Phase 2: the strict posture, with exactly one package approved.
	approvalURL := startSelectiveApprovalStub(t, "requests")
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":      "pypi",
		"FW_SCORECARD_MODE": "stub", // flat 7.5 for everything — no score drift
		// Above the stub score, so nothing is allowed on its merits; the approval stub is
		// the ONLY thing that can open a package.
		"FW_SCORE_THRESHOLD":   "8.0",
		"FW_UNSCORABLE_POLICY": "block",
		"FW_UNVERIFIED_POLICY": "closed",
		"FW_APPROVAL_URL":      approvalURL,
		"FW_URL_SIGNING_KEY":   e2eSigningKey,
	})

	// ── Anti-vacuity 1 (the control #77 asks for): an HONESTLY signed metadata fetch must
	// SUCCEED in this same run. Without it, every refusal below is satisfied by a firewall
	// that simply refuses everything — and a signing bug that broke verification outright
	// would masquerade as a successful defence four times over.
	honest := pypiMetadataURL(requests.pkg, requests.objectPath, requests.sig)
	code, body := rawGet(t, fwHost(), fw.port, honest)
	if name := coreMetadataName(body); code != http.StatusOK || name != "requests" {
		t.Fatalf("control: the approved package's honestly signed PEP 658 fetch was NOT served "+
			"(status %d, %d bytes, name %q) — the relaxation legs below cannot be evaluated, because "+
			"a firewall that refuses everything would pass them all.\npath: %s\n--- firewall ---\n%s",
			code, len(body), name, honest, logAround(fw.log.String(), 30, "_files", "signature"))
	}
	t.Logf("control: approved decoy served %d bytes of core metadata from its own minted signed URL", len(body))

	// ── Anti-vacuity 2: the blocked package must really be refused on its OWN honest,
	// correctly signed metadata URL. This is the leg that proves "six is blocked" is a fact
	// about this firewall rather than an assumption — and note it is the VERDICT refusing
	// here, not the signature, since this URL is entirely authentic.
	blocked := pypiMetadataURL(six.pkg, six.objectPath, six.sig)
	if code, body := rawGet(t, fwHost(), fw.port, blocked); code == http.StatusOK && pypiLeak(body) != "" {
		t.Fatalf("control: six is NOT blocked — its honest metadata URL returned %d with %s. "+
			"Every confused-deputy leg below is vacuous.\n--- firewall ---\n%s",
			code, pypiLeak(body), logAround(fw.log.String(), 30, "_files", "six"))
	}

	// ── The attacks.
	//
	// A fabricated object path under the APPROVED package: the filename grammar accepts it
	// (it is spelled "requests-<version>-...whl"), the verdict accepts it, and no signature
	// was ever minted for it. Built from the real path's directory so it is a plausible
	// address rather than an obviously malformed one.
	unminted := requests.objectPath
	if i := strings.LastIndex(unminted, "/"); i >= 0 {
		unminted = unminted[:i+1] + "requests-99.99.99-py3-none-any.whl"
	}

	for _, tc := range []refuseCase{
		{
			// #77's headline case: the confused deputy, wearing the PEP 658 shape. An
			// allowed prefix, a blocked package's object, and a signature that is real but
			// covers neither pairing.
			name: "approved prefix + blocked package's object + .metadata",
			path: pypiMetadataURL(requests.pkg, six.objectPath, requests.sig),
			why: "the repair would have to strip the suffix and then verify against something " +
				"other than the (package, object path) pair actually being requested",
		},
		{
			// The same attack with the other signature the attacker holds. This one is
			// authentic for the object being fetched — it just was not minted for the
			// package named in the prefix. It isolates the PACKAGE half of the binding.
			name: "approved prefix + blocked package's object and ITS OWN signature + .metadata",
			path: pypiMetadataURL(requests.pkg, six.objectPath, six.sig),
			why: "the signed tuple would have to omit the package, letting any authentic " +
				"object signature be presented under any prefix",
		},
		{
			// The relaxation's own boundary. The repair strips ONE suffix, so what remains
			// is "<sig>.metadata" — not valid base64url, and not a signature over anything.
			// Attacks the APPROVED package on purpose: nothing but the signature can refuse
			// it, so a pass here is a statement about the signature and only the signature.
			name: "approved package, .metadata appended TWICE",
			path: pypiMetadataURL(requests.pkg, requests.objectPath, requests.sig+pep658Suffix),
			why: "the repair would have to strip the suffix repeatedly (or ignore what is " +
				"left over), turning a fixed one-step derivation into an open-ended one",
		},
		{
			// The derivative of an object that was never authorised. Again the approved
			// package, so grammar and verdict both pass and the signature stands alone.
			name: "approved package, .metadata on a base that was never minted",
			path: pypiMetadataURL(requests.pkg, unminted, requests.sig),
			why: "one signature would have to cover any object path sharing a package, " +
				"rather than the exact path it was minted for",
		},
		{
			// Signing is ON, so every "/_files/" URL is one we minted and must carry a
			// signature. An unsigned one is either a lockfile predating the feature or an
			// attacker declining to present what they cannot forge.
			name: "no signature at all while signing is on",
			path: "/_files/" + requests.pkg + requests.objectPath,
			why:  "an absent signature would have to be treated as an acceptable one",
		},
		{
			// The unsigned request in pip's own shape: with no query to land on, ".metadata"
			// stays on the path. Included because the honest-looking spelling is the one an
			// attacker reaches for after the bare unsigned request is refused.
			name: "no signature, .metadata on the path",
			path: "/_files/" + requests.pkg + requests.objectPath + pep658Suffix,
			why:  "the suffix on the path would have to excuse the request from carrying a signature",
		},
		{
			// The mutation that would arise from putting the repair in the wrong place —
			// stripping ".metadata" off the PATH instead of off the signature. Here the
			// signature is authentic for the base object but the request asks for the
			// derivative directly, so the two disagree about which object is being fetched.
			name: "valid signature for the base, .metadata moved onto the path",
			path: "/_files/" + requests.pkg + requests.objectPath + pep658Suffix + "?_yjsig=" + requests.sig,
			why: "the relaxation would have to extend to a general 'strip .metadata from the " +
				"path' rule, which is not the fixed-address derivation !114 authorised",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, hdr, body := rawGetHeaders(t, fwHost(), fw.port, tc.path)

			if leak := pypiLeak(body); leak != "" {
				t.Errorf("SIGNED-BINDING BYPASS: GET %s returned %d with %d bytes of %s.\n"+
					"For this to happen, %s.\n--- firewall ---\n%s",
					tc.path, code, len(body), leak, tc.why,
					logAround(fw.log.String(), 30, "_files", "signature"))
				return
			}
			// A 2xx carrying nothing recognisable is not a pass: it means the request
			// reached upstream and we merely failed to recognise the response.
			if code >= 200 && code < 300 {
				t.Errorf("GET %s returned %d and was RELAYED (%d bytes) — it must be refused before "+
					"reaching upstream\n--- firewall ---\n%s",
					tc.path, code, len(body), logAround(fw.log.String(), 30, "_files", "signature"))
				return
			}
			// And the refusal has to be OURS, and specifically the SIGNATURE's. An upstream
			// 404 for a path it dislikes is not the binding working; neither is the filename
			// grammar catching a case the signature was supposed to cover. See sigRefusal.
			reason := hdr.Get("X-Yellowjack-Reason")
			switch {
			case reason == "":
				t.Errorf("GET %s was refused with %d but carries no X-Yellowjack-Reason — this is the "+
					"UPSTREAM's refusal, not ours, so the signed binding was never what stopped it\n"+
					"--- firewall ---\n%s",
					tc.path, code, logAround(fw.log.String(), 30, "_files", "signature"))
			case !strings.Contains(reason, sigRefusal):
				t.Errorf("GET %s was refused with %d, but by %q — NOT by the signed binding.\n"+
					"Something else (most likely the filename grammar) is standing in front of the "+
					"signature for this case, so this leg would stay green with signature verification "+
					"removed entirely. The signature is what #77 asks to be measured.\n--- firewall ---\n%s",
					tc.path, code, reason, logAround(fw.log.String(), 30, "_files", "signature"))
			}
		})
	}
}
