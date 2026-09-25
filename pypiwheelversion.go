package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"strings"
)

// The version a PyPI wheel is served AS must be the version it declares (issue #136).
//
// A wheel filename encodes its version — "{name}-{version}-{py}-{abi}-{plat}.whl" — and
// the distribution declares one of its own in its core metadata.
//
// ⚠️ WHETHER pip COMPARES THEM DEPENDS ON THE PATH, AND AN EARLIER VERSION OF THIS
// COMMENT GOT IT WRONG. Resolving from an INDEX with PEP 658 metadata, real pip 26.2.1
// compares them itself and discards the file:
//
//	Discarding …/yjprobe-1.0.0-py3-none-any.whl: Requested yjprobe from … has
//	inconsistent version: expected '1.0.0', but metadata has '9.9.9'
//
// It never requests the wheel. So on the ordinary install path pip is not blind to this,
// and this gate is NOT the only thing standing in the way — a claim to the contrary was
// merged in the first version of this file and is corrected here.
//
// Installing a LOCAL wheel file is where pip really does not compare. Measured against
// real pip 26.2.1 with three crafted wheels, `pip install ./x.whl`:
//
//   - filename 1.0.0, insides 9.9.9: pip installs 9.9.9, silently, exit 0. A pinned
//     requirements.txt records 1.0.0 and the environment has 9.9.9.
//   - filename 1.0.0, only METADATA saying 9.9.9: pip PRINTS "Successfully installed
//     yjprobe-1.0.0" while `pip show` and the importable code both say 9.9.9 — its own
//     success line disagrees with its own metadata store.
//
// On that local-file path pip checks the NAME and not the VERSION: a wheel whose
// .dist-info directory disagrees with the filename's name is rejected outright ("does not
// start with"), while the same wheel with a disagreeing version installs without comment.
//
// SO WHAT IS THIS WORTH, HONESTLY. Not "pip is blind to this" — it is not, where it
// matters most. What this buys is the thing #52 actually argued for: *"when a client-side
// check does fire, it fails on one developer's laptop as a confusing install error the
// security team never hears about … so verifying centrally is mostly NEW VISIBILITY."*
// pip's own refusal is invisible to the operator; ours is a log line and an audit record.
//
// That is why the mismatch is reported when the METADATA is observed rather than only
// when the wheel is fetched. Reporting it only on the byte path would produce nothing at
// all for pip, because pip discards the file first and never asks for the bytes — the
// measurement that forced this design, found by running the e2e leg rather than reasoning
// about it. The byte-path refusal remains for a resolver that reads the metadata without
// checking it.
//
// WHY THE METADATA SIBLING AND NOT THE WHEEL. The obvious implementation reads the
// wheel, and it is the wrong one. A ZIP's authoritative index is its central directory,
// at the END of the file, so a blocking check on the wheel cannot decide from a prefix
// the way npmversion.go does — it would have to hold the whole artifact before releasing
// a byte. Measured: the largest wheel in the latest release of 18 popular packages is
// tensorflow at 572.88 MB, torch at 554.62 MB, median 10.96 MB. That is delayed
// first-byte and held memory for every wheel, against #21's added-latency budget.
//
// PEP 658 publishes the same metadata as a separate small file, and pip fetches it
// BEFORE the wheel to resolve dependencies — measured in !269, where pip's fetch order
// was pre-registered as the detail most likely to be wrong and held. So the document is
// already crossing the gate and nothing extra is fetched: we read what is already
// flowing and remember it, the bind-don't-parse shape D164/!269 established. Measured
// availability on the /simple/ index: 20,051 of 20,054 wheels across twelve packages,
// 99.99%. (The legacy /pypi/<pkg>/json API reports core_metadata as null for every
// wheel and must not be used to re-check this.)
//
// WHAT THIS IS AND IS NOT. It compares the version in the URL against the version the
// INDEX publishes for that file. That is strictly weaker than npmversion.go, which
// compares the URL against the bytes being handed over, and the reason string says so:
// it never claims the artifact was verified. It catches issue #52's actual threat model
// — a wrong file under a right name, from a buggy or stale or substituted upstream —
// and it catches a case pip is structurally exposed to, since pip resolves from this
// metadata without downloading the wheel at all. It does NOT catch an upstream that
// lies consistently in both places. Verifying the sibling against the wheel's own
// central directory is the stronger check and is the one that would need the buffering
// above; it is deliberately not built here.
//
// FALSE POSITIVES WERE MEASURED TWICE, AND THE SECOND DRAW IS THE ONE THAT COUNTS.
// An exact string compare matched 160 of 160 real wheels sampled across 20 popular
// packages. That draw is the one LEAST likely to contain the case that would bite:
// popular packages have well-behaved publishers. So the comparison was measured again
// on a draw selected for version-string ODDITY — 6,818 candidates whose filename
// version carries a pre-release, post-release, dev, epoch or local segment, 140 sampled
// — and that matched 140 of 140 too.
//
// Three hundred agreeing wheels is still not a proof, and the failure mode it would
// miss is the expensive one: a LEGITIMATE wheel refused because its two version strings
// differ only by PEP 440 normalisation. A wheel filename cannot contain "-" at all (it
// is the field separator), so a publisher who writes "1.0.0-rc1" in their metadata gets
// "1.0.0rc1" in the filename and the two strings differ while naming one version. An
// exact compare would refuse that install.
//
// So the comparison deliberately does NOT compare strings. It compares only the numeric
// RELEASE segment, which no normalisation rule can change, and has no opinion when the
// difference is confined to the pre/post/dev/local suffix. That makes a false refusal
// structurally impossible for the whole normalisation class rather than merely
// unobserved in 300 samples — and it costs only the case of a suffix-only
// misrepresentation, which is logged rather than refused and is stated here so it is
// not later mistaken for coverage.

// pypiMetadataInspectBytes bounds how much of a core-metadata document is read before
// giving up on finding a version. Real siblings are a few kilobytes (requests-2.34.2 is
// 4,806 bytes against a 73,075-byte wheel); 1 MiB is ample headroom and keeps a hostile
// upstream from making the gate hold an unbounded document — the #135 rule applied here
// rather than rediscovered.
const pypiMetadataInspectBytes = 1 << 20

// pypiWheelFilenameVersion returns the version a wheel's filename encodes.
//
// The grammar is fixed by PEP 427: "{distribution}-{version}(-{build})?-{python}-{abi}-
// {platform}.whl", with the distribution name normalised so it can never itself contain
// a "-". So the version is the second hyphen-separated field, and the field count tells
// a well-formed name from anything else.
//
// Anything that is not a wheel — an sdist, a signature, a checksum — returns false and
// is simply not checked. sdists are NOT covered: they carry no PEP 658 sibling, so there
// is nothing to compare against, and claiming otherwise would be the code-vs-effect gap
// this project keeps rediscovering.
func pypiWheelFilenameVersion(objectPath string) (string, bool) {
	file := objectPath
	if i := strings.LastIndexByte(file, '/'); i >= 0 {
		file = file[i+1:]
	}
	if !strings.HasSuffix(file, ".whl") {
		return "", false
	}
	parts := strings.Split(strings.TrimSuffix(file, ".whl"), "-")
	// 5 fields without a build tag, 6 with one. Fewer means it is not a wheel name we
	// understand, and guessing at a malformed one is how a reader becomes confidently
	// wrong.
	if len(parts) != 5 && len(parts) != 6 {
		return "", false
	}
	if parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

// pypiDeclaredVersion reads the "Version:" field out of a core-metadata document.
//
// Core metadata is RFC 822-shaped: headers, then a blank line, then the description.
// Only the header block is read, so a description that happens to contain a line
// beginning "Version:" cannot be mistaken for the field.
//
// A document declaring the field more than once yields ok=false rather than a guess.
// That is the npm lesson in a second format: npm's extractor takes the LAST manifest,
// and Python's zipfile returns the LAST entry of a duplicated name (measured — a wheel
// with two METADATA entries installs as the second one). Where a real consumer's
// tie-break is not known, this refuses to have an opinion instead of inventing one, and
// the caller treats "no opinion" as unverified rather than as a mismatch.
func pypiDeclaredVersion(r io.Reader) (string, bool) {
	body, err := io.ReadAll(io.LimitReader(r, pypiMetadataInspectBytes))
	if err != nil && len(body) == 0 {
		return "", false
	}
	version, found := "", 0
	for _, line := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			break // end of the header block; the description follows
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // a folded continuation of the previous header
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "version") {
			continue
		}
		found++
		version = strings.TrimSpace(value)
	}
	if found != 1 || version == "" {
		return "", false
	}
	return version, true
}

// pypiReleaseSegment returns the numeric release part of a PEP 440 version — the
// leading "N(.N)*" run, with trailing zero components trimmed so "1.0" and "1.0.0"
// are the same release.
//
// Everything normalisation is allowed to touch is discarded first: case, a leading "v",
// an epoch ("1!2.0"), a local segment ("+ubuntu1"), and the whole pre/post/dev suffix.
// What remains cannot be rewritten by any normalisation rule, which is the property
// that makes a false refusal impossible rather than merely unobserved.
//
// ok=false means "no opinion" — an unparseable version yields no comparison at all,
// never a mismatch.
func pypiReleaseSegment(version string) ([]int, bool) {
	v := strings.ToLower(strings.TrimSpace(version))
	if i := strings.IndexByte(v, '!'); i >= 0 { // epoch
		v = v[i+1:]
	}
	if i := strings.IndexByte(v, '+'); i >= 0 { // local version
		v = v[:i]
	}
	v = strings.TrimPrefix(v, "v")

	var out []int
	for {
		j := 0
		for j < len(v) && v[j] >= '0' && v[j] <= '9' {
			j++
		}
		if j == 0 {
			break // not a digit run: the pre/post/dev suffix starts here
		}
		n := 0
		for _, c := range v[:j] {
			n = n*10 + int(c-'0')
		}
		out = append(out, n)
		v = v[j:]
		if len(v) == 0 || v[0] != '.' {
			break
		}
		v = v[1:]
	}
	if len(out) == 0 {
		return nil, false
	}
	for len(out) > 1 && out[len(out)-1] == 0 { // "1.0" and "1.0.0" name one release
		out = out[:len(out)-1]
	}
	return out, true
}

// pypiVersionsNameDifferentReleases reports whether two version strings name different
// RELEASES, which is the only disagreement this gate refuses on.
//
// It answers false whenever it cannot be certain — either version unparseable, or the
// difference confined to the suffix normalisation may rewrite. The caller logs those
// cases rather than refusing; see the file comment for why that trade is the right way
// round for a gate.
func pypiVersionsNameDifferentReleases(served, declared string) bool {
	a, okA := pypiReleaseSegment(served)
	b, okB := pypiReleaseSegment(declared)
	if !okA || !okB {
		return false
	}
	if len(a) != len(b) {
		return true
	}
	for i := range a {
		if a[i] != b[i] {
			return true
		}
	}
	return false
}

// relayMetadataRecordingVersion relays a PEP 658 core-metadata document and remembers the
// version it declares for the wheel it belongs to (issue #136).
//
// It is the streamResponse seam its own comment describes: read a bounded prefix, then
// hand the prefix and the remainder on joined, so the client sees byte-identical output
// and the short-transfer accounting still sees the whole body. Nothing here can change
// what the client receives — a document we cannot parse simply records nothing.
func (p *proxyServer) relayMetadataRecordingVersion(w http.ResponseWriter, r *http.Request, target, objectPath, pkg string) {
	resp, srcIP, ok := p.openUpstream(w, r, target, false, flowID{Package: pkg, Kind: flowArtifact})
	if !ok {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK || r.Method == http.MethodHead {
		p.streamResponse(w, r, target, resp, resp.Body, flowID{Package: pkg, Kind: flowArtifact}, srcIP)
		return
	}

	held, readErr := io.ReadAll(io.LimitReader(resp.Body, pypiMetadataInspectBytes))
	if v, found := pypiDeclaredVersion(bytes.NewReader(held)); found {
		if p.pypiFileVersions != nil {
			p.pypiFileVersions.put(objectPath, v)
		}
		// Say it HERE, not only when the wheel is fetched. Measured against real pip
		// 26.2.1: resolving from an index, pip compares these itself and DISCARDS the
		// file ("has inconsistent version: expected '1.0.0', but metadata has '9.9.9'")
		// without ever requesting the wheel. So a refusal on the byte path would never
		// fire for pip, and the operator would learn nothing.
		//
		// That is precisely the gap #52 names: a client-side check "fails on one
		// developer's laptop as a confusing install error the security team never hears
		// about", and verifying centrally is "mostly NEW VISIBILITY". The visibility has
		// to be emitted at the moment we can see it, which is now.
		if served, parsed := pypiWheelFilenameVersion(objectPath); parsed {
			switch {
			case pypiVersionsNameDifferentReleases(served, v):
				log.Printf("GET _files %s -> INDEX DISAGREES: %s is published under version %s but its metadata declares %s; a resolver that checks will discard it, one that does not will be refused the bytes",
					pkg, objectPath, served, v)
			case pypiVersionsDisagreeInSuffixOnly(served, v):
				// Not refused here — see pypiVersionsDisagreeInSuffixOnly — but pip DOES
				// refuse it, so the operator would otherwise hear nothing about a build
				// their developers cannot install.
				log.Printf("GET _files %s -> INDEX DISAGREES: %s is published under version %s but its metadata declares %s; the release is the same so the gate serves it, but pip refuses this as an inconsistent version",
					pkg, objectPath, served, v)
			}
		}
	}
	var body io.Reader = bytes.NewReader(held)
	if readErr == nil {
		body = io.MultiReader(bytes.NewReader(held), resp.Body)
	}
	p.streamResponse(w, r, target, resp, body, flowID{Package: pkg, Kind: flowArtifact}, srcIP)
}

// pypiServedVersionDisagrees reports whether the wheel at objectPath is being served
// under a version that names a different RELEASE than the one its core-metadata sibling
// declared, and returns both versions for the log.
//
// ok=false is the normal case and covers everything uncertain: not a wheel, no sibling
// seen (the client resolved from a cache, or the file has no core-metadata — measured at
// roughly 3 in 20,000), an unparseable version on either side, or a difference confined
// to the suffix normalisation may rewrite. Only a definite release disagreement is a
// finding.
func (p *proxyServer) pypiServedVersionDisagrees(objectPath string) (served, declared string, ok bool) {
	if p.pypiFileVersions == nil {
		return "", "", false
	}
	declared, seen := p.pypiFileVersions.get(objectPath)
	if !seen {
		return "", "", false
	}
	served, parsed := pypiWheelFilenameVersion(objectPath)
	if !parsed {
		return "", "", false
	}
	if !pypiVersionsNameDifferentReleases(served, declared) {
		return "", "", false
	}
	return served, declared, true
}

// pypiVersionSuffix returns everything after the numeric release segment — the
// pre/post/dev/local part — with the separators PEP 440 normalisation is free to move
// removed, and an epoch dropped.
//
// "1.0.0rc1" and "1.0.0-rc1" both yield "rc1"; "1.0.0" yields "". That is the
// distinction pip itself draws, measured below.
func pypiVersionSuffix(version string) string {
	v := strings.ToLower(strings.TrimSpace(version))
	if i := strings.IndexByte(v, '!'); i >= 0 {
		v = v[i+1:]
	}
	v = strings.TrimPrefix(v, "v")
	i := 0
	for i < len(v) && (v[i] >= '0' && v[i] <= '9' || v[i] == '.') {
		i++
	}
	rest := v[i:]
	rest = strings.ReplaceAll(rest, "-", "")
	rest = strings.ReplaceAll(rest, "_", "")
	rest = strings.ReplaceAll(rest, ".", "")
	return rest
}

// pypiVersionsDisagreeInSuffixOnly reports a disagreement pip REJECTS but this gate does
// not refuse: same release, different pre/post/dev segment.
//
// MEASURED AGAINST REAL PIP 26.2.1, resolving from an index, filename against metadata:
//
//	1.0      vs 1.0.0      INSTALLED   (pip parses; trailing zeros are one version)
//	1.0.0rc1 vs 1.0.0-rc1  INSTALLED   (pip parses; separators are one version)
//	1.0.0    vs 1.0.0rc1   REJECTED    "has inconsistent version"
//	1.0.0    vs 9.9.9      REJECTED    "has inconsistent version"
//
// The first two are why the refusal compares release segments rather than strings: an
// exact compare would refuse two builds pip installs, which is the false-refusal half of
// a parser differential (#122) and the expensive direction for a gate.
//
// The third is the case this function exists for. The gate does not refuse it — a suffix
// difference is where a normalisation rule could still surprise us, and refusing is the
// irreversible choice — but pip DOES, so staying silent would leave the operator hearing
// nothing about a build their developers cannot install. Reporting without refusing keeps
// both halves honest: no false refusal, and no silent blind spot where the client is
// stricter than we are.
func pypiVersionsDisagreeInSuffixOnly(served, declared string) bool {
	if pypiVersionsNameDifferentReleases(served, declared) {
		return false // a release difference; the caller reports that more strongly
	}
	if _, ok := pypiReleaseSegment(served); !ok {
		return false
	}
	if _, ok := pypiReleaseSegment(declared); !ok {
		return false
	}
	return pypiVersionSuffix(served) != pypiVersionSuffix(declared)
}
