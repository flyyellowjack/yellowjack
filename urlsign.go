package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// Signed artifact URLs — the general fix for issue #67's confused deputy (D103).
//
// Both byte routes mint an artifact URL that carries the authoritative package name
// as a path segment and peels it back off at fetch time: PyPI's "/_files/<pkg>/<object
// path>" and npm's "/_tarball/<pkg>/<object path>". The <pkg> prefix says which
// package we are about to DECIDE about; the object path says which bytes come back.
// Nothing tied the two together, so a client could pair an allowed package's prefix
// with a blocked package's object path and be handed the blocked bytes under a verdict
// rendered about something else.
//
// PyPI closed this with a grammar check (pypiFilenameBindsToPackage): its filenames
// are predictable enough to bind a file to a package. That check stays. npm's tarball
// paths offer no equivalent purchase, and D101 declined to guess at one.
//
// A signature needs no grammar. We sign the (ecosystem, package, object path) TUPLE
// when we mint the URL and verify it when the bytes are fetched, so the pairing is
// something we asserted rather than something we infer.
//
// # This is a BINDING, not an authorisation — the load-bearing distinction
//
// The signature proves "we minted this pkg/path pair", and deliberately says NOTHING
// about the verdict. The verdict is still re-evaluated on every byte fetch, exactly as
// before (proxyToFiles, proxyArtifactBytes). That is what makes the design work at all,
// because a signed URL's real lifetime is not ours to choose: npm records it in
// package-lock.json as "resolved", and `npm ci` replays it weeks or months later, in
// CI, on a machine that never fetched the packument. Had we signed an ALLOW, that
// lockfile would carry a stale grant that outlived the decision behind it —
// proxyArtifactBytes already names this failure ("can never go stale the way a signed
// allow-token minted at metadata time could"), and it is why the byte gate re-evaluates.
//
// Two consequences fall out of that choice, and both are the reason there is no expiry
// here:
//
//   - Replay is not a threat. Replaying a signed URL gets you a fresh evaluation of the
//     package it names. If the package was blocked in the meantime, the replay is
//     refused — the signature never spoke to that question.
//   - Revocation still works, because nothing was granted at mint time. Blocking a
//     package takes effect on the next fetch, including fetches of URLs minted long
//     before.
//
// So an expiry would buy no security property we do not already have, while breaking
// `npm ci` on any lockfile older than the window. The one thing a short lifetime would
// bound is the damage from a LEAKED SIGNING KEY — and a leaked key is recovered from by
// rotating it (below), which is both faster and complete, rather than by waiting out a
// timer. Deliberately no expiry; see docs/DECISIONS.md.
//
// # Opt-in
//
// Per D103 this is opt-in: with no key configured there is no signer, and the byte
// routes behave exactly as they do today. The absent-key case is a first-class
// supported configuration, not a degraded one — the default install must keep needing
// no secret at all.

// minSigningKeyLen is the shortest key we accept. A signature is only as good as the
// key behind it, and an operator who sets FW_URL_SIGNING_KEY=secret should be told at
// startup rather than left with a forgeable binding that looks like a working feature.
const minSigningKeyLen = 16

// sigLen is how many bytes of the HMAC tag we keep. 16 bytes (128 bits) is far beyond
// forgery reach and keeps the URL — which lands in lockfiles people read — short.
const sigLen = 16

// urlSigner signs and verifies the (ecosystem, package, object path) binding.
//
// A nil *urlSigner means the feature is off. Its Verify returns FALSE rather than true,
// so a call site that forgets to check Enabled() fails CLOSED and shows up immediately,
// instead of silently verifying nothing — the "check that can only report green"
// failure this project keeps having to dig out.
type urlSigner struct {
	// mint is the key new URLs are signed with. accept holds every key a presented
	// signature may be verified against — mint first, then any previous key.
	//
	// The previous key is what makes rotation survivable: lockfiles minted under the
	// old key are still in flight (that is the whole point of the lockfile-replay case
	// above), so an operator rotates by moving the old key to FW_URL_SIGNING_KEY_PREVIOUS,
	// letting in-flight lockfiles verify, and dropping it once they have aged out.
	// Without it, rotation would break every existing lockfile at the instant it happened.
	mint   []byte
	accept [][]byte
}

// newURLSigner builds a signer from the injected key material. An empty current key
// means the feature is off and returns (nil, nil) — the supported default, not an error.
func newURLSigner(current, previous string) (*urlSigner, error) {
	if current == "" {
		if previous != "" {
			// A previous key with no current key cannot mint anything, so this is
			// almost certainly a half-finished rotation rather than an intent to
			// disable. Say so instead of silently running unsigned.
			return nil, fmt.Errorf("FW_URL_SIGNING_KEY_PREVIOUS is set but FW_URL_SIGNING_KEY is empty: " +
				"signing is off and previously minted URLs cannot be verified")
		}
		return nil, nil
	}
	if len(current) < minSigningKeyLen {
		return nil, fmt.Errorf("FW_URL_SIGNING_KEY must be at least %d bytes, got %d", minSigningKeyLen, len(current))
	}
	s := &urlSigner{mint: []byte(current)}
	s.accept = append(s.accept, s.mint)
	if previous != "" {
		if len(previous) < minSigningKeyLen {
			return nil, fmt.Errorf("FW_URL_SIGNING_KEY_PREVIOUS must be at least %d bytes, got %d", minSigningKeyLen, len(previous))
		}
		s.accept = append(s.accept, []byte(previous))
	}
	return s, nil
}

// Enabled reports whether URL signing is configured. Safe on a nil receiver so call
// sites can ask without a preceding nil check.
func (s *urlSigner) Enabled() bool { return s != nil }

// signingInput builds the canonical message the HMAC covers.
//
// Each field is LENGTH-PREFIXED rather than joined by a separator, because a separator
// can be forged into a field. Plain concatenation would make ("a", "bc") and ("ab", "c")
// the same message, so a package name ending in the separator could claim an object path
// that was never signed with it — which is the very confusing-of-two-fields this whole
// file exists to prevent. Length prefixes make the parse unambiguous for any input,
// including names carrying slashes, NULs or percent-encoding.
func signingInput(ecosystem, pkg, objectPath string) []byte {
	var b bytes.Buffer
	for _, field := range []string{ecosystem, pkg, objectPath} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(field)))
		b.Write(n[:])
		b.WriteString(field)
	}
	return b.Bytes()
}

func tag(key []byte, ecosystem, pkg, objectPath string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(signingInput(ecosystem, pkg, objectPath))
	return m.Sum(nil)[:sigLen]
}

// Sign returns the signature for one artifact URL, base64url with no padding so it is
// safe in a path segment and in a lockfile. Empty when signing is off.
//
// The ecosystem is part of the signed tuple so a signature minted by an npm deployment
// cannot be presented to a PyPI one that happens to share a key.
func (s *urlSigner) Sign(ecosystem, pkg, objectPath string) string {
	if s == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(tag(s.mint, ecosystem, pkg, objectPath))
}

// sigParam is the query parameter the signature rides in.
//
// A query parameter rather than a path segment, deliberately: the artifact path shapes
// ("/_tarball/<pkg>/…", "/_files/<pkg>/…") are parsed by npmArtifactPath, proxyToFiles
// and the path guard, all of which are load-bearing and well covered. Threading a new
// segment through them would put the blast radius of this change inside that parsing;
// a query parameter leaves every one of those paths byte-identical and confines the
// change to minting and one verification step.
const sigParam = "_yjsig"

// pep658MetadataSuffix is what pip appends to a distribution's URL to fetch its METADATA
// file without downloading the distribution (PEP 658 / PEP 714).
//
// It is appended to the WHOLE URL, query included, so on a signed link it lands on the
// signature rather than on the path. proxyToFiles repairs that; the constant lives here
// because it is a property of how the signature is carried, not of PyPI's index format.
const pep658MetadataSuffix = ".metadata"

// appendSignature adds the signature to a minted artifact URL, preserving any query
// string the upstream URL already carried.
func appendSignature(rawURL, sig string) string {
	if sig == "" {
		return rawURL
	}
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + sigParam + "=" + sig
}

// takeSignature pulls the signature out of a raw query string and returns it along with
// the query as it should be FORWARDED UPSTREAM — that is, with our parameter removed.
// The upstream registry never sees a parameter it did not issue.
//
// Other parameters are preserved in their original order, so this cannot disturb an
// upstream URL that legitimately carries a query.
func takeSignature(rawQuery string) (sig, forwarded string) {
	if rawQuery == "" {
		return "", ""
	}
	parts := strings.Split(rawQuery, "&")
	kept := parts[:0]
	for _, part := range parts {
		if part == sigParam || strings.HasPrefix(part, sigParam+"=") {
			// Last one wins, matching how a duplicated parameter would be read anyway;
			// a mismatched duplicate simply fails to verify.
			sig = strings.TrimPrefix(strings.TrimPrefix(part, sigParam), "=")
			continue
		}
		kept = append(kept, part)
	}
	return sig, strings.Join(kept, "&")
}

// Verify reports whether sig is a signature this deployment minted for exactly this
// (ecosystem, package, object path) tuple. False on a nil signer — see the type comment.
func (s *urlSigner) Verify(ecosystem, pkg, objectPath, sig string) bool {
	if s == nil {
		return false
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(got) != sigLen {
		return false
	}
	// Every accepted key is tried, and the comparison is constant-time, so neither the
	// outcome nor the timing tells an attacker which key matched or how far a guess got.
	ok := false
	for _, k := range s.accept {
		if hmac.Equal(got, tag(k, ecosystem, pkg, objectPath)) {
			ok = true
		}
	}
	return ok
}
