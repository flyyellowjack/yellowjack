package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"hash"
	"net/http"
	"regexp"
	"strings"
)

// Artifact integrity on relay (#64, variant (a) of that issue's open question).
//
// WHAT THIS IS. The gate streams artifact bytes through verbatim and never looked at
// them, so today it can detect a TRUNCATED transfer (streamResponse's short-transfer
// guard) but never a CORRUPT-BUT-COMPLETE one. This hashes the bytes as they pass and
// compares the result against the digest the request itself names.
//
// WHY OCI FIRST, AND WHY IT IS NOT AN ARBITRARY CHOICE. #64's scope says to thread an
// expected digest from the metadata request to the later byte fetch, reusing the
// identity-threading shape that "/_files/<pkg>/" and "/_tarball/<pkg>/" already solve.
// OCI needs none of that: the registry API puts the digest IN THE BLOB URL
// ("/v2/<name>/blobs/sha256:<hex>"), so the expected value is already in the request
// being served. No table, no cache, nothing to go stale, and nothing that can bind the
// wrong digest to the right bytes. npm's dist.integrity and PyPI's "#sha256=" fragment
// both need recorded state and are deliberately NOT here -- see the MR.
//
// ⚠️ WHAT THIS CANNOT DO, which is the finding worth carrying. A mismatch is a POSITIVE
// FINDING, and D72 says a positive finding blocks bytes even in the permissive default.
// It cannot, here, and no amount of care changes that: the status line and headers are
// committed to the client BEFORE the last byte is read, so by the time the hash is known
// most of the artifact has already been written. This is the identical constraint the
// short-transfer guard hit in the same function, recorded there in the same words.
//
// So the enforcement available is to ABORT THE TRANSFER: stop writing, drop the
// connection, and let the client see a broken download. That is strictly weaker than a
// refusal -- the client got a prefix of a bad artifact rather than a 403 and a reason --
// and it must be described that way rather than as "we block corrupt artifacts". What it
// buys is real all the same: the client's own length or digest check fails instead of
// silently accepting, and the operator gets a log line naming the image, which is the
// visibility half #64 is actually about.
//
// The alternative -- buffer the artifact, verify, then decide -- is ruled out by the
// issue itself: artifacts legitimately run to hundreds of megabytes, and buffering them
// would trade a corruption case for an availability one.

// digestAlgos maps an OCI digest algorithm to its hash and hex length. The length is
// carried explicitly rather than derived, because a well-formed prefix with the wrong
// number of hex characters is exactly what a hand-written or truncated URL looks like,
// and accepting it would hash the body and compare against a value that can never match
// -- a verification failure manufactured by the parser rather than by the bytes.
var digestAlgos = map[string]struct {
	new    func() hash.Hash
	hexLen int
}{
	"sha256": {sha256.New, 64},
	"sha512": {sha512.New, 128},
}

// expectedBlobDigest reads the digest an OCI blob request names for itself.
//
// Returns ok=false for anything that is not a well-formed digest, and that is the
// common case rather than an error: blob UPLOAD paths land in the byte gate by design
// and yield "uploads/<uuid>", a client may address a blob by a shape we do not know, and
// a future algorithm must be unverifiable rather than wrongly verified. Every one of
// those relays exactly as it does today.
func expectedBlobDigest(escapedPath string) (algo, want string, ok bool) {
	ref := ociBlobRef(escapedPath)
	i := strings.IndexByte(ref, ':')
	if i <= 0 {
		return "", "", false
	}
	algo, want = ref[:i], ref[i+1:]
	spec, known := digestAlgos[algo]
	if !known || len(want) != spec.hexLen {
		return "", "", false
	}
	// Registries spell digests in lowercase hex and the spec requires it. Anything
	// else is not a digest we recognise, so it is relayed unverified rather than
	// normalised into one -- normalising here would mean deciding that two different
	// strings name the same blob, which is the registry's call and not ours.
	if _, err := hex.DecodeString(want); err != nil || want != strings.ToLower(want) {
		return "", "", false
	}
	return algo, want, true
}

// verifiableTransfer reports whether THIS response is one whose whole body can be
// compared against a whole-artifact digest.
//
// Each exclusion is a way to make every ordinary pull fail, so they are listed rather
// than folded into one condition:
//
//   - A HEAD carries no body at all (RFC 9110 5.1), so hashing it yields the digest of
//     nothing. This is #108's shape, which already broke the registry-in-front topology
//     once through the short-transfer guard in this same function.
//   - A 206 is a RANGE of the blob. Container clients resume interrupted layers with
//     Range routinely, and a range hashes to something that by construction does not
//     match the whole blob's digest. Verifying it would break exactly the pulls that
//     are already having a bad day.
//   - A non-2xx body is the registry's error document, not an artifact.
//   - A response with a Content-Encoding is the artifact COMPRESSED FOR TRANSPORT, and
//     every published digest is of the decoded file. Measured against Maven Central:
//     asked with "Accept-Encoding: gzip" it gzips a .pom and still sends the
//     X-Checksum-SHA1 of the plain XML. The relay forwards the client's Accept-Encoding
//     and streams the encoded body through untouched, so verifying it would abort every
//     pom fetch of an ordinary mvn resolve.
//
// A request that CARRIES a Range header is excluded even when the registry answers 200
// and ignores the range, because that response is the whole blob and would verify fine
// -- the exclusion is for the case where it does not, and treating the two differently
// on the same request shape would make the check's behaviour depend on the upstream's
// mood.
func verifiableTransfer(r *http.Request, resp *http.Response) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if resp.StatusCode != http.StatusOK {
		return false
	}
	if r.Header.Get("Range") != "" {
		return false
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return false
	}
	return true
}

// integrityCheck hashes the bytes written through it. It is an io.Writer so the caller
// can hand it to io.MultiWriter beside the client, which keeps the single streaming copy
// that #64 requires -- the bytes are never held, only summed.
type integrityCheck struct {
	algo string
	want string
	h    hash.Hash
}

func newIntegrityCheck(algo, want string) *integrityCheck {
	spec, ok := digestAlgos[algo]
	if !ok {
		spec, ok = checksumOnlyAlgos[algo]
	}
	if !ok {
		return nil
	}
	return &integrityCheck{algo: algo, want: want, h: spec.new()}
}

func (c *integrityCheck) Write(p []byte) (int, error) { return c.h.Write(p) }

func (c *integrityCheck) got() string { return hex.EncodeToString(c.h.Sum(nil)) }

// matches reports whether the bytes seen so far sum to the expected digest. Called once,
// after the copy, and only for a transfer that completed -- a short transfer is already
// a failure and comparing its partial sum would report a mismatch whose real cause is
// truncation, which is a different defect with a different fix.
func (c *integrityCheck) matches() bool { return c.got() == c.want }

// ---- PyPI (#64, second ecosystem) ------------------------------------------------------
//
// PyPI's expected digest does NOT travel with the byte request, unlike OCI's. The index
// publishes it -- as a "#sha256=" URL fragment in the PEP 503 HTML form, and as
// files[].hashes.sha256 in the PEP 691 JSON form -- and a fragment is never sent to a
// server, so by the time pip asks for the wheel the digest is gone. It has to be read off
// the index on the way past and remembered, in the same bind-don't-parse table shape the
// interception path already uses for "which package does this file belong to" (D164).
//
// Why this is worth more than the OCI half. Docker and containerd verify a layer's digest
// themselves, so for OCI this check is mostly VISIBILITY. pip verifies nothing unless the
// user runs hash-checking mode, which almost nobody does, so for PyPI a tampered wheel is
// otherwise installed silently. Here the aborted transfer is the only thing standing
// between a corrupt-but-complete wheel and a developer's site-packages.
//
// Coverage, stated rather than implied: the digest is known only for a file whose index
// this replica relayed within the binding TTL. pip fetches the index before every
// resolve, so the ordinary install is covered. A client that fetches a file URL it
// remembered from elsewhere -- a lockfile tool replaying recorded URLs -- finds no entry,
// and that transfer relays unverified, exactly as it did before this existed.

// pypiDigestAlgo is the only algorithm read off a PyPI index. PEP 503 permits others in
// the fragment, but PyPI publishes sha256, and a second algorithm here would be a code
// path no real index exercises -- untested by construction.
const pypiDigestAlgo = "sha256"

// pypiIndexDigests reads each listed file's sha256 from a relayed /simple/ index, keyed
// by its object path on the files host ("/packages/aa/bb/.../x.whl", no query).
//
// Links that are not absolute URLs on the configured files host are skipped rather than
// resolved: a relative link means some other server is answering for PyPI, and guessing
// what it is relative to would bind a digest to the wrong path.
func pypiIndexDigests(body []byte, filesUpstream string) map[string]string {
	prefix := strings.TrimRight(filesUpstream, "/") + "/"
	out := map[string]string{}
	add := func(rawURL, hexDigest string) {
		if !strings.HasPrefix(rawURL, prefix) {
			return
		}
		tail := rawURL[len(prefix):]
		if i := strings.IndexAny(tail, "?#"); i >= 0 {
			tail = tail[:i]
		}
		// Lower-cased on purpose, unlike OCI's refusal of upper-case digests. There the
		// digest is an IDENTIFIER in a path and two spellings would be two names; here it
		// is a hex encoding of bytes, and case carries no meaning.
		want := strings.ToLower(hexDigest)
		if tail == "" || len(want) != 64 {
			return
		}
		if _, err := hex.DecodeString(want); err != nil {
			return
		}
		out["/"+tail] = want
	}

	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && trimmed[0] == '{' {
		var doc struct {
			Files []struct {
				URL    string            `json:"url"`
				Hashes map[string]string `json:"hashes"`
			} `json:"files"`
		}
		if json.Unmarshal(trimmed, &doc) == nil {
			for _, f := range doc.Files {
				add(f.URL, f.Hashes[pypiDigestAlgo])
			}
		}
		return out
	}
	for _, m := range pypiFragmentRe.FindAllSubmatch(body, -1) {
		add(string(m[1]), string(m[2]))
	}
	return out
}

// pypiFragmentRe matches an href's URL up to a "#sha256=<hex>" fragment. The URL half is
// matched loosely and filtered by add(), so the host check lives in one place.
var pypiFragmentRe = regexp.MustCompile(`(https?://[^"'#\s<>]+)#sha256=([0-9a-fA-F]{64})`)

// expectedDigestKey carries a digest the caller learned elsewhere down to the one
// function that streams the body. A context value rather than a new parameter on relay:
// relay has a dozen callers and exactly one of them knows a digest, and the explicit
// attachment is the point -- the PEP 658 metadata sibling of a wheel streams through the
// SAME function, and inferring the digest from the URL there would check a metadata
// document against its wheel's hash and abort every resolve.
type expectedDigestKey struct{}

type expectedDigest struct{ algo, want string }

func withExpectedDigest(r *http.Request, algo, want string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), expectedDigestKey{}, expectedDigest{algo, want}))
}

// expectedDigestFor is the single place streamResponse asks "what should these bytes sum
// to": an explicitly attached digest first, then OCI's self-describing blob URL, then the
// checksum a Maven repository sends on the response itself.
func (p *proxyServer) expectedDigestFor(r *http.Request, resp *http.Response) (algo, want string, ok bool) {
	if d, has := r.Context().Value(expectedDigestKey{}).(expectedDigest); has {
		return d.algo, d.want, true
	}
	switch p.cfg.Ecosystem {
	case "oci":
		return expectedBlobDigest(r.URL.EscapedPath())
	case "maven":
		return mavenHeaderDigest(resp.Header)
	}
	return "", "", false
}

// ---- Maven (#64, third ecosystem) ------------------------------------------------------
//
// Maven publishes a checksum as a SIBLING FILE (x.jar.sha1), which would cost a second
// upstream request per artifact against a registry that has throttled us before (D25).
// It does not have to: Maven Central sends the checksum as a HEADER on the artifact's own
// response -- measured, "X-Checksum-SHA1: 8ac9e16d..." on junit-4.13.2.jar, which is the
// sha1 of the body -- and Artifactory sends X-Checksum-Sha256 as well. So the digest
// arrives with the bytes, costs nothing, and needs no state.
//
// ⚠️ WHAT THAT DOES AND DOES NOT PROVE, stated because it is narrower than the OCI and
// PyPI halves. The header and the bytes come from the SAME response, so a party able to
// rewrite the response -- a hostile mirror, an interceptor in front of the upstream --
// rewrites both and this check passes. What it catches is bytes that no longer match the
// checksum the repository stored for them: corruption or substitution between the
// repository's storage and us, of the kind a CDN edge or a broken intermediary produces.
// Its value over the client's own check is that Maven's DEFAULT checksum policy only
// WARNS on a mismatch (measured in !203), so today that artifact is built into the
// developer's classpath; here the transfer is aborted instead.
//
// A response with no checksum header -- a repository that does not send one -- relays
// unverified exactly as before, which is a coverage gap and not a verdict.

// checksumOnlyAlgos are algorithms accepted from a repository's checksum header and from
// nowhere else. sha1 is here, and NOT in digestAlgos, because digestAlgos also decides
// what an OCI blob URL may name, and the OCI spec registers no sha1: adding it there
// would quietly widen the OCI parser to accept a digest no registry issues.
var checksumOnlyAlgos = map[string]struct {
	new    func() hash.Hash
	hexLen int
}{
	"sha1": {sha1.New, 40},
}

// mavenChecksumHeaders is read strongest first, so a repository that sends both is
// checked against sha256. MD5 is sent too and deliberately never read: a check built on
// it would verify against a hash that is broken for exactly the substitution case.
var mavenChecksumHeaders = []struct{ header, algo string }{
	{"X-Checksum-Sha256", "sha256"},
	{"X-Checksum-Sha1", "sha1"},
}

// mavenHeaderDigest reads the strongest well-formed checksum header. Hex is lower-cased,
// as for PyPI and for the same reason: it encodes bytes, and case carries no meaning.
// A malformed value is skipped rather than failing the check, so a repository that
// spells one header oddly still gets checked against the other.
func mavenHeaderDigest(h http.Header) (algo, want string, ok bool) {
	for _, c := range mavenChecksumHeaders {
		v := strings.ToLower(strings.TrimSpace(h.Get(c.header)))
		spec, known := digestAlgos[c.algo]
		if !known {
			spec = checksumOnlyAlgos[c.algo]
		}
		if len(v) != spec.hexLen {
			continue
		}
		if _, err := hex.DecodeString(v); err != nil {
			continue
		}
		return c.algo, v, true
	}
	return "", "", false
}
