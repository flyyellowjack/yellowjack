package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The OCI source-repo resolution lives here (separate from the small ecosystem
// glue in ecosystem.go) because it's the most involved ecosystem: it speaks the
// OCI distribution protocol, handles the registry's bearer-token auth dance, and
// follows multi-arch manifest indexes to reach the image config blob — whose
// org.opencontainers.image.source label is the source repo Scorecard needs.

// ociManifestAccept advertises every manifest media type we can parse: both OCI
// and Docker schema2, and both single-image manifests and multi-arch indexes.
const ociManifestAccept = "application/vnd.oci.image.index.v1+json, " +
	"application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.docker.distribution.manifest.v2+json"

// ociManifest is the slice of a manifest (or index) we read: the config blob
// pointer (single-image manifest), the child list (index), and any annotations.
type ociManifest struct {
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Manifests []struct {
		Digest string `json:"digest"`
		// Platform is parsed ONLY to tell a pullable platform image from a buildx
		// ATTESTATION manifest, which declares the placeholder platform
		// unknown/unknown. Nothing selects a platform here: the gate binds every
		// architecture (#126), it does not choose one.
		Platform struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		} `json:"platform"`
	} `json:"manifests"`
	// Layers is parsed ONLY so an approved manifest can enumerate the blobs that
	// belong to it (D164). Nothing scores a layer; the digests are the binding
	// between "this version was approved" and "these bytes may be served".
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
	Annotations map[string]string `json:"annotations"`
}

// ociImageConfig is the slice of an image config blob carrying the labels.
type ociImageConfig struct {
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"config"`
}

// ociBlobBindingTTL bounds how long an approved manifest keeps vouching for its
// blobs. It is short on purpose: the binding is a fan-out optimisation for the
// pull that is happening NOW (one manifest, then its layers, seconds apart), not a
// durable record of approval. Letting it live longer would start to resemble the
// approval store D164 says belongs at the version level in real storage.
const ociBlobBindingTTL = 10 * time.Minute

// ociBlobBindings maps a blob digest -> the versioned image identity whose manifest
// enumerated it. This is the binding D164 calls for:
//
//  1. approve a manifest digest;
//  2. record its config + layer digest set;
//  3. admit a blob request only if its digest is in an approved set.
//
// WHY IT IS NEEDED AT ALL. Once a verdict is keyed to a VERSION, the two halves of
// the OCI gate stop speaking the same language: a manifest request carries a
// reference ("/v2/nginx/manifests/v2") but a blob request carries only a digest
// ("/v2/nginx/blobs/sha256:…"). Without a binding the byte gate would fall back to
// judging the bare image name — i.e. "latest" — so under FW_BYTE_GATE=enforce a
// BLOCKED version could still have its layers served because a DIFFERENT version of
// the same name is allowed. The binding is what stops the version fix from opening
// that hole; the two must land together.
//
// It is deliberately ADDITIVE. A digest we have never seen is not refused here — it
// falls back to the bare-image identity, which is exactly the behaviour that shipped
// before this existed. So a client with a locally cached manifest, one resuming a
// partial layer, or `crane blob` reading a layer cold is judged no more harshly than
// it is today. Turning an unknown digest into a refusal is a stricter posture that
// would break working pulls, so it is a separate, ruled decision — not a side effect
// of fixing the version defect.
type ociBlobBindings = ttlLRU[string]

func newOCIBlobBindings() *ociBlobBindings {
	return newTTLLRU[string](ociBlobBindingTTL, 0)
}

// bindBlobs records every blob the manifest enumerates as belonging to pkg. Called
// on the resolution path, where the manifest is already in hand, so it costs no
// extra fetch. Digests are validated before being stored: they are about to be
// compared against a client-supplied path, and a malformed one from a hostile or
// corrupt registry has no business becoming a lookup key.
func (e ociEcosystem) bindBlobs(pkg string, man ociManifest) {
	if e.bindings == nil {
		return
	}
	image, _ := ociSplitRef(pkg)
	record := func(d string) {
		if d != "" && validOCIRef(d) {
			e.bindings.put(ociBindingKey(image, d), pkg)
		}
	}
	record(man.Config.Digest)
	for _, l := range man.Layers {
		record(l.Digest)
	}
}

// boundPackage returns the versioned identity that vouched for a blob digest.
func (e ociEcosystem) boundPackage(image, digest string) (string, bool) {
	if e.bindings == nil || digest == "" {
		return "", false
	}
	return e.bindings.get(ociBindingKey(image, digest))
}

// ociBindingKey scopes a binding to the repository it was observed under.
//
// Keying on the digest ALONE is wrong, and the mode matrix proves it rather than
// this comment asserting it: the same blob is legitimately reachable under several
// repository names (shared base layers, cross-repo mount), so a global digest map
// lets a binding recorded for one image decide a request for another. That is the
// same rule ociBlobPath already states — the client asked for this blob under THIS
// name, so that is the identity whose policy applies. Two names for one blob are
// two independent decisions, by design.
func ociBindingKey(image, digest string) string {
	return image + "@" + digest
}

// ociJoinRef renders image + reference in Docker's own canonical spelling —
// "name:tag" or "name@sha256:…" — so the identity that reaches a verdict, the
// approval queue, the audit record and the logs is the one an operator would type.
//
// D164 is why the reference is part of the identity at all: "we should always
// architect based on the idea that we're verifying package versions, not packages
// themselves in perpetuity." A tag is a mutable pointer, so a verdict recorded
// against a bare image name is a verdict about whatever that name meant once.
//
// An empty reference falls back to "latest" rather than returning "": a bare "" from
// PackageNameFromPath means "pass this through ungated", and inventing a new ungated
// path out of a malformed request is how a bypass gets added by accident. This keeps
// the gated surface exactly as wide as it was.
// ociDigestFromTag recognises a digest spelled in TAG position -- "sha256-<64 hex>" --
// and returns it in digest form. That spelling is the OCI 1.1 referrers-tag fallback
// (and cosign's signature-tag convention): a request for manifests/sha256-<hex> is a
// lookup ABOUT the image whose manifest digest is <hex>, and it arrived through a
// registry:2 pull-through cache in the #98 run (issue #109). Read as a tag it named
// nothing we had seen: the lookup fetched manifests/sha256-<hex> for the config label,
// got a 404, and filed an image scored seconds earlier as UNSCORABLE -- waved through
// under fail-open, refused under fail-closed. The verdict must follow the image the
// digest names; the RELAY still forwards the client's path verbatim, because the
// tag's content -- a referrers index, a signature, or nothing -- is what was asked for.
//
// Only the exact shape qualifies. cosign's "sha256-<hex>.sig" / ".att" / ".sbom" are
// TAGS that live beside the image and must stay tags; so must a shorter or non-hex
// suffix, and the uppercase spellings a digest grammar does not admit.
func ociDigestFromTag(ref string) (string, bool) {
	const prefix = "sha256-"
	if len(ref) != len(prefix)+64 || !strings.HasPrefix(ref, prefix) {
		return "", false
	}
	for i := len(prefix); i < len(ref); i++ {
		c := ref[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", false
		}
	}
	return "sha256:" + ref[len(prefix):], true
}

// ociDigestRepoTTL bounds how long a manifest digest remembers the repo it resolved
// to. A digest names immutable content, so the answer never goes stale; the TTL only
// keeps a long-lived firewall's map from growing without bound.
const ociDigestRepoTTL = time.Hour

// ociMaxIndexChildren bounds how many children of a multi-arch index we will fetch to
// bind their layers (#126). Every child costs one small manifest fetch on a cold
// resolve, and resolution is coalesced and cached, so this is once per image version
// rather than per request. Real indexes list roughly a dozen platforms plus a matching
// set of attestation manifests; the cap exists so a hostile index cannot turn one
// resolve into thousands of fetches.
const ociMaxIndexChildren = 32

// ociAttestationChild reports whether an index child is a buildx ATTESTATION manifest
// rather than a pullable platform image.
//
// WHAT IT DECIDES IS ONE THING ONLY: whether the child is FETCHED. Fetching every
// child (#126) costs one manifest request each on a cold resolve, and MEASURED on
// Docker Hub exactly half of every real index is attestations -- alpine:3.20,
// nginx:stable and python:3.12-slim are 8 platforms + 8 attestations each,
// node:22-alpine is 5 + 5, golang:1.23 is 9 + 7. Not fetching them halves the registry
// requests a cold resolve makes, which matters because the anonymous pull budget is the
// documented way this suite has been taken down before (see scripts/dev.sh, the
// 2026-08-31 incident behind #106).
//
// WHY NOT FETCHING IS SAFE, stated rather than assumed. An attestation manifest's blobs
// are in-toto SBOM and provenance DOCUMENTS ABOUT the image, not the image: they carry
// none of the software a blocked version would deliver. So an unbound attestation BLOB
// falls back to the bare image name exactly as it did before #126, and the bytes that
// fallback can serve are metadata, never executable content. Binding every child that
// can deliver CODE is what D164 asks for, and that is unchanged.
//
// IT DOES NOT DECIDE WHETHER THE CHILD IS BOUND, and the difference is #129. The
// attestation MANIFEST's own digest is recorded in `seen` regardless, because the
// Docker daemon requests it by digest on every pull and an unrecorded digest resolves
// no repo, reads as unscorable and refuses the whole pull. Binding needs no fetch --
// the digest is already in the index we parsed -- so the cost argument above does not
// reach it. Do not "tidy" the two back together: a reader who sees one skip naturally
// assumes the other.
//
// The marker is the OCI/buildx convention: a placeholder platform of unknown/unknown.
// A child that declares neither is NOT treated as an attestation -- the test is for the
// explicit placeholder, so an index that omits platform information keeps its binding.
func ociAttestationChild(os, arch string) bool {
	return strings.EqualFold(strings.TrimSpace(os), "unknown") &&
		strings.EqualFold(strings.TrimSpace(arch), "unknown")
}

// ociManifestMaxBytes bounds a single manifest or index read. Real ones are a few
// KB; the cap only stops a hostile registry streaming an unbounded body into the
// hash below. Past it the JSON is truncated, fails to parse, and the lookup fails
// closed.
const ociManifestMaxBytes = 4 << 20

// ociConfigMaxBytes bounds the config blob, which is the read this pair was missing
// (#135) — and it was the worse omission of the two, because the manifest is capped
// and the blob it POINTS AT is uploaded by the image publisher.
//
// The cost of leaving it open was measured, not argued: decoding a well-formed
// config with a large Labels map through the real ociImageConfig type grows the heap
// by about 5.6x the body — a 76.1 MB blob becomes 429.3 MB, against the 60.8 MiB
// idle footprint #21 measures for the whole firewall. The 10s client timeout bounds
// DURATION, not bytes, and 10s is ample for that body on an ordinary link.
//
// 4 MB matches the manifest cap and is enormous for this document: real image
// configs measure in the hundreds of BYTES (240–372 across the images on the dev
// host), and even a long history and rootfs list stays in the low tens of KB.
const ociConfigMaxBytes = 4 << 20

func ociJoinRef(name, ref string) string {
	if ref == "" {
		ref = "latest"
	}
	if d, ok := ociDigestFromTag(ref); ok {
		ref = d // a digest in tag position is the digest (#109)
	}
	if strings.Contains(ref, ":") { // already a digest, e.g. "sha256:abc…"
		return name + "@" + ref
	}
	return name + ":" + ref
}

// ociSplitRef is ociJoinRef's inverse. Per the distribution spec's name grammar a
// repository name may contain "/" but never ":" or "@", so the LAST separator is
// unambiguous and no escaping is needed. A name with neither is read as "latest",
// which is what a bare `docker pull nginx` means.
func ociSplitRef(pkg string) (image, ref string) {
	if i := strings.LastIndex(pkg, "@"); i > 0 {
		return pkg[:i], pkg[i+1:]
	}
	if i := strings.LastIndex(pkg, ":"); i > 0 {
		return pkg[:i], pkg[i+1:]
	}
	return pkg, "latest"
}

const ociSourceLabel = "org.opencontainers.image.source"

// LookupRepo resolves an image's declared source repo. Flow: get a pull token,
// fetch the manifest (following an index to a concrete manifest), check
// manifest-level annotations, then read the config blob's source label. Returns
// "" (no error) when no usable source repo is declared — which becomes
// "unscorable" and is quarantined under the fail-closed default.
func (e ociEcosystem) LookupRepo(c *http.Client, pkg string) (string, error) {
	// The caller's identity carries the version (D164). Before this, ref was
	// hard-coded to "latest", so every verdict described whatever that tag pointed
	// at — meaning anyone who controlled ONE tag on an image could decide which
	// version we judged, while the client pulled a different one.
	image, ref := ociSplitRef(pkg)

	// Validate BEFORE the name becomes a URL (issue #17). The #59 path guard already
	// refuses paths that are ambiguous about which package they address; this is the
	// narrower question of whether the name is a legal OCI name at all, which the
	// guard deliberately does not ask.
	if err := checkOCITarget(image, ref); err != nil {
		return "", err
	}

	// A digest names IMMUTABLE content, so a repo resolved under it once is the
	// answer for as long as we remember it (#109). This is what makes a warm pull
	// through a pull-through cache -- which revalidates by digest -- cost nothing: the
	// tag's evaluation already read this manifest and recorded its digest below.
	byDigest := strings.Contains(ref, ":")
	if byDigest && e.repoByDigest != nil {
		if repo, ok := e.repoByDigest.get(ociBindingKey(image, ref)); ok {
			return repo, nil
		}
	}

	repo, seen, err := e.resolveRepo(c, pkg, image, ref)
	if err != nil {
		return "", err
	}
	if e.repoByDigest != nil {
		for _, d := range seen {
			e.repoByDigest.put(ociBindingKey(image, d), repo)
		}
	}
	return repo, nil
}

// resolveRepo is LookupRepo's network half: token, manifest (following an index to
// a concrete manifest), annotations, then the config blob's source label. It returns
// every manifest digest it read on the way -- the index's and the child's -- so the
// caller can remember the answer under each of them.
func (e ociEcosystem) resolveRepo(c *http.Client, pkg, image, ref string) (string, []string, error) {
	token, err := e.ociToken(c, image, ref)
	if err != nil {
		return "", nil, err
	}

	man, dig, err := e.ociFetchManifest(c, image, ref, token)
	if errors.Is(err, errOCIUnauthorized) && token != "" {
		// The token came from the cache and the registry no longer honours it
		// (ocitoken.go). Forget it, fetch once, try once. Never loops: a fresh token
		// refused again is the registry's answer, and it is returned.
		e.forgetToken(image)
		if token, err = e.ociToken(c, image, ref); err != nil {
			return "", nil, err
		}
		man, dig, err = e.ociFetchManifest(c, image, ref, token)
	}
	if err != nil {
		return "", nil, err
	}
	seen := []string{dig}
	// Record the blobs this manifest enumerates BEFORE any early return: the
	// annotation shortcut below skips the config read, but the byte gate still needs
	// to know which layers belong to this version (D164).
	e.bindBlobs(pkg, man)

	if repo := normalizeGitHub(man.Annotations[ociSourceLabel]); repo != "" {
		return repo, seen, nil
	}

	// Multi-arch index: follow the children to reach a config blob, and bind the
	// layers of EVERY one of them.
	//
	// Binding only the first child was a bypass (#126). D164's rule is that an
	// approved VERSION vouches for its layers, and for a multi-arch image the approved
	// version IS the index -- so it has to vouch for every byte it can deliver, not
	// just the first platform's. Measured before the fix: with an index whose children
	// are amd64 then arm64, a BLOCKED tag's amd64 layer was refused (403) and its arm64
	// layer was served byte-for-byte (200), because the arm64 layer was never bound and
	// fell back to the bare image name in proxy.go. The first child is conventionally
	// linux/amd64, so the protection covered amd64 and left every ARM client exposed.
	if man.Config.Digest == "" && len(man.Manifests) > 0 {
		children := man.Manifests
		if len(children) > ociMaxIndexChildren {
			// Nothing stops a hostile or broken registry returning an index with
			// thousands of entries, and each one costs a fetch. Real indexes run to
			// roughly a dozen platforms plus a matching set of attestation manifests.
			log.Printf("oci %s: index lists %d children, binding the first %d (the rest keep the "+
				"pre-#126 fallback to the bare image name)", pkg, len(children), ociMaxIndexChildren)
			children = children[:ociMaxIndexChildren]
		}

		var firstMan ociManifest
		var firstDig string
		attestations, boundAttestations := 0, 0
		for i, child := range children {
			// An attestation manifest carries in-toto documents ABOUT the image, never
			// the image's own layers, so it is not FETCHED -- half the children of a
			// real index, hence half the registry requests (#126). Never skipped for
			// i == 0: that child is where the source label comes from and keeps its
			// pre-#126 behaviour exactly, and no real index puts an attestation first.
			//
			// It IS still bound, and binding costs nothing here: the digest is already
			// in the index bytes we parsed, so recording it is a map write rather than
			// a request. Not binding it was #129. The Docker daemon GETs these
			// manifests on every pull, so with no entry the digest resolved no repo,
			// read as UNSCORABLE, and the default block policy refused the pull of a
			// perfectly good image -- AFTER every real layer had already been served.
			// 16 of 16 Docker Hub official images sampled carry attestations, this
			// tree's own registry:2 and verdaccio among them. crane never asks for
			// one, which is why every OCI e2e leg was green throughout.
			//
			// The digest recorded is the one the INDEX declares, not one a fetch
			// confirmed. That is the index's own trust level, and we verified the
			// index: a child digest inside it cannot change without changing the index
			// digest. It still gets the grammar check, being an upstream-supplied
			// string on its way to a map key (#17).
			if i > 0 && ociAttestationChild(child.Platform.OS, child.Platform.Architecture) {
				attestations++
				if !validOCIRef(child.Digest) {
					log.Printf("oci %s: attestation child %d has malformed digest %q, left unbound", pkg, i, child.Digest)
					continue
				}
				seen = append(seen, child.Digest)
				boundAttestations++
				continue
			}
			// This digest comes from the UPSTREAM response, not the client, and is
			// about to be interpolated into a URL exactly like a client-supplied ref.
			// A hostile or corrupt registry is inside the threat model of a gate whose
			// whole job is distrusting what it fetches, so it gets the same grammar
			// check (#17).
			if !validOCIRef(child.Digest) {
				if i == 0 {
					return "", nil, fmt.Errorf("%w: registry returned child manifest digest %q for %q", errOCIMalformedRef, child.Digest, image)
				}
				// A later child being malformed is not a reason to fail a resolve that
				// worked before this change; it loses that child's binding and says so.
				log.Printf("oci %s: child %d has malformed digest %q, left unbound", pkg, i, child.Digest)
				continue
			}
			cman, cdig, cerr := e.ociFetchManifest(c, image, child.Digest, token)
			if cerr != nil {
				if i == 0 {
					return "", nil, cerr
				}
				// Same reasoning: the FIRST child is load-bearing for the source label
				// and keeps its old error behaviour exactly. The others are additive --
				// an attestation manifest that 404s must not break a working resolve.
				log.Printf("oci %s: child %d (%s) unreadable, left unbound: %v", pkg, i, child.Digest, cerr)
				continue
			}
			seen = append(seen, cdig)
			// The child manifest carries the real layer set for its architecture; the
			// index above enumerated manifests, not blobs.
			e.bindBlobs(pkg, cman)
			if i == 0 {
				firstMan, firstDig = cman, cdig
			}
		}
		if attestations > 0 {
			// Counted separately because the two bindings are not the same thing: a
			// platform child was fetched and vouches for its LAYERS, an attestation
			// child was not fetched and vouches only for ITSELF (#129).
			log.Printf("oci %s: bound %d platform child(ren) with their layers, and %d of %d "+
				"attestation manifest(s) by identity alone (not fetched)",
				pkg, len(seen)-1-boundAttestations, boundAttestations, attestations)
		}
		if firstDig == "" {
			return "", seen, nil // no readable child to take a label from
		}
		man, dig = firstMan, firstDig

		if repo := normalizeGitHub(man.Annotations[ociSourceLabel]); repo != "" {
			return repo, seen, nil
		}
	}
	if man.Config.Digest == "" {
		return "", seen, nil // nothing to read labels from
	}
	if !validOCIRef(man.Config.Digest) {
		return "", nil, fmt.Errorf("%w: registry returned config digest %q for %q", errOCIMalformedRef, man.Config.Digest, image)
	}

	cfg, err := e.ociFetchConfig(c, image, man.Config.Digest, token)
	if err != nil {
		return "", nil, err
	}
	repo := normalizeGitHub(cfg.Config.Labels[ociSourceLabel])
	if repo == "" {
		noteUnsupportedForge("oci", pkg, man.Annotations[ociSourceLabel], cfg.Config.Labels[ociSourceLabel])
	}
	return repo, seen, nil
}

// ociTransient maps the registry statuses that mean "try again later" onto the shared
// sentinel taxonomy, and returns nil for everything else so each caller keeps its own
// specific error message.
//
// Without this, every non-OK status collapsed into a plain fmt.Errorf carrying no
// sentinel, so the firewall read a transient registry outage as "could not determine
// the source repository" — i.e. UNSCORABLE. That is a verdict about the image, and it
// is the wrong one in both directions: under the default byte gate an unscorable soft
// deny SERVES the layer (the #60 bypass, reachable again by a different route), and
// under enforce it returns a 403, dressing a passing outage up as a permanent refusal
// that a client is entitled to treat as final.
//
// Deliberately NARROWER than classifyStatus, which also maps 404 to errPkgNotFound.
// That mapping means "the package does not exist, so pass the request through and let
// the registry answer" — correct for a missing package, wrong here: a missing CONFIG
// BLOB would turn a corrupt or hostile image into an ungated relay.
func ociTransient(status int) error {
	if status == http.StatusTooManyRequests || status >= 500 {
		return classifyStatus(status)
	}
	return nil
}

// ociToken performs the registry auth dance: probe the manifest endpoint
// unauthenticated; if the registry answers 401 with a Bearer challenge, fetch a
// pull-scoped token from the realm it names. Returns "" (no error) when the
// registry needs no auth.
func (e ociEcosystem) ociToken(c *http.Client, image, ref string) (string, error) {
	// A token this image was issued recently is still good (ocitoken.go); presenting
	// it skips the probe and the token endpoint. "" is a real cached answer too: the
	// registry needed no auth, and the probe that learned so need not be repeated.
	if tok, ok := e.cachedToken(image); ok {
		return tok, nil
	}
	tok, expiresIn, err := e.fetchToken(c, image, ref)
	if err != nil {
		return "", err
	}
	e.rememberToken(image, tok, expiresIn)
	return tok, nil
}

// fetchToken is the network half of ociToken: the probe, and the token endpoint if the
// probe is challenged. Returns the token ("" for an anonymous registry) and the
// expires_in the endpoint stated (0 when it stated none).
func (e ociEcosystem) fetchToken(c *http.Client, image, ref string) (string, int, error) {
	// Probe the reference we actually intend to fetch, not a hard-coded "latest".
	// This was the SECOND copy of the D164 defect and it is not cosmetic: the probe
	// is an unauthenticated GET, so against a registry where "latest" exists and the
	// requested version does not (or vice versa) the challenge — and any 503/429
	// classification we draw from it — described a different object than the one
	// under evaluation. Found by TestLookupRepoResolvesTheRequestedVersion, which
	// asserts on the wire rather than on the parse, which is why it saw this at all.
	probe := fmt.Sprintf("%s/v2/%s/manifests/%s", e.base, image, ref)
	// The error is HANDLED, not discarded (issue #17). It was `req, _ :=` here, and a
	// name carrying a control character — reachable as /v2/library/ng%00inx/... —
	// makes url.Parse reject the URL, so NewRequest returns a nil request and the
	// next line panicked the handler on an unauthenticated request.
	req, err := http.NewRequest(http.MethodGet, probe, nil)
	if err != nil {
		return "", 0, fmt.Errorf("%w: building manifest probe for %q: %v", errOCIMalformedRef, image, err)
	}
	req.Header.Set("Accept", ociManifestAccept)
	resp, err := c.Do(req)
	if err != nil {
		// No answer at all -- refused, reset, timed out. TRANSIENT, the same way
		// npm/PyPI/Maven/deps.dev already file it (issue #117). Returned raw, this
		// fell through Evaluate's catch-all as UNSCORABLE, a verdict about the image,
		// and under the SHIPPED DEFAULTS the byte gate then served a hard-denied
		// image's layers with only a log line, because on the blob route an unscorable
		// image is visibility-first (D72) -- the #60 shape by a third route, a dead
		// socket rather than a 5xx. ociTransient (!93) covers the status codes; this
		// covers the four places there is no status to classify.
		return "", 0, fmt.Errorf("oci manifest probe: %w: %v", errUpstreamUnavailable, err)
	}
	closeDrained(resp.Body)
	if resp.StatusCode == http.StatusOK {
		return "", 0, nil
	}
	if resp.StatusCode != http.StatusUnauthorized {
		if err := ociTransient(resp.StatusCode); err != nil {
			return "", 0, err
		}
		return "", 0, fmt.Errorf("manifest probe returned %d", resp.StatusCode)
	}

	realm, service, scope := parseBearerChallenge(resp.Header.Get("WWW-Authenticate"))
	if realm == "" {
		return "", 0, fmt.Errorf("no bearer realm in auth challenge")
	}
	tokenURL := realm + "?service=" + url.QueryEscape(service) + "&scope=" + url.QueryEscape(scope)
	tr, err := c.Get(tokenURL)
	if err != nil {
		return "", 0, fmt.Errorf("oci token: %w: %v", errUpstreamUnavailable, err) // #117, see the probe
	}
	defer closeDrained(tr.Body)
	if tr.StatusCode != http.StatusOK {
		if err := ociTransient(tr.StatusCode); err != nil {
			return "", 0, err
		}
		return "", 0, fmt.Errorf("token endpoint returned %d", tr.StatusCode)
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := decodeCapped(tr.Body, smallJSONMaxBytes, &t); err != nil {
		return "", 0, err
	}
	if t.Token != "" {
		return t.Token, t.ExpiresIn, nil
	}
	return t.AccessToken, t.ExpiresIn, nil
}

// parseBearerChallenge extracts realm/service/scope from a
// `WWW-Authenticate: Bearer realm="...",service="...",scope="..."` header.
func parseBearerChallenge(h string) (realm, service, scope string) {
	h = strings.TrimSpace(h)
	if !strings.HasPrefix(h, "Bearer ") {
		return "", "", ""
	}
	for _, part := range strings.Split(h[len("Bearer "):], ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		val := strings.Trim(kv[1], `"`)
		switch kv[0] {
		case "realm":
			realm = val
		case "service":
			service = val
		case "scope":
			scope = val
		}
	}
	return realm, service, scope
}

func (e ociEcosystem) ociFetchManifest(c *http.Client, image, ref, token string) (ociManifest, string, error) {
	u := fmt.Sprintf("%s/v2/%s/manifests/%s", e.base, image, ref)
	req, err := http.NewRequest(http.MethodGet, u, nil) // error handled, not discarded — see ociToken (#17)
	if err != nil {
		return ociManifest{}, "", fmt.Errorf("%w: building manifest request for %q@%q: %v", errOCIMalformedRef, image, ref, err)
	}
	req.Header.Set("Accept", ociManifestAccept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return ociManifest{}, "", fmt.Errorf("oci manifest: %w: %v", errUpstreamUnavailable, err) // #117
	}
	defer closeDrained(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		return ociManifest{}, "", fmt.Errorf("manifest fetch for %s:%s: %w", image, ref, errOCIUnauthorized)
	}
	if resp.StatusCode != http.StatusOK {
		if err := ociTransient(resp.StatusCode); err != nil {
			return ociManifest{}, "", err
		}
		return ociManifest{}, "", fmt.Errorf("manifest fetch returned %d", resp.StatusCode)
	}
	// Read the bytes rather than stream-decode them: the digest OF THIS BODY is the
	// identity a pull-through cache will revalidate with (#109), and a manifest is
	// small enough that holding it costs nothing.
	body, err := readCapped(resp.Body, ociManifestMaxBytes)
	if err != nil {
		// Left UNWRAPPED on purpose: a body that ends early was a decode error before
		// this read existed, i.e. "bad metadata", and the #108 short-transfer control
		// relies on that classification. Reclassifying it is a separate decision.
		return ociManifest{}, "", err
	}
	var m ociManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return ociManifest{}, "", err
	}
	sum := sha256.Sum256(body)
	return m, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (e ociEcosystem) ociFetchConfig(c *http.Client, image, digest, token string) (ociImageConfig, error) {
	u := fmt.Sprintf("%s/v2/%s/blobs/%s", e.base, image, digest)
	// Same fix, and this one's digest comes from the UPSTREAM manifest rather than the
	// client — so a hostile or corrupt registry response could reach it too (#17).
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return ociImageConfig{}, fmt.Errorf("%w: building config-blob request for %q@%q: %v", errOCIMalformedRef, image, digest, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return ociImageConfig{}, fmt.Errorf("oci config blob: %w: %v", errUpstreamUnavailable, err) // #117
	}
	defer closeDrained(resp.Body)
	if resp.StatusCode != http.StatusOK {
		if err := ociTransient(resp.StatusCode); err != nil {
			return ociImageConfig{}, err
		}
		return ociImageConfig{}, fmt.Errorf("config blob fetch returned %d", resp.StatusCode)
	}
	var cfg ociImageConfig
	if err := decodeCapped(resp.Body, ociConfigMaxBytes, &cfg); err != nil {
		return ociImageConfig{}, err
	}
	return cfg, nil
}
