package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Sentinel errors LookupRepo implementations use to classify failures, so the
// firewall can react to each correctly instead of treating them all as
// "unscorable metadata":
//
//	errPkgNotFound — the registry says the package doesn't exist (404). The
//	  right response is to pass the request through and let the registry's own
//	  404 answer; gating a nonexistent package would flood the approval queue
//	  with every typo'd install and scanner probe.
//	errUpstreamUnavailable — no answer at all (network failure, 5xx, or a 429
//	  rate limit). Transient: surfaced to the client as a 503 so package
//	  managers retry, rather than misfiled as "this package has bad metadata".
//	errUpstreamRateLimited — a more specific errUpstreamUnavailable: the upstream
//	  answered 429. It WRAPS errUpstreamUnavailable, so every existing
//	  errors.Is(..., errUpstreamUnavailable) transient check still fires and the
//	  D17 taxonomy is unchanged (still a retryable 503, never a 403/quarantine).
//	  Callers that want to *name* the rate limit for the developer instead test
//	  errors.Is(..., errUpstreamRateLimited) (D25).
//
// Anything else is a genuine metadata problem and routes to the unscorable
// policy / approval flow.
var (
	errPkgNotFound         = errors.New("package not found upstream")
	errUpstreamUnavailable = errors.New("upstream temporarily unavailable")
	errUpstreamRateLimited = fmt.Errorf("upstream rate limited (HTTP 429): %w", errUpstreamUnavailable)

	// errOCIMalformedRef — the image name or reference is not legal per the OCI
	// distribution spec (issue #17). Deliberately NOT errPkgNotFound: that sentinel
	// means "pass the request through and let the registry answer", which for a
	// malformed name would forward exactly the string we refused to construct a URL
	// from. It is a genuine metadata problem, so it routes to the unscorable policy
	// and is quarantined under the fail-closed default.
	errOCIMalformedRef = errors.New("malformed OCI reference")
)

// classifyStatus maps a metadata-endpoint HTTP status onto the sentinel
// taxonomy above; returns nil for statuses the caller should handle generically.
// 429 and 5xx are both transient, but 429 gets the distinct rate-limited sentinel
// so the client-facing reason can name it (D25) — both still route to a 503.
func classifyStatus(status int) error {
	switch {
	case status == http.StatusNotFound:
		return errPkgNotFound
	case status == http.StatusTooManyRequests:
		return errUpstreamRateLimited
	case status >= 500:
		return errUpstreamUnavailable
	default:
		return nil
	}
}

// Ecosystem captures the ONLY parts of the firewall that differ between package
// ecosystems (npm, PyPI, …). Everything else — scoring, threshold comparison,
// the approval workflow, allow/block — is shared in firewall.go and works on a
// package name and a repo URL, regardless of where the package came from.
type Ecosystem interface {
	// Name identifies the ecosystem, for logs.
	Name() string
	// PackageNameFromPath extracts the package identity from a request path,
	// or "" if the path isn't a package request we gate.
	PackageNameFromPath(path string) string
	// ControlPlanePath reports whether a path that yielded NO package identity is
	// nonetheless a known registry-infrastructure endpoint that must pass for the
	// client to work: npm's /-/ endpoints, OCI's /v2/ handshake, PyPI's index
	// root, Maven's checksums. Consulted only after PackageNameFromPath and the
	// byte-path parsers have all declined, so it never competes with the gate.
	//
	// THIS ENUMERATION IS THE ENTIRE FAIL-OPEN SURFACE (issue #58, D76). Anything
	// it does not name is PathUnknown and falls to the classification ruleset's
	// terminal block. Keep it short enough to review at a glance, and prefer
	// leaving something out: a missing entry breaks a client loudly and is fixed
	// with FW_UNKNOWN_PATH_POLICY, while a spurious entry is a silent hole of
	// exactly the kind #11/#56/#57/#59 all were.
	//
	// MATCH STRICTLY — no case folding, no prefix tests where an exact one will
	// do. The instinct from #57 is to fold case, but that lesson runs the other
	// way here: ociNameBefore folds so that "/V2/…/blobs/…" PARSES and is GATED,
	// whereas folding in this method would make "/V2/" an ALLOWED control-plane
	// path. Strictness here fails closed; there it fails open.
	ControlPlanePath(escapedPath string) bool
	// LookupRepo fetches the package's metadata and returns a normalized
	// "github.com/owner/name" repo, or "" if none is usable. An error means the
	// lookup itself failed (network/non-200) — distinct from "no repo".
	LookupRepo(c *http.Client, pkg string) (string, error)
}

// newEcosystem builds the Ecosystem named by `name`, using `base` as its registry
// base URL (for metadata lookups). Unknown names error rather than defaulting.
func newEcosystem(name, base string) (Ecosystem, error) {
	base = strings.TrimRight(base, "/")
	switch name {
	case "npm":
		return npmEcosystem{base: base}, nil
	case "pypi":
		return pypiEcosystem{base: base}, nil
	case "oci":
		return ociEcosystem{
			base:         base,
			bindings:     newOCIBlobBindings(),
			repoByDigest: newTTLLRU[string](ociDigestRepoTTL, 0),
			tokens:       newTTLLRU[ociTokenEntry](ociTokenCacheBound, 0),
		}, nil
	case "maven":
		return mavenEcosystem{
			base:  base,
			cache: newMavenFetchCache(mavenFetchCacheTTL),
			gate:  newMavenProbeGate(mavenProbeConcurrency),
			ages:  newMavenAgeCache(mavenFetchCacheTTL),
		}, nil
	default:
		return nil, fmt.Errorf("unknown ecosystem %q (want \"npm\", \"pypi\", \"oci\", or \"maven\")", name)
	}
}

// ───────────────────────── npm ─────────────────────────

type npmEcosystem struct{ base string }

func (e npmEcosystem) Name() string { return "npm" }

// PackageNameFromPath handles plain ("/lodash/...") and scoped ("/@scope/name/...")
// npm package paths. Returns "" if nothing usable is found.
func (e npmEcosystem) PackageNameFromPath(p string) string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return ""
	}
	// "/-/" marks npm's registry control plane — tarball downloads
	// ("/lodash/-/lodash-4.17.21.tgz"), "/-/npm/v1/..." audit/search endpoints,
	// login, etc. These are not package-METADATA requests, so this parser (which
	// drives the metadata control point) still returns "" for them: treating a
	// tarball as a metadata request would re-score on every byte fetch and misparse
	// control endpoints as a package named after their first segment.
	//
	// That is NOT the same as leaving them ungated. Tarball fetches get their own,
	// separately-configurable gate on the byte path — see npmArtifactPath below and
	// proxyServer.proxyArtifactBytes (issue #11).
	if strings.Contains(p, "/-/") || strings.HasPrefix(p, "-/") {
		return ""
	}
	segments := strings.Split(p, "/")
	if strings.HasPrefix(segments[0], "@") {
		if len(segments) >= 2 {
			name, _ := url.PathUnescape(segments[0] + "/" + segments[1])
			return name
		}
		return segments[0]
	}
	name, _ := url.PathUnescape(segments[0])
	return name
}

// ControlPlanePath: npm's registry control plane lives under "/-/" — the audit and
// advisory-bulk endpoints npm/pnpm call on every install, /-/ping, /-/whoami,
// /-/v1/search, /-/user/... — plus the registry root, which clients probe for
// reachability. A "/<pkg>/-/<file>.tgz" tarball never reaches here: npmArtifactPath
// claims it earlier and routes it through the byte gate, so by this point a "/-/"
// path is one that STARTS with it, i.e. genuinely not addressed to a package.
//
// Deliberately NOT a "contains /-/" test. That would re-admit exactly what the byte
// gate exists to catch: a path npmArtifactPath declined (an unescapable name, an
// empty prefix) but which still contains the marker would be waved through as
// infrastructure.
func (e npmEcosystem) ControlPlanePath(p string) bool {
	return p == "/" || p == "" || strings.HasPrefix(p, "/-/")
}

// npmTarballPrefix is the path prefix relayRewritten mints for npm artifact URLs:
// "/_tarball/<escaped package name>/<upstream object path>". Threading the package
// identity through the URL is the same trick PyPI's "/_files/<pkg>/" uses (D22) —
// the byte fetch then gates on the name the METADATA request resolved, instead of
// re-deriving it from a filename.
const npmTarballPrefix = "/_tarball/"

// npmArtifactPath decides whether an incoming request is an npm ARTIFACT (tarball)
// byte fetch and, if so, returns the package it belongs to plus the object path to
// forward upstream. escapedPath must be r.URL.EscapedPath(), so a percent-encoded
// scoped name survives intact.
//
// Two shapes reach us, and both must be recognized — this is the whole reason the
// side-door in issue #11 stayed open:
//
//  1. "/_tarball/<pkg>/<object path>" — what relayRewritten mints. Authoritative:
//     <pkg> is the name the metadata request itself resolved, so the byte verdict
//     can never drift from the index verdict, whatever URL shape the upstream uses.
//
//  2. "/<pkg>/-/<file>.tgz" — the registry's OWN convention, which we must handle
//     because we will keep receiving it no matter what we mint: lockfiles already in
//     the wild record this shape in their "resolved" URLs, and modern npm/pnpm build
//     it themselves by swapping only the ORIGIN of dist.tarball for the configured
//     registry. Gating only shape 1 would close the door for future resolutions while
//     leaving every existing `npm ci` walking straight through it.
//
// The package name in shape 2 comes from the path SEGMENTS BEFORE "/-/", never from
// the filename after it: "lodash-4.17.21.tgz" cannot be split into name and version
// unambiguously (both may contain hyphens), and a mis-parse would evaluate the wrong
// package — which, for an unknown name, resolves toward allow and silently bypasses
// the gate. The prefix has no such ambiguity; it is how the registry addresses the
// package.
//
// An EMPTY prefix is npm's control plane ("/-/npm/v1/security/audits", "/-/ping",
// "/-/whoami", "/-/user/..."), not a package — those keep passing through ungated.
func npmArtifactPath(escapedPath string) (pkg, objectPath string, ok bool) {
	if rest := strings.TrimPrefix(escapedPath, npmTarballPrefix); rest != escapedPath {
		slash := strings.IndexByte(rest, '/')
		if slash <= 0 {
			return "", "", false
		}
		name, err := url.PathUnescape(rest[:slash])
		if err != nil || name == "" {
			return "", "", false
		}
		return name, rest[slash:], true
	}
	// Shape 2. Split on the FIRST "/-/": a package name cannot contain "/-/" (npm
	// names allow at most one "/", the scope separator), so the first occurrence is
	// always the real boundary.
	idx := strings.Index(escapedPath, "/-/")
	if idx <= 0 { // <=0 also rejects the leading "/-/..." control plane
		return "", "", false
	}
	name, err := url.PathUnescape(strings.TrimPrefix(escapedPath[:idx], "/"))
	if err != nil || name == "" {
		return "", "", false
	}
	return name, escapedPath, true
}

// npmObjectPathBindsToPackage reports whether objectPath is the registry's own tarball
// path FOR pkg. This is the npm half of issue #67, ruled by D159.
//
// npmArtifactPath peels <pkg> off the "/_tarball/<pkg>/<object path>" URL we mint and
// proxyArtifactBytes evaluates it — but nothing bound the two halves together. Any client
// could pair an ALLOWED package's prefix with a BLOCKED package's object path, and the
// gate would judge the decoy and stream the target (measured at 318 KB). The prefix is
// authoritative about WHICH DECISION WAS MADE; it says nothing about which bytes come back.
//
// PyPI's sibling (pypiFilenameBindsToPackage) can only ask the weak question "could this
// file belong to that package?", because an sdist's "{name}-{version}" is genuinely
// ambiguous and a mis-parse evaluates the wrong package. npm needs no such heuristic, and
// that is precisely why D159 could partially reverse D101's "no heuristic refusal for
// npm": the registry addresses a tarball as "/<name>/-/<file>.tgz", so the name is an
// EXACT path segment rather than something inferred from a filename. We recover it and
// require equality. Same "/-/" boundary rule as shape 2 above, and for the same reason —
// a package name cannot contain "/-/", so the first occurrence is always the real one.
//
// An object path with NO "/-/" is refused rather than waved through, which deliberately
// narrows the "odd upstream shape" case bytegate_test.go documents. That narrowing is
// what makes the default safe WITHOUT a signing key (D159 item 3): a rule that applies
// only to paths of a certain shape is a rule the attacker simply declines to trigger.
// D159 item 2 rules the cost in scope — registries not using the canonical shape are
// assumed not to exist in practice, and where they do they are "not really our problem
// to solve".
func npmObjectPathBindsToPackage(pkg, objectPath string) bool {
	idx := strings.Index(objectPath, "/-/")
	if idx <= 0 { // <=0 also rejects a leading "/-/", which addresses no package at all
		return false
	}
	// The object path travels ESCAPED (it is forwarded verbatim), so decode before
	// comparing: "@babel%2Fcore" and "@babel/core" are the same package and an attacker
	// should not get a second spelling to hide behind.
	name, err := url.PathUnescape(strings.TrimPrefix(objectPath[:idx], "/"))
	if err != nil {
		return false
	}
	return name == pkg
}

// npmMetadata is the minimal slice of npm's package JSON we read.
type npmMetadata struct {
	Repository repoField `json:"repository"`
}

// repoField absorbs every shape the packument "repository" field takes in the
// wild. Modern publishes use an object {"type","url","directory"}; a large
// slice of older packages used a bare string ("git://…", "owner/repo",
// "github:owner/repo"); a few historical ones used an array of either. A strict
// struct decode fails the WHOLE packument on the string form — misclassifying
// perfectly scorable packages as unscorable — so this type accepts all shapes
// and treats anything unrecognized as "no repository declared", never an error.
type repoField struct {
	URL string
}

func (r *repoField) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		r.URL = s
		return nil
	}
	var obj struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(b, &obj) == nil {
		r.URL = obj.URL
		return nil
	}
	// Array form: take the first element that yields a URL (elements re-enter
	// this method, so string and object elements are both handled).
	var arr []repoField
	if json.Unmarshal(b, &arr) == nil {
		for _, el := range arr {
			if el.URL != "" {
				r.URL = el.URL
				return nil
			}
		}
	}
	return nil // unknown shape == no usable repository, never a decode failure
}

// npmMetaMaxBytes caps how much metadata we'll buffer per lookup. The /latest
// version manifest is a few KB; the full-packument fallback can be much larger
// (it carries every version ever published), but beyond this cap we treat the
// metadata as unreadable (-> unscorable) rather than risk unbounded memory
// under concurrent installs.
const npmMetaMaxBytes = 32 << 20 // 32 MB

// pypiMetaMaxBytes bounds the PyPI project JSON, and exists because its npm twin
// above did and this did not (#135).
//
// MEASURED rather than guessed, because a cap that breaks a real package is a worse
// bug than the one it fixes: the largest of twelve popular projects is awscli at
// 3.60 MB (numpy 3.50, boto3 3.12, cryptography 3.07). 32 MB matches npm's cap and
// leaves ~9x headroom over the largest thing anyone actually publishes.
const pypiMetaMaxBytes = 32 << 20 // 32 MB

func (e npmEcosystem) LookupRepo(c *http.Client, pkg string) (string, error) {
	// Ask for the "latest" version manifest, NOT the full packument: the
	// packument for an old, busy package runs to tens of megabytes, and we only
	// need one repository link, which the version manifest also carries. (The
	// packument IS parsed for version-level filtering, #35 — but in the rewrite of
	// a document already being relayed to a client, never as a scoring fetch.)
	meta, err := e.fetchMeta(c, fmt.Sprintf("%s/%s/latest", e.base, url.PathEscape(pkg)))
	if errors.Is(err, errPkgNotFound) {
		// Ambiguous on third-party registries that don't serve the /latest
		// convenience route: confirm against the packument before declaring the
		// package nonexistent.
		meta, err = e.fetchMeta(c, fmt.Sprintf("%s/%s", e.base, url.PathEscape(pkg)))
	}
	if err != nil {
		return "", err
	}
	repo := normalizeGitHub(npmGitHubSpelling(meta.Repository.URL))
	if repo == "" {
		noteUnsupportedForge("npm", pkg, meta.Repository.URL)
	}
	return repo, nil
}

// npmGitHubSpelling rewrites the three ways npm itself spells a GitHub repository into
// the URL form normalizeGitHub reads (#162). npm resolves `owner/repo`, `github:owner/repo`
// and `git@github.com:owner/repo.git` to GitHub (hosted-git-info), and since npm 7 the
// registry serves them verbatim, so a package that DOES declare its repository was being
// refused as "does not declare a usable source repository". Measured by E109: 0.33% of
// benign weekly npm download volume -- formidable alone is 24 M/week -- and 47% of
// everything that stage refuses by weight.
//
// npm ONLY, deliberately. normalizeGitHub is shared with PyPI's project_urls and OCI's
// source label, where a bare `a/b` is a docs path or a relative link, not a repository;
// reading it as one there would let an arbitrary string name the repo whose score a
// package borrows (#10). Anything that is not exactly one of these spellings, with names
// GitHub itself would accept, is returned unchanged and is refused exactly as before.
func npmGitHubSpelling(raw string) string {
	s := strings.TrimSpace(raw)
	rest, ok := "", false
	for _, prefix := range []string{"github:", "git@github.com:", "git+ssh://git@github.com:", "ssh://git@github.com:"} {
		if strings.HasPrefix(s, prefix) {
			rest, ok = strings.TrimPrefix(s, prefix), true
			break
		}
	}
	if !ok {
		rest = s // the bare shorthand, if it is one
	}
	if !isGitHubOwnerRepo(rest) {
		return raw
	}
	return "https://github.com/" + rest
}

// isGitHubOwnerRepo reports whether s is exactly "<owner>/<repo>", optionally followed by
// ".git" or "#<committish>", with names GitHub accepts: an owner of letters, digits and
// hyphens, a repo of letters, digits, '-', '_' and '.', and never "." or "..". Strict on
// purpose -- `../evil` must not become github.com/../evil.
func isGitHubOwnerRepo(s string) bool {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	owner, repo, ok := strings.Cut(s, "/")
	if !ok || owner == "" || repo == "" {
		return false
	}
	repo = strings.TrimSuffix(repo, ".git")
	if repo == "" || repo == "." || repo == ".." {
		return false
	}
	for _, r := range owner {
		if !(r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	for _, r := range repo {
		if !(r == '-' || r == '_' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func (e npmEcosystem) fetchMeta(c *http.Client, metaURL string) (npmMetadata, error) {
	var meta npmMetadata
	resp, err := c.Get(metaURL)
	if err != nil {
		return meta, fmt.Errorf("npm metadata: %w: %v", errUpstreamUnavailable, err)
	}
	defer closeDrained(resp.Body)
	if resp.StatusCode != http.StatusOK {
		if cerr := classifyStatus(resp.StatusCode); cerr != nil {
			return meta, fmt.Errorf("npm metadata: %w (status %d)", cerr, resp.StatusCode)
		}
		return meta, fmt.Errorf("npm metadata returned status %d", resp.StatusCode)
	}
	if err := decodeCapped(resp.Body, npmMetaMaxBytes, &meta); err != nil {
		// %w, not %v. This wrap used to FLATTEN the error to text, so errUpstreamTooLarge
		// (#139) arrived at the classifier as an ordinary decode failure with the words
		// "exceeds the inspection cap" in it and nothing able to act on them. The test that
		// drives this path is what caught it; the helper's own tests passed either way.
		return meta, fmt.Errorf("npm metadata: %w", err)
	}
	return meta, nil
}

// ───────────────────────── PyPI ─────────────────────────

type pypiEcosystem struct{ base string }

func (e pypiEcosystem) Name() string { return "pypi" }

// PackageNameFromPath parses pip's PEP 503 "simple" index paths:
// "/simple/<project>/" -> "<project>". Returns "" for the index root or anything
// that isn't a project page.
func (e pypiEcosystem) PackageNameFromPath(p string) string {
	p = strings.Trim(p, "/")
	p = strings.TrimPrefix(p, "simple/")
	if p == "" || p == "simple" {
		return ""
	}
	seg := strings.SplitN(p, "/", 2)[0]
	name, _ := url.PathUnescape(seg)
	return name
}

// ControlPlanePath: PyPI's only ungated infrastructure is the root and the /simple/
// index listing EVERY project, which pip fetches when resolving from a bare index
// URL. A project page ("/simple/<name>/") is a package request and is gated by
// PackageNameFromPath, so it never arrives here.
//
// Matched case-sensitively, mirroring PackageNameFromPath's own case-sensitive
// TrimPrefix. That is not an oversight: "/Simple/foo" does not strip there either,
// so it parses as a package named "Simple" and gets GATED. Folding case here would
// instead make "/Simple/" a control-plane path and hand back the whole index
// ungated.
func (e pypiEcosystem) ControlPlanePath(p string) bool {
	return p == "/" || p == "" || p == "/simple" || p == "/simple/"
}

// pypiMetadata is the minimal slice of PyPI's JSON API we read. PyPI exposes the
// source repo inconsistently — sometimes in project_urls under various keys
// ("Source", "Repository", "Homepage", …), sometimes only in home_page — so we
// search all of them for a GitHub URL.
type pypiMetadata struct {
	Info struct {
		HomePage    string            `json:"home_page"`
		ProjectURLs map[string]string `json:"project_urls"`
	} `json:"info"`
}

func (e pypiEcosystem) LookupRepo(c *http.Client, pkg string) (string, error) {
	metaURL := fmt.Sprintf("%s/pypi/%s/json", e.base, url.PathEscape(pkg))
	resp, err := c.Get(metaURL)
	if err != nil {
		return "", fmt.Errorf("pypi metadata: %w: %v", errUpstreamUnavailable, err)
	}
	defer closeDrained(resp.Body)
	if resp.StatusCode != http.StatusOK {
		if cerr := classifyStatus(resp.StatusCode); cerr != nil {
			return "", fmt.Errorf("pypi metadata: %w (status %d)", cerr, resp.StatusCode)
		}
		return "", fmt.Errorf("pypi metadata returned status %d", resp.StatusCode)
	}
	var m pypiMetadata
	if err := decodeCapped(resp.Body, pypiMetaMaxBytes, &m); err != nil {
		return "", err
	}
	// Prefer any declared project URL that points at GitHub, choosing by the LABEL
	// PyPI stores beside it and, within a rank, in sorted order.
	//
	// This loop used to be `for _, u := range m.Info.ProjectURLs` — a range over a
	// MAP, whose order Go deliberately randomises. When a project declared more than
	// one URL that normalises to a GitHub repo, the repo we scored was therefore
	// chosen AT RANDOM, per process (#134).
	//
	// That is not a rare shape: measured across 124 popular PyPI packages, 10 (8.1%)
	// declare two or more, and the wrong one is not a harmless near-miss. `attrs`
	// resolves to either python-attrs/attrs or sponsors/hynek with even odds; under
	// the shipped defaults the second disagrees with deps.dev's SOURCE_REPO, so
	// verifyRepo fires the borrow-a-score tripwire and REFUSES a top-100 package,
	// logging that it may be borrowing a score. Half of all `pip install attrs`.
	if repo := pypiRepoFromProjectURLs(m.Info.ProjectURLs); repo != "" {
		return repo, nil
	}
	// Fall back to home_page.
	repo := normalizeGitHub(m.Info.HomePage)
	if repo == "" {
		// Report the coverage gap from the SOURCE-ish URLs only, in the same ranked
		// order the repo chooser uses.
		//
		// The first version passed every project_urls value, sorted, and that made the
		// report wrong in a way it admitted but did not fix: any "host/a/b" shape reads
		// as a forge, so a "Documentation" entry reported docs.python.org as an
		// unsupported FORGE. It is not one — it is a docs site, and nothing about it
		// says the package's source lives somewhere we cannot score.
		//
		// #134 supplied the missing evidence: the LABEL is what distinguishes a source
		// URL from a docs, funding or tracker URL, and pypiURLRank already encodes it.
		// Reusing it here means the report and the repo chooser agree by construction —
		// the report now names the forge of a URL that WOULD have been chosen, which is
		// the only kind that represents a real gap.
		noteUnsupportedForge("pypi", pkg, append(pypiSourceish(m.Info.ProjectURLs), m.Info.HomePage)...)
	}
	return repo, nil
}

// ───────────────────────── OCI (Docker) ─────────────────────────

type ociEcosystem struct {
	base string
	// bindings lets an approved manifest vouch for the blobs it enumerates, so the
	// byte gate can judge the VERSION a layer belongs to rather than the bare image
	// name (D164). A pointer, so the value-typed ecosystem copies share one cache.
	bindings *ociBlobBindings
	// repoByDigest remembers the source repo resolved under each manifest digest,
	// so a reference that names an already-read digest -- a pull-through cache's
	// warm revalidation, a client pulling by digest -- reuses the answer instead
	// of re-walking the registry (#109). Keyed like bindings: (image, digest).
	repoByDigest *ttlLRU[string]
	// tokens remembers the pull-scoped bearer token per image for as long as the token
	// endpoint said it lives (ocitoken.go), so revalidating a tag on a challenged
	// registry costs one request, not three.
	tokens *ttlLRU[ociTokenEntry]
}

func (e ociEcosystem) Name() string { return "oci" }

// PackageNameFromPath gates on the OCI distribution manifest request —
// "/v2/<name>/manifests/<ref>" -> "<name>" — which is the point a `docker pull`
// commits to an image, before any blobs are fetched. Note <name> can itself
// contain slashes (e.g. "library/nginx"). Everything else (the "/v2/" version
// handshake, tag listings, token endpoints) returns "" so the proxy passes it
// through ungated.
//
// BLOB fetches are deliberately NOT handled here, and that is not the same as
// leaving them ungated (it was, until issue #57). They get their own gate on the
// byte path — see ociBlobPath below and proxyServer.proxyArtifactBytes — for the
// same reason npm's tarballs do: a byte fetch is not a metadata request, and
// treating it as one would re-score on every layer and misparse the control plane.
func (e ociEcosystem) PackageNameFromPath(p string) string {
	name := ociNameBefore(p, "/manifests/")
	if name == "" {
		return "" // unchanged: no identity here, pass through ungated
	}
	// The reference is part of the identity, not decoration (D164): a tag is a
	// mutable pointer, so a verdict recorded against a bare image name is a verdict
	// about whatever that name happened to mean when it was recorded. Carrying it
	// here is what makes the score cache, the repo cache, the approval queue and the
	// audit log version-keyed — none of them needed changing, because they all key
	// on whatever this returns.
	return ociJoinRef(name, ociRefAfter(p, "/manifests/"))
}

// ociRefAfter returns the reference following the last sep — the tag or digest a
// client committed to. Mirrors ociNameBefore exactly (same "v2/" check, same
// case-folded split, same unescape) so the name and the reference can never be
// taken from different interpretations of one path.
func ociRefAfter(p, sep string) string {
	p = strings.TrimPrefix(p, "/")
	const apiPrefix = "v2/"
	if len(p) < len(apiPrefix) || !strings.EqualFold(p[:len(apiPrefix)], apiPrefix) {
		return ""
	}
	rest := p[len(apiPrefix):]
	idx := lastIndexFold(rest, sep)
	if idx <= 0 {
		return ""
	}
	ref, err := url.PathUnescape(rest[idx+len(sep):])
	if err != nil {
		return ""
	}
	return ref
}

// ociBlobPath decides whether an incoming request is an OCI BLOB byte fetch and,
// if so, returns the image it belongs to. Issue #57.
//
// The identity problem is smaller than it looks: a blob DIGEST carries no image
// name, but the distribution spec puts the repository name directly in the URL —
// "/v2/<name>/blobs/<digest>" — in the same position the manifest path carries it.
// So the byte gate evaluates exactly the identity the manifest gate would have,
// with no digest→image association table to maintain.
//
// Why gate the blob path at all, when the manifest is "the" control point: the
// manifest only gates the blob if the client asks for it, in this session, every
// time. A client whose manifest is cached locally, one pulling by digest, one
// resuming a partial layer, and any tool that reads blobs directly (`crane blob`,
// `oras blob fetch`) all skip it. `crane blob` pulled 3,630,321 bytes of a BLOCKED
// image's layer with no manifest request at all — that is what settled #57.
//
// CROSS-REPOSITORY BLOBS: the same blob can be reachable under several repository
// names (shared layers, cross-repo mount). Gating on <name> is still correct and is
// not a hole to "fix" later: under the cooperative-client model the client asked for
// this blob under THIS name, so that is the identity whose policy applies. Two names
// for one blob simply means two independent decisions, which is the intended
// behaviour, not a collision.
func ociBlobPath(escapedPath string) (image string, ok bool) {
	name := ociNameBefore(escapedPath, "/blobs/")
	return name, name != ""
}

// ociBlobRef returns the reference AFTER the last "/blobs/" — normally a digest, but
// deliberately not validated as one here. Blob UPLOAD paths ("/v2/<name>/blobs/
// uploads/…") also land in the byte gate by design (see ControlPlanePath), and they
// yield "uploads/…" rather than a digest. That is harmless: an unrecognised value
// simply never matches a recorded binding, so the caller falls back to the bare
// image name — the behaviour that shipped before the binding existed.
func ociBlobRef(escapedPath string) string {
	const sep = "/blobs/"
	i := strings.LastIndex(strings.ToLower(escapedPath), sep)
	if i < 0 {
		return ""
	}
	ref, err := url.PathUnescape(escapedPath[i+len(sep):])
	if err != nil {
		return ""
	}
	return ref
}

// ociNameBefore extracts "<name>" from "/v2/<name><sep><rest>", or "" if the path
// isn't that shape. Shared by the manifest and blob parsers so the two views of one
// image can never drift — the property the whole byte gate rests on.
//
// Splits on the LAST occurrence of sep, not the first. <name> may contain slashes
// and "manifests"/"blobs" are themselves legal name components, while a tag or
// digest contains none — so the last occurrence is the unambiguous boundary. With
// the first, a request for repository "evil/blobs/x" would be evaluated as "evil":
// a different package, with a different verdict.
//
// STRUCTURAL TOKENS ARE MATCHED CASE-INSENSITIVELY ("/V2/", "/Blobs/"), and that is a
// security fix, not politeness. Found by the tier-3 pass on issue #57: with a strictly
// lowercase match, "/V2/library/alpine/blobs/<digest>" matched neither parser, so it
// was classified as registry infrastructure and RELAYED UNGATED — the blocked image's
// layer came back with a 200. The same hole existed on the manifest gate long before
// the byte gate did.
//
// registry-1.docker.io happens to 404 that spelling, but the upstream is the
// operator's choice (Harbor, Artifactory, GitLab, ECR, or any CDN in front of them),
// case-insensitive HTTP routing is common, and predicting an upstream's normalization
// is precisely the assumption that failed in issue #59. We fold the tokens so the
// request is still RECOGNISED and evaluated; if the upstream then 404s, nothing is
// lost, and if it serves, we gated it.
//
// The NAME is never folded — only the tokens around it. OCI requires lowercase
// repository names, but some registries are laxer, and lowercasing the identity we
// evaluate while forwarding the original would re-create the same divergence in the
// opposite direction.
func ociNameBefore(p, sep string) string {
	p = strings.TrimPrefix(p, "/")
	const apiPrefix = "v2/"
	if len(p) < len(apiPrefix) || !strings.EqualFold(p[:len(apiPrefix)], apiPrefix) {
		return ""
	}
	rest := p[len(apiPrefix):]
	idx := lastIndexFold(rest, sep)
	if idx <= 0 {
		return ""
	}
	name, err := url.PathUnescape(rest[:idx])
	if err != nil {
		return ""
	}
	return name
}

// lastIndexFold is strings.LastIndex with ASCII-case-insensitive matching. Written as
// a scan rather than the obvious strings.LastIndex(strings.ToLower(s), sep) because
// ToLower is not length-preserving for all of Unicode (U+0130 lowercases to two
// runes), which would slide the returned offset and slice the name in the wrong place.
// Paths are short, so the scan costs nothing worth optimizing.
func lastIndexFold(s, sep string) int {
	for i := len(s) - len(sep); i >= 0; i-- {
		if strings.EqualFold(s[i:i+len(sep)], sep) {
			return i
		}
	}
	return -1
}

// normalizePypiName folds a PyPI project name to the one spelling PyPI itself treats
// as canonical (PEP 503): case-folded, with every run of "-", "_" and "." collapsed to
// a single "-". `Zope.Interface`, `zope_interface` and `zope-interface` are the same
// project, so any comparison between a requested name and a filename has to happen
// here or it is comparing spellings rather than identities.
//
// THIS IS THE ONLY PyPI NORMALIZER, and it is worth keeping that way. It decides two
// separate things that have to agree: which artifact bytes may be served under a
// requested name (pypiFilenameBindsToPackage, #67) and which identity a known-malware
// advisory or operator list entry matches (malwareKey). A second copy drifting from
// this one would mean a package blocked under one spelling and served under another,
// which is a bypass rather than an inconsistency — malware.go carried exactly such a
// copy until it was folded back in here.
//
// Written out rather than pulled in as a dependency: it is a dozen lines, and this is
// security software where every third-party package is our own attack surface.
func normalizePypiName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSep := false
	for _, r := range strings.ToLower(s) {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
			}
			prevSep = true
			continue
		}
		b.WriteRune(r)
		prevSep = false
	}
	return b.String()
}

// pypiFilenameBindsToPackage reports whether the artifact filename at the end of
// objectPath actually belongs to pkg.
//
// This closes issue #67. proxyToFiles peels <pkg> off "/_files/<pkg>/<object path>"
// and evaluates it, but NOTHING bound the prefix to the path behind it: any client can
// mint a request pairing an allowed package's prefix with a blocked package's object
// path, and the gate would evaluate the decoy and stream the target. The prefix is
// authoritative about *which decision was made*, never about *which bytes come back*.
//
// The original code deliberately did not parse the filename, because an sdist's
// "{name}-{version}" is genuinely ambiguous — a hyphenated name is not separable from
// the version that follows, and a mis-parse evaluates the wrong package or an unknown
// one (which resolves to allow, silently bypassing the firewall). That reasoning is
// sound and this function does NOT overturn it: it never tries to recover the name.
// It only asks the much weaker question the prefix already answers — "could this file
// belong to that package?" — which needs no split.
//
// The rule is prefix + a version must follow, and both halves were measured against
// 82,970 real artifacts across 59 packages harvested from /simple/:
//
//   - Recovering the name exactly and comparing: 2,118 false rejects (2.55%), almost
//     all legacy platform installers (numpy-1.5.1.win32-py2.7-nosse.exe), where the
//     sdist grammar mis-splits. Unshippable — every one is a broken install.
//   - Prefix alone: 1 false reject, but it accepts "requests-evil-1.0.tar.gz" under
//     "requests". An attacker publishes a name EXTENDING an allowed one and the
//     bypass survives the fix. A corpus of real packages cannot show this, because
//     it contains no attacker-chosen name — it was found by simulating one.
//   - Prefix + version-start (this): 1 false reject in 82,970 (0.0012%), 0 false
//     accepts. The lone reject is correct — project "path.py" serving "path-2.2.zip"
//     genuinely is a different distribution name (the project renamed).
//
// Requiring a PEP 440-ish version to follow is what defeats the extension attack:
// an attacker controls their package name, but cannot make "evil" look like a version.
func pypiFilenameBindsToPackage(pkg, objectPath string) bool {
	file := objectPath
	if i := strings.LastIndexByte(file, '/'); i >= 0 {
		file = file[i+1:]
	}
	// The object path travels escaped so the filename survives intact; compare the
	// decoded form, since that is what the upstream will actually resolve.
	if decoded, err := url.PathUnescape(file); err == nil {
		file = decoded
	}

	prefix := normalizePypiName(pkg) + "-"
	name := normalizePypiName(file)
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	// What follows the name must START a version. normalizePypiName has already
	// lowercased, so only 'v' needs checking, not 'V'.
	rest := name[len(prefix):]
	switch {
	case rest == "":
		return false
	case rest[0] >= '0' && rest[0] <= '9':
		return true
	case rest[0] == 'v' && len(rest) > 1 && rest[1] >= '0' && rest[1] <= '9':
		return true
	default:
		return false
	}
}

// ControlPlanePath: the OCI distribution endpoints that carry no image content —
// the "/v2/" version handshake every client opens with, tag listings, and the
// registry-local token endpoints some deployments expose (Docker Hub's live on a
// different host and never reach us).
//
// Strictly lowercase, and that is load-bearing in the opposite direction from
// ociNameBefore. That function folds case so "/V2/name/blobs/<digest>" still PARSES
// and gets gated — the hole !76's tier-3 pass found. Folding here would do the
// reverse and make "/V2/" an allowed infrastructure path, so "/V2/" instead falls
// to PathUnknown and is refused.
//
// Blob UPLOADS ("/v2/<name>/blobs/uploads/...") are deliberately absent here, but
// NOT for the reason you would expect, and the difference was found by the tier-3
// pass rather than by reading the code. They never reach classification at all:
// ociBlobPath splits on the LAST "/blobs/", so an upload path yields the image name
// and is claimed by the BYTE GATE, which evaluates it as if it were a download of
// that image. A push to a blocked image is therefore refused, and a push to an
// allowed one is proxied to the registry (which then applies its own auth).
//
// So listing uploads here would be actively wrong — it would exempt them from the
// byte gate that currently covers them. Whether a pull-through firewall should be
// relaying push traffic at all is a separate posture question, filed rather than
// decided here.
// The REFERRERS endpoint (OCI 1.1, "/v2/<name>/referrers/<digest>") is here for the
// same reason tags/list is, and it was missing: it is a LISTING, not content. It
// answers "which manifests refer to this digest" -- signatures, SBOMs, attestations --
// and every manifest it names is still gated when the client goes on to fetch it.
//
// Leaving it out broke real pulls, which is how it was found rather than by reading the
// spec. A Docker daemon that already holds an image's content skips the index entirely
// and asks referrers about a digest it has locally; that request fell to the terminal
// block, and `docker pull` died with "unrecognized request path" on an image nothing
// was wrong with. It fires only for a partially-cached image, which is why no clean-state
// measurement shows it and why it read as intermittent.
func (e ociEcosystem) ControlPlanePath(p string) bool {
	if p == "/" || p == "" || p == "/v2" || p == "/v2/" {
		return true
	}
	if strings.HasPrefix(p, "/v2/") && strings.HasSuffix(p, "/tags/list") {
		return true
	}
	// Strictly a /referrers/<ref> SEGMENT, never a suffix match: "/v2/x/referrers/" with
	// nothing after it names no digest, and a repository literally called "referrers"
	// must not open a hole. The reference itself is not validated here -- this decides
	// only that the PATH is a listing endpoint, and the relay forwards it verbatim.
	if strings.HasPrefix(p, "/v2/") {
		// i > len("/v2/") demands at least one character of repository NAME before the
		// segment, so "/v2/referrers/<ref>" -- which names no repository -- stays out.
		if i := strings.Index(p, "/referrers/"); i > len("/v2/") && len(p) > i+len("/referrers/") {
			return true
		}
	}
	return p == "/token" || p == "/v2/token" || p == "/v2/auth"
}

// LookupRepo for OCI is implemented in oci.go — it resolves the source repo from
// the image's config-blob label (org.opencontainers.image.source), handling the
// registry's bearer-token auth and multi-arch manifest indexes.

// ─────────────── picking the right repo out of PyPI's project_urls ───────────────

// The four tiers a project_urls label falls into. Named rather than spelled 0..3
// inline because two callers now depend on the ORDER: the repo chooser takes the
// best, and the coverage report keeps everything at pypiRankUnrecognised or better.
// A bare 3 in one of them and a bare 2 in the other would be a silent disagreement.
const (
	pypiRankSource       = 0 // "Source", "Repository", "GitHub: repo", "Code"
	pypiRankHomepage     = 1 // "Homepage" — usually the project, sometimes a docs site
	pypiRankUnrecognised = 2 // a label we do not know; might be the source
	pypiRankNotSource    = 3 // "Funding", "Documentation", "Bug Tracker", "Q & A" …
)

// pypiURLRank orders a project_urls LABEL by how strongly it claims to be the
// package's own source repository. Lower is better; anything unrecognised sits
// between "clearly the source" and "clearly not".
//
// The label is the only evidence available. The URLs themselves are
// indistinguishable — github.com/sponsors/hynek and github.com/python-attrs/attrs
// have identical shape — so a chooser that reads only URLs cannot do better than
// chance, which is exactly the defect this replaces (#134).
//
// Matching is on a normalised label (lower-cased, punctuation and spaces dropped)
// because publishers spell these freely: "Source", "source", "Source Code",
// "GitHub: repo", "Issue Tracker", "Bug Tracker", "Q & A" all occur in the
// measured sample.
func pypiURLRank(label string) int {
	l := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		}
		return -1 // drop spaces, ':', '&', '-', '_' …
	}, label)

	switch {
	// Says "this is the code" outright.
	case strings.Contains(l, "sourcecode"), strings.Contains(l, "source"),
		strings.Contains(l, "repository"), strings.Contains(l, "repo"),
		l == "code", l == "github", l == "gitlab":
		return pypiRankSource
	// Usually the project, occasionally a docs site — good, not authoritative.
	case l == "homepage", l == "home":
		return pypiRankHomepage
	// Explicitly NOT the source repo, and each of these produced a measured
	// wrong-repo pick: Funding/Sponsor -> a Sponsors page; Code of Conduct -> the
	// org's shared .github repo; Q&A -> a different project; Bug Tracker -> the
	// parent project.
	case strings.Contains(l, "funding"), strings.Contains(l, "sponsor"),
		strings.Contains(l, "donate"), strings.Contains(l, "codeofconduct"),
		strings.Contains(l, "qa"), strings.Contains(l, "chat"),
		strings.Contains(l, "tracker"), strings.Contains(l, "issues"),
		strings.Contains(l, "changelog"), strings.Contains(l, "changes"),
		strings.Contains(l, "documentation"), strings.Contains(l, "docs"):
		return pypiRankNotSource
	default:
		return pypiRankUnrecognised
	}
}

// pypiRepoFromProjectURLs picks the source repo out of project_urls, or "".
//
// DETERMINISTIC BY CONSTRUCTION: ranked by label, then by label name, then by URL.
// The same metadata must always yield the same repo — a firewall whose verdict
// depends on Go's map seed is one that blocks a package on some replicas and
// allows it on others, which is the property !132 asserts and this path evaded.
func pypiRepoFromProjectURLs(urls map[string]string) string {
	type cand struct {
		rank       int
		label, url string
	}
	cands := make([]cand, 0, len(urls))
	for label, u := range urls {
		if normalizeGitHub(u) == "" {
			continue // not a repo we can score; nothing to rank
		}
		cands = append(cands, cand{pypiURLRank(label), label, u})
	}
	if len(cands) == 0 {
		return ""
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].rank != cands[j].rank {
			return cands[i].rank < cands[j].rank
		}
		if cands[i].label != cands[j].label {
			return cands[i].label < cands[j].label
		}
		return cands[i].url < cands[j].url
	})
	return normalizeGitHub(cands[0].url)
}

// pypiSourceish returns the project_urls values whose LABEL claims to be the source
// repository, best-ranked first, for the coverage report.
//
// Deliberately a different question from pypiRepoFromProjectURLs, which asks "which
// of these is the repo we can SCORE" and therefore only considers URLs that already
// normalise to GitHub. This asks "which of these was MEANT to be the repo", so it
// keeps the ones that normalise to nothing — those are exactly the candidates the
// gap report exists to name.
//
// Labels ranked worse than "unrecognised" are dropped: a Documentation, Funding or
// Bug Tracker URL on another host is not evidence that the PACKAGE's source lives on
// an unsupported forge, and counting it is what made the first version of this report
// announce docs.python.org as a forge.
func pypiSourceish(urls map[string]string) []string {
	type cand struct {
		rank  int
		label string
		url   string
	}
	cands := make([]cand, 0, len(urls))
	for label, u := range urls {
		if u == "" {
			continue
		}
		r := pypiURLRank(label)
		if r > pypiRankUnrecognised {
			continue // explicitly NOT the source: docs, funding, tracker, chat
		}
		cands = append(cands, cand{r, label, u})
	}
	// Sorted for the same reason the chooser sorts: project_urls is a map, and an
	// unstable "which forge" line would make the gap look like it was moving when only
	// the iteration was.
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].rank != cands[j].rank {
			return cands[i].rank < cands[j].rank
		}
		if cands[i].label != cands[j].label {
			return cands[i].label < cands[j].label
		}
		return cands[i].url < cands[j].url
	})
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		out = append(out, c.url)
	}
	return out
}
