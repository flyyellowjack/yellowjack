package main

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// mavenEcosystem gates Maven artifact pulls (Maven Central by default). Maven is
// the most involved ecosystem so far: there is no single JSON metadata endpoint
// like npm/PyPI. Artifacts live at
//
//	/{group/with/slashes}/{artifactId}/{version}/{artifactId}-{version}.{ext}
//
// and the source repo, when declared, is in the POM's <scm>/<url> — which we
// reach via maven-metadata.xml (to find a version) then that version's .pom.
type mavenEcosystem struct {
	base string
	// cache dedups the metadata/POM fetch fan-out across the many artifacts a single
	// cold `mvn` resolve gates at once — chiefly the shared parent POMs they all climb
	// to (D25). nil in hand-built test ecosystems, which the cache treats as off.
	cache *mavenFetchCache
	// gate coalesces concurrent probes for the same URL (before the cache is warm) and
	// bounds how many outbound probes run at once (D25 item c). The cache removes the
	// SHARED-parent multiplier; the gate shrinks the FIRST-attempt burst the cache can't
	// see. nil in hand-built test ecosystems, which the gate treats as off (direct call).
	gate *mavenProbeGate
	// ages memoises the per-artifact release-time probe behind the release window
	// (#26, D22) — see mavenage.go. nil in hand-built test ecosystems, which the
	// cache treats as off, so every probe goes to the upstream.
	ages *mavenAgeCache
}

func (e mavenEcosystem) Name() string { return "maven" }

// PackageNameFromPath gates any artifact under a Maven GAV path
// ("group/path/artifact/version/<file>") and returns the package identity
// "group:artifact" — version-agnostic, so a human approves the library once, not
// once per version.
//
// It gates on the PATH SHAPE with a narrow exclusion list, NOT on an extension
// allowlist, and that inversion is the whole point (issue #56).
//
// The gate used to return an identity only for .jar/.pom/.aar/.war and "" for
// everything else — and "" means "not an identifiable package request", which
// proxy.go relays UNGATED. An extension allowlist is a denylist in disguise: it
// gates what someone thought of and passes everything else, so every packaging
// nobody enumerated defaulted to fail-OPEN. Measured, all ten of the extensions a
// real resolve pulls delivered a BLOCKED package's bytes in full:
//
//	.module .zip .tar.gz .ear .nar .jmod .exe .dll .so .dylib
//
// .module is the sharpest, because Gradle 6+ requests Gradle Module Metadata for
// EVERY dependency on a normal resolve — so the bypass was on the common path, not
// an exotic one. .exe/.dll/.so/.dylib are the ugliest: native binaries.
//
// Now the default is to GATE, and only the listed non-artifact files pass through.
// A new packaging type — Maven packaging is open-ended — is gated the day it exists
// instead of silently walking past.
func (e mavenEcosystem) PackageNameFromPath(p string) string {
	group, artifact, _, ok := mavenGAV(p)
	if !ok {
		return ""
	}
	return group + ":" + artifact
}

// VersionFromPath returns the VERSION this request is for, which the identity above
// deliberately throws away.
//
// Both come from ONE parse (mavenGAV) rather than from two functions that agree by
// inspection. That is the same reasoning ociRefAfter records for mirroring
// ociNameBefore, only stronger: if a name and a version could be taken from different
// readings of one path, a request could be gated under one coordinate and
// version-checked against another — and the mismatch would be silent.
//
// This exists because Maven's identity is version-agnostic ON PURPOSE ("a human
// approves the library once, not once per version"), which is right for approvals and
// leaves version-pinned known-malware advisories (issue #103) with nothing to match
// on. The version is in the path; it just is not in the identity.
func (e mavenEcosystem) VersionFromPath(p string) (string, bool) {
	_, _, version, ok := mavenGAV(p)
	return version, ok
}

// mavenGAV parses a Maven repository path into its coordinate, or reports ok=false if
// the path is not a gated artifact request. It is the single definition of what this
// ecosystem considers an artifact — see PackageNameFromPath's comment for why the
// default is to GATE and only mavenUngatedFile passes through (issue #56).
func mavenGAV(p string) (group, artifact, version string, ok bool) {
	p = strings.Trim(p, "/")
	if p == "" {
		return "", "", "", false
	}
	segs := strings.Split(p, "/")
	if len(segs) < 4 { // need at least group/artifact/version/file
		return "", "", "", false
	}
	file := segs[len(segs)-1]
	version = segs[len(segs)-2]
	artifact = segs[len(segs)-3]
	if mavenUngatedFile(file, artifact) {
		return "", "", "", false
	}
	group = strings.Join(segs[:len(segs)-3], ".")
	if group == "" || artifact == "" || version == "" {
		return "", "", "", false
	}
	return group, artifact, version, true
}

// mavenExtensionlessSuffixes are the non-artifact files that must keep passing
// through ungated. Kept SHORT and explicit on purpose: everything not named here is
// gated, so this list is the entire fail-open surface and is meant to be reviewable
// at a glance.
//
//   - maven-metadata.xml — the version index. It carries no artifact bytes, and it is
//     what a resolve reads to discover versions; gating it would break resolution
//     before any artifact is ever requested. Prefix-matched because SNAPSHOT builds
//     serve one per version directory, and because its own checksums sit beside it.
//   - checksums and signatures — tens of bytes of hex or a detached signature. No
//     payload can ride in them, and a resolver fetches them for artifacts it has
//     already been allowed to fetch.
var mavenUngatedSuffixes = []string{".sha1", ".md5", ".sha256", ".sha512", ".asc"}

// mavenUngatedFile reports whether the last segment of a GAV-shaped path is a
// non-artifact file that must pass through, or a DIRECTORY rather than a file at all.
// artifact is the artifactId from the path (segs[-3]), used to recognise the canonical
// filename shape.
//
// Telling a file from a directory is not cosmetic. "com/evil/badlib/1.0.0" also has
// four segments, and parsing it positionally yields the WRONG identity — the version
// slot holds the artifactId, giving "com:evil". Gating a request under a name that is
// not its own is worse than not gating it, because the verdict then belongs to some
// other package.
//
// The discriminator is the repository layout itself rather than a guess about
// extensions. Maven addresses an artifact as
// "<artifactId>-<version>[-<classifier>].<ext>", so:
//
//  1. a name starting "<artifactId>-" is an artifact of THIS GAV — gate it, whatever
//     its extension is. This is the case that must not depend on an extension list.
//  2. otherwise, a name starting with a digit is a version directory ("1.0.0",
//     "1.0.0-SNAPSHOT", "1.0.RELEASE") — not a file, so nothing to gate.
//  3. anything else is a file that does not follow the layout convention. It is GATED,
//     because it can still carry bytes, and fail-closed is the direction this whole
//     issue is about.
//
// TWO EARLIER ATTEMPTS AT THIS WERE WRONG, both caught by the tier-3 pass, and both
// worth recording because they are the shapes a reviewer will suggest:
//
//   - "does the last dot-segment look like an extension?" — it required the extension
//     to be alphabetic, so ".tar.bz2" (and .7z, and anything else carrying a digit)
//     read as a directory and went straight back to being ungated.
//   - "a name starting with a digit is a version directory" — then "2FA.jar" is a
//     digit-initial name, so an attacker gates nothing by simply naming the file so it
//     starts with a number. Measured: 200, full payload delivered.
//
// Both failures have the same root: they infer file-ness from the NAME, and the name
// is attacker-chosen. So the only signal used here is one the attacker does not
// control — the trailing slash that marks a directory request, checked by the caller —
// after which anything left is treated as a file and gated.
func mavenUngatedFile(file, artifact string) bool {
	// EXACT match, not a prefix. A prefix test passes "maven-metadata.xml.evil.jar",
	// which is a fully-functional artifact URL that no longer gets gated — measured at
	// 200 with the payload. The real checksums of the metadata file
	// ("maven-metadata.xml.sha1") are covered by the suffix rule below, so nothing
	// legitimate needs the looser test.
	if file == "maven-metadata.xml" {
		return true
	}
	for _, s := range mavenUngatedSuffixes {
		if strings.HasSuffix(file, s) {
			return true
		}
	}
	// Everything else at this depth is treated as an artifact and gated — names that do
	// not follow the "<artifactId>-<version>" convention, and DIRECTORY LISTINGS too.
	//
	// Listings are gated rather than exempted, and that is the third and final version
	// of this decision. Exempting them needs a rule for telling a listing from a file,
	// and every such rule was a bypass:
	//
	//	name looks like an extension  -> ".tar.bz2" ungated
	//	name starts with a digit      -> "2FA.jar" ungated
	//	path ends in a slash          -> "badlib-1.0.0.jar/" ungated, and a CDN that
	//	                                 normalizes the slash away then serves the jar —
	//	                                 the identity-divergence class of issue #59
	//
	// The information simply is not in the request: only the repository knows whether a
	// name is a file, and the name itself is chosen by whoever published it. So a
	// listing is gated under a positionally-shifted identity ("com/evil/badlib/1.0.0"
	// reads as "com:evil") and refused under the fail-closed default. No resolver ever
	// requests one — resolvers build exact URLs from coordinates — so the cost is a 403
	// on a URL only a human browsing a repository would type, and the benefit is that
	// there is no name an attacker can choose that skips the gate.
	return false
}

// ControlPlanePath mirrors mavenUngatedFile's exemption list — maven-metadata.xml
// (EXACT, never a prefix) and the checksum/signature suffixes — so the set of files
// Maven relays ungated is defined in exactly one place. If !80's list changes, this
// follows automatically.
//
// It re-checks the FILE NAME at any depth, which matters because PackageNameFromPath
// bails on "len(segs) < 4" before ever consulting mavenUngatedFile. A real
// maven-metadata.xml lives at "<group>/<artifact>/maven-metadata.xml", and for a
// short group like "junit/junit/maven-metadata.xml" that is only 3 segments — so
// without this the file every Maven resolve fetches would land in PathUnknown and be
// refused.
//
// Everything else shallow — "/com/google/", a bare group directory — is NOT named
// here and is therefore refused, which is the same call !80 made for deeper listings:
// no resolver requests one, because resolvers build exact URLs from coordinates.
func (e mavenEcosystem) ControlPlanePath(p string) bool {
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return true // repository root — clients probe it for reachability
	}
	segs := strings.Split(trimmed, "/")
	file := segs[len(segs)-1]
	if file == "maven-metadata.xml" {
		return true
	}
	for _, suffix := range mavenUngatedSuffixes {
		if strings.HasSuffix(file, suffix) {
			return true
		}
	}
	return false
}

// mavenMetadata is the slice of maven-metadata.xml we read to pick a version.
type mavenMetadata struct {
	Versioning struct {
		Release string `xml:"release"`
		Latest  string `xml:"latest"`
	} `xml:"versioning"`
}

// mavenPOM is the slice of a POM carrying the source repo. Go's xml decoder maps
// these to the children of the root <project> element regardless of its name.
// Parent is read so we can follow the inheritance chain when a POM declares no
// <scm> of its own (very common for parent/aggregator POMs).
type mavenPOM struct {
	URL string `xml:"url"`
	SCM struct {
		URL        string `xml:"url"`
		Connection string `xml:"connection"`
	} `xml:"scm"`
	Parent struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	} `xml:"parent"`
}

// LookupRepo resolves "group:artifact" to a normalized GitHub repo by reading the
// latest release's POM, following the <parent> chain when the artifact's own POM
// declares no <scm> (see repoFromParents). Returns "" (no error) when no usable
// GitHub source is found — which becomes "unscorable" and routes to the approval
// workflow (manual association is acceptable for the less-numerous
// Maven world).
func (e mavenEcosystem) LookupRepo(c *http.Client, pkg string) (string, error) {
	group, artifact, ok := strings.Cut(pkg, ":")
	if !ok || group == "" || artifact == "" {
		return "", nil
	}
	groupPath := strings.ReplaceAll(group, ".", "/")

	version, err := e.latestVersion(c, groupPath, artifact)
	if err != nil {
		return "", err
	}
	if version == "" {
		return "", nil
	}

	pomURL := fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom", e.base, groupPath, artifact, version, artifact, version)
	pom, err := e.fetchPOM(c, pomURL)
	if err != nil {
		return "", err
	}
	if repo := mavenRepo(pom); repo != "" {
		return repo, nil
	}
	// The artifact's own POM declares no usable repo. Maven POMs commonly inherit
	// <scm> from a <parent> (parent/aggregator POMs — like the shared maven-plugins
	// parent — carry the SCM their children omit), so walk the parent chain. A real
	// client hits this immediately: at fail-closed policy, Maven's own core plugins
	// were unscorable because their parent POM held the SCM. Scoring the parent
	// project's repo is a sound build-practices signal and strictly better than
	// blocking as unscorable; the approval workflow can still correct it.
	repo := e.repoFromParents(c, pom)
	if repo == "" {
		// The artifact's own POM, in the order mavenRepo tried them. The parent
		// chain's URLs are deliberately NOT included: a child inheriting from a
		// GitHub-hosted parent is not evidence that THIS artifact lives on another
		// forge, and counting it would inflate the gap with the shared parents every
		// Maven resolve walks.
		conn := strings.TrimPrefix(pom.SCM.Connection, "scm:git:")
		conn = strings.TrimPrefix(conn, "scm:")
		noteUnsupportedForge("maven", pkg, pom.SCM.URL, conn, pom.URL)
	}
	return repo, nil
}

// maxParentDepth bounds how far up the <parent> chain we climb. Real chains are
// short (artifact -> project parent -> org parent, e.g. org.apache:apache); the
// bound stops a malformed or cyclic chain from fanning out into unbounded fetches.
const maxParentDepth = 5

// repoFromParents walks a POM's <parent> chain, fetching each parent and returning
// the first usable GitHub repo in its <scm>/<url>. Maven appends the child's
// artifactId to an inherited SCM path, but we only need the repo (normalizeGitHub
// already reduces to github.com/owner/name), so the parent's own SCM repo is the
// right answer. A fetch failure, or a chain that ends without an SCM, returns ""
// (the artifact stays unscorable and routes to the approval workflow).
func (e mavenEcosystem) repoFromParents(c *http.Client, child mavenPOM) string {
	for depth := 0; depth < maxParentDepth; depth++ {
		p := child.Parent
		if p.GroupID == "" || p.ArtifactID == "" || p.Version == "" {
			return "" // no complete parent reference: chain ends here
		}
		groupPath := strings.ReplaceAll(p.GroupID, ".", "/")
		pomURL := fmt.Sprintf("%s/%s/%s/%s/%s-%s.pom", e.base, groupPath, p.ArtifactID, p.Version, p.ArtifactID, p.Version)
		parent, err := e.fetchPOM(c, pomURL)
		if err != nil {
			return "" // parent POM unfetchable: give up, stay unscorable
		}
		if repo := mavenRepo(parent); repo != "" {
			return repo
		}
		child = parent // climb one level
	}
	return ""
}

func (e mavenEcosystem) latestVersion(c *http.Client, groupPath, artifact string) (string, error) {
	u := fmt.Sprintf("%s/%s/%s/maven-metadata.xml", e.base, groupPath, artifact)
	body, err := e.fetchBody(c, u, "maven-metadata")
	if err != nil {
		return "", err
	}
	var m mavenMetadata
	if err := xml.Unmarshal(body, &m); err != nil {
		return "", err
	}
	if m.Versioning.Release != "" {
		return m.Versioning.Release, nil
	}
	return m.Versioning.Latest, nil // may be "" — caller treats that as no repo
}

func (e mavenEcosystem) fetchPOM(c *http.Client, pomURL string) (mavenPOM, error) {
	body, err := e.fetchBody(c, pomURL, "pom fetch")
	if err != nil {
		return mavenPOM{}, err
	}
	var p mavenPOM
	if err := xml.Unmarshal(body, &p); err != nil {
		return mavenPOM{}, err
	}
	return p, nil
}

// mavenBodyMaxBytes bounds a single metadata/POM read. Real POMs are a few KB; this
// generous cap only stops a hostile or broken upstream from streaming an unbounded
// body into memory — we read the whole body (rather than stream-decode) so it can be
// cached and re-parsed on a hit.
const mavenBodyMaxBytes = 8 << 20 // 8 MiB

// mavenFetchCacheTTL is deliberately short: the cache only needs to span one cold
// `mvn` resolve's probe burst (seconds to a couple of minutes). Released POMs are
// immutable so a longer window would also be safe, but a short TTL keeps a long-lived
// firewall's map from accumulating stale entries.
const mavenFetchCacheTTL = 5 * time.Minute

// fetchBody GETs url and returns its body, consulting the URL cache first and
// populating it on a fresh 200 (see mavenFetchCache) — this is what collapses the
// shared-parent-POM re-fetch across a resolve into one GET per URL. Non-200s route
// through the shared D17 taxonomy and are NEVER cached: a 429/5xx must stay live so a
// later retry re-hits the upstream, and a 404 must not pin "not found". `what` is the
// error-message prefix ("maven-metadata" or "pom fetch") so callers keep their wording.
func (e mavenEcosystem) fetchBody(c *http.Client, url, what string) ([]byte, error) {
	if body, ok := e.cache.get(url); ok {
		return body, nil
	}
	// Coalesce concurrent identical probes: when several artifacts' parent walks race
	// to the SAME URL before the cache is warm, exactly one goroutine performs the GET
	// and the rest receive its result (mavenProbeGate). This shrinks the FIRST-attempt
	// burst the URL cache can't see (the cache only helps a SECOND fetch of a URL). A
	// nil gate (hand-built test ecosystems) degrades to a plain call.
	return e.gate.do(url, func() ([]byte, error) {
		// Bound the number of OUTBOUND probes running at once so a cold resolve's burst
		// is smoothed under the upstream's rate window. Followers waiting in do() hold
		// no slot — only the one goroutine that actually hits the network does. A nil or
		// unbounded gate makes acquire a no-op.
		release := e.gate.acquire()
		defer release()

		resp, err := c.Get(url)
		if err != nil {
			// No answer at all: transient (D17) — surfaced as a 503 so mvn retries,
			// never misfiled as "this artifact has bad metadata".
			return nil, fmt.Errorf("%s: %w: %v", what, errUpstreamUnavailable, err)
		}
		defer closeDrained(resp.Body)
		if resp.StatusCode != http.StatusOK {
			// Maven Central rate-limits readily (429); a 429/5xx must become a retryable
			// 503, NOT a quarantine, and a 404 = artifact unknown upstream. Never cached.
			if cerr := classifyStatus(resp.StatusCode); cerr != nil {
				return nil, fmt.Errorf("%s: %w (status %d)", what, cerr, resp.StatusCode)
			}
			return nil, fmt.Errorf("%s returned status %d", what, resp.StatusCode)
		}
		body, err := readCapped(resp.Body, mavenBodyMaxBytes)
		if err != nil {
			// A read failure mid-body is a truncated/interrupted transfer — transient.
			return nil, fmt.Errorf("%s: %w: %v", what, errUpstreamUnavailable, err)
		}
		e.cache.put(url, body)
		return body, nil
	})
}

// mavenRepo picks the best source URL from a POM and normalizes it: prefer
// <scm><url>, then <scm><connection> (strip its "scm:git:"/"scm:" prefix), then
// the project <url>.
func mavenRepo(p mavenPOM) string {
	if r := normalizeGitHub(p.SCM.URL); r != "" {
		return r
	}
	conn := strings.TrimPrefix(p.SCM.Connection, "scm:git:")
	conn = strings.TrimPrefix(conn, "scm:")
	if r := normalizeGitHub(conn); r != "" {
		return r
	}
	return normalizeGitHub(p.URL)
}

// mavenFetchCache is a short-TTL, URL-keyed cache of successful (200) POM and
// maven-metadata bodies. Maven is the one ecosystem whose repo lookup fans out into
// many upstream fetches per artifact — maven-metadata.xml + the artifact's own POM +
// up to maxParentDepth parent POMs (repoFromParents) — and a cold `mvn` resolve gates
// dozens of artifacts at once, most of which climb to the SAME shared parent POMs
// (org.apache:apache, com.google:google, …). Without this, each package's parent walk
// re-fetches those identical parents independently, and the burst trips Maven
// Central's per-IP rate limit (D25). Keying by URL collapses the shared-parent
// re-fetch to one GET per URL per TTL window — the biggest fan-out multiplier.
//
// Only 200 bodies are cached — never a 404/429/5xx, which must stay live so the D17
// transient-vs-not taxonomy (errPkgNotFound / errUpstreamRateLimited / …) still
// classifies each fetch. A released version's POM is immutable, so even minutes of
// staleness is safe; maven-metadata.xml can gain a newer version, but a slightly
// stale "latest" only changes which version's POM we read a repo URL from — harmless
// for a build-practices score.
//
// Same mutex / nil-safe / TTL-disabled idiom as scoreCache and repoCache: a nil cache
// always misses, and a ttl <= 0 makes put a no-op so the whole thing is off.
type mavenFetchCache struct {
	mu  sync.RWMutex
	ttl time.Duration
	m   map[string]mavenFetchEntry
}

type mavenFetchEntry struct {
	body   []byte
	expiry time.Time
}

func newMavenFetchCache(ttl time.Duration) *mavenFetchCache {
	return &mavenFetchCache{ttl: ttl, m: make(map[string]mavenFetchEntry)}
}

// get returns the cached body for url if present and unexpired. Nil-safe: a nil
// cache always misses, so callers never need a nil check.
func (c *mavenFetchCache) get(url string) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.m[url]
	if !ok || time.Now().After(e.expiry) {
		return nil, false
	}
	return e.body, true
}

// put stores body under url with the configured TTL. A nil cache or ttl <= 0
// disables caching, so put is a no-op and get always misses.
func (c *mavenFetchCache) put(url string, body []byte) {
	if c == nil || c.ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[url] = mavenFetchEntry{body: body, expiry: time.Now().Add(c.ttl)}
}

// mavenProbeConcurrency bounds how many metadata/POM probes hit the upstream at
// once. The URL cache (mavenFetchCache) already collapses the dominant shared-parent
// multiplier, so this is a conservative safety valve on what's left of a cold
// resolve's first-attempt burst — low enough to sit under Maven Central's per-IP
// window, high enough not to serialize a large legit resolve (POM/metadata bodies are
// small and fast). It's a const to mirror mavenFetchCacheTTL; the real ceiling-raiser
// is upstream authentication (D25 item e), not this bound. <= 0 would mean unbounded.
const mavenProbeConcurrency = 4

// mavenProbeGate is the coalesce-and-bound layer around the raw upstream GET in
// fetchBody — the second half of the D25 fan-out fix (item c), complementing the URL
// cache (item b):
//
//   - Singleflight (inflight map): the cache only helps the SECOND fetch of a URL, so a
//     cold resolve where many artifacts' parent walks race to the SAME parent POM before
//     any of them has cached it still bursts. do() lets exactly one goroutine per URL run
//     the GET; the others block until it returns and share its result.
//   - Semaphore (sem): even across DISTINCT URLs, acquire() bounds concurrent outbound
//     probes so the burst is smoothed under the upstream's rate window.
//
// Singleflight sits OUTSIDE the semaphore (do wraps acquire): a follower waiting on an
// in-flight leader holds no semaphore slot, so followers never count against the bound
// and can't deadlock a low bound. A single LookupRepo walks its parent chain
// sequentially, so one goroutine holds at most one slot at a time regardless of depth.
//
// Same nil-safe / "zero = off" idiom as mavenFetchCache: a nil gate (hand-built test
// ecosystems) makes do a direct call and acquire a no-op; a gate built with
// concurrency <= 0 coalesces but does not bound.
// The coalescing half now lives in singleflight.go as the generic flightGroup —
// shared with the npm/PyPI/deps.dev lookups that grew the same guard in issue #16 —
// so this type is just "that, plus the outbound-concurrency bound". The bodies it
// shares between callers are read-only to them (they only xml.Unmarshal them),
// exactly as the URL cache already shares its stored slice.
type mavenProbeGate struct {
	sem     chan struct{} // counting semaphore; nil = unbounded
	flights *flightGroup[[]byte]
}

func newMavenProbeGate(concurrency int) *mavenProbeGate {
	g := &mavenProbeGate{flights: newFlightGroup[[]byte]()}
	if concurrency > 0 {
		g.sem = make(chan struct{}, concurrency)
	}
	return g
}

// do runs fn to fetch key, coalescing concurrent calls for the same key so fn runs
// once and every caller gets its result. A nil gate degrades to a direct fn() call
// (no coalescing) so callers need no nil check.
func (g *mavenProbeGate) do(key string, fn func() ([]byte, error)) ([]byte, error) {
	if g == nil {
		return fn()
	}
	return g.flights.do(key, fn)
}

// acquire takes one semaphore slot and returns a release func (call it with defer).
// A nil gate or an unbounded one (sem == nil) returns a no-op release.
func (g *mavenProbeGate) acquire() func() {
	if g == nil || g.sem == nil {
		return func() {}
	}
	g.sem <- struct{}{}
	return func() { <-g.sem }
}
