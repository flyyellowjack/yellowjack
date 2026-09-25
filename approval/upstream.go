package main

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Harvesting the registry's OWN metadata for the developer lookup (D158's named first
// step: "utilizing parts of the native package manager protocols to scrape and
// populate a UI is the first step anyways").
//
// # Why this lives here rather than in the firewall
//
// D158's sentence — "we already speak those protocols, we are the proxy" — argues for
// the firewall. It is not built there, and the reason is a surface, not a preference:
// the firewall has ONE listener (main.go), the port that serves package-manager
// clients. Any endpoint the console could call would have to join ControlPlanePath,
// which that code calls "THE ENTIRE FAIL-OPEN SURFACE" with a standing instruction to
// prefer leaving things out, because a spurious entry is a silent hole of the kind
// #11, #56, #57 and #59 all were. Four bypasses have come out of that surface; none
// has come out of duplicated parsing.
//
// So the cost is paid where it is visible. This service already aggregates for
// /v1/packages, and the console already talks only to it. ⚠️ It does contradict the
// note on PackageStatus.Upstream that says "this service fetches no registries (the
// firewall does)" — that comment is UPDATED rather than left to rot, because a
// contract sentence that quietly stops being true is worse than one that never was.
//
// # Off by default, and that is deliberate
//
// APPROVAL_UPSTREAM_NPM is empty unless an operator sets it. With it empty this
// service makes no outbound call and the field renders exactly as it did before —
// "not collected by this service". Defaulting to registry.npmjs.org would give every
// existing deployment a new egress destination it never asked for, which is precisely
// the posture (D155, D26) we sell. An air-gapped or mirrored deployment points this at
// the same internal mirror the firewall uses.

// upstreamHarvest is the projection of what the registry itself reports. Deliberately
// small: these are the fields a developer asks about when a build breaks, not
// everything the packument contains. A narrow projection also means an upstream schema
// change cannot silently widen what we store or render.
type upstreamHarvest struct {
	LatestVersion string    `json:"latestVersion,omitempty"`
	PublishedAt   time.Time `json:"publishedAt,omitempty"`
	VersionCount  int       `json:"versionCount,omitempty"`
	Maintainers   int       `json:"maintainers,omitempty"`
	// Deprecated carries the registry's own deprecation MESSAGE, not a boolean. npm
	// lets a maintainer say why, and "why" is the whole value to a developer reading
	// this page.
	Deprecated string `json:"deprecated,omitempty"`
}

// upstreamFetcher reads registry metadata. An interface so the handler can be tested
// without a network, and so a second ecosystem slots in beside npm rather than through
// it.
type upstreamFetcher interface {
	// Fetch returns the harvest, or an availability marker explaining why not. It
	// returns an error ONLY for a transport/parse failure — "this package is not in
	// the registry" is an answer, not an error.
	Fetch(pkg string) (upstreamHarvest, bool, error)
}

// npmUpstream fetches an npm packument.
type npmUpstream struct {
	base string
	http *http.Client
}

// newUpstreamFetcher builds the fetcher for an ecosystem, or nil when the operator has
// not configured one. A nil fetcher is the shipped default and means "not collected".
func newUpstreamFetcher(ecosystem string) upstreamFetcher {
	// A bounded client, not http.DefaultClient. This runs while an operator waits on
	// a page render, and it talks to a third party: without a timeout a slow registry
	// becomes a hung console, which is the shape of failure #39's "ca keypair
	// generation took xxx seconds" note warns about.
	client := &http.Client{Timeout: upstreamFetchTimeout}
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm":
		base := strings.TrimSpace(os.Getenv("APPROVAL_UPSTREAM_NPM"))
		if base == "" {
			return nil
		}
		return &npmUpstream{base: strings.TrimRight(base, "/"), http: client}
	case "pypi":
		base := strings.TrimSpace(os.Getenv("APPROVAL_UPSTREAM_PYPI"))
		if base == "" {
			return nil
		}
		return &pypiUpstream{base: strings.TrimRight(base, "/"), http: client}
	case "maven":
		base := strings.TrimSpace(os.Getenv("APPROVAL_UPSTREAM_MAVEN"))
		if base == "" {
			return nil
		}
		return &mavenUpstream{base: strings.TrimRight(base, "/"), http: client}
	}
	return nil
}

// upstreamFetchTimeout bounds one harvest, headers AND body.
//
// It was 5 s, which the streaming read (#152) made the binding constraint: measured
// 2026-09-21 from a residential link, compressed, `typescript` takes 3.5 s, `vite` 5.5 s and
// `renovate` 7.7 s -- over a second of each is the registry's own time to first byte. So
// the two largest would have streamed perfectly and still been reported unreachable.
//
// It cannot simply be generous either. The console gives THIS service 10 s for the whole
// /v1/packages answer (console/main.go), and a harvest that outlives its caller is work
// nobody is waiting for. 8 s leaves the rest of the request two; the ordering is pinned by
// TestTheHarvestTimeoutFitsInsideTheConsolesTimeout, which reads the console's number from
// its source because the two binaries share no constant.
const upstreamFetchTimeout = 8 * time.Second

// upstreamMaxBytes bounds the registry document we will read. This is a security product
// parsing an untrusted third-party document: an unbounded read is a memory-exhaustion
// lever held by whoever controls the registry response.
//
// It governs PyPI and Maven. npm no longer uses it: its full packument reaches 67 MB, so
// it is STREAMED under its own budgets instead (#152, npmstream.go). The measurement that
// forced that, 2026-09-20 against the live registries, identity-encoded (the bytes the
// reader counts), is kept here because it is also the evidence that this cap still fits
// the other two:
//
//	npm full packument   renovate 66.9 MB · vite 37.1 · next 29.8 · firebase 28.9 ·
//	                     wrangler 28.3 · npm 24.4 · typescript 15.0 · nx 12.9 ·
//	                     @types/node 10.6 · aws-sdk 10.1    -> ALL OVER
//	                     react 6.7 · webpack 5.0 · @angular/core 3.0   -> under
//	PyPI JSON API        botocore 3.65 MB · awscli 3.60 · numpy 3.50  -> 2.2x headroom
//	Maven metadata       awssdk/s3 59.6 KB · spring-core 11.9 KB      -> ~140x headroom
//
// Ten of twenty sampled npm packages were over this cap, and they are the popular,
// long-lived ones a developer is most likely to look up: that path needs the FULL
// packument (the abbreviated one carries no `time`), which holds every version ever
// published and only grows.
//
// Why the answer was a stream and not a bigger number: json.Decoder buffers the whole
// top-level value before decoding, so memory tracks the cap, and the chart gives this
// service a 128 Mi limit (deploy/helm/yellowjack/values.yaml). A cap big enough for
// renovate would let one lookup OOM-kill the control plane. PyPI is the one to
// re-measure: 2.2x is not much headroom, and its document grows the same way.
const upstreamMaxBytes = 8 << 20

func (n *npmUpstream) Fetch(pkg string) (upstreamHarvest, bool, error) {
	// npm addresses a scoped package as "@scope%2fname". url.PathEscape leaves "@"
	// alone (it is legal in a path segment) and escapes the slash, which is exactly
	// the shape the registry wants.
	endpoint := n.base + "/" + url.PathEscape(pkg)
	resp, err := n.http.Get(endpoint)
	if err != nil {
		return upstreamHarvest{}, false, fmt.Errorf("fetching npm metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Not in the registry. An ANSWER — and a useful one, since "the name you
		// typed does not exist upstream" is a common cause of a broken build.
		return upstreamHarvest{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return upstreamHarvest{}, false, fmt.Errorf("npm registry returned status %d", resp.StatusCode)
	}

	// STREAMED, not decoded (#152): a full packument reaches 67 MB and this process has
	// 128 Mi. See npmstream.go for what is kept and how memory is bounded.
	h, err := harvestNpmPackument(resp.Body)
	if err != nil {
		return upstreamHarvest{}, false, fmt.Errorf("decoding npm metadata: %w", err)
	}
	return h, true, nil
}

// normalizeDeprecated turns npm's loosely-typed field into a message or "".
//
// The registry documents a string but has served a bare `true`, and a `false` appears
// on packages that were un-deprecated. Reading `true` as no-deprecation would hide a
// real warning from the developer, so an unrecognised truthy value gets generic text
// rather than silence.
func normalizeDeprecated(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil && b {
		return "deprecated by its maintainer (no reason given)"
	}
	return ""
}

// pypiUpstream fetches a project's JSON document from a PyPI-compatible index.
//
// Point APPROVAL_UPSTREAM_PYPI at the JSON API root — "https://pypi.org/pypi" for
// the public index, or the same path on a mirror (devpi and pypiserver both expose
// it). NOT the /simple/ index: /simple/ is the INSTALLER protocol (PEP 503, a bare
// link list) and carries none of the fields this page renders.
type pypiUpstream struct {
	base string
	http *http.Client
}

func (p *pypiUpstream) Fetch(pkg string) (upstreamHarvest, bool, error) {
	// PyPI redirects a non-normalized name (PEP 503: case-folded, runs of -_. become
	// one dash) rather than 404ing it, and the bounded client follows the redirect,
	// so "Django" and "django" both resolve. The name is still path-escaped: it is
	// attacker-influenced input being placed into a URL.
	endpoint := p.base + "/" + url.PathEscape(pkg) + "/json"
	resp, err := p.http.Get(endpoint)
	if err != nil {
		return upstreamHarvest{}, false, fmt.Errorf("fetching pypi metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// An answer, not an error — same contract as npm above.
		return upstreamHarvest{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return upstreamHarvest{}, false, fmt.Errorf("pypi index returned status %d", resp.StatusCode)
	}

	var doc struct {
		Info struct {
			Version string `json:"version"`
			// PyPI's analogue of npm's deprecation is a YANK (PEP 592), and it is
			// per-release: info.yanked describes the LATEST release only, which is
			// exactly what this page shows beside "latest version".
			Yanked       bool            `json:"yanked"`
			YankedReason json.RawMessage `json:"yanked_reason"`
		} `json:"info"`
		// Releases maps version -> its files. Only the KEYS are counted here, so the
		// per-file objects are deliberately not modelled — a narrow projection, as
		// with npm's packument above.
		Releases map[string]json.RawMessage `json:"releases"`
		Urls     []struct {
			UploadTime string `json:"upload_time_iso_8601"`
		} `json:"urls"`
	}
	if err := decodeCapped(resp.Body, upstreamMaxBytes, &doc); err != nil {
		return upstreamHarvest{}, false, fmt.Errorf("decoding pypi metadata: %w", err)
	}

	h := upstreamHarvest{
		LatestVersion: doc.Info.Version,
		VersionCount:  len(doc.Releases),
		// Maintainers stays 0 on purpose: the JSON API exposes free-text author and
		// maintainer strings, not the project's collaborator list, and counting
		// prose would produce a confident wrong number. The template omits a zero.
	}
	// When the latest release first appeared: the EARLIEST upload among its files.
	//
	// Not doc.Urls[0], and the comment that used to sit here -- "any entry carries the
	// release's publication moment" -- is not true. PyPI's JSON has no per-release
	// timestamp the way npm's `time` map does (see the npm half above, which reads
	// doc.Time[version] and needs none of this care); it has a per-FILE upload_time,
	// and one release's files are not always uploaded together. Measured on the latest
	// release of these packages:
	//
	//	pyyaml        73 files, spanning 3 days 22:56
	//	numpy         66 files, spanning 3m18s
	//	cryptography  46 files, spanning 1m42s
	//
	// urls[0] was the earliest in every sample checked, so this is a correctness
	// tidy-up rather than a live defect -- but that ordering is not documented
	// anywhere, and a display that silently depends on an undocumented array order is
	// one upstream change away from being wrong. Taking the minimum makes it true by
	// construction instead.
	for _, u := range doc.Urls {
		t, err := time.Parse(time.RFC3339, u.UploadTime)
		if err != nil {
			continue // a file with an unparseable stamp must not hide the others
		}
		if h.PublishedAt.IsZero() || t.Before(h.PublishedAt) {
			h.PublishedAt = t
		}
	}
	if doc.Info.Yanked {
		reason := ""
		// yanked_reason is a string or null; decoded loosely for the same reason
		// npm's deprecated field is (normalizeDeprecated above).
		var rs string
		if err := json.Unmarshal(doc.Info.YankedReason, &rs); err == nil {
			reason = strings.TrimSpace(rs)
		}
		if reason == "" {
			reason = "the latest release was yanked by its maintainer (no reason given)"
		} else {
			reason = "the latest release was yanked: " + reason
		}
		// Rendered through the same Deprecated field: a yank IS PyPI's deprecation
		// signal, and the page's callout ("the maintainer's warning") reads
		// correctly for both.
		h.Deprecated = reason
	}
	return h, true, nil
}

// harvestUpstream runs the fetch and maps every outcome onto an availability marker.
//
// THE MARKER IS THE POINT. An absent field reads as "no problem found", so a fetch
// that failed must never render the same way as one that was never configured, and
// neither may render like a clean result. Three distinct outcomes, three markers.
func harvestUpstream(f upstreamFetcher, pkg string) (*upstreamHarvest, string) {
	if f == nil {
		return nil, availNotCollected
	}
	h, found, err := f.Fetch(pkg)
	switch {
	case errors.Is(err, errBodyTooLarge):
		// The registry ANSWERED. Reporting this as "unreachable" sent the reader hunting a
		// connectivity problem that does not exist, for exactly the packages they are
		// most likely to look up (see upstreamMaxBytes for the measurement). Its own
		// marker, and its own log line naming the cap so the event is countable.
		log.Printf("upstream metadata for %q: the registry answered but the document is over the read cap: %v", pkg, err)
		return nil, availUpstreamTooLarge
	case isTimeout(err):
		log.Printf("upstream metadata for %q: the registry did not finish answering within %s: %v", pkg, upstreamFetchTimeout, err)
		return nil, availUpstreamTimedOut
	case err != nil:
		// Logged, not returned to the caller: the developer gets a marker they can act
		// on, the operator gets the detail. Reporting the transport error verbatim on a
		// page would leak the configured mirror's address to whoever can read it.
		log.Printf("upstream metadata for %q: %v", pkg, err)
		return nil, availUpstreamUnreachable
	case !found:
		return nil, availNotInRegistry
	}
	return &h, availPresent
}

// isTimeout reports whether err is a deadline rather than a refusal. http.Client.Timeout
// covers the BODY as well as the headers, so for a large document over a slow link this is
// what ends the read -- mid-stream, after the registry has plainly been reached.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// mavenUpstream reads a Maven repository's own metadata for the developer lookup.
//
// Point APPROVAL_UPSTREAM_MAVEN at a repository ROOT — "https://repo.maven.apache.org/maven2"
// for Central, or the same path on a Nexus/Artifactory proxy. Off by default, like the
// two fetchers above: with the variable unset this service makes no outbound call and
// the field renders "not collected by this service".
//
// Maven answers three of this page's five fields and genuinely cannot answer the other
// two. Those absences are recorded below rather than filled with a number that would
// look right, because "four ecosystems" being true of the CODE and false of the EFFECT
// is a gap this project has measured twice already (E25 for layer 1; the release window
// before !253).
type mavenUpstream struct {
	base string
	http *http.Client
}

// mavenUpstreamMetadata is the narrow projection of maven-metadata.xml this page needs.
//
// Deliberately re-declared here rather than shared with the firewall's mavenMetadata:
// this is a different process reading a third-party document for DISPLAY, and coupling
// the console's projection to the gate's would mean a field added for one silently
// widens the other. The gate's copy is the one with a security contract.
type mavenUpstreamMetadata struct {
	Versioning struct {
		// Release is the newest non-SNAPSHOT version; Latest can point AT a snapshot,
		// so Release is preferred and Latest is only the fallback — the same order the
		// gate's own latestVersion uses, for the same reason.
		Release  string   `xml:"release"`
		Latest   string   `xml:"latest"`
		Versions []string `xml:"versions>version"`
		// LastUpdated is parsed ONLY so the struct documents that we saw it and did
		// not use it. See the PublishedAt comment in Fetch.
		LastUpdated string `xml:"lastUpdated"`
	} `xml:"versioning"`
}

func (m *mavenUpstream) Fetch(pkg string) (upstreamHarvest, bool, error) {
	// A Maven package name IS "group:artifact" — that is what the gate's
	// PackageNameFromPath mints, and what every decision is keyed on. A name with no
	// colon cannot name a Maven artifact at all, so this is an ANSWER ("not in the
	// registry"), not a transport failure to log and retry.
	group, artifact, ok := strings.Cut(pkg, ":")
	if !ok || group == "" || artifact == "" {
		return upstreamHarvest{}, false, nil
	}
	// The group's dots become path segments. Each segment is still escaped: this is
	// attacker-influenced input going into a URL.
	groupPath := ""
	for i, seg := range strings.Split(group, ".") {
		if i > 0 {
			groupPath += "/"
		}
		groupPath += url.PathEscape(seg)
	}
	artifactPath := url.PathEscape(artifact)

	endpoint := m.base + "/" + groupPath + "/" + artifactPath + "/maven-metadata.xml"
	resp, err := m.http.Get(endpoint)
	if err != nil {
		return upstreamHarvest{}, false, fmt.Errorf("fetching maven metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Not in the repository — an answer, same contract as npm and PyPI above.
		return upstreamHarvest{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return upstreamHarvest{}, false, fmt.Errorf("maven repository returned status %d", resp.StatusCode)
	}

	// readCapped, not io.ReadAll(io.LimitReader(...)): that idiom returns the first 8 MB
	// and a NIL error, so an oversized document was silently TRUNCATED and the XML parser
	// below was handed a prefix (#139).
	body, err := readCapped(resp.Body, upstreamMaxBytes)
	if err != nil {
		return upstreamHarvest{}, false, fmt.Errorf("reading maven metadata: %w", err)
	}
	var doc mavenUpstreamMetadata
	if err := xml.Unmarshal(body, &doc); err != nil {
		return upstreamHarvest{}, false, fmt.Errorf("decoding maven metadata: %w", err)
	}

	h := upstreamHarvest{
		LatestVersion: doc.Versioning.Release,
		VersionCount:  len(doc.Versioning.Versions),
		// Maintainers stays 0, like PyPI's. A POM carries <developers>, but it is
		// publisher-authored prose inside the artifact — frequently absent, frequently
		// a stale list of everyone who ever touched the project — not the repository's
		// record of who may publish. Counting it would produce a confident wrong
		// number; the template omits a zero.
		//
		// Deprecated stays "" because Maven has no deprecation signal at all: there is
		// no equivalent of npm's `deprecated` field or PyPI's PEP 592 yank. An empty
		// string here means "this ecosystem cannot say", and it renders the same as
		// "not deprecated" — a real limitation of the page for Maven, stated here so
		// nobody reads a clean Maven row as a positive statement about the artifact.
	}
	if h.LatestVersion == "" {
		h.LatestVersion = doc.Versioning.Latest
	}

	// PublishedAt is NOT doc.Versioning.LastUpdated, and that is the whole point of
	// this block.
	//
	// maven-metadata.xml carries exactly ONE <lastUpdated> for the whole artifact —
	// measured on guava: 158 <version> entries, one timestamp — so it describes when
	// the artifact was last touched, not when the version beside it was published.
	// Rendering it under "published" would stamp every version with the same date and
	// look entirely plausible while being wrong. mavenage.go records that measurement
	// in full; this is the same finding reached by the same route, and the same answer:
	// the honest source is the per-file Last-Modified the REPOSITORY sets when the file
	// lands, which is distinct per version and is not written by the publisher.
	//
	// Cost, stated: one extra HEAD per lookup, and only when a fetcher is configured at
	// all. A failure here must not lose the versions we already have, so every failing
	// path leaves PublishedAt zero and returns the rest — the template omits a zero
	// date, which reads as "this page cannot date it", not as a date of zero.
	if h.LatestVersion != "" {
		h.PublishedAt = m.releaseTime(groupPath, artifactPath, h.LatestVersion)
	}
	return h, true, nil
}

// releaseTime asks the repository when the latest version's POM landed, or returns the
// zero time. Never an error: an undated release is a worse page, not a failed fetch,
// and turning it into one would replace three good fields with an "unreachable" marker.
func (m *mavenUpstream) releaseTime(groupPath, artifactPath, version string) time.Time {
	v := url.PathEscape(version)
	// The POM, not the jar: every Maven artifact has one whatever its packaging, and
	// HEAD on it moves no bytes. Packaging is open-ended (!80 is the record of what
	// guessing at Maven extensions costs), so asking for the one file that always
	// exists is the only shape that works for every artifact.
	pomURL := m.base + "/" + groupPath + "/" + artifactPath + "/" + v + "/" + artifactPath + "-" + v + ".pom"
	req, err := http.NewRequest(http.MethodHead, pomURL, nil)
	if err != nil {
		return time.Time{}
	}
	resp, err := m.http.Do(req)
	if err != nil {
		return time.Time{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Includes 405 from a repository that forbids HEAD: a statement about the
		// METHOD, which says nothing about the file and must not become a date.
		return time.Time{}
	}
	lm := resp.Header.Get("Last-Modified")
	if lm == "" {
		return time.Time{}
	}
	t, err := http.ParseTime(lm)
	if err != nil {
		// A malformed date is an unknown date, never a guessed one.
		return time.Time{}
	}
	return t.UTC()
}
