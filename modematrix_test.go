package main

// The mode-coverage matrix.
//
// Until now we tested a few representative configurations and REASONED about the
// rest. This rig replaces the reasoning: it enumerates every reachable combination
// of the axes that actually change behaviour, drives a real request through a real
// proxy for each one, and compares what happened against a COMMITTED expectation
// table (docs/mode-matrix.json). Any cell that diverges fails; any cell not present
// in the table fails as "unrecorded". That second rule is the important one — it
// means a new mode, ecosystem or policy cannot be added without someone recording,
// and therefore looking at, what it actually does.
//
// Bypass detection is structural, not incidental. The fake upstreams RECORD every
// path they are asked for, and each cell captures whether the artifact object was
// fetched upstream at all. Checking the status the client saw is not enough: a 403
// with the bytes already pulled from upstream is still a bypass, and this rig is
// what makes that visible.
//
// Regenerate the table (after reviewing the diff!) with:
//
//	sh scripts/mode-matrix.sh --update
//
// Never regenerate to "fix" a red run without reading the diff: the whole point is
// that a behaviour change shows up as a diff a human approves.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// updateMatrix regenerates the committed expectation table instead of asserting
// against it. Wired to `go test -run TestModeMatrix -args -update-matrix`.
var updateMatrix = flag.Bool("update-matrix", false, "rewrite docs/mode-matrix.json from observed behaviour")

const (
	matrixTablePath = "docs/mode-matrix.json"
	matrixDocPath   = "docs/MODE_MATRIX.md"
)

// ───────────────────────── axes ─────────────────────────

// The scenarios are the four package shapes that produce the four interesting
// verdict classes. They differ ONLY in what the registry metadata declares and what
// deps.dev says about it — i.e. in the inputs a real package presents.
const (
	scenGood     = "good"     // declares a repo; deps.dev agrees; scores high  -> allowed
	scenLowScore = "lowscore" // declares a repo; deps.dev agrees; scores low   -> hard deny
	scenNoRepo   = "norepo"   // declares no repo at all                        -> unscorable (soft)
	scenMismatch = "mismatch" // declares a HIGH-reputation repo that isn't its own
	//                           (the borrow-a-score path)                      -> unverified (soft)

	// scenUpstreamDown is the fifth scenario, and unlike the other four it does not
	// vary what the package DECLARES — it varies whether we can find out at all. The
	// fake registry refuses the repo-resolution request, so evaluation produces
	// Unavailable: not a verdict, but an admission that we never reached one.
	//
	// It exists because the matrix could not previously reach that outcome at all.
	// classifyLogLabels recorded "byte-gate-withheld-unavailable" as NOT EXERCISED
	// across all 3072 cells, which mattered: #60 — an upstream outage downgrading a
	// hard deny into served bytes — was a live security bug in exactly this outcome,
	// and a golden table that cannot express the outcome cannot catch a regression in
	// it. This is that gap closed.
	scenUpstreamDown = "upstreamdown" // registry unreachable -> Unavailable (not a verdict)
)

// The three request kinds. These are the distinct paths bytes and decisions can
// travel, and the whole reason the matrix exists: a gate that holds on one kind and
// not another is exactly the issue-#11 shape.
const (
	kindMetadata = "metadata" // the index/packument/manifest — the documented control point
	kindBytes    = "bytes"    // the artifact itself: tarball, wheel, layer blob, jar
	kindBytesAlt = "bytes-alt"
	//                          a SECOND route to artifact bytes in the same ecosystem
	kindInfra = "infra" // control-plane/registry infrastructure endpoints
)

// byteKinds are the request kinds that fetch ARTIFACT bytes. There is more than one
// per ecosystem, and that is the point (issue #63): every bug this matrix exists to
// find — the npm lockfile side-door (#11), the OCI blob gap (#57), the Maven
// extension allowlist (#56) — is "the same bytes reachable by a SECOND route". A
// matrix that drives one route per ecosystem measures the first route and reasons
// about the rest, which is the habit the matrix was built to replace. Concretely: when
// #56 was fixed, the matrix did not move by a single cell, because `.jar` was already
// gated and none of the ten alternate packagings were in the cross-product.
//
// A second KIND, deliberately, not a second axis: a kind adds one column per
// configuration (+768 cells), an axis multiplies all 2,304 and makes the committed
// table too big for the human review it exists to receive.
var byteKinds = []string{kindBytes, kindBytesAlt}

func isByteKind(kind string) bool {
	for _, k := range byteKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// keyIsByteCell reports whether a committed-table KEY names a byte-route cell. Keys
// are "<eco>/<kind>/<scen>/…", so the kind is matched with its delimiters — note that
// "/bytes/" does NOT match "…/bytes-alt/…", which is exactly why every place that
// scans the table for byte cells has to go through here rather than hardcoding one
// kind. Missing the alt kind would silently exclude half the byte routes from the
// bypass baseline, i.e. stop alarming on the routes this issue added.
func keyIsByteCell(key string) bool {
	for _, k := range byteKinds {
		if strings.Contains(key, "/"+k+"/") {
			return true
		}
	}
	return false
}

var (
	allEcosystems = []string{"npm", "pypi", "oci", "maven"}
	allKinds      = []string{kindMetadata, kindBytes, kindBytesAlt, kindInfra}
	allScenarios  = []string{scenGood, scenLowScore, scenNoRepo, scenMismatch, scenUpstreamDown}
	allByteGates  = []string{byteGateOff, byteGateAllowButLog, byteGateEnforce}
	allUnscorable = []string{"allow", "block"}
	allUnverified = []string{unverifiedPolicyClosed, unverifiedPolicyOpen}
	// "local" mode is deliberately absent — see uncoveredCells() for the written reason.
	allModes      = []string{"stub", "api"}
	allVerifyRepo = []bool{true, false}
)

// matrixThreshold is fixed across the matrix so the SCENARIO, not the threshold,
// decides the verdict class. deps.dev scores below feed it: good/borrowed are above,
// lowscore is below.
const matrixThreshold = 5.0

// ───────────────────────── fixtures ─────────────────────────

// declaredRepo is what each scenario's registry metadata claims as its source repo.
// scenMismatch claims a high-reputation repo it does not own — the borrow-a-score
// attack the deps.dev cross-check (D33) exists to catch.
func declaredRepo(scen string) string {
	switch scen {
	case scenGood:
		return "https://github.com/yj/goodpkg"
	case scenLowScore:
		return "https://github.com/yj/lowpkg"
	case scenMismatch:
		return "https://github.com/yj/borrowed"
	default: // scenNoRepo
		return ""
	}
}

// depsDevRepo is what deps.dev independently says the package's source repo is.
// For every scenario but scenMismatch it agrees with the declaration; for
// scenMismatch it disagrees, which is what makes the package UNVERIFIED.
func depsDevRepo(scen string) string {
	if scen == scenMismatch {
		return "github.com/yj/real"
	}
	r := declaredRepo(scen)
	return strings.TrimPrefix(r, "https://")
}

// depsDevScores is the precomputed Scorecard score the fake deps.dev serves per repo.
// "borrowed" deliberately scores HIGH: that is the point of borrowing it.
var depsDevScores = map[string]float64{
	"github.com/yj/goodpkg":  9.0,
	"github.com/yj/lowpkg":   1.0,
	"github.com/yj/borrowed": 9.5,
	"github.com/yj/real":     9.0,
}

// matrixPkg is the package identity for a scenario in a given ecosystem, in the form
// that ecosystem's own paths use.
func matrixPkg(eco, scen string) string {
	switch eco {
	case "oci":
		return "library/" + scen + "pkg"
	case "maven":
		return "com.yj:" + scen + "pkg"
	default: // npm, pypi
		return scen + "pkg"
	}
}

// matrixLayer is the fake layer/artifact payload. A cell that finds this string in a
// response body has proof the ARTIFACT BYTES were delivered — not merely that some
// status came back.
const matrixLayer = "ARTIFACT-BYTES-DELIVERED"

// ───────────────────────── artifact routes ─────────────────────────

// artifactRoute is ONE addressable way to fetch a package's artifact bytes: the path
// a client requests, paired with the marker that identifies THAT object among the
// paths the fake upstream was asked for.
//
// Path and marker live in one literal on purpose. The marker is the bypass detector —
// the matrix decides `artifact_fetched` by looking for it in the upstream's hit list —
// so a route whose marker cannot match its own path reports artifact_fetched=false for
// EVERY cell of that route: a rig that always says "no bytes moved", i.e. one that
// cannot fail. That is strictly worse than not driving the route at all, because it
// looks like coverage. Keeping the two in a single struct is what stops them drifting;
// TestModeMatrixRoutesAreDetectable asserts they agree.
type artifactRoute struct {
	path func(pkg string) string
	// A FUNCTION of the package, not a constant, because one route's marker genuinely
	// varies with it: an OCI config blob is content-addressed, so its digest -- which
	// is both its path and its marker -- is the hash of a body that carries the
	// package's own declared repository. A registry cannot serve one constant digest
	// for four different config documents, and until #64 nothing noticed that this
	// fixture did.
	marker func(pkg string) string
}

// fixedMarker is the ordinary case: a route whose object is named the same way for
// every package.
func fixedMarker(s string) func(string) string { return func(string) string { return s } }

// artifactRoutes maps ecosystem -> request kind -> the byte route that kind drives.
//
// Markers are as SPECIFIC as the object they name. OCI's used to be the bare
// substring "/blobs/", which is also what the firewall's own scoring fetch of the
// image CONFIG blob looks like (ociEcosystem.LookupRepo reads the
// org.opencontainers.image.source label out of it) — so on any cell where the repo
// resolution is not cached, "/blobs/" recorded artifact_fetched=true for a layer that
// never left the upstream. Digests distinguish the two objects; a substring does not.
var artifactRoutes = map[string]map[string]artifactRoute{
	"npm": {
		// The registry's OWN convention: what a lockfile's "resolved" URL already
		// records, and what npm/pnpm mint by swapping only the ORIGIN of dist.tarball.
		kindBytes: {
			path:   func(pkg string) string { return "/" + pkg + "/-/" + pkg + "-1.0.0.tgz" },
			marker: fixedMarker(".tgz"),
		},
		// The shape relayRewritten mints, threading the package identity the METADATA
		// request resolved through the URL. Both npm routes deliberately share the
		// ".tgz" marker: the "/_tarball/<pkg>/" prefix is peeled off before forwarding,
		// so the two routes reach the SAME upstream object. Distinct markers are needed
		// when routes address distinct objects (see oci), not merely distinct URLs.
		kindBytesAlt: {
			path: func(pkg string) string {
				return npmTarballPrefix + url.PathEscape(pkg) + "/" + pkg + "/-/" + pkg + "-1.0.0.tgz"
			},
			marker: fixedMarker(".tgz"),
		},
	},
	"pypi": {
		// The shape the /simple/ index is rewritten to (D22): the byte fetch carries
		// the package identity the INDEX resolved.
		kindBytes: {
			path: func(pkg string) string {
				return "/_files/" + pkg + "/packages/ab/cd/" + pkg + "-1.0.0-py3-none-any.whl"
			},
			marker: fixedMarker(".whl"),
		},
		// The sdist. Same relay, different artifact: pip falls back to the source
		// distribution whenever no wheel matches the platform, so this is an ordinary
		// resolve path, not an exotic one.
		kindBytesAlt: {
			path: func(pkg string) string {
				return "/_files/" + pkg + "/packages/ab/cd/" + pkg + "-1.0.0.tar.gz"
			},
			marker: fixedMarker(".tar.gz"),
		},
	},
	"oci": {
		// The layer blob — the image payload itself.
		kindBytes: {
			path:   func(pkg string) string { return "/v2/" + pkg + "/blobs/" + matrixLayerDigest() },
			marker: fixedMarker(matrixLayerDigest()),
		},
		// The CONFIG blob. Same /v2/<name>/blobs/<digest> endpoint, different object:
		// it carries the image's env, entrypoint and labels, so it is content worth
		// gating in its own right, and `crane config` fetches it alone.
		kindBytesAlt: {
			path:   func(pkg string) string { return "/v2/" + pkg + "/blobs/" + matrixConfigDigestFor(pkg) },
			marker: matrixConfigDigestFor,
		},
	},
	"maven": {
		kindBytes: {
			path: func(pkg string) string {
				group, artifact := mavenParts(pkg)
				return "/" + group + "/" + artifact + "/1.0.0/" + artifact + "-1.0.0.jar"
			},
			marker: fixedMarker(".jar"),
		},
		// Gradle Module Metadata. The sharpest of the ten packagings that walked
		// through the pre-#56 extension allowlist, because Gradle 6+ fetches it for
		// every dependency on an ordinary resolve — the bypass sat on the common path.
		kindBytesAlt: {
			path: func(pkg string) string {
				group, artifact := mavenParts(pkg)
				return "/" + group + "/" + artifact + "/1.0.0/" + artifact + "-1.0.0.module"
			},
			marker: fixedMarker(".module"),
		},
	},
}

// requestPath builds the URL for one (ecosystem, kind, scenario) triple. Artifact
// kinds come from artifactRoutes so a route's path can never drift from its marker;
// metadata and infra are inline because neither is measured by a marker.
func requestPath(eco, kind, scen string) string {
	pkg := matrixPkg(eco, scen)
	if r, ok := artifactRoutes[eco][kind]; ok {
		return r.path(pkg)
	}
	switch eco {
	case "npm":
		if kind == kindMetadata {
			return "/" + pkg
		}
		return "/-/ping" // npm control plane
	case "pypi":
		if kind == kindMetadata {
			return "/simple/" + pkg + "/"
		}
		return "/"
	case "oci":
		if kind == kindMetadata {
			return "/v2/" + pkg + "/manifests/latest"
		}
		return "/v2/" // the OCI version handshake
	default: // maven
		if kind == kindMetadata {
			group, artifact := mavenParts(pkg)
			return "/" + group + "/" + artifact + "/maven-metadata.xml"
		}
		return "/"
	}
}

// mavenParts splits "com.yj:name" into its URL group path and artifact id.
func mavenParts(pkg string) (groupPath, artifact string) {
	g, a, _ := strings.Cut(pkg, ":")
	return strings.ReplaceAll(g, ".", "/"), a
}

func matrixLayerDigest() string {
	sum := sha256.Sum256([]byte(matrixLayer))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// artifactMarker is the substring that identifies an ARTIFACT-object fetch in the
// upstream's hit list. Metadata fetches are legitimate (scoring needs them), so the
// bypass detector must look specifically for the artifact.
//
// It is per-ROUTE, not per-ecosystem: two routes of the same ecosystem can address
// different objects (an OCI layer blob and an OCI config blob), and a marker broad
// enough to cover both cannot tell which one moved. Non-artifact kinds have no marker
// and are never measured for a byte fetch.
func artifactMarker(eco, kind, pkg string) string {
	m := artifactRoutes[eco][kind].marker
	if m == nil {
		return ""
	}
	return m(pkg)
}

// artifactFetched reports whether the UPSTREAM was asked for this route's artifact
// object. The empty-marker guard is load-bearing: strings.Contains(p, "") is true for
// every path, so handing a metadata or infra kind's (absent) marker to contacted()
// would report artifact_fetched=true for every such cell — turning the bypass
// detector into a constant. Kinds with no route fetch no artifact by definition.
func artifactFetched(reg *spyRegistry, eco, kind, pkg string) bool {
	marker := artifactMarker(eco, kind, pkg)
	if marker == "" {
		return false
	}
	return reg.contacted(marker)
}

// ───────────────────────── the fake upstreams ─────────────────────────

// spyRegistry serves all four ecosystems' path shapes (they don't collide) and
// records every path it is asked for. The recorder IS the bypass detector.
type spyRegistry struct {
	*httptest.Server
	mu  sync.Mutex
	hit []string
}

func (s *spyRegistry) record(p string) {
	s.mu.Lock()
	s.hit = append(s.hit, p)
	s.mu.Unlock()
}

func (s *spyRegistry) reset() {
	s.mu.Lock()
	s.hit = nil
	s.mu.Unlock()
}

func (s *spyRegistry) contacted(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.hit {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

// scenarioOf recovers which scenario a path refers to, so the fake can serve that
// scenario's declared repo. Package names embed the scenario ("goodpkg", "norepopkg").
func scenarioOf(path string) string {
	// Longest first: "norepopkg" must not match before "goodpkg" etc.
	for _, s := range []string{scenUpstreamDown, scenMismatch, scenLowScore, scenNoRepo, scenGood} {
		if strings.Contains(path, s+"pkg") {
			return s
		}
	}
	return ""
}

// servesArtifactBytes reports whether a path is one the fake upstream answers with
// opaque ARTIFACT bytes, as opposed to the metadata a verdict is derived from. Only
// scenUpstreamDown consults it, to decide what an outage takes down.
//
// The OCI CONFIG blob is deliberately NOT counted as artifact bytes even though it
// lives under "/blobs/": it is how an image's source repo is resolved, so an outage has
// to take it down along with the rest of the metadata. That has a measurable cost worth
// stating rather than hiding — under scenUpstreamDown the OCI config route reports no
// bytes because the FIXTURE refused them, not because the gate held. It is recorded in
// classifyLogLabels so nobody reads that column as evidence about the gate.
func servesArtifactBytes(p string) bool {
	if strings.Contains(p, "/blobs/") {
		return !strings.Contains(p, matrixConfigDigestFor(p))
	}
	for _, ext := range []string{".tgz", ".whl", ".tar.gz", ".jar", ".module"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

func newSpyRegistry() *spyRegistry {
	s := &spyRegistry{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		s.record(p)
		scen := scenarioOf(p)
		repo := declaredRepo(scen)

		// scenUpstreamDown models an upstream OUTAGE: the registry cannot answer the
		// request a VERDICT depends on, so evaluation yields Unavailable — not a verdict,
		// but an admission that we never reached one.
		//
		// The ARTIFACT bytes are still served, deliberately. If the fixture refused those
		// too, every cell in this scenario would record bytes_delivered=false and look
		// like a gate holding, when in fact nothing was ever offered to gate — precisely
		// the trap described on the artifact routes below. Serving them is what makes
		// "the gate withheld bytes on an Unavailable verdict" a measurable claim about
		// the gate rather than an artefact of the fixture.
		if scen == scenUpstreamDown && !servesArtifactBytes(p) {
			http.Error(w, "simulated upstream outage", http.StatusServiceUnavailable)
			return
		}

		switch {
		// ---- artifact bytes (checked first: most specific) ----
		// Every extension here is a route the matrix drives; ".tar.gz" (PyPI sdist) and
		// ".module" (Gradle Module Metadata) are the second routes added for issue #63.
		// A route the fixture does not serve here falls through to the packument
		// catch-all below and returns JSON, which never contains matrixLayer — so the
		// route would record bytes_delivered=false in every cell and look like a gate
		// holding, when in fact nothing was ever offered to gate.
		case strings.HasSuffix(p, ".tgz"), strings.HasSuffix(p, ".whl"), strings.HasSuffix(p, ".tar.gz"),
			strings.HasSuffix(p, ".jar"), strings.HasSuffix(p, ".module"), strings.Contains(p, "/blobs/"):
			// An OCI config blob must still parse as a config; everything else is
			// opaque artifact bytes. It carries matrixLayer in a spare label so the
			// config route's bytes_delivered is measured the same way as its layer
			// twin's — otherwise the two routes' observations could not be compared,
			// and the config route would report "no bytes delivered" unconditionally.
			if strings.Contains(p, "/blobs/") && strings.Contains(p, matrixConfigDigestFor(p)) {
				// Byte-for-byte the document matrixConfigDigestFor hashed, or the blob
				// would not be content-addressed and #64's check would abort the pull.
				fmt.Fprint(w, matrixConfigBody(repo))
				return
			}
			fmt.Fprint(w, matrixLayer)

		// ---- OCI manifest ----
		case strings.Contains(p, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			body := fmt.Sprintf(`{"config":{"digest":%q},"layers":[{"digest":%q}]}`,
				matrixConfigDigestFor(p), matrixLayerDigest())
			// The spec requires Docker-Content-Digest on a manifest response and every
			// registry measured on #93 sends it on HEAD; the gate's tag revalidation
			// (ocirevalidate.go) reads it. Without it this stand-in would be the one
			// registry that cannot be revalidated, and every cell would re-resolve.
			w.Header().Set("Docker-Content-Digest", ociDigest(body))
			if r.Method == http.MethodHead {
				return
			}
			fmt.Fprint(w, body)

		// ---- Maven ----
		case strings.HasSuffix(p, "maven-metadata.xml"):
			fmt.Fprint(w, `<metadata><versioning><release>1.0.0</release></versioning></metadata>`)
		case strings.HasSuffix(p, ".pom"):
			if repo == "" {
				fmt.Fprint(w, `<project></project>`)
				return
			}
			fmt.Fprintf(w, `<project><scm><url>%s</url></scm></project>`, repo)

		// ---- PyPI ----
		case strings.HasPrefix(p, "/pypi/") && strings.HasSuffix(p, "/json"):
			if repo == "" {
				fmt.Fprint(w, `{"info":{"home_page":"","project_urls":{}}}`)
				return
			}
			fmt.Fprintf(w, `{"info":{"home_page":%q,"project_urls":{"Source":%q}}}`, repo, repo)
		case strings.HasPrefix(p, "/simple/"):
			// The index offers BOTH a wheel and an sdist, as a real project's does, so
			// the sdist route the matrix drives is one this index actually resolves to
			// rather than a URL invented by the test.
			pkg := strings.Trim(strings.TrimPrefix(p, "/simple/"), "/")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><body>`+
				`<a href="%[1]s/packages/ab/cd/%[2]s-1.0.0-py3-none-any.whl">%[2]s-1.0.0</a>`+
				`<a href="%[1]s/packages/ab/cd/%[2]s-1.0.0.tar.gz">%[2]s-1.0.0</a>`+
				`</body></html>`, s.Server.URL, pkg)

		// ---- npm ----
		case strings.HasSuffix(p, "/latest"):
			fmt.Fprintf(w, `{"repository":{"url":%q}}`, repo)
		case p == "/-/ping":
			fmt.Fprint(w, `{}`)
		default:
			// npm packument (also the catch-all for infra roots like "/" and "/v2/").
			pkg := strings.Trim(p, "/")
			if scen != "" && !strings.Contains(p, "/v2/") {
				fmt.Fprintf(w, `{"repository":{"url":%q},"versions":{"1.0.0":{"dist":{"tarball":"%s/%s/-/%s-1.0.0.tgz"}}}}`,
					repo, s.Server.URL, pkg, pkg)
				return
			}
			fmt.Fprint(w, `{}`)
		}
	}))
	return s
}

// matrixConfigBody is the config document the fake registry serves for an image whose
// declared source repository is `repo`.
//
// It exists as a named function because a config blob is CONTENT-ADDRESSED: its digest
// must be the hash of exactly these bytes, so the body and the digest cannot be written
// in two places. Before #64 they were, and nothing failed -- the fixture served one
// constant digest for four different documents, which no real registry can do. The
// check that reads a blob's own URL as a claim about its bytes is what found it.
func matrixConfigBody(repo string) string {
	return fmt.Sprintf(`{"config":{"Labels":{"org.opencontainers.image.source":%q,"yj.matrix.payload":%q}}}`,
		repo, matrixLayer)
}

// matrixConfigDigestFor is the digest of the config blob served for `s`, which may be a
// package name or any path containing one -- both callers have one or the other, and
// scenarioOf already keys on the embedded "<scen>pkg".
func matrixConfigDigestFor(s string) string {
	sum := sha256.Sum256([]byte(matrixConfigBody(declaredRepo(scenarioOf(s)))))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// spyDepsDev is a fake deps.dev serving both roles the real one plays: the
// precomputed Scorecard score (api mode) and the package->source-repo record the
// cross-check compares against (FW_VERIFY_REPO).
func newSpyDepsDev() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		// GetProject: the score for a repo.
		case strings.HasPrefix(p, "/v3/projects/"):
			repo := strings.TrimPrefix(p, "/v3/projects/")
			score, ok := depsDevScores[repo]
			if !ok {
				http.NotFound(w, r)
				return
			}
			fmt.Fprintf(w, `{"scorecard":{"overallScore":%v}}`, score)

		// GetVersion: the related projects (the source-repo record).
		case strings.Contains(p, "/versions/"):
			scen := scenarioOf(p)
			repo := depsDevRepo(scen)
			if repo == "" {
				fmt.Fprint(w, `{"relatedProjects":[]}`)
				return
			}
			fmt.Fprintf(w, `{"relatedProjects":[{"relationType":"SOURCE_REPO","projectKey":{"id":%q}}]}`, repo)

		// GetPackage: the version list.
		case strings.Contains(p, "/packages/"):
			fmt.Fprint(w, `{"versions":[{"versionKey":{"version":"1.0.0"},"isDefault":true}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

// ───────────────────────── cells and observations ─────────────────────────

// cell is one point in the mode cross-product: a configuration plus the request
// being made under it.
type cell struct {
	Ecosystem  string
	Kind       string
	Scenario   string
	ByteGate   string
	Unscorable string
	Unverified string
	Mode       string
	VerifyRepo bool
}

// key is the stable identity of a cell, used as the JSON table key. Order is fixed
// so the committed table diffs cleanly.
func (c cell) key() string {
	return fmt.Sprintf("%s/%s/%s/bytegate=%s/unscorable=%s/unverified=%s/mode=%s/verify=%t",
		c.Ecosystem, c.Kind, c.Scenario, c.ByteGate, c.Unscorable, c.Unverified, c.Mode, c.VerifyRepo)
}

// observation is what actually happened in a cell — the recorded expectation.
type observation struct {
	Status int `json:"status"`
	// ArtifactFetched: did the UPSTREAM get asked for the artifact object? This is
	// the bypass detector. A denial status with ArtifactFetched=true means the bytes
	// left the upstream anyway.
	ArtifactFetched bool `json:"artifact_fetched"`
	// BytesDelivered: did the artifact payload reach the client?
	BytesDelivered bool `json:"bytes_delivered"`
	// LogSignal names which decision log line fired (or "none" when the request was
	// passed through without the firewall evaluating anything).
	LogSignal string `json:"log_signal"`
	// Verdict is the human-facing class: allowed / hard-deny / soft-deny / pending /
	// unavailable / ungated.
	Verdict string `json:"verdict"`
}

// -- Divergence classes (issue #96) ------------------------------------------
//
// A red cell has more than one cause, and they demand OPPOSITE responses. Until this
// split every difference printed as one "N cells DIVERGED", so a load flake and a
// real security change were the same sentence. Three separate sessions each
// re-derived the attribution by hand against a pristine main, and one nearly
// regenerated the golden instead -- which would have laundered the flake into the
// baseline. Same family as "exit code alone cannot validate a gate": one coarse
// signal shared by an innocent and a guilty cause.

const (
	divergenceIncomplete  = "incomplete"
	divergenceUnavailable = "unavailable"
	divergenceVerdict     = "verdict"
)

// didNotComplete reports that the rig never got an answer out of its own in-process
// upstream stub, so this observation is not a policy outcome at all.
//
// Status 502 is the unambiguous tell: it is recorded ZERO times across all 3,840
// cells of docs/mode-matrix.json, which only ever holds 200, 403 and 503. It can
// therefore never be a legitimate expectation, so a 502 on the got side always means
// the request did not finish rather than that the firewall decided something.
func (o observation) didNotComplete() bool {
	return o.Status == http.StatusBadGateway
}

// looksUnavailable reports the "upstream was not there" family that IS legitimately
// recorded: 400 cells expect withheld-unavailable and 64 expect 503/unavailable
// (#60, D102).
//
// Unlike didNotComplete this is AMBIGUOUS on the got side -- the #96 load flake
// produces it, and so would a genuine break in the fetch path. It is the class that
// still needs a pristine-main baseline, and it must never be auto-dismissed.
func (o observation) looksUnavailable() bool {
	return o.Status == http.StatusServiceUnavailable ||
		o.Verdict == "unavailable" ||
		strings.Contains(o.LogSignal, "unavailable")
}

// classifyDivergence names WHY a cell differs, returning "" when it does not differ.
// TestModeMatrix and its negative control share this function deliberately: a control
// that re-implements the rule tests a copy of the logic rather than the code that runs.
func classifyDivergence(want, got observation) string {
	switch {
	case got == want:
		return ""
	case got.didNotComplete() && !want.didNotComplete():
		return divergenceIncomplete
	case got.looksUnavailable() && !want.looksUnavailable():
		return divergenceUnavailable
	default:
		return divergenceVerdict
	}
}

// ───────────────────────── running a cell ─────────────────────────

// runCell configures a proxy for the cell, issues the request, and records what
// happened. It returns the observation.
//
// For a bytes cell it first issues the METADATA request, so the observation can be
// interpreted against the verdict the package actually receives — that is what makes
// "the gate denied this package but served its bytes" detectable rather than merely
// "the byte path returned 200".
func runCell(t *testing.T, reg *spyRegistry, depsDev string, c cell) observation {
	t.Helper()

	cfg := Config{
		Ecosystem:        c.Ecosystem,
		UpstreamRegistry: reg.Server.URL,
		FilesUpstream:    reg.Server.URL,
		UnscorablePolicy: c.Unscorable,
		UnverifiedPolicy: c.Unverified,
		ScoreThreshold:   matrixThreshold,
		ScorecardMode:    c.Mode,
		ScoreCacheTTL:    time.Minute,
		DepsDevBase:      depsDev,
		VerifyRepo:       c.VerifyRepo,
		ByteGate:         c.ByteGate,
	}
	fw, err := NewFirewall(cfg)
	if err != nil {
		t.Fatalf("NewFirewall(%s): %v", c.key(), err)
	}
	p := newProxyServer(cfg, fw)

	// Capture the firewall's decision log for this cell only.
	var logBuf strings.Builder
	prev := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(prev)

	// For a byte fetch, walk the metadata path first the way a real client does —
	// this is also what populates the caches a real byte request would hit.
	if isByteKind(c.Kind) {
		mreq := httptest.NewRequest(http.MethodGet, "http://fw.local"+requestPath(c.Ecosystem, kindMetadata, c.Scenario), nil)
		p.ServeHTTP(httptest.NewRecorder(), mreq)
	}

	// Only now start watching for an ARTIFACT fetch, so the metadata walk above
	// can't be mistaken for one.
	//
	// The log buffer MUST be reset here too, and forgetting it is not hypothetical:
	// the first run of this rig reported "0 bypasses" because the metadata walk's
	// "allowed=..." line was still in the buffer when the BYTE request was
	// classified. Every ungated OCI blob was therefore recorded as "allowed" — the
	// rig printed green over a bypass that had already been proven by hand. The
	// verdict must be classified from the log of the request under test, alone.
	reg.reset()
	logBuf.Reset()

	req := httptest.NewRequest(http.MethodGet, "http://fw.local"+requestPath(c.Ecosystem, c.Kind, c.Scenario), nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	body := rec.Body.String()
	return observation{
		Status:          rec.Code,
		ArtifactFetched: artifactFetched(reg, c.Ecosystem, c.Kind, matrixPkg(c.Ecosystem, c.Scenario)),
		BytesDelivered:  strings.Contains(body, matrixLayer),
		LogSignal:       classifyLog(logBuf.String()),
		Verdict:         classifyVerdict(rec.Code, logBuf.String(), body),
	}
}

// classifyLog reduces a cell's log output to the single marker that matters, so the
// committed table records WHICH log line fired rather than a volatile transcript.
func classifyLog(s string) string {
	// The byte-gate markers are matched against the HEADS of the log lines only —
	// the text before " -> " — not the whole blob.
	//
	// Every decision line here has the shape `<marker> <pkg> -> <payload>`, where the
	// payload is author-controlled text: reasons, verdict fields, and now the NAME of
	// the policy rule that fired (issue #58 increment 4). A whole-blob Contains lets
	// that payload forge a marker, which is not hypothetical — a rule named
	// "allow-but-log: byte gate is in visibility mode" moved 38 cells of the committed
	// table from decision-denied to byte-gate while the status, the bytes and the
	// verdict were all identical. A golden table whose labels can be changed by
	// rewording a string reports a behaviour change that did not happen, and would
	// equally hide one that did.
	//
	// Keying on the head makes the marker unforgeable by payload. The allowed=
	// cases below deliberately still match the whole blob: those ARE payload fields.
	// The four allow-but-log outcomes are matched on their bracketed token (#68).
	// They used to be one label, because three of them emit the byte-identical head
	// "byte gate (allow-but-log) <pkg>" and the fourth differed only in CASE — so the
	// uppercase one matched nothing here and fell through to the allowed= cases,
	// recording "the gate looked and SERVED the bytes" as an ordinary denial. That is
	// the exact inversion this table exists to make visible: #11, #56, #57 and #59
	// were all "we never even asked" bugs, and a matrix that cannot tell "asked and
	// served anyway" from "never asked" cannot show one.
	//
	// Ordered most-specific first. A blob containing several lines takes the first
	// match, which is deliberate: the terminal outcome for a cell is the one that
	// decided the bytes, and these tokens are mutually exclusive per request.
	heads := logLineHeads(s)
	switch {
	case strings.Contains(heads, "[served-anyway]"):
		return "byte-gate-served-anyway"
	// RENAMED from "byte-gate-withheld-unavailable" (#76). The token is no longer
	// byte-gate-only: the metadata path and the PyPI relay emit the same one, because
	// "the registry was unreachable so we never evaluated" is ONE event and must leave
	// ONE record. Keeping a byte-gate-specific label would have preserved the split this
	// issue exists to remove — npm/OCI reporting one value and PyPI/Maven another for an
	// identical input.
	case strings.Contains(heads, "[withheld-unavailable]"):
		return "withheld-unavailable"
	case strings.Contains(heads, "[hard-deny]"):
		return "byte-gate-blocked"
	case strings.Contains(heads, "[allowed]"):
		return "byte-gate-allowed"
	case strings.Contains(heads, "byte gate (allow-but-log)"):
		// An allow-but-log line carrying none of the four tokens. Not reachable from
		// the call sites as written, and deliberately NOT folded into a neighbouring
		// label: a new outcome added without a token must show up as its own
		// unfamiliar value in the golden diff, rather than quietly joining a bucket.
		return "byte-gate-allow-but-log-untagged"
	case strings.Contains(heads, "byte gate"):
		return "byte-gate"
	case strings.Contains(heads, "[deferred-pending]"):
		return "deferred-pending"
	// Layer 1 and the release window get labels of their own, ABOVE the verdict tokens,
	// because they are more specific: both short-circuit Evaluate, so a line carrying one
	// of them was decided before scoring was ever consulted.
	//
	// Neither is produced by any committed cell today — uncoveredCells keeps
	// FW_MALWARE_LIST and FW_MIN_RELEASE_AGE_DAYS off the matrix's axes — so adding these
	// two cases cannot move the golden table, and it is verified that it does not. They
	// are here because the FW_MALWARE_LIST exclusion is written to be voidable ("If that
	// test ever fails, this exclusion is void and the axis belongs in the matrix"), and
	// without a label of its own a layer-1 malware block would fall through to the
	// allowed= fallbacks and be recorded as an ordinary score denial — erasing exactly
	// the distinction this matrix exists to draw. Two lines now, versus a silent
	// mislabelling on the day the axis is added.
	case strings.Contains(heads, "[known-malware]"):
		return "known-malware-blocked"
	case strings.Contains(heads, "[release-window]"):
		return "release-window-blocked"
	// The operator's own VERSION-SCOPED deny (#155), for the same reason as the two
	// above: it short-circuits Evaluate, and a developer's next step for "your
	// organisation denied this release" is a colleague, not an advisory or a wait. No
	// committed cell produces it (FW_DENY_LIST is off the matrix's axes), so this
	// cannot move the golden table.
	// Not listed in classifyLogLabels, for the same reason known-malware-blocked and
	// release-window-blocked are not: no committed cell can produce it, and the map's
	// contract is "a label listed with an empty reason MUST appear in the table".
	case strings.Contains(heads, "[operator-denied]"):
		return "operator-denied-version"
	// An ALLOW that outranked a known-malware advisory (D312). It is an allow, and it
	// must not be recorded as an ordinary one: the whole point of the ruling's second
	// half is that the organisation can see which allows were made over a finding.
	case strings.Contains(heads, "[administrator-override]"):
		return "administrator-override"
	// The verdict tokens are matched here rather than left to the allowed= fallbacks so a
	// verdict line is identified by what the CALL SITE wrote, not by a payload field. The
	// fallbacks stay below for any line that predates the tokens.
	case strings.Contains(heads, "[verdict-blocked]"):
		return "decision-denied"
	case strings.Contains(heads, "[verdict-allowed]"):
		return "decision-allowed"
	case strings.Contains(s, "allowed=false"):
		return "decision-denied"
	case strings.Contains(s, "allowed=true"):
		return "decision-allowed"
	case strings.Contains(s, "->"):
		return "relay-only" // a bare proxy line: the firewall evaluated nothing
	default:
		return "none"
	}
}

// logLineHeads returns the part of each log line BEFORE " -> ", joined back together.
// That is the part the emitting call site controls literally, as opposed to the part
// it fills in from a decision — which is what makes it a trustworthy marker. A line
// with no arrow is kept whole, since it has no payload to be confused by.
func logLineHeads(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, " -> "); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// classifyVerdict maps status + log + body onto the verdict classes the matrix
// reports. Two subtleties, both of which the first version of this rig got wrong:
//
//   - "ungated" is the security-relevant class: a 200 the firewall never evaluated.
//     It is distinguished from "allowed" by the ABSENCE of a decision line.
//   - PyPI does not express a block as a 403. It serves the index with every release
//     YANKED-with-reason, because pip backtracks around a 403 but honours a yank
//     (D22). That is a 200 with a decision line — indistinguishable from an allow on
//     status alone, which is why the body is inspected for the yank marker. Calling
//     it "allowed" would have reported PyPI as ungated-by-policy across the board.
func classifyVerdict(status int, logs, body string) string {
	evaluated := strings.Contains(logs, "allowed=")
	yanked := strings.Contains(body, `data-yanked="`) || strings.Contains(body, `"yanked":"`)
	switch {
	case status == http.StatusOK && !evaluated:
		return "ungated"
	case status == http.StatusOK && yanked && strings.Contains(logs, "below required"):
		return "hard-deny-via-yank"
	case status == http.StatusOK && yanked:
		return "soft-deny-via-yank"
	case status == http.StatusOK:
		return "allowed"
	case status == http.StatusForbidden && strings.Contains(logs, "below required"):
		return "hard-deny"
	case status == http.StatusForbidden:
		return "soft-deny"
	case status == http.StatusServiceUnavailable && strings.Contains(logs, "scanning"):
		return "pending"
	case status == http.StatusServiceUnavailable:
		return "unavailable"
	default:
		return fmt.Sprintf("status-%d", status)
	}
}

// ───────────────────────── the test ─────────────────────────

// allCells enumerates the full cross-product, in a deterministic order.
func allCells() []cell {
	var out []cell
	for _, eco := range allEcosystems {
		for _, kind := range allKinds {
			for _, scen := range allScenarios {
				for _, bg := range allByteGates {
					for _, us := range allUnscorable {
						for _, uv := range allUnverified {
							for _, mode := range allModes {
								for _, vr := range allVerifyRepo {
									out = append(out, cell{eco, kind, scen, bg, us, uv, mode, vr})
								}
							}
						}
					}
				}
			}
		}
	}
	return out
}

// rigDialBudget bounds how many TCP connections one run of the rig may open, whatever
// its size.
//
// The two shapes it sits between are both measured, not reasoned. A pool per cell -- the
// #96 leak -- dials at least once per cell (1.96 measured across the full rig), because
// nothing ever reuses a connection. Shared pools dial a HANDFUL for the whole run
// (3 for 3,840 cells) now that every upstream answer is read to EOF before it is
// closed (#118): one keep-alive connection per (pool, host) pair, redialled only when the
// fixture drops one. Before #118 the shared rig still dialled 1,330 times, because a
// body closed unread makes Go discard its connection, and the budget had to be a ratio
// (one per two cells) to sit between the two shapes. Now they are three orders of
// magnitude apart, and TestModeMatrixRigReusesConnections proves both sides on the same
// cells: 128 cells with a pool each overshoot this by themselves.
const rigDialBudget = 64

// sharedRigTransports makes every firewall and proxy the rig builds draw on ONE
// connection pool per pool shape, the way a single long-lived process does, and returns
// a counter of every dial attempted while it is installed.
//
// This is the fix for issue #96. Each cell's NewFirewall and newProxyServer built a
// fresh keep-alive pool that nothing closed, so a run dialled 7,511 times for 3,840
// cells and held every socket open until the 90-second idle timeout -- longer than the
// run. Measured on Windows: 11,830 established loopback sockets mid-run and 7,636 left
// in TIME_WAIT afterwards, against an ephemeral range of 16,384 ports. Alone, the rig
// fits. Beside anything else that uses sockets -- `go test ./...`, a sibling run -- the
// pool is already partly spent, dials fail, and the failure is recorded as the upstream
// being unavailable: the RIGHT verdict for a dead upstream, in a cell whose upstream was
// fine. Three concurrent runs of the old rig: 3 of 3 failed, ~500 cells each, spread
// across all three divergence classes; the fixed rig under the same load: 3 of 3 green.
//
// The seam is newTransport (transport.go). Production never reassigns it; the rig swaps
// in a memo keyed by pool shape, so the firewall's capped probe pool and the proxy's
// uncapped relay pool stay distinct exactly as they are in one real process.
func sharedRigTransports(t *testing.T) *atomic.Int64 {
	t.Helper()
	pools := map[int]*http.Transport{}
	prev := newTransport
	// The memo is keyed by pool shape alone because the rig never configures an upstream
	// CA bundle, so roots is nil in every cell; a rig that did would need it in the key.
	newTransport = func(maxConnsPerHost int, roots *x509.CertPool) *http.Transport {
		tr, ok := pools[maxConnsPerHost]
		if !ok {
			tr = pooledTransport(maxConnsPerHost, roots)
			pools[maxConnsPerHost] = tr
		}
		return tr
	}
	var dials atomic.Int64
	unobserve := setEgressObserver(func(_, _ string) { dials.Add(1) })
	t.Cleanup(func() {
		newTransport = prev
		unobserve()
		// Nothing lingers into the next test: the shared pools' idle connections are
		// released here rather than left to the 90-second idle timeout.
		for _, tr := range pools {
			tr.CloseIdleConnections()
		}
	})
	return &dials
}

// TestModeMatrix is the rig. It runs every cell and asserts the observation matches
// the committed table, failing on divergence AND on any cell the table doesn't record.
func TestModeMatrix(t *testing.T) {
	reg := newSpyRegistry()
	defer reg.Close()
	depsDev := newSpyDepsDev()
	defer depsDev.Close()
	dials := sharedRigTransports(t)

	cells := allCells()
	got := make(map[string]observation, len(cells))
	for _, c := range cells {
		got[c.key()] = runCell(t, reg, depsDev.URL, c)
	}
	// The rig's own health, asserted beside the table. If connection reuse regresses to
	// a pool per cell this fails deterministically, alone, on the first run -- whereas
	// the port exhaustion it prevents fails only when something else happens to be
	// running, which is how #96 stayed open across four sessions.
	if n, budget := dials.Load(), int64(rigDialBudget); n > budget {
		t.Errorf("the rig dialled %d times for %d cells (budget %d): connections are not being "+
			"reused across cells. This is the issue #96 leak; its next symptom is a random subset "+
			"of cells failing whenever the host's ephemeral ports are partly spent.", n, len(cells), budget)
	}

	if *updateMatrix {
		writeMatrixTable(t, got)
		writeMatrixDoc(t, got)
		t.Logf("wrote %d cells to %s and %s — REVIEW THE DIFF", len(got), matrixTablePath, matrixDocPath)
		return
	}

	want := readMatrixTable(t)

	var missing []string
	byClass := map[string][]string{}
	note := func(class, k string, w, g observation) {
		byClass[class] = append(byClass[class],
			fmt.Sprintf("%s\n    want %+v\n    got  %+v", k, w, g))
	}
	for _, c := range cells {
		k := c.key()
		w, ok := want[k]
		if !ok {
			missing = append(missing, k)
			continue
		}
		if class := classifyDivergence(w, got[k]); class != "" {
			note(class, k, w, got[k])
		}
	}
	// A cell in the table that no longer exists is also a divergence: it means an
	// axis was removed and the table is stale.
	for k := range want {
		if _, ok := got[k]; !ok {
			byClass[divergenceVerdict] = append(byClass[divergenceVerdict],
				fmt.Sprintf("%s\n    recorded in the table but no longer produced by the rig", k))
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d UNRECORDED cells — every reachable mode must have a recorded expectation.\n"+
			"Run `sh scripts/mode-matrix.sh --update` and review the diff.\nFirst few:\n  %s",
			len(missing), strings.Join(missing[:min(len(missing), 10)], "\n  "))
	}
	// Every class below still FAILS the test. This split changes the DIAGNOSIS, never
	// the tolerance: a genuine break in the fetch path produces the "did not complete"
	// shape too, so that heading is a lead, not an acquittal.
	report := func(class, headline, guidance string) {
		found := byClass[class]
		if len(found) == 0 {
			return
		}
		sort.Strings(found)
		t.Errorf("%d cells %s\n%s\nFirst few:\n  %s",
			len(found), headline, guidance,
			strings.Join(found[:min(len(found), 15)], "\n  "))
	}
	report(divergenceIncomplete,
		"DID NOT COMPLETE - status 502, the rig never reached its own in-process stub.",
		"  502 is not a recordable expectation anywhere in the table, so this is not a policy\n"+
			"  change. It is the issue #96 signature and is usually machine load.\n"+
			"  CONFIRM rather than assume: re-run this test ALONE with\n"+
			"      go test -count=1 -run TestModeMatrix$ .\n"+
			"  If it fails in isolation too, or the cell count is STABLE across runs, it is a real\n"+
			"  break in the fetch path. Never regenerate the golden to make this pass.")
	report(divergenceUnavailable,
		"BECAME UNAVAILABLE - a recorded verdict was replaced by an unavailable state.",
		"  AMBIGUOUS: the #96 load flake and a genuine fetch-path regression produce the same\n"+
			"  shape here, because 464 cells legitimately record an unavailable expectation.\n"+
			"  Attribute against a PRISTINE origin/main worktree before dismissing. Never regenerate.")
	report(divergenceVerdict,
		"CHANGED VERDICT - the firewall did something different with the same inputs.",
		"  This is a security-relevant change in what the firewall does. Read every line.\n"+
			"  Usually a policy movement -- but the #96 leak reached this class too, through\n"+
			"  OCI cells that filed a failed connection as unscorable (#117). That was a\n"+
			"  product defect, not a rig one: a verdict must not change because a socket failed.\n"+
			"  Regenerate only after deciding the new behaviour is correct.")
}

// TestModeMatrixNoRecordable502 enforces the premise didNotComplete() rests on.
//
// The classifier treats a 502 as "the rig never answered" rather than as a verdict.
// That is sound only while 502 is not a legitimate expectation anywhere in the table.
// If a future cell ever records one, didNotComplete() would start calling a REAL
// recorded outcome a flake -- so this fails the moment the premise stops holding,
// instead of leaving it as a comment someone has to happen to read.
func TestModeMatrixNoRecordable502(t *testing.T) {
	want := readMatrixTable(t)
	if len(want) == 0 {
		t.Fatal("the table is empty -- this check would pass vacuously")
	}
	var offenders []string
	for k, o := range want {
		if o.didNotComplete() {
			offenders = append(offenders, k)
		}
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Errorf("%d cells RECORD a 502 expectation, breaking the premise of didNotComplete():\n  %s\n"+
			"Either a real rig defect is being baked into the golden, or the divergence\n"+
			"classifier needs a different discriminator. Do not simply delete this test.",
			len(offenders), strings.Join(offenders[:min(len(offenders), 10)], "\n  "))
	}
}

// TestModeMatrixRigReusesConnections is the control for the dial budget in
// TestModeMatrix. It runs the same cells both ways -- a pool per cell, then shared
// pools -- and requires the budget to sit between the two shapes. Without it a budget
// that can never be exceeded (an observer that does not fire, a seam that is not on the
// path) would sit green beside a rig that had quietly regressed to the #96 shape.
func TestModeMatrixRigReusesConnections(t *testing.T) {
	reg := newSpyRegistry()
	defer reg.Close()
	depsDev := newSpyDepsDev()
	defer depsDev.Close()

	// Every 30th cell: 128 cells spanning every ecosystem and request kind, so this
	// measures the rig, not one route -- and enough of them that the per-cell shape
	// must overshoot the budget by itself.
	var sample []cell
	for i, c := range allCells() {
		if i%30 == 0 {
			sample = append(sample, c)
		}
	}
	budget := int64(rigDialBudget)
	if int64(len(sample)) <= budget {
		t.Fatalf("sample of %d cells cannot overshoot a budget of %d on its own; the control would be vacuous", len(sample), budget)
	}

	// Leg 1 -- a pool per cell, the shape the rig had before the fix. Every pool this
	// leg creates is closed afterwards so the control does not itself leak.
	var made []*http.Transport
	prev := newTransport
	newTransport = func(n int, roots *x509.CertPool) *http.Transport {
		tr := pooledTransport(n, roots)
		made = append(made, tr)
		return tr
	}
	var perCell atomic.Int64
	unobserve := setEgressObserver(func(_, _ string) { perCell.Add(1) })
	for _, c := range sample {
		runCell(t, reg, depsDev.URL, c)
	}
	unobserve()
	newTransport = prev
	for _, tr := range made {
		tr.CloseIdleConnections()
	}
	switch n := perCell.Load(); {
	case n < int64(len(sample)):
		t.Fatalf("NEGATIVE CONTROL FAILED: %d cells built with a pool each dialled only %d times; "+
			"the counter cannot see the leak this test exists to catch", len(sample), n)
	case n <= budget:
		t.Fatalf("NEGATIVE CONTROL FAILED: the per-cell shape dialled %d times, within the budget of %d; "+
			"TestModeMatrix's budget could not have caught the #96 regression", n, budget)
	}

	// Leg 2 -- shared pools, the fixed rig, on exactly the same cells.
	dials := sharedRigTransports(t)
	for _, c := range sample {
		runCell(t, reg, depsDev.URL, c)
	}
	if n := dials.Load(); n > budget {
		t.Errorf("shared pools still dialled %d times for %d cells (budget %d): the seam is not on "+
			"the path every firewall and proxy is built through", n, len(sample), budget)
	}
	t.Logf("%d cells: %d dials with a pool per cell, %d with shared pools (budget %d)",
		len(sample), perCell.Load(), dials.Load(), budget)
}

// TestModeMatrixDivergenceClassesAreDistinguishable is the negative control for
// classifyDivergence. A classifier that cannot disagree is decoration -- and here it
// would be WORSE than the single bucket it replaced, because a real policy regression
// printed under "did not complete" reads as a heading that invites dismissal.
func TestModeMatrixDivergenceClassesAreDistinguishable(t *testing.T) {
	var (
		allowed  = observation{Status: 200, ArtifactFetched: true, BytesDelivered: true, LogSignal: "decision-allowed", Verdict: "allowed"}
		denied   = observation{Status: 403, LogSignal: "decision-denied", Verdict: "hard-deny"}
		stubDied = observation{Status: 502, LogSignal: "relay-only", Verdict: "relay-only"}
		withheld = observation{Status: 403, LogSignal: "withheld-unavailable", Verdict: "soft-deny"}
		unavail  = observation{Status: 503, LogSignal: "relay-only", Verdict: "unavailable"}
		leaked   = observation{Status: 403, LogSignal: "decision-denied", Verdict: "hard-deny", BytesDelivered: true}
	)

	cases := []struct {
		name      string
		want, got observation
		class     string
	}{
		{"an identical cell is not a divergence at all", allowed, allowed, ""},
		{"a recorded withheld cell that still withholds is not a divergence", withheld, withheld, ""},
		{"a stub that never answered did not complete", allowed, stubDied, divergenceIncomplete},
		{"502 outranks the unavailable family when both could match", unavail, stubDied, divergenceIncomplete},
		{"an allow that became withheld is ambiguous, not a verdict change", allowed, withheld, divergenceUnavailable},
		{"an allow that became 503 is ambiguous", allowed, unavail, divergenceUnavailable},
		{"an ALLOW that became a DENY is a policy movement", allowed, denied, divergenceVerdict},
		{"a DENY that became an ALLOW is a policy movement", denied, allowed, divergenceVerdict},
		{"a cell that stops withholding is a policy movement", withheld, allowed, divergenceVerdict},
		{"a DENY that leaked bytes is a policy movement, never a flake", denied, leaked, divergenceVerdict},
	}

	seen := map[string]int{}
	for _, tc := range cases {
		got := classifyDivergence(tc.want, tc.got)
		if got != tc.class {
			t.Errorf("%s:\n  want class %q\n  got  class %q\n  (want %+v, got %+v)",
				tc.name, tc.class, got, tc.want, tc.got)
		}
		seen[got]++
	}

	// NEGATIVE CONTROL: the classifier must be able to REACH every class. A constant
	// function would satisfy several of the cases above on its own.
	for _, class := range []string{"", divergenceIncomplete, divergenceUnavailable, divergenceVerdict} {
		if seen[class] == 0 {
			t.Errorf("classifier never returned %q -- it cannot distinguish what it claims to", class)
		}
	}

	// The load-flake heading must never be able to swallow a security change.
	if classifyDivergence(allowed, denied) == divergenceIncomplete {
		t.Fatal("a policy movement was classified as an incomplete run -- that heading invites dismissal")
	}
	if classifyDivergence(denied, leaked) != divergenceVerdict {
		t.Fatal("a deny that delivered bytes must read as a POLICY movement - it is the bypass this rig exists to catch")
	}
}

// TestModeMatrixBypasses is the security-facing view of the same data: it lists
// every cell where a package the firewall DENIED still had its artifact bytes
// fetched from upstream or delivered to the client.
//
// This does not fail on its own — the byte gate's "off" mode is a documented,
// deliberate escape hatch and would make it permanently red. It fails when the SET
// of bypassing cells changes, which is the thing worth alarming on: a new bypass
// appearing, or a fixed one silently coming back.
func TestModeMatrixBypasses(t *testing.T) {
	want := readMatrixTable(t)

	var bypasses []string
	for k, o := range want {
		if !keyIsByteCell(k) {
			continue
		}
		// A bypass is bytes escaping while the package is NOT allowed on its merits:
		// either the firewall never evaluated the request at all (ungated), or it
		// evaluated and denied but the bytes moved anyway.
		if o.Verdict == "ungated" && (o.BytesDelivered || o.ArtifactFetched) {
			bypasses = append(bypasses, k)
		}
	}
	sort.Strings(bypasses)

	recorded := readBypassBaseline(t)
	if diff := diffStrings(recorded, bypasses); diff != "" {
		t.Errorf("the set of BYPASSING cells changed:\n%s\n\n"+
			"If this is a fix, update docs/mode-matrix-bypasses.json. If it is new, it is a defect.", diff)
	}
	t.Logf("%d byte-path cells serve artifact bytes with no firewall evaluation", len(bypasses))
}

// TestModeMatrixRoutesAreDetectable is the negative control for the bypass detector
// itself: it proves the rig CAN report a byte fetch on every route it claims to drive.
//
// The failure it exists to catch is silent and looks like success. `artifact_fetched`
// is computed by searching the upstream's hit list for the route's marker, so a marker
// that cannot match its own route's path reports artifact_fetched=false for every one
// of that route's 192 cells. The matrix then goes green while measuring nothing — the
// table grows by 192 rows of "no bytes moved", which reads as a gate holding
// perfectly. Adding a route without this check is worse than adding no route at all,
// because the coverage is now claimed in a committed document.
//
// Two independent checks, because either alone is defeatable:
//
//   - STATIC: the marker is non-empty and occurs in the path the route requests. Cheap,
//     and catches the copy-paste (a ".jar" marker on the ".module" route).
//   - EMPIRICAL: in the COMMITTED table, every byte route has at least one cell where
//     the artifact was actually fetched and its payload actually delivered. This is the
//     one that cannot be reasoned past: it is read from observed behaviour. Every
//     ecosystem has FW_BYTE_GATE=off cells — the documented escape hatch — so a route
//     that is genuinely wired must produce a fetch there. Zero means the fixture never
//     served the object, or the marker never matched, or the proxy never recognised the
//     path. All three are the same defect from the reader's point of view: a row of the
//     table that can only say "no".
func TestModeMatrixRoutesAreDetectable(t *testing.T) {
	// Definition of done for issue #63: every ecosystem drives at least two routes.
	for _, eco := range allEcosystems {
		var got []string
		for _, kind := range byteKinds {
			if _, ok := artifactRoutes[eco][kind]; ok {
				got = append(got, kind)
			}
		}
		if len(got) < 2 {
			t.Errorf("%s drives %d artifact route(s) %v; the matrix must drive at least two, "+
				"because the bug class it exists to find is a second route to the same bytes", eco, len(got), got)
		}
	}

	// Static: a route's marker must be able to match its own path.
	for eco, routes := range artifactRoutes {
		for kind, r := range routes {
			if !isByteKind(kind) {
				t.Errorf("%s/%s: only byte kinds may have an artifact route; %q is measured by no marker", eco, kind, kind)
				continue
			}
			// Checked for EVERY scenario, not just one. A marker that varies with the
			// package (OCI's config blob) can agree with its path for one package and
			// not another, and a single representative would report that route
			// detectable while it silently measured nothing for the other three.
			for _, scen := range []string{scenGood, scenLowScore, scenMismatch, scenNoRepo} {
				pkg := matrixPkg(eco, scen)
				m := artifactMarker(eco, kind, pkg)
				if m == "" {
					t.Errorf("%s/%s/%s: empty marker — artifact_fetched would be reported false for every cell", eco, kind, scen)
					continue
				}
				if p := r.path(pkg); !strings.Contains(p, m) {
					t.Errorf("%s/%s/%s: marker %q does not occur in its own route path %q — "+
						"this route can never report a byte fetch", eco, kind, scen, m, p)
				}
			}
		}
	}

	// Empirical: the committed table must contain evidence each route can move bytes.
	table := readMatrixTable(t)
	for _, eco := range allEcosystems {
		for _, kind := range byteKinds {
			prefix := eco + "/" + kind + "/"
			cells, fetched, delivered := 0, 0, 0
			for k, o := range table {
				if !strings.HasPrefix(k, prefix) {
					continue
				}
				cells++
				if o.ArtifactFetched {
					fetched++
				}
				if o.BytesDelivered {
					delivered++
				}
			}
			switch {
			case cells == 0:
				t.Errorf("%s%s: no cells in the committed table", eco, kind)
			case fetched == 0:
				t.Errorf("%s: %d cells, but artifact_fetched is false in ALL of them — the route is "+
					"decorative: either the marker never matches, the fixture never serves the object, "+
					"or the proxy never recognises the path", prefix, cells)
			case delivered == 0:
				t.Errorf("%s: %d cells, but bytes_delivered is false in ALL of them — the fixture is not "+
					"serving this route's payload, so the route cannot distinguish a gate from a 404", prefix, cells)
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// diffStrings renders the symmetric difference of two sorted slices, or "" if equal.
func diffStrings(want, got []string) string {
	w := map[string]bool{}
	for _, s := range want {
		w[s] = true
	}
	g := map[string]bool{}
	for _, s := range got {
		g[s] = true
	}
	var b strings.Builder
	for _, s := range got {
		if !w[s] {
			fmt.Fprintf(&b, "  + NEW bypass: %s\n", s)
		}
	}
	for _, s := range want {
		if !g[s] {
			fmt.Fprintf(&b, "  - no longer bypassing: %s\n", s)
		}
	}
	return b.String()
}

// ───────────────────────── table I/O ─────────────────────────

func readMatrixTable(t *testing.T) map[string]observation {
	t.Helper()
	b, err := os.ReadFile(matrixTablePath)
	if err != nil {
		t.Fatalf("read %s: %v\nGenerate it with `sh scripts/mode-matrix.sh --update`", matrixTablePath, err)
	}
	var m map[string]observation
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse %s: %v", matrixTablePath, err)
	}
	return m
}

func writeMatrixTable(t *testing.T, m map[string]observation) {
	t.Helper()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(matrixTablePath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	// The bypass baseline is derived from the same run, so the two can't drift.
	var bypasses []string
	for k, o := range m {
		if keyIsByteCell(k) && o.Verdict == "ungated" && (o.BytesDelivered || o.ArtifactFetched) {
			bypasses = append(bypasses, k)
		}
	}
	sort.Strings(bypasses)
	bb, _ := json.MarshalIndent(bypasses, "", "  ")
	if err := os.WriteFile("docs/mode-matrix-bypasses.json", append(bb, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readBypassBaseline(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("docs/mode-matrix-bypasses.json")
	if err != nil {
		t.Fatalf("read bypass baseline: %v", err)
	}
	var s []string
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// uncoveredCells documents, in code, the axes this rig deliberately does NOT drive
// and why — the same discipline as the review board's no_brick. A reason lives here
// rather than in prose so it is read alongside the coverage it qualifies.
var uncoveredCells = map[string]string{
	"mode=local": "local mode scores via the scheduler, which launches a run-once " +
		"scorecard CONTAINER per scan; it cannot run in-process. Covered instead by " +
		"e2e/async_local.sh + docker-compose.e2e.yml, which exercise pending/cold-scan.",
	"real clients": "npm/pip/docker/mvn behaviour (lockfile replay, resume, cached " +
		"manifests) cannot be proven by an in-process request. Covered by the live " +
		"matrix in e2e/ — notably e2e/oci_blob_test.go and e2e/npm_test.go.",
	"FW_MAX_RELEASE_AGE_DAYS": "an independent PyPI-only policy axis (D22) that does " +
		"not interact with the verdict classes here; covered by its own unit tests.",
	"FW_MIN_RELEASE_AGE_DAYS": "the cooldown (#26) -- the same PyPI-only index-filtering " +
		"axis as FW_MAX_RELEASE_AGE_DAYS and its inverse; it yanks entries rather than " +
		"changing a verdict class, so it does not move a matrix cell. Covered by its own " +
		"unit tests, including a negative control and the both-bounds-at-once case.",
	"FW_MALWARE_LIST": "D172 layer 1 short-circuits Evaluate AHEAD of every " +
		"mode-sensitive step (backoff, repo resolution, scoring), so its verdict cannot " +
		"vary across the axes this matrix drives -- adding a 2x axis would double the " +
		"committed cells to prove the same block 3,840 times. That is a claim, so it is " +
		"RUN: TestKnownMalwareVerdictIsIndependentOfEveryMode sweeps unscorable x " +
		"unverified x byte-gate x threshold and asserts one verdict throughout. If that " +
		"test ever fails, this exclusion is void and the axis belongs in the matrix.",
	"third and further artifact routes": "each ecosystem drives TWO byte routes " +
		"(issue #63), not every one. Maven alone has ten alternate packagings that " +
		"bypassed the pre-#56 gate; the matrix drives .jar and .module. Two routes make " +
		"the CLASS measurable — a gate that holds on one route and not another — which " +
		"one route could not; enumerating every filename is the unit twins' job " +
		"(bytegate_test.go, maven_bytegate_test.go, oci_bytegate_test.go), where a case " +
		"costs one line instead of 192 committed cells.",
}

// writeMatrixDoc renders the human-readable table — the artifact we can put in front
// of anyone: for every mode, this is what actually happens.
func writeMatrixDoc(t *testing.T, m map[string]observation) {
	t.Helper()
	if err := os.WriteFile(matrixDocPath, []byte(renderMatrixDoc(m)), 0o644); err != nil {
		t.Fatal(err)
	}
}

// renderMatrixDoc is the rendering, split out from the writing so the SAME code can
// re-derive the doc from the committed table and assert the checked-in file matches
// (TestModeMatrixDocInSync).
func renderMatrixDoc(m map[string]observation) string {
	var b strings.Builder
	b.WriteString("# Mode coverage matrix\n\n")
	b.WriteString("**Generated — do not edit by hand.** Regenerate with `sh scripts/mode-matrix.sh --update`.\n\n")
	b.WriteString("Every row is a real request driven through a real proxy against the committed\n")
	b.WriteString("fake upstreams, not a reasoned expectation. `artifact_fetched` records whether the\n")
	b.WriteString("UPSTREAM was asked for the artifact — a denial with `artifact_fetched=true` means the\n")
	b.WriteString("bytes left the upstream regardless of what the client was told.\n\n")

	fmt.Fprintf(&b, "Cells: **%d**.\n\n", len(m))

	// Summary: verdict distribution per ecosystem × kind.
	b.WriteString("## What each ecosystem does per request kind\n\n")
	b.WriteString("| ecosystem | request kind | verdicts observed | bytes ever delivered while ungated |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, eco := range allEcosystems {
		for _, kind := range allKinds {
			verdicts := map[string]int{}
			leak := 0
			for k, o := range m {
				if !strings.HasPrefix(k, eco+"/"+kind+"/") {
					continue
				}
				verdicts[o.Verdict]++
				if o.Verdict == "ungated" && (o.BytesDelivered || o.ArtifactFetched) {
					leak++
				}
			}
			var parts []string
			for v, n := range verdicts {
				parts = append(parts, fmt.Sprintf("%s×%d", v, n))
			}
			sort.Strings(parts)
			mark := "—"
			if leak > 0 {
				mark = fmt.Sprintf("**%d**", leak)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", eco, kind, strings.Join(parts, ", "), mark)
		}
	}

	b.WriteString("\n## Deliberately not covered\n\n")
	var keys []string
	for k := range uncoveredCells {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "- **%s** — %s\n", k, uncoveredCells[k])
	}
	return b.String()
}

// TestModeMatrixDocInSync asserts the committed docs/MODE_MATRIX.md is the rendering
// of the committed docs/mode-matrix.json.
//
// Nothing used to check this, and the gap is not theoretical — it fired while issue
// #63 was being built. The negative control (reverting Maven's gate to the pre-#56
// extension allowlist) was run via `--update`, which rewrites all THREE artifacts. The
// two JSON files were restored from a snapshot afterwards; the Markdown was not. The
// full matrix suite then passed — TestModeMatrix compares against the JSON and never
// reads the doc — while the committed doc claimed `maven | bytes-alt | ungated×192`,
// i.e. advertised a live Maven bypass that did not exist.
//
// That is the worst failure mode this repo has: green tests over a document that is
// the thing humans actually read. The doc is the deliverable; the JSON is the
// machine's copy. They must not be able to disagree quietly.
func TestModeMatrixDocInSync(t *testing.T) {
	want := renderMatrixDoc(readMatrixTable(t))
	raw, err := os.ReadFile(matrixDocPath)
	if err != nil {
		t.Fatalf("read %s: %v", matrixDocPath, err)
	}
	// Compare line endings normalized: the working tree is CRLF on the Windows dev
	// host (git core.autocrlf) while the renderer emits LF, and that difference is
	// not a staleness signal — it would make this test permanently and uselessly red.
	got := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if got != want {
		t.Errorf("%s is STALE — it is not the rendering of %s.\n"+
			"Regenerate BOTH together with `sh scripts/mode-matrix.sh --update` and review the diff.\n"+
			"(A partial restore of one artifact but not the other is how this happens.)",
			matrixDocPath, matrixTablePath)
	}
}

// classifyLogLabels is every value classifyLog can return, paired with why it is
// absent from the committed table when it is absent.
//
// The point of this list is the ABSENT ones. A label that no cell produces looks
// identical, in a passing test run, to a label that is thoroughly exercised — and
// this table is the instrument we reach for to decide whether a gate is covered. An
// uncovered outcome that nobody has written down reads as covered.
var classifyLogLabels = map[string]string{
	"relay-only":              "", // "" = must actually be present in the table
	"decision-allowed":        "",
	"decision-denied":         "",
	"byte-gate":               "",
	"byte-gate-allowed":       "",
	"byte-gate-blocked":       "",
	"byte-gate-served-anyway": "",

	// Was documented as NOT EXERCISED until scenUpstreamDown was added: no scenario made
	// the upstream unreachable, so an Unavailable verdict could not arise in any of the
	// 3072 cells, and #60 — an upstream outage downgrading a hard deny into served bytes
	// — lived in an outcome this table could not express. Now observed.
	// RENAMED from "byte-gate-withheld-unavailable" (#76): the token is no longer
	// byte-gate-only. The metadata path and the PyPI relay emit the same one, so an
	// upstream outage leaves ONE record across all four ecosystems instead of two.
	"withheld-unavailable": "",

	"deferred-pending": "NOT EXERCISED: the matrix has no async/local cold-pull scenario, so no " +
		"cell reaches the Pending outcome. Listed rather than omitted because classifyLog can " +
		"return it, and an unlisted-but-returnable label is how the other direction of this " +
		"test stops being trustworthy.",

	"byte-gate-allow-but-log-untagged": "UNREACHABLE BY CONSTRUCTION. Every allow-but-log call site " +
		"carries one of the four bracketed tokens; this label exists so a NEW outcome added " +
		"without a token surfaces as an unfamiliar value in the golden diff instead of quietly " +
		"joining a neighbouring bucket.",
}

// TestModeMatrixLabelCoverage asserts that every label classifyLog can emit is either
// actually present in the committed table or carries a written reason for its absence
// — and, in the other direction, that the table holds no label this file has not
// heard of.
//
// The second direction is what makes the first trustworthy. Without it, renaming a
// label in classifyLog and regenerating would leave this list describing outcomes that
// no longer exist while the new ones went unlisted and unexamined.
func TestModeMatrixLabelCoverage(t *testing.T) {
	raw, err := os.ReadFile(matrixTablePath)
	if err != nil {
		t.Fatalf("read %s: %v", matrixTablePath, err)
	}
	var table map[string]observation
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatalf("parse %s: %v", matrixTablePath, err)
	}

	present := map[string]int{}
	for _, c := range table {
		present[c.LogSignal]++
	}

	for label, whyAbsent := range classifyLogLabels {
		n := present[label]
		if whyAbsent == "" && n == 0 {
			t.Errorf("label %q is expected in the table but NO cell produces it.\n"+
				"Either the axes stopped reaching that outcome — in which case the matrix quietly "+
				"lost coverage while still passing — or it is now unreachable and needs a written "+
				"reason here.", label)
		}
		if whyAbsent != "" && n > 0 {
			t.Errorf("label %q is documented as absent, but %d cells now produce it.\n"+
				"That is good news: delete the justification and set it to \"\". A stale reason is "+
				"worse than none, because the next reader trusts it.\nCurrent text: %s", label, n, whyAbsent)
		}
	}
	for label := range present {
		if _, known := classifyLogLabels[label]; !known {
			t.Errorf("the table contains label %q, which classifyLogLabels has never heard of.\n"+
				"Add it — with \"\" if it is genuinely exercised, or a reason if it is not. A label "+
				"nobody listed is a label nobody decided was correct.", label)
		}
	}
}
