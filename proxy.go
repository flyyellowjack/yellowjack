package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// proxyServer is the HTTP front of the application: the "proxy" half of the
// proxy/firewall. It is stateless — it holds only configuration, a reusable
// HTTP client, and a pointer to the firewall engine, no per-user data — which is
// exactly what lets us run many copies behind a load balancer for the HA story.
type proxyServer struct {
	cfg      Config
	firewall *Firewall
	client   *http.Client

	// undatedWarned makes warnIfUpstreamUndated fire once per process (D337). An
	// atomic.Bool rather than a sync.Once so the struct stays safe to copy in tests.
	undatedWarned atomic.Bool

	// npmTarballRe matches a packument's `"tarball":"<upstream>/` prefix, the only
	// field relayRewritten redirects through the artifact byte gate. nil for every
	// ecosystem but npm. Immutable after construction, so it is safe to share across
	// the per-request goroutines (regexp is safe for concurrent use).
	npmTarballRe *regexp.Regexp

	// npmTarballSignRe is npmTarballRe extended to also capture the rest of the URL,
	// which minting needs in order to sign the object path. Compiled ONLY when signing
	// is on, so the unsigned path keeps running the original prefix-swap byte for byte.
	npmTarballSignRe *regexp.Regexp

	// pypiFilesSignRe matches an artifact URL on the PyPI files host, capturing the
	// object path so each link can be signed individually. Stops before "#" so the
	// "#sha256=" integrity fragment is left alone and the signature lands in the query,
	// where it belongs — a fragment is never sent to a server. nil unless signing is on.
	pypiFilesSignRe *regexp.Regexp

	// pypiFilesLinkRe matches an artifact URL on the PyPI files host in a relayed index,
	// capturing the object path. Compiled for every pypi instance (unlike the signing
	// regex, which exists only with signing on) because the INTERCEPTED path needs it to
	// bind each listed file to the package whose index listed it (increment 8).
	pypiFilesLinkRe *regexp.Regexp

	// pypiFileBindings maps a files-host object path to the package whose relayed index
	// listed it — the OCI blob-binding shape (D164) applied to PyPI, for the interception
	// path where a wheel URL carries no package name and the filename must never be
	// parsed for one (!89). Short TTL: pip fetches the wheel seconds after the index.
	pypiFileBindings *ttlLRU[string]

	// pypiFileVersions maps a wheel's object path to the version its PEP 658 core-metadata
	// sibling declared, recorded as that sibling was relayed (issue #136). The same
	// bind-don't-parse shape as pypiFileBindings and the same TTL, for the same reason:
	// pip fetches the wheel seconds after the metadata it resolved from. Nothing is
	// fetched to fill this — the document is one the client asked for and we were
	// relaying anyway, which is what keeps the check free against #21's budget.
	pypiFileVersions *ttlLRU[string]

	// pypiFileDigests maps a files-host object path to the sha256 its relayed index
	// published for it (#64). Same bind-don't-parse shape and TTL as the two tables
	// above: the fragment carrying the digest never reaches us on the byte request, so it
	// is read off the index on the way past. Filled in BOTH modes, unlike
	// pypiFileBindings, because the cooperative client loses the fragment just the same.
	pypiFileDigests *ttlLRU[string]

	// ociRealm is the Bearer realm the configured registry named in its most recent 401
	// challenge relayed under interception (increment 11). The intercepted client is
	// pointed at /_token on the registry host instead, and this is where /_token is
	// relayed to. Nil until the registry has challenged through this gate.
	ociRealm atomic.Pointer[string]

	// signer binds an artifact URL's package prefix to its object path (issue #72).
	// nil when FW_URL_SIGNING_KEY is unset, which is the default and a fully supported
	// configuration. Immutable after construction, so it is safe to share across the
	// per-request goroutines.
	signer *urlSigner

	// flowEmit ships the recorder's counters to the control plane on an interval.
	// nil when emission is disabled (no approval URL, or a zero interval).
	flowEmit *flowEmitter

	// trustedProxies is the parsed FW_TRUSTED_PROXIES set, consulted by clientIP to
	// decide whether to believe X-Forwarded-For. Parsed once at startup; immutable
	// after, so it is safe to read from every per-request goroutine.
	trustedProxies []*net.IPNet

	// flow accumulates per-package traffic and failure counters (#32 Phase C). It is
	// the capacity dashboard's data source, deliberately separate from the audit log
	// (see flow.go). Never nil in a real server; a nil recorder is a safe no-op.
	flow *flowRecorder
}

func newProxyServer(cfg Config, fw *Firewall) *proxyServer {
	// One client, reused for all requests. The timeout budget covers the phases
	// BEFORE a response body starts (dial, TLS, waiting for the upstream's
	// headers) but deliberately NOT the body copy: http.Client.Timeout counts the
	// entire body read, and artifact downloads (OCI layer blobs, npm tarballs)
	// legitimately stream for minutes — a 30s whole-request timeout truncated
	// large blobs mid-download (found live pulling grafana/grafana). Setting the
	// timeout on the transport's ResponseHeaderTimeout instead still guarantees a
	// hung upstream can't tie up a request indefinitely, without capping a healthy
	// long download.
	//
	// POOLED, BUT DELIBERATELY NOT CAPPED (issue #54). This is the highest-volume path
	// in the product — every relayed packument, POM, manifest and artifact blob — and
	// it used to clone http.DefaultTransport as-is, keeping only 2 idle connections per
	// host. Against a remote registry over TLS that means re-dialing and re-handshaking
	// constantly under any real parallelism, which is pure latency on the critical path
	// (the same churn that, against our own L2, produced issue #1).
	//
	// pooledTransport's <= 0 argument gives us the pooling WITHOUT a per-host ceiling,
	// and the missing ceiling is the point rather than an oversight: a cap makes excess
	// requests block waiting for a free connection, and this client deliberately has NO
	// http.Client.Timeout (see above — a whole-request timeout truncated large blobs).
	// So a ceiling here could stall a client indefinitely behind other downloads, with
	// nothing to break the wait. Adding one later means also giving the queue its own
	// bounded deadline, which is a separate design step; it is NOT covered by
	// FW_MAX_CONNS_PER_HOST, which docs/SETUP.md scopes to the firewall's own probes.
	tr := newTransport(-1, cfg.upstreamRoots)
	tr.ResponseHeaderTimeout = 30 * time.Second
	trusted, invalid := parseTrustedProxies(cfg.TrustedProxies)
	for _, bad := range invalid {
		// A malformed trusted-proxy entry is EXCLUDED (fail-safe: we fall back to the
		// raw peer, never trust a spoofable header on its account), but warn loudly so
		// the operator fixes the typo rather than silently losing XFF resolution.
		log.Printf("WARNING: FW_TRUSTED_PROXIES entry %q is not a valid IP or CIDR; ignoring it", bad)
	}
	p := &proxyServer{
		cfg:            cfg,
		firewall:       fw,
		client:         &http.Client{Transport: tr},
		trustedProxies: trusted,
		flow:           newFlowRecorder(cfg.Ecosystem),
	}
	// Precompiled here rather than per response: the upstream half of the pattern is
	// fixed for the process's lifetime, and this regexp is run over every relayed
	// packument (tens of MB for an old, busy package).
	if cfg.Ecosystem == "npm" {
		p.npmTarballRe = regexp.MustCompile(`"tarball"\s*:\s*"` +
			regexp.QuoteMeta(strings.TrimRight(cfg.UpstreamRegistry, "/")+"/"))
	}

	// Signed artifact URLs (#72). Built here so bad key material stops the process at
	// startup with one actionable message, rather than surfacing later as installs that
	// mysteriously fail to verify.
	signer, err := newURLSigner(cfg.URLSigningKey, cfg.URLSigningKeyPrevious)
	if err != nil {
		log.Fatalf("startup failed: %v", err)
	}
	p.signer = signer
	if signer.Enabled() && cfg.Ecosystem == "npm" {
		// Same pattern as npmTarballRe, plus the remainder of the URL up to the closing
		// quote — minting has to see the object path to sign it. Compiled only on this
		// branch so that with signing off the rewrite is the original, untouched code.
		p.npmTarballSignRe = regexp.MustCompile(`"tarball"\s*:\s*"` +
			regexp.QuoteMeta(strings.TrimRight(cfg.UpstreamRegistry, "/")+"/") + `([^"]*)"`)
	}
	if signer.Enabled() && cfg.Ecosystem == "pypi" {
		// The object path runs to the first character that can end a URL in an HTML
		// index or a PEP 691 JSON one. "#" is excluded so the integrity fragment stays
		// put and the signature is appended before it.
		p.pypiFilesSignRe = regexp.MustCompile(
			regexp.QuoteMeta(strings.TrimRight(cfg.FilesUpstream, "/")+"/") + `([^"'#\s<>\\]*)`)
	}
	if cfg.Ecosystem == "pypi" {
		// Same pattern, always on: the intercepted index is scanned to bind each listed
		// file to this package (increment 8). Cooperative requests never reach the scan.
		p.pypiFilesLinkRe = regexp.MustCompile(
			regexp.QuoteMeta(strings.TrimRight(cfg.FilesUpstream, "/")+"/") + `([^"'#\s<>\\]*)`)
		p.pypiFileBindings = newTTLLRU[string](ociBlobBindingTTL, 0)
		p.pypiFileVersions = newTTLLRU[string](ociBlobBindingTTL, 0)
		p.pypiFileDigests = newTTLLRU[string](ociBlobBindingTTL, 0)
	}
	// Start shipping the counters. A separate, short-timeout client from the relay's:
	// telemetry must never inherit the relay transport's deliberate absence of a
	// whole-request timeout, or a wedged control plane could hold a flush goroutine
	// open indefinitely.
	// The firewall's audit emitter is passed in so its drop counter rides along on the
	// same heartbeat: both "we lost audit events" and "we lost capacity batches" are the
	// same question for an operator, and one report is one thing to keep working.
	// fw may be nil in tests that exercise the proxy's own construction, so the audit
	// emitter is read defensively; a nil one reports zero drops rather than panicking,
	// matching how every other nil in this telemetry path behaves.
	var auditEmit *auditEmitter
	if fw != nil {
		auditEmit = fw.audit
	}
	// The emitter shares the pooled transport rather than carrying a bare client on
	// http.DefaultTransport. Two reasons, and the second is the load-bearing one:
	// its POSTs go to the same approval host the L2 lookups already pool connections
	// to, and — per issue #27 — a client that skips pooledTransport skips the egress
	// observation point with it, which would make the zero-egress assertion quietly
	// incomplete for the one path most deserving of scrutiny: the telemetry path.
	p.flowEmit = newFlowEmitter(cfg.ApprovalURL, flowInstanceID(cfg),
		&http.Client{Timeout: 10 * time.Second, Transport: tr}, p.flow, cfg.FlowFlushInterval, auditEmit)

	// What this replica is actually enforcing, reported on the same heartbeat (#32 Phase D
	// / D4). Snapshotted once here because policy cannot change at runtime yet — D2 is the
	// increment that adds poll-and-cache, and it is what turns this into a live read. A
	// snapshot is correct today and wrong the moment refresh exists, which is why the
	// heartbeat re-sends it every beat rather than reporting it once at startup: the
	// reporting shape already tolerates a policy that changes.
	//
	// The posture is LOGGED in main.go, not here. This constructor runs once in
	// production but once per matrix cell under test, where the line accounted for
	// 3,840 of 3,853 output lines — it buried the very diff the matrix exists to
	// show. Startup logging belongs at startup; the snapshot below is wiring.
	if fw != nil {
		// A live read, not a snapshot (D195). The comment above predicted this: refresh
		// now exists, because the operator lists re-read from disk while we run.
		p.flowEmit.policy = func() *PolicyView {
			view := fw.describePolicy()
			return &view
		}
	}
	return p
}

// flowInstanceID names this replica in the capacity dataset.
//
// It must be STABLE across restarts and DISTINCT per replica. The hostname is both in
// every deployment that matters: Kubernetes gives each pod a unique one, Compose gives
// each container one, and a bare-metal host has its own. Falling back to the ecosystem
// alone is deliberate and safe — several replicas then share one identity and their rows
// SUM, which is the correct total, merely losing the per-replica breakdown. Inventing a
// random ID per boot would be worse: every restart would mint a new "instance", and the
// dashboard's instance filter would fill with dead entries.
func flowInstanceID(cfg Config) string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return cfg.Ecosystem
}

// ServeHTTP is called by Go's HTTP machinery once per incoming request. Go runs
// each call in its own goroutine automatically, so this server is concurrent by
// default — that satisfies the multithreading requirement with no thread code.
func (p *proxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Health endpoint bypasses all logic, so orchestration can check liveness
	// without triggering a real package fetch.
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok\n")
		return
	}
	// Readiness is a DIFFERENT question from liveness (D165). /healthz says the process
	// is alive and must never vary with anything external (D163). /readyz says the policy
	// in force is the policy on the deployment mounts: a rolling update must never route
	// to a gate that has not loaded the config it was deployed with, and a gate whose
	// list file has become unreadable leaves rotation while it enforces the last good
	// list. Local and bounded like liveness -- a registry outage does not make a gate
	// unready. Answered here, ahead of every gate, for the same reason /healthz is.
	if r.URL.Path == "/readyz" {
		p.serveReadyz(w)
		return
	}

	// Refuse ambiguous request paths BEFORE any parsing or dispatch (issue #59).
	// Everything below this line — the metadata gate, the byte gate, the ungated
	// control-plane relay — decides using a package identity parsed out of the path,
	// and then we forward that path to a CDN that normalizes it differently. A path
	// the two sides read differently is a gate bypass, so it never reaches them.
	// Placed above the ecosystem branches on purpose: the exploitable shape differs
	// per ecosystem (npm and PyPI leaked through different ones), and one choke point
	// cannot drift the way four parsers can. See pathguard.go.
	if why := checkRequestPath(r.URL.EscapedPath()); why != pathOK {
		// Logged at full volume: a legitimate package manager does not emit these, so
		// this line is an attempted-evasion signal, not routine noise.
		log.Printf("REFUSED ambiguous request path %q: %s — refusing rather than guessing which package the upstream would resolve (issue #59)",
			r.URL.EscapedPath(), why)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Yellowjack-Reason", sanitizeHeaderValue(string(why)))
		w.WriteHeader(http.StatusBadRequest)
		// Marshalled, not formatted -- see writeForbidden. These particular reasons are
		// fixed constants today, so %q happened to be safe here; it is replaced anyway
		// because the safety was incidental. The moment someone interpolates the
		// offending path into one of them, %q silently starts emitting Go escapes that
		// JSON does not accept, and the refusal becomes unreadable to the client it is
		// refusing. Leaving one hand-rolled encoder beside a fixed one invites the next
		// person to copy the wrong pattern.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":  "ambiguous request path refused by firewall",
			"reason": string(why),
		})
		return
	}

	// Refuse WRITES before any ecosystem dispatch (issue #66).
	//
	// Placed here, beside the path guard, for the identical reason: everything below
	// decides using a package identity parsed by an ecosystem-specific parser, and
	// those parsers were all written for downloads. `POST /v2/<name>/blobs/uploads/`
	// parses as a perfectly good blob path, so an upload was handed to the byte gate
	// and judged on the image's PULL score — and if that score passed, the push was
	// forwarded upstream. One choke point above the four parsers cannot drift the way
	// four separate checks would.
	//
	// The question a write asks is not one this product answers. "Does this package's
	// source repo score well enough" is about consuming a package; it says nothing
	// about whether someone may publish one. Relaying a write is not a gate bypass —
	// it is a capability nobody chose, arriving through a parser written for reads.
	//
	// SCOPED TO OCI, and the scoping is the load-bearing part. The first draft applied
	// this to every ecosystem, on the reasoning that "we are a read-only gate" is a
	// property of the product rather than of a protocol. Two existing tests went red and
	// were RIGHT: npm's control plane mixes reads and writes on the same surface.
	// `npm audit` is POST /-/npm/v1/security/advisories/bulk — a read expressed as POST
	// because the query body is large — and `npm login` is PUT /-/user/…, a write that
	// private-registry users genuinely need. So for npm the read/write boundary runs
	// through the control plane, and deciding which registry operations Yellow Jack
	// supports is a product question (issue #30 exists because another tool broke npm's
	// control plane exactly this way).
	//
	// OCI has no such ambiguity: every read in the distribution spec is GET or HEAD, and
	// every write is POST/PATCH/PUT/DELETE. That makes the method a complete and exact
	// signal here and only here. npm/PyPI/Maven are left alone pending a ruling — see
	// #66.
	if p.cfg.Ecosystem == "oci" && isWriteRequest(r.Method) {
		switch policy := writePolicy(p.cfg.WritePolicy); policy {
		case writePolicyAllow:
			// The operator explicitly said writes are their business, not ours, so no
			// log line — but the request must NOT fall through to the gate below.
			// See relayWriteUngated for why that is a correctness requirement.
			p.relayWriteUngated(w, r)
			return
		default:
			// Both block and allow-but-log record it. A write reaching a pull-through
			// firewall is either a misconfigured client or someone probing what else
			// we forward, and neither should be silent.
			log.Printf("WRITE REQUEST %s %s (FW_WRITE_POLICY=%s) — Yellow Jack is a pull-through gate; it does not evaluate publishes (issue #66)",
				r.Method, r.URL.EscapedPath(), policy)
			if policy != writePolicyBlock {
				// allow-but-log: recorded above, then relayed UNGATED for the same
				// reason as the allow case.
				p.relayWriteUngated(w, r)
				return
			}
			if policy == writePolicyBlock {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Yellowjack-Reason", "write requests are not proxied")
				// 405, not 403: this is not a verdict about a package. The method is
				// simply not one this endpoint implements, which is what 405 means,
				// and it keeps "403 from Yellow Jack" meaning "the firewall blocked
				// this package" — a distinction operators and clients both rely on.
				w.Header().Set("Allow", "GET, HEAD")
				w.WriteHeader(http.StatusMethodNotAllowed)
				// Marshalled, not formatted -- see writeForbidden.
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":  "write requests are not proxied by this firewall",
					"method": r.Method,
					"reason": "yellow jack is a pull-through gate; set FW_WRITE_POLICY=allow to relay writes",
				})
				return
			}
		}
	}

	// PyPI artifact relay: wheels/sdists live on a DIFFERENT host
	// (files.pythonhosted.org) than the /simple/ index. relayRewritten rewrites those
	// file URLs so the fetches come back to us under "/_files/<pkg>/…"; proxyToFiles
	// re-evaluates <pkg> and gates the byte fetch (D22) before forwarding to the files
	// upstream. Gated on the pypi ecosystem so the prefix can never shadow a real
	// package path in npm/oci/maven.
	if p.cfg.Ecosystem == "pypi" && strings.HasPrefix(r.URL.Path, "/_files/") {
		p.proxyToFiles(w, r)
		return
	}
	// INTERCEPTED OCI token exchange (increment 11): the registry's 401 challenge was
	// relayed with its realm rewritten to /_token on THIS host, so the client's token
	// request arrives here and is relayed to the realm the registry actually named. No
	// package identity, no verdict -- the same infrastructure relay the /v2/ ping gets.
	if intercepted(r) && p.cfg.Ecosystem == "oci" && r.URL.Path == "/_token" {
		p.proxyInterceptedToken(w, r)
		return
	}
	// INTERCEPTED PyPI artifact fetch (increment 8): the client asked the FILES host
	// directly, so the URL carries no package name. Resolve it through the binding the
	// relayed index recorded, then hand it to the same byte gate in the same shape.
	if intercepted(r) && p.cfg.Ecosystem == "pypi" && p.isFilesHost(r.Host) {
		p.proxyInterceptedFile(w, r)
		return
	}

	// npm artifact (tarball) byte fetches: gated separately from metadata, because
	// `npm ci` and friends fetch tarballs straight from a lockfile's "resolved" URL
	// and never re-request metadata — so the metadata control point alone leaves a
	// side-door (issue #11). Handled before the metadata parse below, which
	// deliberately returns "" for these paths.
	if p.cfg.Ecosystem == "npm" {
		if pkg, objectPath, ok := npmArtifactPath(r.URL.EscapedPath()); ok {
			// Only the "/_tarball/" shape is ours; npm's native "/<pkg>/-/<file>.tgz"
			// is not, and must not be asked for a signature we never minted.
			minted := strings.HasPrefix(r.URL.EscapedPath(), npmTarballPrefix)

			// The prefix names the package we are about to DECIDE about; on its own it
			// says nothing about which bytes come back, so a client can pair an allowed
			// package's prefix with a blocked package's object path and have the gate
			// judge the decoy while the target streams (#67, ruled by D159). Only the
			// MINTED shape needs this: npm's own "/<pkg>/-/<file>.tgz" derives its name
			// from the very path it forwards, so its two halves cannot disagree.
			//
			// Deliberately checked BEFORE artifactURLAuthentic, so the posture that
			// closes the bypass is the DEFAULT one — no signing key, which is what an
			// operator who installs us and changes nothing is running. Signing stays
			// opt-in defence in depth (D103/D159 item 3), not a security feature hidden
			// behind a flag.
			if minted && !npmObjectPathBindsToPackage(pkg, objectPath) {
				log.Printf("artifact %s -> refused: object path %q does not address this package", pkg, objectPath)
				writeBlock(w, p.cfg.Ecosystem, pkg, "artifact-binding", "artifact path does not belong to the requested package", notAReviewItem)
				return
			}
			if !p.artifactURLAuthentic(w, r, pkg, objectPath, minted) {
				return
			}
			p.proxyArtifactBytes(w, r, pkg, objectPath)
			return
		}
	}

	// OCI blob (layer/config) byte fetches, gated on the same FW_BYTE_GATE knob as
	// npm's tarballs rather than a parallel one (issue #57). The manifest below is
	// still the primary control point; this covers every client that reaches the
	// bytes without asking for it — a locally cached manifest, a pull by digest, a
	// resumed layer, or a direct blob read like `crane blob`, which sends no manifest
	// request at all and pulled 3.6 MB of a blocked image before this existed.
	//
	// The firewall's OWN config-blob read (ociEcosystem.LookupRepo) does not come
	// back through here — it talks to cfg.UpstreamRegistry directly — so evaluating
	// a blob cannot recurse into itself.
	if p.cfg.Ecosystem == "oci" {
		if image, ok := ociBlobPath(r.URL.EscapedPath()); ok {
			// Judge the VERSION this blob belongs to, not the bare image name (D164).
			// A blob URL carries a digest but no tag, so the identity comes from the
			// manifest that enumerated it. Unknown digest -> fall back to the image
			// name, which is exactly what this line did before the binding existed,
			// so no pull that works today starts failing.
			id := image
			if eco, ok := p.firewall.eco.(ociEcosystem); ok {
				if bound, found := eco.boundPackage(image, ociBlobRef(r.URL.EscapedPath())); found {
					id = bound
				}
			}
			p.proxyArtifactBytes(w, r, id, r.URL.EscapedPath())
			return
		}
	}

	// Pull the package name out of the request path. The active ecosystem knows
	// its own URL conventions (npm scoped packages, PyPI's /simple/ index, …), so
	// we delegate parsing to it rather than hardcoding npm's shape here.
	pkgName := p.firewall.PackageNameFromPath(r.URL.Path)
	if pkgName == "" {
		// No package identity. This branch USED TO relay the request ungated, with
		// no decision recorded at all — the implicit default-ALLOW that produced
		// #11, #56, #57 and #59. It now goes through the classification ruleset
		// (D76, issue #58), which allows the ecosystem's enumerated control-plane
		// endpoints and lets everything else fall to the implicit terminal BLOCK.
		p.serveUnidentified(w, r)
		return
	}

	// Attached before relayAsAllowed below captures r, so every relay from this request
	// can reach it. It stays inert unless the allow path arms it (verdicthold.go).
	r, hold := withVerdictHold(r)

	// LAYER 1's version-pinned half, for an ecosystem whose PATH names the version
	// while its identity does not — Maven (issue #103). It runs HERE, ahead of
	// Evaluate, for the same reason layer 1 runs first inside Evaluate: it needs no
	// network, so a known-malicious release is still refused while upstream is down,
	// while we are backing off a 429, and inside an air-gap.
	//
	// It cannot live inside Evaluate because Evaluate is handed an identity, and
	// Maven's is deliberately version-agnostic ("group:artifact", so a human approves
	// the library once rather than once per release). Putting a version-specific
	// verdict behind that identity would also be wrong in a second way: the decision
	// is cached and queued per identity, so a refusal of 1.2.3 would attach itself to
	// 1.2.4 as well.
	// What the ALLOW path for this request does, captured once so every refusal below can
	// hand it to the sink as "what would have happened instead" under FW_MODE=report.
	// Defined here rather than inlined per site so report mode cannot drift from the real
	// allow path -- the final allow at the bottom of this function calls the same closure.
	relayAsAllowed := func() {
		// Under interception (intercept.go) the metadata is still POLICY-edited -- PEP 592
		// yanks are how a PyPI block reaches pip (D22), and npm's version filter is its
		// soft block (!221) -- but never LINK-rewritten: the client believes it is talking
		// to the registry, and a rewritten dist.tarball would point it at a host it never
		// configured and record our address in its lockfile (#20). That split lives in
		// relayRewritten, keyed on intercepted(r); here the rewrite pass is simply on.
		rewriteMeta := r.Method == http.MethodGet &&
			((p.cfg.Ecosystem == "npm" && !strings.Contains(r.URL.Path, "/-/")) ||
				(p.cfg.Ecosystem == "pypi" && strings.HasPrefix(r.URL.Path, "/simple/")))
		p.proxyToUpstream(w, r, rewriteMeta, flowID{Package: pkgName, Kind: flowMetadata})
	}

	if d, blocked := p.firewall.pinnedMalwareOnPath(pkgName, r.URL.Path); blocked {
		log.Printf("%s [known-malware] %s -> allowed=%v (%s)", r.Method, pkgName, d.Allowed, d.Reason)
		p.versionVerdict(w, r, pkgName, d, relayAsAllowed)
		return
	}

	// The operator's own version-scoped deny (#155), at the same control point and after
	// the feed, for the reason Evaluate gives for the name-scoped pair: if a release is on
	// both, the advisory's reason is the more informative one.
	if d, blocked := p.firewall.operatorVersionOnPath(pkgName, r.URL.Path); blocked {
		log.Printf("%s [operator-denied] %s -> allowed=false (%s)", r.Method, pkgName, d.Reason)
		p.versionVerdict(w, r, pkgName, d, relayAsAllowed)
		return
	}

	// The release window for an ecosystem whose PATH names the version — Maven (#26).
	//
	// It sits here, beside the version-pinned check above, for the same structural
	// reason: Evaluate is handed a version-agnostic identity, so a per-version verdict
	// placed behind it would be cached and queued against "group:artifact" and a
	// refusal of 1.2.3 would attach itself to 1.2.4.
	//
	// npm and PyPI do NOT come through here. They apply the same window by filtering
	// the metadata document they already rewrite, which is better where it is possible
	// — the resolver walks to the next compliant version instead of failing the build.
	// Maven has no such document to filter: maven-metadata.xml carries one timestamp
	// for the whole artifact (measured: 158 versions, 1 <lastUpdated>), so there is
	// nothing per-version to yank and the honest answer is to refuse the request with
	// a reason that says when it will clear.
	if d, blocked := p.releaseWindowOnPath(pkgName, r.URL.Path); blocked {
		log.Printf("%s [release-window] %s -> allowed=false (%s)", r.Method, pkgName, d.Reason)
		if d.Unavailable {
			// The probe could not reach upstream, so we did not evaluate. D102's
			// taxonomy: a non-verdict state is a 403 carrying its own reason, not a
			// refusal dressed up as policy and not D18's old 503.
			p.writeDeferred(w, pkgName, d, relayAsAllowed)
			return
		}
		p.versionVerdict(w, r, pkgName, d, relayAsAllowed)
		return
	}

	// Ask the firewall for a decision. In this single-service design this is a
	// direct method call; if the firewall later becomes its own service, only
	// this line changes (to an HTTP call), nothing else.
	decision := p.firewall.Evaluate(pkgName)

	log.Printf("%s %s %s -> allowed=%v score=%.1f hasScore=%v (%s)",
		r.Method, outcomeToken(decision), pkgName,
		decision.Allowed, decision.Score, decision.HasScore, decision.Reason)

	if decision.Pending {
		// Async local mode (D18): first (cold) pull of an unscored package. We've
		// quarantined it and kicked a background scan; we don't have a verdict YET.
		// A 403 with its own explanation, not the old retryable 503 — see
		// writeDeferred for the ruling (D102) and the accepted cost. Still NOT a
		// block: the next pull reads the cached score and decides for real.
		p.writeDeferred(w, pkgName, decision, relayAsAllowed)
		return
	}

	if decision.Unavailable {
		// We couldn't consult metadata/score sources at all — so we did not evaluate,
		// and we say permission denied with that stated as the reason (D102).
		p.writeDeferred(w, pkgName, decision, relayAsAllowed)
		return
	}

	// Every path below is a TERMINAL verdict — allow or block. Record it once to the
	// append-only audit log (the console's audit view reads it). This is the single
	// package-level control point, so exactly one event per requested package; the
	// emit is fire-and-forget and never delays this request. Pending/Unavailable
	// returned above are not verdicts and are intentionally not audited.
	//
	// An ALLOW is recorded after the relay, not before it: npm's version filter runs
	// inside the relay and can still refuse this request, and the record must say what
	// the client got (D346). A block is final here, so it is recorded at once.
	if decision.Allowed {
		hold.armed, hold.d = true, decision
		srcIP := clientIP(r, p.trustedProxies)
		defer func() { p.firewall.auditVerdict(pkgName, srcIP, hold.d) }()
	} else {
		p.firewall.auditVerdict(pkgName, clientIP(r, p.trustedProxies), decision)
	}

	if !decision.Allowed {
		// PyPI BLOCK is special: a 403 on the /simple/ index makes pip read the
		// package as "route around this" and silently BACKTRACK other packages to
		// old (often CVE-laden) versions. Instead we serve the real index with every
		// release marked YANKED (PEP 592) carrying our reason: pip won't select a
		// yanked release during normal resolution, and the file URLs are still
		// rewritten to /_files/ so if they force it with an exact "==" pin the bytes
		// still route through us (gate-able at the fetch). This is the "protect +
		// inform + let them choose" posture.
		//
		// THIS COMMENT USED TO SAY pip "PRINTS the reason to the developer". It does
		// not, and #79 exists because it does not. Measured 2026-09-18 across four
		// resolvers on an identical index, exactly one prints it:
		//
		//	uv 0.12.10   "Because requests==… was yanked (reason: BLOCKED: …)"  <- ours
		//	pip 25.0.1   "No matching distribution found"
		//	poetry 2.4.3 "Could not find a matching version"
		//	pdm 2.29.2   "Unable to find candidates"
		//
		// Keep the yank anyway, and know which of its two jobs each half does. The
		// BACKTRACK-avoidance above is why it beats a 403 for every client; uv is the
		// only one that also reads the reason. Swapping this for a 403 on /simple/ is
		// an option #79 still lists, and it would cost uv's rendering and gain nothing
		// — e2e/blockreason_test.go's "uv" leg fails if anyone tries it.
		if p.cfg.Ecosystem == "pypi" && r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/simple/") {
			delivered := yankDeliveredReason(decision.Reason)
			w.Header().Set("X-Yellowjack-Reason", delivered)
			target := strings.TrimRight(p.cfg.UpstreamRegistry, "/") + r.URL.EscapedPath()
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			p.relay(w, r, target, true, delivered, flowID{Package: pkgName, Kind: flowMetadata})
			return
		}

		// BLOCK path. Return a 403 with the reason. Where the package manager's
		// protocol surfaces this text, the developer sees why. The reason also
		// goes in a response header: docker resolves manifests with HEAD requests,
		// which carry no body, so a header is the only channel that always
		// survives (visible in daemon debug logs and `curl -I`). writeBlock picks
		// the OCI distribution-spec vs. npm-style body per ecosystem.
		p.refuseDecision(w, pkgName, decision, relayAsAllowed)
		return
	}

	// ALLOW path: transparently proxy the original request to the real registry.
	// For metadata/index responses we rewrite artifact URLs in the body so the
	// client's NEXT requests (the actual bytes) come back THROUGH the firewall
	// instead of straight to the upstream host:
	//   npm  — the packument's "dist.tarball" links (not tarballs themselves,
	//          which carry "/-/" in the path); rewrites the upstream-registry host.
	//   pypi — the /simple/ index's wheel/sdist links, which point at a DIFFERENT
	//          host (files.pythonhosted.org); rewrites that host to our /_files/.
	relayAsAllowed()
}

// serveReadyz answers the readiness probe (D165): 200 when every reloadable list in force
// is the file on its mount, 503 naming each one that is not. The body is for the human
// reading a probe failure in `kubectl describe`; the status is for the orchestrator.
func (p *proxyServer) serveReadyz(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if p.firewall != nil {
		if reasons := p.firewall.notReady(); len(reasons) > 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "not ready: %s\n", strings.Join(reasons, "; "))
			return
		}
	}
	io.WriteString(w, "ready\n")
}

// serveUnidentified handles a request the gate could not resolve to a package:
// PackageNameFromPath returned "", and none of the byte-path parsers claimed it.
//
// THIS FUNCTION IS THE POINT OF ISSUE #58. Until now this case was a bare
// `proxyToUpstream(...)` — relayed to the registry with no decision evaluated and
// no decision logged. That implicit ALLOW is the shape of every bypass we have
// found: #11 (tarballs), #56 (Maven's non-allowlisted extensions), #57 (OCI
// blobs) and #59 (respelled paths) were each a route to bytes that arrived here
// and was waved through. Fixing them one at a time fixed four paths; routing this
// branch through the ordered ruleset fixes the shape.
//
// The ruleset allows the ecosystem's ENUMERATED control-plane endpoints and lets
// everything else fall to the implicit terminal block. So an endpoint nobody
// thought of now fails closed and says so, instead of failing open and staying
// silent.
func (p *proxyServer) serveUnidentified(w http.ResponseWriter, r *http.Request) {
	// EscapedPath, not Path: the classification must read the same bytes we would
	// forward upstream. Deciding on the decoded form and forwarding the escaped one
	// is the identity divergence of issue #59.
	path := r.URL.EscapedPath()

	kind := PathUnknown
	if p.firewall.ControlPlanePath(path) {
		kind = PathControlPlane
	}

	rule, action := p.firewall.classifyRuleset().Decide(Facts{Path: path, Kind: kind})

	switch action {
	case ActionAllow:
		// Either an enumerated control-plane endpoint, or FW_UNKNOWN_PATH_POLICY=allow
		// (the pre-#58 escape hatch). Relay as registry infrastructure.
		p.proxyToUpstream(w, r, false, flowID{Kind: flowInfra})

	case ActionAllowLog:
		// The migration ramp. This line is the whole value of the mode: it names the
		// EXACT path we failed to classify, so an operator who has to switch the knob
		// on can tell us precisely which endpoint the enumeration is missing. Logged
		// at full volume — it should be rare enough to be worth reading, and if it is
		// not, that is itself the finding.
		log.Printf("UNKNOWN REQUEST PATH %q -> RELAYED UNGATED by rule %q — no package identity and not a known %s registry endpoint; "+
			"set FW_UNKNOWN_PATH_POLICY=block to refuse it (issue #58)",
			path, rule.Name, p.cfg.Ecosystem)
		p.proxyToUpstream(w, r, false, flowID{Kind: flowInfra})

	default: // ActionReject — including the implicit terminal rule
		reason := fmt.Sprintf("unrecognized request path: no package identity, and not a known %s registry endpoint (matched %q)",
			p.cfg.Ecosystem, rule.Name)
		log.Printf("REFUSED %q: %s — set FW_UNKNOWN_PATH_POLICY=allow-but-log to relay it with a log line instead (issue #58)",
			path, reason)
		// An unrecognized path is a CONFIGURATION question, not a package one, so the
		// next step names the knob rather than a reviewer -- and names the operator as
		// the person who holds it, since the developer cannot act on this at all.
		p.refuse(w, path, blockErrMsg, reason,
			"This is not a judgement about any package and nothing is queued for review. "+
				"The firewall did not recognise this request path, and only its operator can "+
				"change that (FW_UNKNOWN_PATH_POLICY)",
			verdictMeta{Kind: "unknown-path", Rule: p.firewall.classifyRuleset().ruleID(chainClassification, rule), Source: p.firewall.policySource()},
			func() { p.proxyToUpstream(w, r, false, flowID{Kind: flowInfra}) })
	}
}

// hopByHopHeaders are connection-level headers (RFC 9110 §7.6.1) that describe
// a single hop's connection, not the message, and must not be forwarded by a
// proxy — relaying Connection or Transfer-Encoding verbatim fights the HTTP
// stack's own connection management on both sides.
var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// copyEndToEndHeaders copies src into dst, dropping the standard hop-by-hop set
// plus anything the Connection header itself names as connection-specific.
func copyEndToEndHeaders(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
	for _, c := range src.Values("Connection") {
		for _, name := range strings.Split(c, ",") {
			dst.Del(strings.TrimSpace(name))
		}
	}
	for _, h := range hopByHopHeaders {
		dst.Del(h)
	}
}

// Top-level error strings for the three 403 outcomes. They are DISTINCT on purpose
// (D102): all three are "permission denied", but a developer has to be able to tell
// "we looked and said no" from "we haven't finished looking" from "we couldn't look",
// because the three call for completely different actions.
const (
	blockErrMsg       = "blocked by firewall"
	pendingErrMsg     = "not yet approved: the firewall is still scanning this package"
	unavailableErrMsg = "not approved: the firewall could not verify this package"
)

// writeForbidden emits a 403 in the body shape the ecosystem's client actually
// prints (OCI's distribution-spec error vs. the npm-style body every other client
// reads), with the reason also on X-Yellowjack-Reason for HEAD/body-less clients.
// Shared by the index and byte-fetch paths so the two can never drift.
func writeForbidden(w http.ResponseWriter, ecosystem, pkg, errMsg, reason, nextStep string, v verdictMeta) {
	w.Header().Set("Content-Type", "application/json")
	// The reason is sanitized before it becomes a header value. Go replaces CR and LF
	// when serializing, so it is not a response-splitting risk -- but it does NOT strip
	// other control bytes, and a raw NUL on the wire makes the whole response
	// unparseable to a strict HTTP client (Go's own reader rejects it as a "malformed
	// MIME header line"). See sanitizeHeaderValue.
	w.Header().Set("X-Yellowjack-Reason", sanitizeHeaderValue(reason))
	// The next step rides in its own header and its own JSON field, and is appended to
	// the PRINTED message -- never folded into reason (#50).
	//
	// reason is the machine field: it is what the audit log records and what the console
	// renders in the queue. Appending guidance prose to it would put a sentence of advice
	// into every stored decision record, where it is noise that ages badly. The developer
	// needs the sentence; the record does not.
	//
	// Sanitized too. These particular strings are our own constants, so no control byte
	// can reach them today -- but the sink is what has to be safe, not the caller, or the
	// next person to build a next step from package metadata reintroduces the NUL defect
	// in a header that was never audited for it.
	if nextStep != "" {
		w.Header().Set("X-Yellowjack-Next-Step", sanitizeHeaderValue(nextStep))
	}
	// The structured verdict (D182, #20), as headers so it survives a HEAD and a body
	// nobody reads, and again in the body below for clients that keep only that.
	for name, val := range map[string]string{
		"X-Yellowjack-Kind":   v.Kind,
		"X-Yellowjack-Rule":   v.Rule,
		"X-Yellowjack-Source": v.Source,
	} {
		if val != "" {
			w.Header().Set(name, sanitizeHeaderValue(val))
		}
	}
	w.WriteHeader(http.StatusForbidden)

	// printed is what the client SHOWS a human: the reason plus what to do about it.
	printed := errMsg + ": " + reason
	if nextStep != "" {
		printed += ". " + nextStep
	}

	// THE BODY IS MARSHALLED, NOT FORMATTED.
	//
	// This was built with fmt.Sprintf and %q, which is GO quoting, not JSON quoting. The
	// two grammars agree on the common cases -- quote, backslash, newline -- and diverge
	// on the control characters: Go writes a NUL as \x00 where JSON requires \u0000, and
	// the same for the DEL and BEL bytes. So a package whose name carried any of those
	// produced a body that is not valid JSON at all.
	//
	// That matters because npm PARSES this body and prints its "error" field. An invalid
	// body means the developer gets a parse failure instead of the reason they were
	// blocked -- and the name is chosen by whoever published the package, so it was an
	// attacker's choice whether their own block is legible. Found by tier-3 testing; a
	// real client never sends such a name, so tier 2 could not have found it.
	//
	// encoding/json is the only thing that knows JSON's escaping rules. Hand-rolling them
	// with a format verb is what created the bug.
	if ecosystem == "oci" {
		// The OCI distribution-spec error shape.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"errors": []map[string]any{{
				"code":    "DENIED",
				"message": printed,
				"detail": map[string]any{
					"package": pkg, "reason": reason, "nextStep": nextStep,
					"kind": v.Kind, "rule": v.Rule, "source": v.Source,
				},
			}},
		})
		return
	}
	// The reason goes in "error" too, not only in "reason". npm parses this body and
	// prints ONLY the "error" field, so a reason carried solely in "reason" reaches the
	// operator log and never the developer: they see
	//   403 Forbidden - GET .../pkg - blocked by firewall
	// with no cause, which is indistinguishable from a broken registry. The MVP scope
	// requires a block to return "an error with the reason, WHERE THE NPM PROTOCOL
	// SURFACES IT" -- this is that place. The OCI branch above already does it; only this
	// branch was dropping the reason, and the e2e ladder's top rung is what caught it.
	//
	// It matters most for the two NON-verdict outcomes (D102): "still scanning" and
	// "could not verify" are actionable only if the developer can read which one they
	// hit. "reason" is kept as a separate unprefixed field for machine consumers.
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":    printed,
		"package":  pkg,
		"reason":   reason,
		"nextStep": nextStep,
		"kind":     v.Kind,
		"rule":     v.Rule,
		"source":   v.Source,
	})
}

// sanitizeHeaderValue makes a string safe to put in an HTTP header value.
//
// Go's net/http already replaces CR and LF when it serializes headers, so this is not
// what stops response splitting. What it stops is the OTHER control bytes, which Go
// passes through untouched: a raw NUL in a header value produces a response that a
// strict HTTP parser rejects outright, so the client sees a protocol error rather than
// our 403 and never learns why the package was refused.
//
// Reason text is built from package names and repository URLs, both of which are written
// by the package's publisher, so these bytes are an attacker's choice.
//
// Replaced with a space rather than dropped: eliding bytes silently can splice two
// unrelated tokens together, and the point of the header is that a human reads it.
func sanitizeHeaderValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// refuse is the ONE place a client-facing POLICY refusal is emitted, and therefore the
// one place FW_MODE=report takes effect.
//
// relayInstead is what the ALLOW path for this request would have done. Making it a
// required argument rather than something the sink infers is the point: the compiler
// forces whoever adds a refusal to say how the request would otherwise have been served,
// so a new refusal path cannot silently become un-suppressable in report mode. It is
// never called in enforce mode.
//
// NOT for request-integrity refusals (object-path binding, filename binding, artifact
// URL signature). Those are not judgements about a package -- they refuse a request whose
// two halves disagree -- and relaying them in report mode would make report mode LESS
// safe than enforce, which is the one thing an evaluation setting must never be. Those
// keep calling writeBlock directly, and TestEveryPolicyRefusalGoesThroughTheModeSink
// allows exactly those three by name.
// verdictMeta is the structured half of a refusal (D182, #20): the kind of denial, the
// identifier of the rule that fired, and the policy or feed it came from. It rides on
// three headers and three body fields beside the prose, so a client or a log scraper can
// answer "why, under which rule, from which policy" without parsing a sentence.
type verdictMeta struct {
	Kind, Rule, Source string
}

func metaOf(d Decision) verdictMeta {
	return verdictMeta{Kind: string(d.Deny), Rule: d.Rule, Source: d.Source}
}

func (p *proxyServer) refuse(w http.ResponseWriter, pkg, errMsg, reason, nextStep string, v verdictMeta, relayInstead func()) {
	if p.cfg.reporting() {
		// One line per suppressed refusal, at full volume and with a stable prefix, so
		// "what would this have blocked last week?" is a grep rather than a research
		// task. It names the verdict, not merely that something happened -- an operator
		// counting these is deciding whether to switch enforcement on.
		log.Printf("REPORT MODE: WOULD HAVE REFUSED %s -> %s (relayed anyway; set FW_MODE=enforce to refuse)", pkg, reason)
		relayInstead()
		return
	}
	writeForbidden(w, p.cfg.Ecosystem, pkg, errMsg, reason, nextStep, v)
}

// versionVerdict applies a VERSION-scoped verdict: a version-pinned known-malware
// advisory, the operator's version-scoped deny, or a path-level release window. These
// run before Evaluate, at the control points where the request names a release (an npm
// tarball, a PyPI file, a Maven path), and they return a Decision of their own.
//
// It does the two things every caller used to skip:
//
//   - It RECORDS the verdict. Evaluate's verdict is audited once per package on the
//     metadata route, but a version-scoped verdict is a different verdict (the package
//     may be served while THIS release is refused) and was never written to the audit log.
//     So the refusal of a hijacked release -- the one an incident responder most needs to
//     find -- left a log line and no record, and the console could not show it.
//   - It SERVES an administrator override (D312). pinnedMalwareVerdict reports an allow
//     entry naming the release as blocked=true with Allowed=true, and every caller refused
//     it: the developer got a 403 whose reason said "served by administrator override".
//     Evaluate returns the same decision as an allow on OCI; the byte paths now agree.
func (p *proxyServer) versionVerdict(w http.ResponseWriter, r *http.Request, pkg string, d Decision, serve func()) {
	p.firewall.auditVerdict(pkg, clientIP(r, p.trustedProxies), d)
	if d.Allowed {
		serve()
		return
	}
	p.refuseDecision(w, pkg, d, serve)
}

// refuseDecision is refuse for an evaluated VERDICT, carrying the decision's own reason
// and next step.
func (p *proxyServer) refuseDecision(w http.ResponseWriter, pkg string, d Decision, relayInstead func()) {
	p.refuse(w, pkg, blockErrMsg, d.Reason, nextStepFor(d.Deny), metaOf(d), relayInstead)
}

// writeBlock emits the 403 for an actual VERDICT: we evaluated the package and the
// answer is no.
// writeBlock emits a 403 for a refusal that is NOT a verdict reached by evaluating a
// package: an integrity mismatch, or a request path we decline to relay.
//
// nextStep is a required argument rather than an omitted one on purpose. None of these
// refusals put anything in the approval queue, so the reviewer sentence would be a
// promise nothing keeps -- but "" is not the right answer either, because a developer
// staring at a bare refusal has nowhere to go. Making the caller name the step forces
// the question to be answered per site instead of defaulted away for all of them.
//
// rule names WHICH integrity check refused: the reason a developer reads is prose, the
// rule is what a log scraper or a ticket keys on (D182).
func writeBlock(w http.ResponseWriter, ecosystem, pkg, rule, reason, nextStep string) {
	writeForbidden(w, ecosystem, pkg, blockErrMsg, reason, nextStep, verdictMeta{Kind: "integrity", Rule: rule, Source: sourceIntegrity})
}

// notAReviewItem is the next step for the byte-integrity refusals (#67/D159): the bytes
// on offer do not belong to the package that was evaluated.
//
// It says plainly that approving something will not help, because the instinct on seeing
// "blocked" is to go and ask for an override -- and an override here would clear a
// package/artifact mismatch, which is the confused-deputy bypass itself.
const notAReviewItem = "Nothing is queued for review and no approval will clear this: it " +
	"is a mismatch between the package that was checked and the bytes that were served, " +
	"not a judgement about the package. Re-running will not help. Report it to whoever " +
	"operates this firewall"

// writeBlockDecision emits the 403 for an evaluated VERDICT and tells the developer what
// happens next, chosen by WHY the package was denied (#50).
func writeBlockDecision(w http.ResponseWriter, ecosystem, pkg string, d Decision) {
	writeForbidden(w, ecosystem, pkg, blockErrMsg, d.Reason, nextStepFor(d.Deny), metaOf(d))
}

// nextStepFor answers the two questions #50 requires a block to answer: what happens
// now, and who decides it.
//
// Derived from the denial KIND rather than configured, because the honest answer really
// does differ per kind and one configured sentence would be wrong for most of them. The
// distinction that carries the most weight is whether WAITING HELPS: a queued package is
// waiting on a person and will never clear itself, a malware advisory will not clear at
// all, and a cold scan clears on its own. Telling a developer to "try again later" in the
// first two cases is how a queue gets routed around -- #50 records three separate bypass
// mechanisms and teams hand-rolling functionality rather than waiting for review.
//
// What these deliberately do NOT contain is a URL. Naming a console to click is issue #49
// ("every block must be self-serve clearable by the operator in one step") and needs a
// config knob to hold the address; inventing one here would spend from the #51 config
// budget for half a feature. Role terms are honest without it.
func nextStepFor(kind denyKind) string {
	switch kind {
	case denyKnownMalware:
		// The strongest positive finding the gate can make. Deliberately does NOT invite
		// an override: pointing at an approval path here reads as "ask nicely and this
		// malware will be let through", which is not a process anyone should start.
		return "This is a published advisory naming this package, not a policy threshold. " +
			"It will not clear by waiting or by re-running. Use a different package; if you " +
			"believe the advisory is wrong, that is a conversation with whoever operates " +
			"this firewall, not a retry"
	case denyOperator:
		// A local policy decision, and the guidance has to say so. The failure mode this
		// avoids is a developer reading a refusal as a security finding about the package
		// and either abandoning a perfectly good dependency or -- worse, and this is the
		// #50 pattern -- routing around the proxy because they think it is malfunctioning.
		// Naming the deny list as the thing to change points at a colleague, which is the
		// true and actionable answer.
		return "This package is on your organisation's own deny list -- a local policy " +
			"decision, not a published advisory about the package. Waiting will not clear " +
			"it and neither will re-running; it is reversible by whoever maintains this " +
			"firewall's deny list"
	case denyReleaseWindow:
		return "Every version of this package is outside the release window this firewall " +
			"is configured to serve -- a cooldown that holds back brand-new releases, an " +
			"age floor that holds back stale ones, or a registry that gave no publish " +
			"dates to judge by. A local policy, not a finding about the package. A " +
			"cooldown clears on its own once the release is old enough; the window itself " +
			"is set by whoever operates this firewall"
	case denyHuman:
		return "A person has already reviewed this package and denied it. Nothing retries " +
			"and re-running will not change the answer -- it is reversible only by the " +
			"reviewer who works this firewall's approval queue"
	case denyScore, denyUnscorable, denyUnverified:
		// All three enter the same queue: applyHumanRuling records the package pending on
		// first sighting for the below-threshold and the no-trust cases alike (D11).
		return "This package is now in the firewall's approval queue, waiting on a person. " +
			"Nothing retries on its own and nothing expires, so re-running the install will " +
			"return this same error -- the reviewer who works that queue can approve it, or " +
			"supply the correct source repository if the wrong one was scored"
	default:
		return ""
	}
}

// writeDeferred emits the 403 for the two outcomes that are NOT verdicts about the
// package (D102): Pending ("scanning right now") and Unavailable ("we could not
// reach the registry or the score source, so we did not evaluate").
//
// These used to be a retryable 503 + Retry-After, on the reasoning that npm and pip
// retry a 5xx and treat a 403 as final — which made the cold-scan path self-healing:
// the client's own retry landed after the background scan finished. The project ruled that
// taxonomy wrong: "503 generally means the server failed in some way; if these are
// not failure states, then we should not report them as failures... ultimately these
// are both block states, they are permissions errors and should be treated as 403s,
// but they should give different explanations of the 403."
//
// The cost is real and was accepted deliberately: without the automatic retry, the
// first pull of an unscanned package FAILS and the developer re-runs by hand. The project
// named that in the same ruling — "ultimately there needs to be a better way of
// requesting a new package scan besides running npm install and getting a failure,
// but for now, and for taxonomy reasons, it should correctly state permission
// denied." So the missing piece is a scan-request mechanism, not a return to 5xx.
//
// No Retry-After: no client honours it on a 403, and emitting a header that nothing
// acts on would be decoration. The wait is put in the reason text instead, which is
// what the developer actually reads.
//
// Genuine infrastructure failures — the upstream relay breaking mid-stream, a body
// we could not read — deliberately stay 5xx. Flattening that distinction would
// defeat the point of the ruling, which is that a status code should say what
// actually happened.
func (p *proxyServer) writeDeferred(w http.ResponseWriter, pkg string, d Decision, relayInstead func()) {
	// A property the move from 503 to 403 quietly removed, and which has to be put
	// back by hand: 403 is a CACHEABLE status for intermediaries, where 503 is not
	// cached by default. Without this, a corporate proxy between the developer and us
	// can retain "permission denied" for a package that was only mid-scan — and the
	// retry the developer is told to make would be answered from that cache, never
	// reaching us, so the package would look permanently denied.
	//
	// Scoped to these two outcomes on purpose. Both are by definition about to change,
	// so they must never be stored. A real VERDICT is left as it was: whether an
	// approval should invalidate a cached block is a separate question about the
	// approval workflow, not something for this change to decide by side effect.
	w.Header().Set("Cache-Control", "no-store")
	if d.Pending {
		reason := d.Reason
		if p.cfg.PendingRetryAfterSeconds > 0 {
			reason = fmt.Sprintf("%s (a background scan is running; try again in about %d seconds)",
				reason, p.cfg.PendingRetryAfterSeconds)
		}
		// Pending is the one outcome where retrying IS the next step: the scan is running
		// and will finish. Saying so is what stops a developer reading a transient state as
		// a permanent denial and routing around us.
		p.refuse(w, pkg, pendingErrMsg, reason,
			"No one needs to approve this -- a scan is running now and it will clear on its "+
				"own. Re-run the install shortly. If it keeps returning this, the scan is "+
				"failing and the firewall's operator should look at it",
			verdictMeta{Kind: "pending"}, relayInstead)
		return
	}
	p.refuse(w, pkg, unavailableErrMsg, d.Reason,
		"This is not a verdict about the package -- the firewall could not reach the sources "+
			"it needs to evaluate it. That is an outage on our side, not a finding about your "+
			"dependency, and it clears when those sources are reachable again",
		verdictMeta{Kind: "unavailable"}, relayInstead)
}

// proxyToUpstream forwards the incoming request to the configured upstream
// registry and copies the response back. This is the "proxy" mechanic: the
// client thinks it's talking to npm; really it's talking to us, and we relay.
// With rewriteMeta set, a 200 response body is relayed through rewriteRegistry
// URLs instead of streamed verbatim.
func (p *proxyServer) proxyToUpstream(w http.ResponseWriter, r *http.Request, rewriteMeta bool, id flowID) {
	// EscapedPath (not Path) preserves the client's percent-encoding — npm
	// requests scoped packages as /@scope%2fname, and Path would silently
	// re-expand that into a shape we never received.
	target := strings.TrimRight(p.cfg.UpstreamRegistry, "/") + r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	p.relay(w, r, target, rewriteMeta, "", id)
}

// proxyToFiles relays a PyPI artifact request (a wheel/sdist under the "/_files/"
// prefix that relayRewritten rewrote into the /simple/ index) to the files upstream
// (files.pythonhosted.org), which is a DIFFERENT host than the index upstream.
//
// It GATES the byte fetch — the D22 fix. The rewritten URL is /_files/<pkg>/<object
// path>, where <pkg> is the authoritative package name the index request resolved.
// We peel <pkg> back off and Evaluate it, rather than parse it out of the ambiguous
// wheel/sdist filename (an sdist's hyphens make name-vs-version ambiguous, and a
// mis-parse would evaluate the WRONG or an unknown package — which resolves to allow
// — silently bypassing the firewall). This closes the one escape hatch left by the
// yanked-index posture: an exact pin (pip install foo==1.2.3) installs a yanked
// release anyway, but its bytes route through here, so a blocked package fails closed
// unless an admin override flipped it to allowed. Re-evaluating per fetch is
// L1-cache-cheap and keeps us stateless: a fresh override applies on the next fetch.
func (p *proxyServer) proxyToFiles(w http.ResponseWriter, r *http.Request) {
	// Peel the <pkg> segment off /_files/<pkg>/<object-path>. Work on EscapedPath so
	// a percent-encoded name stays intact; unescape only the peeled segment back to
	// the identity the index used, and keep the remainder as the real object path.
	rest := strings.TrimPrefix(r.URL.EscapedPath(), "/_files/")
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		http.Error(w, "malformed artifact path", http.StatusBadRequest)
		return
	}
	pkg, err := url.PathUnescape(rest[:slash])
	if err != nil || pkg == "" {
		http.Error(w, "malformed artifact path", http.StatusBadRequest)
		return
	}
	objectPath := rest[slash:] // remainder, including the leading "/"

	// The <pkg> prefix says which package we are about to DECIDE about; on its own it
	// says nothing about which bytes come back. Any client can pair an allowed
	// package's prefix with a blocked package's object path, and without this check we
	// would gate the decoy and stream the target (issue #67 — a confused deputy).
	// Refuse before evaluating, and log it: a bypass that leaves no audit trail is
	// worse than a loud one.
	// Every "/_files/" URL is one WE minted — pip only ever follows links out of the
	// index we rewrote — so with signing on, all of them must carry a valid signature.
	// This runs BEFORE the filename check rather than replacing it: the signature is
	// exact where the filename check is a grammar, and keeping both means an operator
	// who has not opted in still has the grammar, while one who has gets both.
	//
	// PEP 658 first, or the check below refuses honest installs. pip fetches a wheel's
	// METADATA without the wheel by appending ".metadata" to the distribution's URL —
	// appended to the WHOLE URL, query and all. On a signed link that suffix therefore
	// lands on OUR SIGNATURE ("?_yjsig=abc.metadata"), corrupting it, while the object
	// pip actually wants ("....whl.metadata") is one we never minted a signature for.
	// Note where the suffix lands: the request PATH still ends in ".whl", so the repair
	// is to take the suffix off the signature and put it back on the object.
	//
	// Real pip found this; every unit test until then had built the URL the way we
	// imagined pip would. npm is unaffected — it has no equivalent.
	//
	// Verifying against the BASE artifact is not a loosening: the metadata file is a
	// fixed-suffix derivative of an object we authorised, at an address the client
	// cannot choose. Anything else still has to carry its own signature.
	wantsMetadata := false
	if sig, rest := takeSignature(r.URL.RawQuery); strings.HasSuffix(sig, pep658MetadataSuffix) {
		wantsMetadata = true
		q := sigParam + "=" + strings.TrimSuffix(sig, pep658MetadataSuffix)
		if rest != "" {
			q = rest + "&" + q
		}
		r.URL.RawQuery = q
	}
	if !p.artifactURLAuthentic(w, r, pkg, objectPath, true) {
		return
	}

	if !pypiFilenameBindsToPackage(pkg, objectPath) {
		log.Printf("GET _files %s -> refused: artifact %q does not belong to this package", pkg, objectPath)
		writeBlock(w, p.cfg.Ecosystem, pkg, "artifact-filename-binding", "artifact filename does not belong to the requested package", notAReviewItem)
		return
	}

	// Issue #136: a wheel must not be served under a version that names a different
	// RELEASE than its own PEP 658 metadata declared. An INTEGRITY refusal, not a policy
	// verdict — the package is not unknown, the file is misrepresenting itself — so it
	// sits beside the filename binding above, refuses the same way, and survives report
	// mode for the same reason the binding does: suppressing an integrity guard would
	// introduce a bypass that enforce mode does not have.
	//
	// The reason deliberately says the INDEX disagrees, never that the artifact was
	// verified: this compares the URL against what the index published, not against the
	// bytes. See pypiwheelversion.go for what that does and does not buy.
	// A PEP 658 request reaches us in TWO shapes, and only one of them was obvious. With
	// signing ON the suffix rides on our signature and is peeled off above, leaving
	// objectPath ending in ".whl" (wantsMetadata). With signing OFF there is no signature
	// to land on, so the suffix stays on the object path itself. The first version of this
	// handled only the signed shape and recorded nothing in the default configuration —
	// caught by the rig below, which runs unsigned exactly as a default install does.
	metadataOf := objectPath
	isMetadataRequest := wantsMetadata
	if trimmed := strings.TrimSuffix(objectPath, pep658MetadataSuffix); trimmed != objectPath {
		metadataOf, isMetadataRequest = trimmed, true
	}

	if !isMetadataRequest {
		if served, declared, mismatch := p.pypiServedVersionDisagrees(objectPath); mismatch {
			log.Printf("GET _files %s -> refused: served as version %s but its index metadata declares %s", pkg, served, declared)
			writeBlock(w, p.cfg.Ecosystem, pkg, "wheel-version",
				"the index declares a different version for this file than the one it is served under", notAReviewItem)
			return
		}
	}

	// Allowed (or admin-overridden): stream the bytes back verbatim — no rewrite,
	// artifacts are opaque and rewriting them would break pip's hash check. Hoisted into
	// a closure so the refusals below can hand the SAME allow path to the sink as
	// "what would have happened instead" under FW_MODE=report.
	relayAsAllowed := func() {
		target := strings.TrimRight(p.cfg.FilesUpstream, "/") + objectPath
		if wantsMetadata {
			// Put the suffix back where PyPI expects it — on the object, not the query.
			target += pep658MetadataSuffix
		}
		// Our signature parameter is stripped before forwarding; the files upstream never
		// sees a parameter it did not issue. Any other query passes through as before.
		if _, forwarded := takeSignature(r.URL.RawQuery); forwarded != "" {
			target += "?" + forwarded
		}
		if isMetadataRequest {
			// Issue #136: this document names the version the index claims for the wheel,
			// and pip fetches it before the wheel to resolve. Read it on the way past and
			// remember it under the WHEEL's path — nothing extra is fetched, so the later
			// comparison is free.
			p.relayMetadataRecordingVersion(w, r, target, metadataOf, pkg)
			return
		}
		// The wheel or sdist itself -- never the metadata sibling above, which returned
		// already. Attached explicitly because only THIS relay knows which digest applies.
		rr := r
		if p.pypiFileDigests != nil {
			if want, ok := p.pypiFileDigests.get(objectPath); ok {
				rr = withExpectedDigest(r, pypiDigestAlgo, want)
			}
		}
		p.relay(w, rr, target, false, "", flowID{Package: pkg, Kind: flowArtifact})
	}

	// LAYER 1 ON THE BYTE PATH (#103), before the score, for the same reason Evaluate
	// runs it first: it names THIS release and needs no network of its own beyond the
	// join below.
	if d, blocked := p.pypiPinnedMalwareOnFile(pkg, metadataOf); blocked {
		log.Printf("GET _files [known-malware] %s -> allowed=%v (%s)", pkg, d.Allowed, d.Reason)
		p.versionVerdict(w, r, pkg, d, relayAsAllowed)
		return
	}
	if d, blocked := p.pypiOperatorVersionOnFile(pkg, metadataOf); blocked {
		log.Printf("GET _files [operator-denied] %s -> allowed=false (%s)", pkg, d.Reason)
		p.versionVerdict(w, r, pkg, d, relayAsAllowed)
		return
	}

	// Gate exactly like the index path (ServeHTTP), so the byte verdict can't diverge
	// from the index verdict — same four outcomes, same response shapes.
	decision := p.firewall.Evaluate(pkg)
	log.Printf("GET _files %s %s -> allowed=%v (%s)",
		outcomeToken(decision), pkg, decision.Allowed, decision.Reason)

	switch {
	case decision.Pending:
		p.writeDeferred(w, pkg, decision, relayAsAllowed)
		return
	case decision.Unavailable:
		p.writeDeferred(w, pkg, decision, relayAsAllowed)
		return
	case !decision.Allowed:
		p.refuseDecision(w, pkg, decision, relayAsAllowed)
		return
	}

	relayAsAllowed()
}

// pypiPinnedMalwareOnFile is the THIRD control point for version-pinned advisories
// (#103), and the one that was missing.
//
// PyPI's per-version enforcement was the index yank: the named release is served marked
// yanked (PEP 592) with the advisory as its reason, which steers an ordinary resolve away
// from it. That is not enforcement, because PEP 592 tells an installer to ignore a yanked
// file UNLESS the requirement pins that exact version — so `pip install six==1.16.0`
// selects it anyway. Measured with real pip (e2e/pypi_exactpin_test.go): it prints "the
// candidate selected for download or install is a yanked version", fetches the wheel
// through us, and installs it. The comment on npm's tarball path already claimed this
// gate applied the rule; nothing did.
//
// The rule and its fail-closed posture are pinnedMalwareVerdict's, shared with npm's
// tarball path and Maven's request path, so there is one place where "we could not
// determine the version" is decided.
func (p *proxyServer) pypiPinnedMalwareOnFile(pkg, objectPath string) (Decision, bool) {
	if !strings.EqualFold(p.cfg.Ecosystem, "pypi") || p.firewall.malwareFeed() == nil || !pinnedEnforcedIn(p.cfg.Ecosystem) {
		return Decision{}, false
	}
	// NOTHING TO MISS, AND NOTHING TO PAY. No pinned advisory names this package, so
	// there is no version to determine and no metadata document to fetch. This is what
	// keeps the join's cost off every package the feed does not name — which is almost
	// all of them.
	if !p.firewall.malwareFeed().hasPinned(p.cfg.Ecosystem, pkg) {
		return Decision{}, false
	}
	version, known := p.pypiFileVersion(pkg, objectPath)
	return p.firewall.pinnedMalwareVerdict(pkg, version, known)
}

// pypiOperatorVersionOnFile is the operator's version-scoped deny on the PyPI byte path
// (#155), sharing pypiFileVersion's join with its malware twin above. It is the file half
// of the same entry the /simple/ index filter applies: a client that pins the release
// exactly reaches the bytes without the index's opinion mattering (#159), and an operator
// deny that stops there would be advisory rather than enforcement.
func (p *proxyServer) pypiOperatorVersionOnFile(pkg, objectPath string) (Decision, bool) {
	if !strings.EqualFold(p.cfg.Ecosystem, "pypi") {
		return Decision{}, false
	}
	if !p.firewall.deny().hasAnyVersion(p.cfg.Ecosystem, pkg) {
		return Decision{}, false // nothing to miss, and no join to pay for
	}
	version, known := p.pypiFileVersion(pkg, objectPath)
	return p.firewall.operatorVersionVerdict(pkg, version, known)
}

// pypiFileVersion resolves the release a served file belongs to, from PyPI's own
// releases map (filename -> version) — the authoritative join the index filter already
// uses, rather than parsing the filename here. A second parser would be a second place
// for the join to be wrong, and an sdist name ("my-pkg-1.0.tar.gz") cannot be split into
// name and version by grammar alone.
//
// known=false is returned for every way the join can fail — an unreadable metadata
// document, a filename the map does not carry — and the caller fails closed, which only
// bites a package that carries a pinned advisory.
func (p *proxyServer) pypiFileVersion(pkg, objectPath string) (version string, known bool) {
	name := objectPath
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	if un, err := url.PathUnescape(name); err == nil {
		name = un
	}
	name = strings.TrimSuffix(name, pep658MetadataSuffix)
	if name == "" {
		return "", false
	}
	_, versions, err := p.fetchUploadTimes(pkg)
	if err != nil {
		log.Printf("GET _files %s -> could not read the filename->version map (%v); a pinned advisory names "+
			"this package, so the file is refused rather than guessed at", pkg, err)
		return "", false
	}
	v, ok := versions[name]
	return v, ok
}

// outcomeToken names which of the four outcomes a decision is, in the part of a log line
// the call site writes LITERALLY — before the " -> " — so a reader can key on it (#68).
//
// It exists because the same event used to leave two different records (#76). npm and OCI
// reach the byte gate through proxyArtifactBytes, which carries these tokens; PyPI goes
// through proxyToFiles and Maven through the metadata path, and neither did. On an
// identical input — the registry unreachable, so nothing was ever evaluated — npm/OCI
// recorded "withheld-unavailable" while PyPI/Maven recorded a plain denial. Both refused
// the bytes, so there was no enforcement gap; but an operator grepping for outages saw
// two ecosystems and missed two, and the capacity dashboard (#32) consumes these records.
//
// [withheld-unavailable] is deliberately the SAME string the byte gate already emits. The
// point of this issue is one event, one record — a token that differed per code path would
// reproduce the defect in a new spelling.
func outcomeToken(d Decision) string {
	switch {
	case d.Pending:
		return "[deferred-pending]"
	case d.Unavailable:
		return "[withheld-unavailable]"
	case !d.Allowed:
		return "[verdict-blocked]"
	default:
		return "[verdict-allowed]"
	}
}

// artifactURLAuthentic checks the signed binding on an artifact URL we minted (#72),
// answering the question the byte gate cannot: were this package prefix and this object
// path put together by US, or by whoever is making the request?
//
// It writes the refusal itself and returns false when the request must not proceed.
//
// Two cases pass without a signature, and both are deliberate:
//
//   - Signing is off (the default). Nothing was minted signed, so nothing can be
//     required. This is the opt-in half of D103.
//   - The request is npm's OWN "/<pkg>/-/<file>.tgz" shape rather than the
//     "/_tarball/<pkg>/…" we mint. That shape derives the package name from the very
//     path it forwards (npmArtifactPath returns the whole escaped path as the object
//     path), so its identity and its bytes cannot disagree — there is no confused
//     deputy to close, and requiring a signature would break every lockfile already in
//     the wild plus the URL modern npm/pnpm build themselves.
//
// When signing IS on, an unsigned or wrongly signed "/_tarball/" URL is refused. That
// includes URLs minted while signing was off: enabling the feature invalidates them, and
// an operator turning it on should expect one round of lockfile regeneration. Rotation
// is the mechanism for avoiding that in the steady state (URLSigningKeyPrevious).
// weMintedThisShape says whether the request arrived on a URL shape THIS proxy mints
// (and therefore signs), as opposed to one the registry's own convention produces. Only
// a minted shape can be required to carry a signature.
func (p *proxyServer) artifactURLAuthentic(w http.ResponseWriter, r *http.Request, pkg, objectPath string, weMintedThisShape bool) bool {
	// An INTERCEPTED artifact URL is the registry's own, never one we minted, so there is
	// no signature to verify; its binding to a package came from the relayed index
	// instead (proxyInterceptedFile). The parameter says "we minted this shape" and for
	// these requests that is simply false.
	if !p.signer.Enabled() || !weMintedThisShape || intercepted(r) {
		return true
	}
	sig, _ := takeSignature(r.URL.RawQuery)
	if p.signer.Verify(p.cfg.Ecosystem, pkg, objectPath, sig) {
		return true
	}
	// Log it: a bypass attempt that leaves no audit trail is worse than a loud one, and
	// this is the signal that someone is hand-editing lockfile URLs. The object path is
	// included because the whole point is that it did not belong with this package.
	log.Printf("artifact %s -> refused: URL signature does not cover %q (unsigned, tampered, or minted under a retired key)",
		pkg, objectPath)
	writeBlock(w, p.cfg.Ecosystem, pkg, "url-signature", "artifact URL signature is missing or invalid", notAReviewItem)
	return false
}

// proxyArtifactBytes serves an ARTIFACT byte fetch — an npm tarball (issue #11 /
// D49) or an OCI blob (issue #57) — re-evaluating the package first.
//
// It closes the same hole in both ecosystems: the gate's "one control point at the
// metadata request" model assumes the client asks for metadata before bytes, and
// real clients routinely do not. `npm ci` / pnpm / yarn install from a lockfile,
// fetching each tarball directly by its recorded "resolved" URL. (Not hypothetical:
// an operator reported being compromised by the March-31 axios incident while
// running only `npm ci`.) On the OCI side `crane blob` reads a layer with no
// manifest request at all, as do clients with a cached manifest, pulling by digest,
// or resuming a partial layer. A package the firewall blocks at metadata was
// therefore still deliverable byte-for-byte.
//
// One function for both on purpose: the byte verdict and the metadata verdict must
// not drift, and two copies of these four outcomes would eventually drift. It is
// ecosystem-neutral because it only needs an identity and an object path — the
// per-ecosystem work is deciding WHICH requests are artifact fetches and what the
// identity is (npmArtifactPath, ociBlobPath), which is where the shapes differ.
//
// Re-evaluating per fetch is the D49 "Option A" shape, mirroring PyPI's proxyToFiles
// (D22): it is an L1-cache hit for anything the same install already resolved, it
// keeps us stateless (a fresh human override applies on the very next fetch), and it
// can never go stale the way a signed allow-token minted at metadata time could.
// That cache is what makes OCI's fan-out affordable — one manifest, then many blobs,
// all resolving to the same identity and therefore the same cached score.
//
// How hard it bites is the operator's call via FW_BYTE_GATE, which defaults to
// allow-but-log — evaluate and log, serve the bytes regardless. So by DEFAULT this
// function provides visibility, not enforcement, and the side-door stays open until
// someone sets enforce. That is a project ruling, not an oversight; see Config.ByteGate.
//
// The default has exactly TWO carve-outs, and both exist because they are not the
// tradeoff that ruling was about:
//
//   - a HARD deny blocks the bytes (D72) — an affirmative finding was never something
//     the visibility default was aimed at, only the noisy absence-of-trust case was;
//   - an UNAVAILABLE verdict withholds the bytes behind a retryable 503 (#60) — we did
//     not evaluate at all, so nothing was classified either way, and serving on a
//     failed lookup lets availability pressure rewrite a block into a delivery.
func (p *proxyServer) proxyArtifactBytes(w http.ResponseWriter, r *http.Request, pkg, objectPath string) {
	target := strings.TrimRight(p.cfg.UpstreamRegistry, "/") + objectPath
	// Our own signature parameter is stripped before forwarding: the upstream registry
	// should never see a parameter it did not issue. Any other query is passed through
	// untouched, exactly as before.
	if _, forwarded := takeSignature(r.URL.RawQuery); forwarded != "" {
		target += "?" + forwarded
	}
	// Artifacts are opaque bytes: never rewriteMeta here, or we would corrupt the
	// tarball and break npm's dist.integrity check.
	id := flowID{Package: pkg, Kind: flowArtifact}
	serve := func() { p.relay(w, r, target, false, "", id) }
	// npm tarballs carry their own version, and it must be the one the URL serves them
	// as (#52). The check sits in front of the relay rather than in the ruleset because
	// it is not a verdict about the package: it is an integrity property of THIS fetch,
	// like the #67 binding above, and like it it applies in every byte-gate mode — the
	// mode ladder below decides whether policy refusals bite, not whether a wrong file
	// under a right name is a wrong file.
	if served, ok := npmTarballVersionFromPath(pkg, objectPath); ok && p.cfg.Ecosystem == "npm" {
		serve = func() { p.relayNpmTarball(w, r, target, pkg, served, id) }
	}

	mode := byteGateMode(p.cfg.ByteGate)
	if mode == byteGateOff {
		serve() // the pre-#11 passthrough, kept as an escape hatch
		return
	}

	// Version-pinned known-malware advisories on the byte path (#103, npm). A
	// lockfile-driven `npm ci` never reads the packument the filter above edits, so
	// the version the tarball is served as — from the registry's own filename (#52)
	// — is judged here by the same rule PyPI's /_files/ gate and Maven's request path
	// use: pinnedMalwareVerdict, which fails closed when a pinned package's version
	// cannot be read. Package-wide advisories are Evaluate's, below, as before.
	if p.cfg.Ecosystem == "npm" && p.firewall.malwareFeed() != nil {
		served, known := npmTarballVersionFromPath(pkg, objectPath)
		if d, blocked := p.firewall.pinnedMalwareVerdict(pkg, served, known); blocked {
			log.Printf("artifact [known-malware] %s -> allowed=%v (%s)", pkg, d.Allowed, d.Reason)
			p.versionVerdict(w, r, pkg, d, serve)
			return
		}
	}
	// The operator's own version-scoped deny on the same byte path (#155). `npm ci` from a
	// lockfile never reads the packument the filter edits, so an entry that lived only in
	// the filter would be advisory rather than enforcement — the same hole #159 measured on
	// PyPI with an exact pin.
	if p.cfg.Ecosystem == "npm" {
		served, known := npmTarballVersionFromPath(pkg, objectPath)
		if d, blocked := p.firewall.operatorVersionVerdict(pkg, served, known); blocked {
			log.Printf("artifact [operator-denied] %s -> allowed=false (%s)", pkg, d.Reason)
			p.versionVerdict(w, r, pkg, d, serve)
			return
		}
	}

	decision := p.firewall.Evaluate(pkg)

	// The allow-vs-refuse axis now comes from an ordered ruleset (D76, issue #58
	// increment 4) instead of from an inlined hardDeny()/!Allowed test, so the byte
	// route's policy reads in the same vocabulary as the metadata route's and an
	// operator can see WHICH line served or refused their bytes.
	//
	// What is deliberately NOT in the ruleset is the retryability below: Pending and
	// Unavailable are not verdicts (Decision says so), and Pending is mode-dependent,
	// so the mode ladder that remains is about "have we decided yet", not "what did we
	// decide". See byteGateRuleset for the full reasoning.
	rule, action := p.firewall.byteRuleset().Decide(Facts{
		Package:  pkg,
		Allowed:  decision.Allowed,
		Deny:     decision.Deny,
		Score:    decision.Score,
		HasScore: decision.HasScore,
	})

	if mode == byteGateAllowButLog {
		// Visibility mode — with one exception that is the whole point of D72: a HARD
		// deny still blocks the bytes.
		//
		// The exception exists because "blocked" covers two unlike things. A package
		// that scored below the threshold, or that a human explicitly denied, is a
		// POSITIVE FINDING — serving its bytes was never the intent, and letting a
		// lockfile fetch through means the same package installs or fails depending on
		// whether the developer happened to run `npm install` or `npm ci`. A package we
		// merely could not score or verify is an ABSENCE OF TRUST: that fires on plenty
		// of legitimate packages with thin metadata, and quietly blocking those from CI
		// is exactly the breakage the allow-but-log default exists to avoid.
		//
		// So visibility-first is preserved where it was aimed (the noisy case) and
		// dropped where it was never aimed (a package we affirmatively refused).
		//
		// The condition is now the ruleset's, not hardDeny() called here — same
		// predicate, one owner. The rule NAME goes into the log line, so the
		// operator reading it can find the line of policy that refused the bytes.
		if action == ActionReject {
			log.Printf("byte gate (allow-but-log) [hard-deny] %s -> BLOCKED by rule %q: %s [%s] — a hard deny blocks bytes in every BYTE-GATE mode (D72); FW_BYTE_GATE=off disables the gate entirely, and FW_MODE=report suppresses the refusal itself",
				pkg, rule.Name, decision.Reason, decision.Deny)
			p.refuseDecision(w, pkg, decision, serve)
			return
		}
		// The second carve-out (#60): "we could not look" is not "we looked and found
		// nothing conclusive", and only the second justifies serving.
		//
		// An Unavailable verdict means evaluation did not COMPLETE, so the denial kind
		// was never established — the decision arrives here with an empty Deny and is
		// therefore not a hardDeny, even for a package that would be hard-denied on a
		// good day. The observed sequence: the metadata fetch timed out, the verdict
		// became Unavailable with deny="", and the gate served a package it refuses
		// under normal conditions.
		//
		// That makes availability pressure into a policy bypass, which is
		// attacker-influenceable: degrade our path to the registry — slow-loris it,
		// exhaust the connection budget, apply DNS pressure, or just wait for a real
		// outage — and "this package is blocked" becomes "here are its bytes". Losing
		// sight of the upstream must make us more cautious, not less.
		//
		// So withhold the bytes and return the SAME response the metadata path already
		// returns for this state. This is not the visibility-vs-enforcement tradeoff the
		// allow-but-log default is about: nothing is being classified as bad here, we
		// are declining to answer until we can evaluate.
		if decision.Unavailable {
			log.Printf("byte gate (allow-but-log) [withheld-unavailable] %s -> 403 unavailable: %s — evaluation did not complete, so the verdict kind is unknown; bytes are withheld in every BYTE-GATE mode (#60), though FW_MODE=report suppresses the refusal",
				pkg, decision.Reason)
			p.writeDeferred(w, pkg, decision, serve)
			return
		}

		// Everything else is logged and served. Shout specifically when we are serving
		// bytes the gate would have refused under enforce — that single line is the
		// security value of this mode, and it is what an operator greps to decide
		// whether enforce is safe to turn on.
		//
		// This log line IS the ActionAllowLog action — an allow-but-log that
		// produced no record would just be an allow. It is written here rather
		// than inside the engine because the handler has the richer facts (the
		// retryable flags, the reason) that make the line worth grepping.
		if !decision.Allowed || decision.Pending || decision.Unavailable {
			log.Printf("byte gate (allow-but-log) [served-anyway] %s -> allowed=%v pending=%v unavailable=%v deny=%q rule=%q (%s) — SERVING BYTES ANYWAY; set FW_BYTE_GATE=enforce to block",
				pkg, decision.Allowed, decision.Pending, decision.Unavailable, decision.Deny, rule.Name, decision.Reason)
		} else {
			log.Printf("byte gate (allow-but-log) [allowed] %s -> allowed=true (%s)", pkg, decision.Reason)
		}
		serve()
		return
	}

	// The bracketed token in each byte-gate line above — [hard-deny],
	// [withheld-unavailable], [served-anyway], [allowed] — is not decoration (#68).
	//
	// It sits BEFORE the " -> ", in the part of the line the call site writes
	// literally, because that is the only part a reader can trust: everything after
	// the arrow is filled in from the decision, including a policy rule NAME an
	// operator chose. A classifier keying on the payload can be steered by naming a
	// rule after the text it looks for, which has already happened once and silently
	// moved 38 cells of the committed mode matrix.
	//
	// Before these tokens, the four outcomes above were indistinguishable to any
	// head-based reader: three shared the byte-identical head "byte gate
	// (allow-but-log) <pkg>", and the fourth differed only by being UPPERCASE — so
	// "the gate looked and served the bytes anyway" was recorded as a plain denial,
	// which is the opposite of what happened and the single most security-relevant
	// line this mode emits.

	// Enforce: the same four outcomes as the metadata path, produced by the same
	// helpers so the byte verdict and the index verdict can never drift apart.
	//
	// The two non-verdict cases come FIRST and are not ruleset decisions: neither is
	// a verdict, and both must outrank the policy line below, because a ruleset asked
	// about a package we never finished evaluating would answer from incomplete facts
	// — which is exactly how #60 turned an outage into a delivery. They are 403s with
	// their own explanations (D102), not the 503s they used to be.
	log.Printf("byte gate (enforce) %s -> allowed=%v rule=%q (%s)", pkg, decision.Allowed, rule.Name, decision.Reason)
	switch {
	case decision.Pending:
		p.writeDeferred(w, pkg, decision, serve)
	case decision.Unavailable:
		p.writeDeferred(w, pkg, decision, serve)
	case action == ActionReject:
		p.refuseDecision(w, pkg, decision, serve)
	default:
		serve()
	}
}

// relay performs the actual proxy round-trip to an already-computed absolute
// target URL: build the upstream request tied to the client's context, forward
// end-to-end headers, and stream the response back (optionally through the npm
// metadata rewrite). Shared by proxyToUpstream and proxyToFiles so the two only
// differ in how they pick the target host.
// yankDeliveredReason corrects one clause of a verdict's reason for the transport it is
// about to travel on.
//
// The deny-list and known-malware reasons say "refused without contacting upstream", and
// on every 403 transport that is true: npm, Maven and OCI are answered without a relay,
// and the reference deployment's registry stand-ins never see the name. A PyPI block is
// different by design (D22, !16): it RELAYS the real /simple/ index with every release
// marked yanked, so pip prints our reason instead of silently backtracking -- and that
// page cannot be built without fetching the version list. Measured 2026-09-13: the
// deny-listed package's index was fetched from the customer's registry (82,826 bytes)
// under a header claiming no upstream contact. The artifact BYTES were not fetched, and
// that is the half the sentence should carry.
//
// Only the delivered text changes. The log line (already written above) and the audit
// record keep the verdict's own reason, so the mode matrix and every parser of that
// line are untouched; a reason without the clause passes through unchanged.
func yankDeliveredReason(reason string) string {
	const clause = "refused without contacting upstream"
	if !strings.Contains(reason, clause) {
		return reason
	}
	return strings.Replace(reason, clause,
		"the index was fetched to list the releases to yank, and no artifact bytes were", 1)
}

// yankReason, when non-empty (a PyPI /simple/ block), makes the rewritten index
// mark every release yanked with that reason instead of the proxy 403ing — see the
// block path in ServeHTTP. It only takes effect together with rewriteMeta.
// relayWriteUngated forwards a write the operator opted into relaying, WITHOUT
// evaluating it.
//
// This is D134, and it is a correctness requirement rather than an optimisation.
// The ruling: "uploads shouldn't be subjected to ossf scans, for sure, because, well, the
// fact that you are an employee gives you some implicit trust, and many of the
// elements of the scorecard are not applicable to in-house developed containers."
// So scoring a push is WRONG, not merely undecided — a Scorecard verdict describes
// the source repo of an image being CONSUMED, and says nothing about whether someone
// may publish one.
//
// Before this, the non-block policies fell through to the byte gate, so setting
// FW_WRITE_POLICY=allow brought the scoring straight back: a push to an image whose
// score sat below the threshold was refused with "BLOCKED: … scored 7.5, below
// required 9.9" — a verdict about the wrong question, on a request the operator had
// explicitly exempted. The default block merely SHADOWED that path; D134 says to
// delete it rather than leave it dead and re-enablable, which is what this does.
//
// Recorded as flowWrite so the bytes are not counted as a download (#66 item 3).
//
// Note the topology this does NOT build (D134 item 3): in the intended deployment a
// developer pushes DIRECTLY to their registry and any future upload scanning runs
// registry -> us, the opposite direction from the pull path. So this is an escape
// hatch for an operator who has wired things differently, not the seam that upload
// scanning will one day hang off. Do not grow it into one by symmetry with the pull
// path.
func (p *proxyServer) relayWriteUngated(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimRight(p.cfg.UpstreamRegistry, "/") + r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	// No package identity: we deliberately did not parse one, because parsing it is
	// what invited the gate in. An empty Package is what flowInfra-style rows already
	// carry for traffic with no package.
	p.relay(w, r, target, false, "", flowID{Kind: flowWrite})
}

// bodylessResponse reports that this response cannot carry a body at all, so copying
// zero bytes is the CORRECT outcome rather than a truncated transfer.
//
// Deliberately narrow. The three cases here are the ones HTTP defines as bodyless
// regardless of Content-Length; widening it to, say, "any 3xx" would start excusing
// real short transfers, which is the defect the truncation guard exists to catch.
func bodylessResponse(method string, status int) bool {
	return method == http.MethodHead ||
		status == http.StatusNoContent ||
		status == http.StatusNotModified
}

// openUpstream is the first half of relay: the upstream round-trip, up to and including
// the response headers. relay and relayNpmTarball (#52) share it so the request they send
// upstream can never differ; they differ only in what happens between the upstream's
// answer and the client's first byte. ok=false means the error response has already been
// written to the client.
func (p *proxyServer) openUpstream(w http.ResponseWriter, r *http.Request, target string, rewriteMeta bool, id flowID) (*http.Response, string, bool) {
	log.Printf("%s %s -> %s", r.Method, r.URL.Path, target)
	// Resolved once per relay and threaded down, rather than recomputed at each byte
	// accounting point: clientIP walks X-Forwarded-For against the trusted-proxy set,
	// and doing that twice for one response could also disagree with itself if the
	// header were somehow mutated mid-handler.
	srcIP := clientIP(r, p.trustedProxies)
	p.flow.recordRelay(id, srcIP)

	// The request context ties the upstream call to the client connection: if
	// the client hangs up mid-download, the upstream fetch is cancelled too.
	// relayedBody keeps the listener's read bound a bound on a STALLED body rather than
	// on the whole upload (#130, listener.go).
	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, target, relayedBody(w, r))
	if err != nil {
		http.Error(w, "failed to build upstream request", http.StatusInternalServerError)
		return nil, "", false
	}
	// Copy the client's end-to-end headers so things like Accept and
	// Authorization survive, without leaking hop-by-hop ones.
	upstreamReq.Header = make(http.Header)
	copyEndToEndHeaders(upstreamReq.Header, r.Header)
	if rewriteMeta {
		// Dropping Accept-Encoding makes Go's transport negotiate gzip itself
		// and transparently decompress — handing us editable JSON. Forwarding
		// the client's header would hand us compressed bytes we can't rewrite.
		upstreamReq.Header.Del("Accept-Encoding")
		// npm asks for the ABBREVIATED packument (application/vnd.npm.install-v1+json),
		// which carries no `time` map — measured against registry.npmjs.org: its keys
		// are dist-tags, modified, name, versions. The release window (#26) needs the
		// publish dates, so while a window is active we ask for the full document
		// instead; npm accepts either, and an operator who turned a window on has
		// chosen the larger fetch. Nothing changes when no window is configured.
		if p.cfg.Ecosystem == "npm" && p.releaseWindow(time.Now()).active() {
			upstreamReq.Header.Set("Accept", "application/json")
		}
	}

	upstreamResp, err := p.doWithRetry(upstreamReq, id)
	if err != nil {
		// Upstream unreachable even after retries. In a later version this is
		// where a cache would serve a previously-stored copy so builds keep working.
		p.flow.recordTransportError(id)
		http.Error(w, "upstream registry unreachable", http.StatusBadGateway)
		return nil, "", false
	}
	// Count only statuses that are real failures — a 404 is routine probing, see
	// flowRecorder.recordStatus.
	p.flow.recordStatus(id, upstreamResp.StatusCode)
	return upstreamResp, srcIP, true
}

func (p *proxyServer) relay(w http.ResponseWriter, r *http.Request, target string, rewriteMeta bool, yankReason string, id flowID) {
	upstreamResp, srcIP, ok := p.openUpstream(w, r, target, rewriteMeta, id)
	if !ok {
		return
	}
	defer upstreamResp.Body.Close()

	if rewriteMeta && upstreamResp.StatusCode == http.StatusOK {
		copyEndToEndHeaders(w.Header(), upstreamResp.Header)
		p.relayRewritten(w, r, upstreamResp, yankReason, id, srcIP)
		return
	}
	p.streamResponse(w, r, target, upstreamResp, upstreamResp.Body, id, srcIP)
}

// streamResponse is the second half of relay: the upstream's status and headers, then
// `body` streamed to the client verbatim. `body` is normally upstreamResp.Body; a caller
// that has already read a prefix of it passes the prefix and the remainder joined, so the
// short-transfer accounting below still sees the whole body.
func (p *proxyServer) streamResponse(w http.ResponseWriter, r *http.Request, target string, upstreamResp *http.Response, body io.Reader, id flowID, srcIP string) {
	// Relay status, headers, and body back to the client.
	copyEndToEndHeaders(w.Header(), upstreamResp.Header)
	if intercepted(r) && p.cfg.Ecosystem == "oci" && upstreamResp.StatusCode == http.StatusUnauthorized {
		p.rewriteBearerRealm(w.Header(), r)
	}
	w.WriteHeader(upstreamResp.StatusCode)

	// Stream the body back, but do NOT ignore io.Copy's error: an upstream that
	// cuts the connection mid-body (seen with Maven Central resetting a cold
	// resolve's burst) delivers fewer bytes than its Content-Length promised. The
	// status and Content-Length are already committed, so we can't downgrade to a
	// clean error — a short 200 body looks complete and could be cached as a
	// corrupt-but-2xx artifact. Detect the shortfall and abort the handler so the
	// client sees a broken transfer and retries.
	// Artifact integrity on relay (#64). The digest the artifact was published under --
	// an OCI blob's URL, a PyPI index entry, a Maven repository's checksum header -- is
	// checked against the bytes actually delivered, as they stream.
	//
	// The destination is wrapped ONLY when a check is active. io.Copy hands off to
	// http.response's ReadFrom (sendfile) when the destination supports it, and an
	// io.MultiWriter does not, so wrapping unconditionally would slow every relay in
	// the product -- including the metadata path, which has no digest to check -- to
	// pay for a check that is not running. Today's fast path is byte-for-byte the
	// path a non-OCI relay still takes.
	dst := io.Writer(w)
	var check *integrityCheck
	if verifiableTransfer(r, upstreamResp) {
		if algo, want, ok := p.expectedDigestFor(r, upstreamResp); ok {
			if check = newIntegrityCheck(algo, want); check != nil {
				dst = io.MultiWriter(w, check)
			}
		}
	}

	copied, err := io.Copy(dst, body)
	cl := upstreamResp.ContentLength
	// A HEAD response carries NO BODY by definition (RFC 9110 5.1 / 9.3.2), while its
	// Content-Length still advertises what the equivalent GET would return. Comparing
	// bytes copied against that number therefore makes EVERY HEAD look truncated.
	//
	// That is issue #108, and it was not theoretical: the guard aborted the handler, so
	// a registry:2 pull-through cache pointed at us reported
	//
	//	relay: SHORT upstream transfer for HEAD .../manifests/3.19: copied 0 of 8077 bytes
	//
	// and `docker pull` failed with "not found". The registry-in-front topology (D177,
	// #98) simply did not work, and the e2e rig missed it because it drives no HEAD at
	// all -- the coverage gap is the reason this shipped, not the guard's arithmetic.
	short := cl >= 0 && copied < cl && !bodylessResponse(r.Method, upstreamResp.StatusCode)
	// Count what ACTUALLY moved, not what Content-Length promised — the two diverge
	// exactly when something breaks, which is when the number matters most. On this
	// path the bytes are streamed through verbatim, so the upstream and client sides
	// are the same quantity (unlike the rewritten-metadata path below).
	p.flow.recordRelayBytes(id, srcIP, copied, copied)
	if err != nil || short {
		// The client hanging up mid-download lands here too (context cancelled);
		// that's benign — it's their transfer to abandon, not upstream truncation.
		// It is ALSO why nothing is counted here: attributing a developer's Ctrl-C to
		// upstream corruption would make the failure metric track impatience.
		if r.Context().Err() != nil {
			log.Printf("relay: client cancelled %s %s after %d/%d bytes: %v", r.Method, target, copied, cl, err)
			return
		}
		log.Printf("relay: SHORT upstream transfer for %s %s: copied %d of %d bytes (err=%v)", r.Method, target, copied, cl, err)
		if short {
			p.flow.recordTruncated(id)
			panic(http.ErrAbortHandler)
		}
		p.flow.recordRelayError(id)
		return
	}

	// The transfer completed, so the sum over the bytes we delivered is comparable to
	// the digest the request named (#64). Deliberately AFTER the short/error return
	// above: a partial body sums to something that cannot match, and reporting that as
	// a corrupt artifact would rename a truncation defect rather than find a new one.
	if check != nil && !check.matches() {
		// The bytes are already the client's. All that is left is to refuse to be the
		// thing that says the download finished cleanly -- see relayintegrity.go for
		// why a 403 is not on the menu once the status line has gone out.
		log.Printf("relay: INTEGRITY MISMATCH for %s %s: %s digest of %d delivered bytes is %s, the request named %s -- transfer aborted",
			r.Method, target, check.algo, copied, check.got(), check.want)
		p.flow.recordIntegrityMismatch(id)
		panic(http.ErrAbortHandler)
	}
}

// Upstream retry budget for transient transport failures. A cold `mvn` resolve
// fans out into dozens of concurrent per-artifact fetches, and Maven Central
// resets the connection burst — surfacing here as a transport error (not an HTTP
// status). A few jittered retries ride over the reset without an operator noticing.
const (
	upstreamMaxAttempts = 3                      // total tries, including the first
	upstreamRetryBase   = 100 * time.Millisecond // backoff for the first retry
	upstreamRetryCap    = 2 * time.Second        // ceiling on any single backoff
)

// doWithRetry runs the upstream request, retrying ONLY on a transport error
// (p.client.Do's err) and ONLY for idempotent GET/HEAD — which have no request
// body to re-send. It deliberately never inspects the HTTP status: any returned
// response, whatever its status, ends the loop, so retry stays a pure transport
// concern and never touches D17 status classification. Backoff is jittered and
// bounded, and the client's context short-circuits the wait so a hung-up client
// doesn't keep us retrying.
func (p *proxyServer) doWithRetry(req *http.Request, id flowID) (*http.Response, error) {
	idempotent := req.Method == http.MethodGet || req.Method == http.MethodHead
	var resp *http.Response
	var err error
	for attempt := 0; ; attempt++ {
		resp, err = p.client.Do(req)
		if err == nil {
			return resp, nil
		}
		// Stop if the method isn't safe to replay, the client already went away,
		// or we've spent the budget — otherwise the caller's 502 is correct.
		if !idempotent || req.Context().Err() != nil || attempt >= upstreamMaxAttempts-1 {
			return nil, err
		}
		backoff := upstreamBackoff(attempt)
		p.flow.recordRetry(id)
		log.Printf("upstream transport error (attempt %d/%d) for %s %s: %v; retrying in %s",
			attempt+1, upstreamMaxAttempts, req.Method, req.URL, err, backoff)
		select {
		case <-time.After(backoff):
		case <-req.Context().Done():
			return nil, err
		}
	}
}

// upstreamBackoff returns a jittered, capped exponential backoff for the given
// zero-based retry attempt. Full jitter (a uniform draw over [0, delay)) keeps a
// burst of simultaneously-failed fetches from retrying in lockstep and simply
// re-forming the same burst that upstream just reset.
func upstreamBackoff(attempt int) time.Duration {
	delay := upstreamRetryBase << attempt
	if delay > upstreamRetryCap || delay <= 0 { // <=0 guards a shift overflow
		delay = upstreamRetryCap
	}
	return rand.N(delay)
}

// metaRewriteMaxBytes bounds how much metadata we'll buffer for URL rewriting.
// Package documents for huge, old packages run to tens of MB; past this cap we
// refuse rather than serve a silently truncated (= corrupt) JSON document.
const metaRewriteMaxBytes = 128 << 20 // 128 MB

// relayRewritten sends a metadata/index response with every artifact URL
// rewritten to point back at this proxy. This closes the biggest hole in the
// cooperative-client model: the artifact links are ABSOLUTE URLs to the upstream
// host, and clients fetch exactly what they are told, bypassing the firewall
// (or failing, in an egress-blocked network) otherwise. Every registry proxy
// (Verdaccio, Artifactory, devpi) does this same rewrite.
//
//	npm  — the packument's "dist.tarball" links; modern npm/pnpm swap in the
//	       configured registry host, but yarn classic and lockfile "resolved"
//	       URLs follow the literal URL. dist.integrity is untouched.
//	pypi — the /simple/ index's wheel/sdist links (on files.pythonhosted.org),
//	       rewritten to our "/_files/<pkg>/", where <pkg> is the authoritative
//	       package name so the byte fetch re-gates on the same identity as the
//	       index (proxyToFiles). The "#sha256=" integrity fragment rides along
//	       unchanged; we stream the bytes verbatim once the byte fetch is allowed.
//
// When yankReason is non-empty (a blocked PyPI /simple/ request), every release in
// the rewritten index is additionally marked PEP 592 "yanked" with that reason.
func (p *proxyServer) relayRewritten(w http.ResponseWriter, r *http.Request, upstreamResp *http.Response, yankReason string, id flowID, srcIP string) {
	body, err := io.ReadAll(io.LimitReader(upstreamResp.Body, metaRewriteMaxBytes+1))
	if err != nil {
		p.flow.recordMetaError(id)
		http.Error(w, "failed reading upstream metadata", http.StatusBadGateway)
		return
	}
	if len(body) > metaRewriteMaxBytes {
		p.flow.recordMetaError(id)
		http.Error(w, "upstream metadata too large to relay", http.StatusBadGateway)
		return
	}
	// Captured BEFORE the rewrite: this is what crossed the internet link. The body
	// grows or shrinks below (artifact URLs repointed at us, releases yanked), so the
	// client-facing size is a different, equally real number — recorded at the write.
	upstreamBytes := int64(len(body))

	public := strings.TrimRight(p.cfg.PublicURL, "/")
	if public == "" {
		// No configured public URL: use the address the client reached us on —
		// by definition an address that routes back to this proxy. (TLS-fronted
		// deployments should set FW_PUBLIC_URL explicitly.)
		public = "http://" + r.Host
	}
	// Pick the host-prefix rewrite for the active ecosystem. Both are a single
	// absolute-URL prefix swap — the artifact links are absolute URLs in npm's
	// packument and in PyPI's /simple/ index alike — so the same ReplaceAll closes
	// the bypass for both. PyPI's file host differs from its index host, and the
	// files come back under "/_files/" (handled by proxyToFiles); npm's tarballs
	// share the registry host and come back on the same paths.
	// Read each file's published digest BEFORE the link rewrite below moves the URLs off
	// the files host (#64). Both modes: a cooperative client drops the fragment exactly
	// as an intercepted one does, so neither byte request can carry it.
	if p.cfg.Ecosystem == "pypi" && p.pypiFileDigests != nil {
		for objectPath, want := range pypiIndexDigests(body, p.cfg.FilesUpstream) {
			p.pypiFileDigests.put(objectPath, want)
		}
	}
	var from, to string
	if intercepted(r) {
		// No link rewriting under interception -- the whole point of the mode is that the
		// client's URLs stay the registry's own. But the index is where we learn which
		// files belong to which package, and the intercepted byte fetch has nothing else
		// to go on (increment 8), so bind them here. from/to stay empty, which makes the
		// ReplaceAll below a no-op rather than a second branch to keep in step.
		if p.cfg.Ecosystem == "pypi" && p.pypiFilesLinkRe != nil {
			if pkg := p.firewall.PackageNameFromPath(r.URL.Path); pkg != "" {
				n := 0
				for _, sub := range p.pypiFilesLinkRe.FindAllSubmatch(body, -1) {
					tail := string(sub[1])
					if i := strings.IndexByte(tail, '?'); i >= 0 {
						tail = tail[:i]
					}
					if tail != "" {
						p.pypiFileBindings.put("/"+tail, pkg)
						n++
					}
				}
				log.Printf("intercept: %s -> bound %d artifact link(s) from the relayed index", pkg, n)
			}
		}
	} else if p.cfg.Ecosystem == "pypi" {
		// Thread the AUTHORITATIVE package name — the same PackageNameFromPath the
		// index request resolved and evaluated — into the artifact URL as a path
		// segment: /_files/<pkg>/…. proxyToFiles peels it back off and gates the byte
		// fetch on THAT name, so the per-file verdict can never drift from the index
		// verdict, and we never have to parse the name out of an ambiguous wheel/sdist
		// filename (a mis-parse would evaluate the wrong package and silently bypass
		// the gate). Percent-encoded so a name with URL metacharacters stays one segment.
		pkg := p.firewall.PackageNameFromPath(r.URL.Path)
		from = strings.TrimRight(p.cfg.FilesUpstream, "/") + "/"
		to = public + "/_files/" + url.PathEscape(pkg) + "/"
		if p.pypiFilesSignRe != nil && pkg != "" {
			// Signing on (#72): each artifact link gets its own signature, so the swap
			// cannot be a single prefix replacement. Done here, which leaves the generic
			// ReplaceAll below with nothing left to find — it becomes a no-op rather than
			// a second, conflicting rewrite.
			body = p.pypiFilesSignRe.ReplaceAllFunc(body, func(match []byte) []byte {
				sub := p.pypiFilesSignRe.FindSubmatch(match)
				if sub == nil {
					return match // cannot happen; leave the index untouched if it does
				}
				tail := string(sub[1])
				// Sign the PATH only: proxyToFiles derives the object path from
				// EscapedPath, which carries no query, so signing more than this would
				// produce a signature the byte fetch could never reproduce.
				objectPath := "/" + tail
				if i := strings.IndexByte(tail, '?'); i >= 0 {
					objectPath = "/" + tail[:i]
				}
				return []byte(appendSignature(to+tail, p.signer.Sign(p.cfg.Ecosystem, pkg, objectPath)))
			})
		}
	} else {
		from = strings.TrimRight(p.cfg.UpstreamRegistry, "/") + "/"
		to = public + "/"
		// npm: send the ARTIFACT links through "/_tarball/<pkg>/" first, threading in
		// the authoritative package name — the same one this metadata request just
		// evaluated — so the byte fetch re-gates on that identity (proxyArtifactBytes, issue
		// #11), exactly as PyPI's /_files/ does. Only "tarball" values are touched: a
		// whole-body prefix swap would also capture any non-artifact upstream URL in
		// the document and route it through the byte gate as if it were an artifact.
		// The remaining URLs still get the plain host swap on the line below.
		//
		// Skipped in "off" mode, so that mode is byte-for-byte the pre-#11 behavior.
		// (Turning it off later does not strand lockfiles minted while it was on —
		// npmArtifactPath still recognizes /_tarball/ URLs and relays them.)
		if p.npmTarballRe != nil && byteGateMode(p.cfg.ByteGate) != byteGateOff {
			if pkg := p.firewall.PackageNameFromPath(r.URL.Path); pkg != "" {
				mintPrefix := public + npmTarballPrefix + url.PathEscape(pkg) + "/"
				switch {
				case p.npmTarballSignRe != nil:
					// Signing on (#72): each tarball URL gets its OWN signature, so the
					// rewrite can no longer be a single prefix swap — the signature
					// covers the object path, which differs per release.
					body = p.npmTarballSignRe.ReplaceAllFunc(body, func(match []byte) []byte {
						sub := p.npmTarballSignRe.FindSubmatch(match)
						if sub == nil {
							return match // cannot happen; leave the document untouched if it does
						}
						tail := string(sub[1])
						// Sign the PATH only. npmArtifactPath derives the object path from
						// EscapedPath, which excludes the query, so signing anything more
						// would produce a signature the byte fetch could never reproduce.
						// The leading slash matches what that function returns.
						objectPath := "/" + tail
						if i := strings.IndexByte(tail, '?'); i >= 0 {
							objectPath = "/" + tail[:i]
						}
						sig := p.signer.Sign(p.cfg.Ecosystem, pkg, objectPath)
						return []byte(`"tarball":"` + appendSignature(mintPrefix+tail, sig) + `"`)
					})
				default:
					// ReplaceAllLiteral, not ReplaceAll: the replacement carries a package
					// name, and ReplaceAll would expand a "$" inside it as a capture
					// reference and silently mangle the URL.
					body = p.npmTarballRe.ReplaceAllLiteral(body, []byte(`"tarball":"`+mintPrefix))
				}
			}
		}
	}
	if from != "" {
		body = bytes.ReplaceAll(body, []byte(from), []byte(to))
	}

	// On a block, mark every release yanked-with-reason so pip deprioritizes them
	// and prints the reason, rather than us 403ing (which pip backtracks around).
	// Otherwise (the allow path), filter the index per entry: entries outside the
	// configured age window are yanked with an age reason, so a resolver backtrack —
	// from ANY cause — cannot land on an ancient CVE-laden release, and entries named
	// by a version-pinned known-malware advisory are yanked too (#103). On a block both
	// are moot: everything is already yanked with the stronger reason.
	contentType := upstreamResp.Header.Get("Content-Type")
	// 🚨 The malware clause is NOT optional here. This condition used to test only the
	// age bounds, which both default to 0 — so with the shipped defaults the whole pass
	// never ran, and a version-pinned advisory would have been enforced ONLY on
	// deployments that had separately turned on a cooldown. That failure is invisible:
	// the gate loads the advisory, reports it as enforced, and serves the file.
	indexFilterNeeded := p.cfg.MaxReleaseAgeDays > 0 || p.cfg.MinReleaseAgeDays > 0 ||
		(p.firewall.malwareFeed() != nil && pinnedEnforcedIn(p.cfg.Ecosystem)) ||
		// A version-scoped deny entry is a third reason to filter (#155). Without this
		// clause the entry is parsed and never consulted on a gate with no feed and no
		// window -- exactly #103's defect, which is why the predicate says so out loud.
		p.firewall.deny().anyVersionScoped()
	if yankReason != "" {
		body = yankIndex(body, contentType, yankReason)
	} else if p.cfg.Ecosystem == "npm" && (p.firewall.malwareFeed() != nil || p.releaseWindow(time.Now()).active() ||
		p.firewall.deny().anyVersionScoped()) {
		// npm's version-level soft block (#35, and the npm halves of #103 and #26):
		// versions a pinned advisory or the release window refuses leave the packument
		// and dist-tags are reconciled, so npm resolves to the next compliant release
		// instead of failing the install. A refusal
		// comes back only when nothing compliant remains, or the request named the
		// refused version itself — and it is a 403 with a reason, not an empty
		// document. Upstream's headers are dropped before the refusal is written so
		// its ETag or Cache-Control cannot be attached to our answer.
		if pkg := p.firewall.PackageNameFromPath(r.URL.Path); pkg != "" {
			filtered, d := p.npmFilterPackumentForRelay(r, body, pkg)
			if d != nil {
				log.Printf("%s %s %s -> allowed=false (%s)", r.Method, npmRefusalToken(*d), pkg, d.Reason)
				overruleVerdict(r, *d) // the audit record says refused, not the allow Evaluate gave
				serveUnfiltered := func() { p.finishRewritten(w, body, id, srcIP, upstreamBytes) }
				if !p.cfg.reporting() {
					for k := range w.Header() {
						w.Header().Del(k)
					}
				}
				p.refuseDecision(w, pkg, *d, serveUnfiltered)
				return
			}
			body = filtered
		}
	} else if p.cfg.Ecosystem == "pypi" && indexFilterNeeded {
		filtered, err := p.applyAgeWindow(body, contentType, r)
		if err != nil {
			// The floor is ON and we could not apply it (D100). Serving the index now
			// would silently drop the protection the operator explicitly opted into,
			// and the trigger is attacker-choosable: degrade this one endpoint and the
			// guard switches off while everything else looks normal.
			//
			// We refuse, and we say why. The refusal is expressed as a yank of EVERY
			// entry rather than a 403 on the index, because that is how this path
			// already blocks (see yankReason above): pip backtracks around a 403 on an
			// index but reads a yank reason out loud, and backtracking is precisely the
			// behavior the age floor exists to stop. Per D102 this is a block state, not
			// a 503 — nothing here is a server failure.
			log.Printf("age floor: upload times for %q unavailable, blocking rather than serving an unfiltered index: %v",
				p.firewall.PackageNameFromPath(r.URL.Path), err)
			body = yankIndex(body, contentType, "cannot verify release age right now: "+err.Error())
		} else {
			body = filtered
		}
	}

	p.finishRewritten(w, body, id, srcIP, upstreamBytes)
}

// finishRewritten writes a rewritten metadata body: the tail of relayRewritten, split
// out so a refusal decided AFTER the rewrite (the npm version filter) can still serve
// the unfiltered document under FW_MODE=report through the same code.
func (p *proxyServer) finishRewritten(w http.ResponseWriter, body []byte, id flowID, srcIP string, upstreamBytes int64) {
	// The body changed size, and Go's transport already stripped
	// Content-Encoding when it transparently decompressed — reset the length.
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	n, _ := w.Write(body)
	p.flow.recordRelayBytes(id, srcIP, upstreamBytes, int64(n))
}

// yankIndex marks every release in a PyPI /simple/ index as PEP 592 "yanked" with
// the given reason, so pip won't pick one during normal resolution and prints the
// reason. It handles both index shapes:
//   - JSON (PEP 691): set "yanked": "<reason>" on each file entry. Parsed into a
//     generic map so unknown fields (hashes, requires-python, upload-time) survive.
//   - HTML (PEP 503): inject a data-yanked="<reason>" attribute into each <a> tag
//     (the only anchors on a simple page are the file links). The reason is
//     HTML-escaped for safe placement inside the double-quoted attribute value.
//
// On any parse failure the body is returned unchanged (still host-rewritten, still a
// block via the reason header) rather than corrupting the index.
func yankIndex(body []byte, contentType, reason string) []byte {
	if strings.Contains(contentType, "json") {
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			return body
		}
		files, ok := doc["files"].([]any)
		if !ok {
			return body
		}
		for _, f := range files {
			if fm, ok := f.(map[string]any); ok {
				fm["yanked"] = reason
			}
		}
		if out, err := json.Marshal(doc); err == nil {
			return out
		}
		return body
	}
	// HTML PEP 503: `<a href=...>` -> `<a data-yanked="reason" href=...>`.
	inject := []byte(`<a data-yanked="` + html.EscapeString(reason) + `" `)
	return bytes.ReplaceAll(body, []byte("<a "), inject)
}

// applyAgeWindow yanks index entries outside the configured publication window --
// too old (the D22 staleness floor) or too new (the #26 cooldown), or both at once
// (D22). Dates come from the /pypi/<pkg>/json metadata API — deliberately NOT from
// the index itself, because the PEP 503 HTML shape carries no dates at all and a
// floor that old clients silently bypass isn't a floor.
//
// It FAILS CLOSED on a metadata fetch failure, returning an error for the caller to
// turn into a block (D100, issue #70). This reverses the original fail-open, whose
// reasoning — "the floor is CVE hygiene, not the malware gate, so a hiccup shouldn't
// break every install" — was sound about ACCIDENTS and silent about ADVERSARIES: the
// trigger is one endpoint an attacker can choose to degrade, and degrading it turned
// the guard off with nothing but a log line to show for it. The floor is opt-in, so
// the operators it affects are exactly the ones who asked for it.
func (p *proxyServer) applyAgeWindow(body []byte, contentType string, r *http.Request) ([]byte, error) {
	pkg := p.firewall.PackageNameFromPath(r.URL.Path)
	if pkg == "" {
		// No package identity to look up times for. Not an age-floor failure: this
		// isn't a per-package index, so there are no release entries to filter.
		return body, nil
	}
	times, versions, err := p.fetchUploadTimes(pkg)
	if err != nil {
		return nil, err
	}
	w := p.releaseWindow(time.Now())
	// Version-pinned known-malware advisories ride the SAME pass (#103). Not a second
	// filter: the existing comment on ageWindow explains why two independent passes
	// drift — each would have to decide the unknown case, the two answers diverge, and
	// an entry yanked by either looks identical to the developer. One pass, one place
	// where "we could not tell" is decided.
	var mw malwarePin
	if feed := p.firewall.malwareFeed(); feed != nil && pinnedEnforcedIn(p.cfg.Ecosystem) {
		mw = malwarePin{list: feed, allow: p.firewall.allow(), ecosystem: p.cfg.Ecosystem, pkg: pkg, versions: versions}
	}
	// The operator's version-scoped deny rides the SAME pass (#155), for the reason the
	// comment above gives about the feed: two independent passes would each have to decide
	// the unknown case, and an entry yanked by either looks identical to the developer.
	op := operatorPin{deny: p.firewall.deny(), ecosystem: p.cfg.Ecosystem, pkg: pkg, versions: versions}
	return ageYankIndex(body, contentType, w, times, mw, op), nil
}

// malwarePin carries what the index filter needs to act on a version-pinned advisory:
// the loaded feed, the package being served, and PyPI's own filename -> version map.
// A zero value is inert, so ecosystems that do not enforce pinned advisories pass an
// empty struct and the filter behaves exactly as it did before #103.
type malwarePin struct {
	list      *malwareList
	allow     *operatorList // D312: an allow naming a release outranks the advisory for it
	ecosystem string
	pkg       string
	versions  map[string]string // filename -> version, from PyPI's releases map
}

// operatorPin is malwarePin's twin for the operator's own version-scoped deny entries
// (#155). A separate type rather than a field on malwarePin, because the two must not be
// merged: they are different facts about the world, they are actioned by different people,
// and the developer reads the reason (D193, and the design note in operatorlist.go).
type operatorPin struct {
	deny      *operatorList
	ecosystem string
	pkg       string
	versions  map[string]string // filename -> version, from PyPI's releases map
}

// yankFor returns the reason to refuse this file, or "" to leave it alone.
func (o operatorPin) yankFor(filename string) string {
	if !o.deny.hasAnyVersion(o.ecosystem, o.pkg) {
		return ""
	}
	v, known := o.versions[filename]
	if !known {
		// FAIL CLOSED, but only where there is something to miss -- malwarePin's posture,
		// for the same reason: an entry that stops applying because a join broke is a deny
		// that silently stops denying.
		return "on this organisation's deny list: it names specific versions and this file's version could not be determined"
	}
	if o.deny.hasVersion(o.ecosystem, o.pkg, v) {
		return "on this organisation's deny list (version " + v + "); other versions are not affected"
	}
	return ""
}

// yankFor returns the reason to refuse this file, or "" to leave it alone.
func (m malwarePin) yankFor(filename string) string {
	if m.list == nil {
		return ""
	}
	v, known := m.versions[filename]
	if !known {
		// FAIL CLOSED, but only where there is something to miss. If the package
		// carries no version-pinned advisory there is nothing this join could hide, and
		// yanking would deny a clean package for no reason. If it does carry one, an
		// attacker who can break the filename->version join gets exactly the release
		// the advisory names. Same posture as unknown age (D100, #70).
		if m.list.hasPinned(m.ecosystem, m.pkg) {
			return "known-malware advisory names specific versions and this file's version could not be determined"
		}
		return ""
	}
	if e, found := m.list.pinnedFor(m.ecosystem, m.pkg, v); found {
		// D312: an allow entry naming this release outranks the advisory, so the file is
		// left unyanked and its bytes are served by the file gate's own check.
		if m.allow.hasVersion(m.ecosystem, m.pkg, v) {
			return ""
		}
		return "known malware: " + e.ID
	}
	return ""
}

// fetchUploadTimes reads the /pypi/<pkg>/json metadata document and returns each
// released file's upload time, keyed by filename — the join key between the
// metadata API and the /simple/ index entries. (LookupRepo fetches this same
// document for the repo link; sharing that fetch is a later optimization — the
// repo cache means it often isn't fetched at decision time at all.)
func (p *proxyServer) fetchUploadTimes(pkg string) (map[string]time.Time, map[string]string, error) {
	metaURL := fmt.Sprintf("%s/pypi/%s/json", strings.TrimRight(p.cfg.UpstreamRegistry, "/"), url.PathEscape(pkg))
	resp, err := p.client.Get(metaURL)
	if err != nil {
		return nil, nil, err
	}
	defer closeDrained(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("metadata returned status %d", resp.StatusCode)
	}
	var doc struct {
		Releases map[string][]struct {
			Filename   string `json:"filename"`
			UploadTime string `json:"upload_time_iso_8601"`
		} `json:"releases"`
	}
	if err := decodeCapped(resp.Body, metaRewriteMaxBytes, &doc); err != nil {
		return nil, nil, err
	}
	times := make(map[string]time.Time)
	versions := make(map[string]string)
	for version, files := range doc.Releases {
		for _, f := range files {
			if t, err := time.Parse(time.RFC3339, f.UploadTime); err == nil {
				times[f.Filename] = t
			}
			// The version comes from the RELEASES MAP KEY, i.e. from PyPI itself —
			// never parsed out of the filename. Filename parsing would be a second,
			// weaker source of truth for the same fact, and getting it wrong is a
			// SILENT miss: the file is served and looks clean (#103).
			versions[f.Filename] = version
		}
	}
	return times, versions, nil
}

// pep503Anchor matches one file link on a PEP 503 HTML index page; submatch 1 is
// the attribute region, submatch 2 the inner text (which pypi.org sets to the
// filename — the join key against the metadata API's upload times).
var pep503Anchor = regexp.MustCompile(`<a ([^>]*)>([^<]+)</a>`)

// ageYankIndex yanks every index entry uploaded before cutoff, in either index
// shape. Entries the upstream ALREADY yanked keep their original reason — a real
// upstream yank (security pull, bad build) outranks our policy annotation.
//
// An entry whose upload time we do NOT know is yanked too (D100, issue #70). The
// join key between the index and the metadata API is the filename, so "unknown age"
// is reachable by an attacker who can make that join miss — and the fail-open that
// used to live here would have handed back exactly the ancient release the floor
// exists to withhold. Unknown age is not evidence of youth.
// ageWindow is the allowed publication window for an index entry. Both bounds are
// optional and they COMPOSE: an operator may legitimately want "nothing older than a
// year and nothing newer than a week". A zero cutoff means that bound is off.
//
// One type rather than two passes on purpose. Two independent filters would each have
// to decide the unknown-age case, and the two answers would drift -- and the drift
// would be invisible, because an entry yanked by either pass looks identical to the
// developer.
// releaseWindow is the operator's release window at `now` — the age floor
// (FW_MAX_RELEASE_AGE_DAYS, D22) and the cooldown (FW_MIN_RELEASE_AGE_DAYS, #26) — built
// once here so PyPI's index filter and npm's packument filter cannot drift on what the
// knobs mean or how they read.
func (p *proxyServer) releaseWindow(now time.Time) ageWindow {
	var w ageWindow
	if p.cfg.MaxReleaseAgeDays > 0 {
		w.tooOldBefore = now.AddDate(0, 0, -p.cfg.MaxReleaseAgeDays)
		w.tooOldReason = fmt.Sprintf("release older than the configured age floor (%d days)", p.cfg.MaxReleaseAgeDays)
	}
	if p.cfg.MinReleaseAgeDays > 0 {
		w.tooNewAfter = now.AddDate(0, 0, -p.cfg.MinReleaseAgeDays)
		w.tooNewReason = fmt.Sprintf("release is within the %d-day cooldown and has not been held long enough to be reported", p.cfg.MinReleaseAgeDays)
	}
	return w
}

// releaseWindowOnPath applies the operator's release window to an ecosystem that
// carries the version on the request path (Maven, #26). Reports blocked=false when no
// bound is configured, when the ecosystem cannot date a release, or when the release
// is inside the window.
//
// Ordered so the common case costs nothing: the window is checked for being active
// BEFORE the ecosystem is asked for a time, because both bounds default to 0 and the
// probe is a network round trip. A deployment that has not turned the window on must
// not pay for it.
func (p *proxyServer) releaseWindowOnPath(pkgName, path string) (Decision, bool) {
	w := p.releaseWindow(time.Now())
	if !w.active() {
		return Decision{}, false
	}
	rd, ok := p.firewall.eco.(releaseDated)
	if !ok {
		return Decision{}, false
	}
	t, known, err := rd.mavenReleaseTime(p.firewall.client, path)
	if err != nil {
		// Transient by construction: mavenReleaseTime only returns an error for an
		// upstream that did not answer or answered 429/5xx. Surfaced as Unavailable so
		// the caller uses D102's non-verdict path -- an outage must never read as
		// "this release is too new", which the developer would wait out forever.
		//
		// The error itself is LOGGED, not put on the wire: it wraps the upstream URL,
		// and the client-facing reason is the one surface the adversarial suite holds
		// to the disclosure rule (D182).
		log.Printf("release-window: age probe failed for %s: %v", pkgName, err)
		return Decision{
			Allowed:     false,
			Unavailable: true,
			Deny:        denyNone,
			Rule:        "release-window:age-unavailable",
			Source:      sourceReleaseWindow,
			Reason: fmt.Sprintf("could not determine when this release of %q was published, "+
				"so the configured release window could not be applied", pkgName),
		}, true
	}
	reason := w.reasonFor(t, known)
	if reason == "" {
		return Decision{}, false
	}
	return Decision{
		Allowed: false,
		Deny:    denyReleaseWindow,
		Rule:    "release-window",
		Source:  sourceReleaseWindow,
		Reason:  fmt.Sprintf("%s: %s", pkgName, reason),
	}, true
}

type ageWindow struct {
	tooOldBefore time.Time // yank entries uploaded BEFORE this (staleness floor, D22)
	tooOldReason string
	tooNewAfter  time.Time // yank entries uploaded AFTER this (cooldown, #26)
	tooNewReason string
}

func (w ageWindow) active() bool { return !w.tooOldBefore.IsZero() || !w.tooNewAfter.IsZero() }

// reasonFor is THE release-window decision: given a release time and whether we could
// determine it at all, why (if at all) must this release be refused? Returns "" to
// allow.
//
// Extracted from ageYankIndex's closure when Maven gained the window (#26) so the two
// call sites cannot drift. That is the same argument releaseWindow itself records for
// existing — "so PyPI's index filter and npm's packument filter cannot drift on what
// the knobs mean or how they read" — and it now has a third caller whose refusal is a
// 403 rather than a yank, which is exactly the situation where two copies would quietly
// diverge on the unknown-age case.
//
// Unknown age FAILS CLOSED whenever a bound is active: an entry we cannot date is
// exactly the one an attacker would arrange for us not to be able to date (D100).
func (w ageWindow) reasonFor(t time.Time, known bool) string {
	switch {
	case !known:
		if w.active() {
			return "release age could not be verified (no upload time for this file)"
		}
		return ""
	case !w.tooOldBefore.IsZero() && t.Before(w.tooOldBefore):
		return w.tooOldReason
	case !w.tooNewAfter.IsZero() && t.After(w.tooNewAfter):
		return w.tooNewReason
	default:
		return ""
	}
}

// perFileRefuser is a verdict that can refuse ONE file of a package by name. malwarePin
// and operatorPin both satisfy it.
//
// The extra refusers are VARIADIC so the thirteen existing call sites -- which describe the
// age-window and advisory contract and should keep saying exactly that -- are untouched by
// the addition. The operator's own entries are proven through the proxy instead, which is
// where #103's lesson says a filter must be proven anyway: one that is correct and never
// invoked is indistinguishable at runtime from one that is absent.
type perFileRefuser interface {
	yankFor(filename string) string
}

func ageYankIndex(body []byte, contentType string, w ageWindow, times map[string]time.Time, mw malwarePin, extra ...perFileRefuser) []byte {
	// Returns the reason to yank with, or "" to leave the entry alone. Unknown age,
	// known-too-old and known-too-new are three different facts, and the reason string
	// is what the developer actually reads, so they must not be conflated.
	yankFor := func(filename string) string {
		// The malware verdict is checked FIRST and independently of the age window: a
		// known-malware advisory is a fact about the artifact, not a policy dial, so it
		// must apply even when no age bound is configured at all.
		if r := mw.yankFor(filename); r != "" {
			return r
		}
		for _, x := range extra {
			if r := x.yankFor(filename); r != "" {
				return r
			}
		}
		t, ok := times[filename]
		return w.reasonFor(t, ok)
	}
	if strings.Contains(contentType, "json") {
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			return body
		}
		files, ok := doc["files"].([]any)
		if !ok {
			return body
		}
		for _, f := range files {
			fm, ok := f.(map[string]any)
			if !ok {
				continue
			}
			name, _ := fm["filename"].(string)
			if alreadyYanked, isStr := fm["yanked"].(string); isStr && alreadyYanked != "" {
				continue // upstream's own yank reason outranks the floor
			}
			if yr := yankFor(name); yr != "" {
				fm["yanked"] = yr
			}
		}
		if out, err := json.Marshal(doc); err == nil {
			return out
		}
		return body
	}
	// HTML PEP 503: inject data-yanked only into anchors whose inner text (the
	// filename) is older than the cutoff and not already yanked by upstream.
	return pep503Anchor.ReplaceAllFunc(body, func(m []byte) []byte {
		sub := pep503Anchor.FindSubmatch(m)
		if sub == nil || bytes.Contains(sub[1], []byte("data-yanked")) {
			return m
		}
		yr := yankFor(string(sub[2]))
		if yr == "" {
			return m
		}
		inject := `data-yanked="` + html.EscapeString(yr) + `" `
		return append([]byte("<a "+inject), m[len("<a "):]...)
	})
}
