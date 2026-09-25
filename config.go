package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config holds everything the service needs to run. Per the architecture,
// nothing is hardcoded — every value is read from the environment at startup.
// In Kubernetes these come from ConfigMaps/Secrets; on your laptop they come
// from environment variables you set before running. This struct will grow as
// we add layers (upstream registry, score threshold, etc.).
type Config struct {
	// ListenAddr is the address:port this service listens on (e.g. ":8080").
	ListenAddr string

	// Ecosystem selects which package ecosystem this instance gates: "npm" or
	// "pypi". One process serves one ecosystem (clients point at distinct URLs
	// anyway), so the same binary runs as an npm firewall or a PyPI firewall
	// depending only on this injected value.
	Ecosystem string

	// UpstreamRegistry is the real registry we proxy allowed requests to. Its
	// default tracks the chosen Ecosystem so the two can't be mismatched.
	UpstreamRegistry string

	// UnscorablePolicy decides what happens when we CANNOT get a score
	// (no repo link, repo not found, scorecard failed). This is the common
	// "messy metadata" case. Valid values: "allow", "block".
	UnscorablePolicy string

	// ScoreThreshold is the minimum OpenSSF Scorecard score (0.0–10.0) a
	// package's repo must have to be ALLOWED. Below this, it is BLOCKED.
	ScoreThreshold float64

	// ScorecardMode controls how we obtain a score:
	//   "stub"  - return a fixed score (for local dev without network/scorecard)
	//   "api"   - read the precomputed score from Google's deps.dev API
	//   "local" - scan on demand via the scheduler, which launches a run-once
	//             scorecard container per scan (covers repos deps.dev hasn't
	//             scored); requires ScannerURL
	ScorecardMode string

	// ScorecardRequiredChecks is the D271 coverage floor for a PARTIAL Scorecard
	// report (#133): a comma-separated list of Scorecard check names, every one of
	// which must have scored for a partial report to be compared to ScoreThreshold.
	// Empty selects the default (Scorecard's own Critical- and High-risk checks);
	// "none" disables the floor. Only meaningful in "local" mode, the one that runs
	// Scorecard itself.
	ScorecardRequiredChecks string

	// ScannerURL is the base URL of the scheduler service (which runs a scan on
	// demand), used only when ScorecardMode is "local". Empty otherwise. Named
	// FW_SCANNER_URL for continuity; per D16 it now points at the scheduler.
	ScannerURL string

	// ApprovalURL is the base URL of the (optional) approval service. When set,
	// the firewall consults it for human decisions on unscorable packages before
	// applying UnscorablePolicy. Empty = approval integration disabled.
	ApprovalURL string

	// FlowFlushInterval is both the capacity flush cadence and the bucket width.
	FlowFlushInterval time.Duration

	// ScoreCacheTTL is how long a fetched Scorecard score is cached in memory
	// (keyed by repo) to avoid re-scoring the same repo on every request within a
	// single install — the L1 fan-out guard (D18). 0 disables caching.
	// Stale-but-bounded: a score that changes mid-TTL isn't re-read until the
	// entry expires. The package->repo metadata cache uses the same TTL.
	ScoreCacheTTL time.Duration

	// ScoreCacheMaxEntries caps how many entries EACH L1 cache (scores, repos) holds
	// (issue #61). A TTL alone is not a bound: cardinality is the number of distinct
	// packages/repos this process ever proxies, which grows without limit in a
	// long-lived service as build agents pull the long tail of transitive deps.
	//
	// One knob for both caches rather than two, per the config-surface budget (#51):
	// they are filled by the same traffic in roughly the same proportion, and an
	// operator who needs to tune them separately has a more specific problem than this
	// default is for. Entries are tiny and near-uniform (a float64 or a short repo
	// string plus an expiry), so a COUNT is a true bound here — unlike the response
	// cache, whose entries are HTTP bodies and therefore need a byte budget.
	//
	// 0 (or unset) applies the built-in default rather than disabling or unbounding the
	// cache. To turn L1 caching OFF, set FW_SCORE_CACHE_TTL=0 — that knob already exists
	// and keeping one spelling for "off" avoids two ways to say the same thing. See
	// ttlLRU.enabled for why a zero cap must not mean "cache nothing": it would silently
	// disable the cache in every hand-built Config that predates this field.
	ScoreCacheMaxEntries int

	// ScoreL2TTL is the freshness window for the DURABLE L2 score cache (the
	// approval-DB `scores` row, D18). Distinct from ScoreCacheTTL, which bounds only
	// the per-replica in-memory L1: L2 survives restarts and is shared across
	// replicas, so without its own expiry a score is remembered forever — an
	// unexpirable trust cache (issue #12). When an L2 row is older than this window
	// the firewall treats the repo as COLD: it launches a background re-scan and
	// quarantines the pull (pending) exactly as a never-scanned repo would, rather
	// than serving the stale score. 0 = never stale (the prior, non-regressing
	// behavior), an explicit opt-out of freshness.
	ScoreL2TTL time.Duration

	// PublicURL is the externally reachable base URL of THIS proxy (e.g.
	// "https://npm.firewall.internal"), used when rewriting upstream-registry
	// URLs inside npm metadata responses so tarball fetches come back through
	// the firewall. Empty = derive from each request's Host header, which is
	// correct for plain-HTTP setups; TLS-fronted deployments must set it.
	PublicURL string

	// URLSigningKey turns on SIGNED ARTIFACT URLS (issue #72, authorised by D103).
	//
	// When set, every artifact URL we mint carries an HMAC over its (ecosystem,
	// package, object path) tuple, and the byte fetch refuses a URL whose package
	// prefix and object path were not minted together. That closes the confused
	// deputy in #67 without the filename grammar D101 declined: a client can no
	// longer pair an allowed package's prefix with a blocked package's object path.
	//
	// OPT-IN. Empty (the default) means no signer and no behaviour
	// change — the default install must keep needing no secret at all, so the
	// absent-key case is a first-class supported configuration, not a degraded one.
	//
	// Injected, never generated: all replicas must share the key or one replica
	// could not verify a URL another minted. It is read once at startup and never
	// written, which is why it does not make the service stateful — D103's ruling
	// that "state means database", not "an injected secret".
	//
	// The signature is a BINDING, not an authorisation: it says we minted this
	// pair, never that the package was allowed. The verdict is still re-evaluated
	// on every byte fetch. See urlsign.go for why that distinction is what makes a
	// lockfile-recorded URL safe to replay, and why there is deliberately no expiry.
	URLSigningKey string

	// URLSigningKeyPrevious is accepted for VERIFICATION only, never for minting.
	//
	// Rotation needs it: signed URLs get recorded in lockfiles and replayed weeks
	// later by `npm ci`, so without a grace window every in-flight lockfile would
	// break the instant an operator rotated the key. Rotate by moving the old key
	// here, then drop it once those lockfiles have aged out.
	URLSigningKeyPrevious string

	// FilesUpstream is the host that serves PyPI artifact bytes
	// (files.pythonhosted.org) — DISTINCT from the metadata/index host
	// (FW_UPSTREAM defaults to pypi.org). Used only for the "pypi" ecosystem: a
	// later increment rewrites wheel/sdist URLs in the /simple/ index so those
	// fetches come back through this proxy under "/_files/…", and this is the
	// upstream those relayed fetches are sent to. Unused by other ecosystems.
	FilesUpstream string

	// PendingRetryAfterSeconds is how long (in seconds) we tell the developer to
	// wait on an async-local-mode "verdict pending" refusal (D18): a cold pull of an
	// unscored package is quarantined immediately while a background scan runs.
	//
	// It was a Retry-After header until D102 made these refusals 403s, which no
	// client retries — so the number now rides in the REASON TEXT instead. It is the
	// same figure for the same purpose, but it is read by a person rather than acted
	// on by a package manager, which is why it is worth keeping accurate: a cold
	// Scorecard scan takes ~20–80s, and a developer told to retry sooner will retry
	// into a scan that is not finished. Distinct env var so operators
	// can tune it to their scanner's real latency.
	PendingRetryAfterSeconds int

	// RateLimitBackoffTTL is how long a package stays "backed off" after a scoring
	// probe was rate-limited (HTTP 429) by an upstream (D25). While backed off,
	// pulls of that package short-circuit to a retryable 503 instead of re-running
	// the probe fan-out that amplifies the 429 storm. Seconds, not hours: it is a
	// burst circuit-breaker, never a verdict, so a real recovery is picked up fast.
	// 0 disables it (same convention as ScoreCacheTTL).
	RateLimitBackoffTTL time.Duration

	// UpstreamAuth is an Authorization header value sent on the firewall's OWN probe
	// requests to the upstream registry — and only that host (D25 item e). Anonymous
	// probes share the caller's IP rate ceiling, which a cold resolve's fan-out trips
	// (429); authenticating raises it (npm org token, Sonatype/Nexus Basic, …). It is
	// the FULL header value so any scheme works without us encoding credentials, e.g.
	//   FW_UPSTREAM_AUTH="Bearer npm_xxx"   or   FW_UPSTREAM_AUTH="Basic dXNlcjpwYXNz"
	// Empty = anonymous (default). A secret: injected via a Secret, never logged, and
	// scoped to the upstream host so it can't leak to deps.dev/the approval service.
	UpstreamAuth string

	// UpstreamAuthFile is a path to a file holding the same Authorization header value,
	// RE-READ as it changes so a rotated credential is picked up without a restart
	// (issue #53, D177). Mutually exclusive with UpstreamAuth; setting both is refused
	// at startup.
	//
	// This is what makes a SHORT-LIVED upstream credential usable. AWS CodeArtifact —
	// the first integration target under D177 — mints tokens that expire within hours,
	// and Chainguard's are "short-lived and will automatically refresh throughout the
	// day". A value captured once at startup expires with the process still running,
	// so the gate goes down mid-day with no code path at fault.
	//
	// A file rather than a command to run: Kubernetes projected service-account tokens
	// ARE files rotated in place, and Vault agent, a sidecar, or a cron running
	// `aws codeartifact get-authorization-token` all write one. So every refresh
	// mechanism is supported without this process executing anything.
	//
	// A failed or empty read keeps the LAST GOOD value rather than blanking the header
	// — see fileCredential in upstreamcred.go for why that matters more than it looks.
	UpstreamAuthFile string

	// TLS-INTERCEPTION MODE (D51: optional, sysadmin-deployed, OFF unless BOTH are set).
	//
	// InterceptListen is a second listener that accepts CONNECT, terminates the client's
	// TLS with a leaf minted from InterceptCAFile, and hands the plaintext request to the
	// same gate the cooperative path uses. InterceptCAFile is an ABSOLUTE path to a PEM
	// file holding a CA certificate that may sign certificates — in practice an
	// INTERMEDIATE issued by the customer's PKI, never the root (D105) — plus its private
	// key, plus any chain to present. npm-only in this increment (see loadConfig for
	// why), and the listener terminates TLS only for the hostname of FW_UPSTREAM, so it
	// adds no egress destination (docs/EGRESS.md, intercept.go).
	InterceptListen string
	InterceptCAFile string

	// VerifyRepo turns on the deps.dev package->source-repo cross-check (D33, extended
	// to local mode in D39): before scoring, the self-declared source repo (from
	// publisher-controlled metadata) is compared against deps.dev's own record for the
	// package, and a mismatch is treated as unscorable rather than scored on the
	// borrowed repo. On by default; FW_VERIFY_REPO=false restores the pre-D33 "score
	// whatever the metadata claims" behavior as an escape hatch if deps.dev's mapping
	// proves too noisy. Applies to BOTH api and local mode (in local mode it decides
	// which repo the background scan is launched against); a no-op in stub mode, which
	// is offline by design. See repoVerificationEnabled.
	VerifyRepo bool

	// UnverifiedPolicy decides what happens when the deps.dev cross-check (VerifyRepo)
	// cannot DURABLY confirm the package->repo link — deps.dev has no source-repo
	// mapping for the package (404 / no usable record), or its record definitively
	// contradicts the self-declared repo. Valid values:
	//
	//   "closed" (default)     — fail closed (D36 Ruling A, "real firewalls fail
	//                            closed"): the package does not pass on an unverified
	//                            repo. It still routes through the approval path, so a
	//                            human can approve it or correct the repo association,
	//                            but with no ruling it is BLOCKED.
	//   "open-with-visibility" — the pre-D36 behavior: proceed on the self-declared
	//                            repo, logged "unverified" (that log IS the visibility).
	//
	// Anything else reads as "closed" (see unverifiedFailsClosed), so a typo can never
	// silently open the gate; main.go warns about an unrecognized value at startup.
	//
	// DELIBERATELY INDEPENDENT of UnscorablePolicy. The two answer different questions:
	// UnscorablePolicy is "we have no score", UnverifiedPolicy is "we don't trust the
	// repo a score would come from". If unverified merely deferred to UnscorablePolicy,
	// a deployment running FW_UNSCORABLE_POLICY=allow would get NO protection from the
	// cross-check — the exact gap Ruling A closes.
	//
	// Governs DURABLE negatives ONLY. A deps.dev lookup ERROR (5xx / network / 429) is
	// TRANSIENT: under "closed" it yields a retryable 503 (the D17 taxonomy), never a
	// block, so a deps.dev outage cannot become a wall of blocked installs.
	UnverifiedPolicy string

	// MaxConnsPerHost bounds the TCP connections the firewall opens to any one host
	// (upstream registry, deps.dev, the approval service, the scheduler). It is a
	// deployment-shaped knob, not a tuning constant: the right ceiling depends on how
	// much concurrency the operator's L2/approval service and upstream can absorb, so
	// per CLAUDE.md it is injected, not compiled in.
	//
	// ZERO MEANS "USE defaultMaxConnsPerHost", not "unbounded" — deliberately, so the
	// zero value is the safe one. Same reasoning as DepsDevBase below: loadConfig
	// defaults this, but the many tests (and any future caller) that build a Config
	// literal without naming every field go through NewFirewall too, and a zero value
	// that meant "unbounded" would silently opt every one of them out of the pooling
	// this field exists to guarantee.
	//
	// A NEGATIVE value is the explicit unbounded escape hatch (the stdlib's own
	// semantics for Transport.MaxConnsPerHost), for an operator who would rather have
	// unlimited connections than any queueing. See pooledTransport for why the bound
	// exists and what it costs.
	MaxConnsPerHost int

	// DepsDevBase is the base URL of the deps.dev API used for BOTH api-mode scoring
	// and the repo cross-check (D33/D36). Defaults to the public https://api.deps.dev;
	// empty means "use the default", so nothing has to be set for normal operation.
	//
	// Overridable for two reasons, one operational and one about being able to prove
	// our own claims:
	//   - a deployment that cannot reach the public internet can point this at a
	//     mirror/proxy of the API without patching the binary;
	//   - a test can point the WHOLE api-mode path at a server it controls and count
	//     what the firewall actually asked upstream. Unit tests could already do this
	//     by setting the field directly, but an e2e run drives a real firewall
	//     CONTAINER, which has no such reach — its only interface is the environment.
	//     Without this knob the request-coalescing guarantee (issue #16) was provable
	//     in-process only; e2e/coalesce_test.go now measures it through a real client.
	DepsDevBase string

	// MaxReleaseAgeDays is the release-age floor (D22): index entries whose
	// upload date is older than this many days are served yanked-with-reason (PyPI)
	// or removed from the packument with dist-tags repointed (npm, #26/#35), so
	// the resolver — including pip's backtracking that used to silently downgrade
	// to ancient CVE-laden releases — cannot land on them, while an explicit pin
	// still works. 0 disables the floor (default); it is an operator-chosen policy,
	// per the project's "user specifies a date range". Maven and OCI: not yet (#26).
	MaxReleaseAgeDays int

	// MinReleaseAgeDays is the release COOLDOWN (#26): index entries uploaded more
	// recently than this many days are served yanked-with-reason (PyPI) or removed
	// from the packument (npm), so a resolver cannot land on a release that is too
	// new to have been reported yet. It is the
	// INVERSE of MaxReleaseAgeDays above, and the two compose into one window: an
	// operator may legitimately want "nothing older than a year and nothing newer
	// than a week".
	//
	// WHY THIS EXISTS AND WHAT IT IS WORTH. Three parties ship cooldown by default
	// (pnpm v11, npm client controls, Chainguard), so its absence is a visible gap.
	// Chainguard claim a 7-day cooldown "blocks 47% of malicious packages"; measured
	// on our own corpus that reproduces at 46.87% -- but only on the tier it applies
	// to (a real package with one poisoned release), measured on a labelled corpus of
	// known-malicious npm releases.
	//
	// THE CURVE, so whoever picks a default does not have to re-derive it:
	//     1d 30.50% | 3d 37.88% | 7d 46.87% | 14d 58.89% | 30d 69.76% | 90d 84.20%
	// 7 days is a round number, not the knee: ONE day already buys two-thirds of what
	// seven buys, for one-seventh of the delay, and 14d is the largest marginal gain
	// after day one (+12.02). Returns collapse past 60 days.
	//
	// DEFAULT IS 14 DAYS where the window can be enforced (npm, PyPI, Maven), and 0 on
	// OCI, which has no trustworthy release date (see defaultCooldownDays). Ruled by
	// on 2026-09-22 (D335) once the cost side was measured (D332, E108): over
	// 289,662 benign npm packages weighted by downloads, a 14-day hold serves a
	// release older than upstream's newest on 7.39% of fresh resolves and refuses the
	// install outright (every version held) on 0.036%. A lockfile install is never
	// held, since the window is index-only. Set 0 to turn it off.
	MinReleaseAgeDays int

	// MalwareListPath points at a newline-delimited feed of packages already publicly
	// reported as malicious (OSV / OpenSSF Malicious Packages). Empty = off.
	//
	// This is LAYER 1 of D172's three-layer model, and the reason it exists is that
	// laying our stack beside another product's showed ours in the wrong order: we ship
	// the fuzziest layer (Scorecard, which scores repository HYGIENE, and emits a
	// score for a REPO rather than a verdict on a VERSION) and omitted the sharpest
	// one — a precise, near-zero-false-positive lookup against data we already hold.
	//
	// It is a PATH, not a URL, on purpose. The feed ships with the deployment, so the
	// decision costs no egress and stays answerable during an upstream outage, under
	// rate limiting, and in an air-gap. The equivalent elsewhere is a service call;
	// here the zero-egress posture (D155) makes us faster rather than more limited.
	//
	// ⚠️ Do not oversell what a hit rate here means. Known-malware detection is
	// retrospective by construction — ~92% of public malicious-package datasets are
	// already our corpus and only 2.96% is novel — so this buys PRECISION and a
	// countable number, not differentiation.
	//
	// A CONFIGURED FEED THAT FAILS TO LOAD IS A STARTUP FAILURE, never a silent
	// downgrade to "no entries"; see loadMalwareList.
	MalwareListPath string

	// MalwareFeedKey is the Ed25519 public key, base64, that the snapshot at
	// MalwareListPath must be signed with. Empty = no verification, which is what
	// shipped before #157 and stays legal: refusing an unsigned feed would disarm
	// layer 1 for every deployment that has not yet re-generated one.
	//
	// When it IS set, the gate requires a detached signature beside the feed
	// (`<feed>.sig`) and refuses to load a snapshot that does not verify -- at every
	// re-read, not only at startup, because the whole point of re-reading is that the
	// bytes change afterwards. It also then requires the feed's header line, since a
	// signature alone cannot distinguish the CURRENT snapshot from a replayed one.
	//
	// The key is the OPERATOR's choice. Nothing here implies trusting us: a deployment
	// that builds its own feed with scripts/build-malware-feed.py signs it with its own
	// key, and the verification is the same.
	MalwareFeedKey string

	// MalwareFeedURL is where the gate PULLS the signed snapshot from, hourly, and
	// installs it at MalwareListPath once it verifies (#157, D294, D308). Empty = the
	// gate fetches nothing and the operator keeps the file current some other way,
	// which is what shipped before #157. There is deliberately NO default: every
	// address the gate dials comes from operator config (docs/EGRESS.md). Requires
	// MalwareFeedKey (an unsigned pull is refused at startup) and MalwareListPath (the
	// place it installs to, which the existing re-read then picks up).
	MalwareFeedURL string

	// AllowListPath / DenyListPath point at the OPERATOR's own lists: one package name
	// per line, '#' comments, absolute path (D193, issue #58).
	//
	// SEPARATE FROM MalwareListPath ON PURPOSE. That file is the published-advisory feed
	// (OSV / OpenSSF); these two are the operator's own judgements. D193 kept both --
	// 'keep the feed and allow an operator to add to the list' -- and a developer whose
	// install just failed has to be able to tell 'this is publicly reported as malware'
	// from 'my own org blocked this', because the two send them to different people.
	//
	// Empty means 'not configured', which is the shipped default for both: an operator
	// who sets neither gets exactly the pre-D193 behaviour, so the '0 required variables'
	// claim in docs/CONFIGURATION.md stays true.
	AllowListPath string
	DenyListPath  string

	// ByteGate decides whether npm ARTIFACT (tarball) fetches are re-evaluated
	// before their bytes are served, and what happens when that evaluation denies
	// (issue #11 / D49). It exists because the gate's "single control point at the
	// metadata request" model has a hole: `npm ci` (and pnpm/yarn installing from a
	// lockfile) fetches tarballs DIRECTLY by their recorded `resolved` URL and never
	// re-requests metadata — so a package blocked at metadata is still installable
	// byte-for-byte. Valid values:
	//
	//   "allow-but-log" (default) — every tarball fetch is evaluated and the verdict
	//                               LOGGED, but the bytes are always served. Visibility
	//                               without changing which installs succeed.
	//   "enforce"                 — the same evaluation, with the same four outcomes as
	//                               the metadata path (allow / block 403 / pending 503 /
	//                               unavailable 503). This is what actually CLOSES the
	//                               lockfile side-door.
	//   "off"                     — no evaluation and no artifact-URL rewriting: the
	//                               pre-#11 passthrough, kept as an escape hatch.
	//
	// Anything unrecognized reads as the default (see byteGateMode); main.go warns at
	// startup.
	//
	// IMPORTANT — what "allow-but-log" does and does not cover (D72). It is
	// visibility-first for the case it was aimed at, NOT a blanket pass:
	//   - a package denied on a POSITIVE FINDING (score below threshold, or a human
	//     denial) has its bytes REFUSED even here. Serving them was never the intent,
	//     and letting them through means the same package installs or fails depending
	//     only on whether the developer ran `npm install` or `npm ci`.
	//   - a package denied for an ABSENCE OF TRUST (unscorable, unverifiable) is served
	//     and logged, because that fires on plenty of legitimate packages with thin
	//     metadata and silently breaking those CI builds is the exact harm the
	//     visibility-first default exists to avoid.
	// "enforce" additionally blocks that second class plus the two retryable outcomes;
	// "off" is the only setting that serves a hard-denied package's bytes.
	//
	// npm only for now. PyPI has had this gate since D22 (the /_files relay this
	// mirrors); OCI blobs are deliberately deferred — see docs/BUILD_LOG.md.
	ByteGate string

	// Mode decides whether a verdict is ENFORCED or merely REPORTED (P1 #35).
	//
	// WHY IT EXISTS. The single biggest objection to adopting a package firewall is that
	// nobody switches a blocking gate on in front of their build system cold — a false
	// positive is a stopped production deploy, and no operator will take that risk on our
	// say-so. "report" answers it by making our false-positive rate MEASURABLE instead of
	// asserted: run it for a week against real traffic and read what it WOULD have done.
	//
	//   "enforce" (default) — a refusal is a refusal. The shipped behaviour.
	//   "report"            — every verdict is computed and recorded exactly as in
	//                         enforce, and then NOTHING is refused: the request is
	//                         relayed and the counterfactual is logged.
	//
	// WHAT IT SUPPRESSES, AND THE ONE THING IT DOES NOT. "report" suppresses every
	// POLICY VERDICT — the score threshold, the malware feed, the operator deny list,
	// unscorable and unverified packages, unrecognised request paths, and both retryable
	// outcomes. It deliberately does NOT suppress a REQUEST-INTEGRITY refusal: an
	// artifact path or filename that does not address the package being judged, or an
	// invalid artifact-URL signature.
	//
	// That exception is the whole reason this is safe. Those three checks are not
	// judgements about a package — they are the gate refusing to serve a request whose
	// two halves disagree, which is the confused-deputy shape of #67. Relaying them
	// "because nothing is enforced in report mode" would mean report mode INTRODUCES a
	// vulnerability that enforce mode does not have, turning an observability setting
	// into a bypass. An operator evaluating us must never be less safe than one enforcing.
	//
	// Within policy verdicts the contract is all-or-nothing on purpose: a mode that
	// suppressed only some of them would let an operator read "nothing is enforced" while
	// builds still failed. proxy.go's refusal sink is the one place that decides, and
	// TestEveryPolicyRefusalGoesThroughTheModeSink keeps it that way.
	//
	// It does NOT change what is DECIDED. The verdict, the reason, the audit record and
	// the queue entry are identical in both modes — that is the property that makes the
	// numbers you collect in report mode predictive of what enforce would do. Only the
	// response to the client differs.
	//
	// Unrecognized values are refused at startup (D19/!128), and the safe direction here
	// is enforce: a typo must never silently disable the gate.
	Mode string

	// UnknownPathPolicy decides what happens to a request the gate cannot name a
	// package for AND cannot justify as registry infrastructure (issue #58, D76).
	//
	// This knob is the one place the epic's default inversion is configurable.
	// Before it, such a request was relayed UNGATED with no decision recorded —
	// the property behind #11, #56, #57 and #59, each of which was an alternate
	// route to bytes that the gate simply never looked at. Now the request falls
	// through an ordered ruleset to an implicit terminal block.
	//
	//	"block"          (default, D76) — refuse it; nothing allowed it through
	//	"allow-but-log"  — relay, but log the exact path loudly. THE RAMP: the
	//	                   control-plane enumeration is a claim about four registry
	//	                   protocols, and if we got one wrong this is how an
	//	                   operator unbreaks their client and tells us which path
	//	                   we missed.
	//	"allow"          — the pre-#58 passthrough, kept as an escape hatch.
	//
	// An unrecognized value reads as "block", NOT as the most permissive option —
	// a typo here must not silently reopen the hole. See unknownPathPolicy.
	UnknownPathPolicy string

	// WritePolicy decides what happens to a request that would WRITE to the upstream
	// registry — a push, a publish, an upload, a delete (issue #66).
	//
	// Yellow Jack is a pull-through gate. Every question it asks is about consuming a
	// package: "does this package's source repo score well enough to be installed
	// here". Nothing in it implements, tests or reasons about publishing. Yet before
	// this knob, a write was simply relayed — and worse, EVALUATED as though it were a
	// read. `POST /v2/<name>/blobs/uploads/` parses as a blob path, so an upload was
	// handed to the byte gate and judged on the image's pull score; if that score
	// passed, the firewall forwarded the push upstream. A product positioned as a
	// pull-through firewall was silently acting as a push-through proxy.
	//
	// Found by the tier-3 pass on issue #58 and filed as #66. It is not a bypass of
	// the gate — it is a capability nobody chose to have, arriving through a parser
	// written for downloads.
	//
	//	"block"          (default) — refuse it with a reason naming the method.
	//	"allow-but-log"  — relay it, but log every write loudly. The ramp, for an
	//	                   operator who discovers they depend on publishing through us.
	//	"allow"          — the pre-#66 passthrough.
	//
	// An unrecognized value reads as "block", for the same reason FW_UNKNOWN_PATH_POLICY
	// does: this governs a request shape we never designed for, so a typo must not
	// silently restore it. See writePolicy.
	//
	// SCOPED TO THE OCI ECOSYSTEM TODAY, and that limit is deliberate rather than
	// unfinished-by-accident. The first implementation applied it everywhere, on the
	// reasoning that "we are a read-only gate" is a property of the product rather than
	// of a protocol. Two existing tests went red and were right: npm's control plane
	// mixes reads and writes on one surface. `npm audit` is
	// POST /-/npm/v1/security/advisories/bulk — a READ, expressed as POST because the
	// query body is large — and `npm login` is PUT /-/user/…, a write private-registry
	// users genuinely need. So for npm the method is not a sound read/write signal, and
	// choosing which registry operations Yellow Jack supports is a product decision
	// (issue #30 exists because another tool broke npm's control plane exactly this way).
	//
	// OCI has no such ambiguity: every read in the distribution spec is GET or HEAD and
	// every write is POST/PATCH/PUT/DELETE, which makes the method complete and exact
	// there. Extending this to npm/PyPI/Maven needs a ruling, not more code — see #66,
	// and TestNonOciWritesAreStillRelayed, which pins the current limit so it cannot
	// change silently.
	WritePolicy string

	// TrustedProxies is the comma-separated set of reverse-proxy / load-balancer
	// addresses whose X-Forwarded-For header the firewall will believe when recording
	// the source IP of a pull (#41). Each entry is a CIDR ("10.0.0.0/8") or a bare IP.
	// EMPTY (default) means "trust no proxy": the source IP is always the raw connecting
	// peer, which is correct for the default cooperative deployment where clients reach
	// the firewall directly. Set it only when the firewall genuinely sits behind a proxy
	// you control — believing XFF from an untrusted peer would let anyone forge the
	// recorded source (see clientIP).
	TrustedProxies string

	// UpstreamCABundle is an ABSOLUTE path to a PEM file of CA certificates that are
	// APPENDED to the system roots for every TLS connection the firewall MAKES (#137,
	// #39 class 7). Empty (default) = the platform's own roots and nothing else, which
	// is what shipped before it existed. Set it when an enterprise TLS-inspecting proxy
	// sits between this process and the registry — see upstreamtrust.go for what it
	// does and does not claim, and for the two things deliberately left out of it.
	UpstreamCABundle string

	// upstreamRoots and upstreamTrustLine are DERIVED, not read from the environment:
	// loadConfig resolves UpstreamCABundle once, so the bundle is parsed and refused
	// before the listener binds, and every later caller shares one pool. Unexported
	// because nothing outside this package may set them, and nil means "the platform's
	// roots" all the way down to the transport.
	upstreamRoots     *x509.CertPool
	upstreamTrustLine string
}

// loadConfig reads configuration from environment variables, applying sensible
// defaults so the service runs out of the box for local testing.
// loadConfig reads the injected environment into a Config, returning an error
// naming every FW_* value it had to reject (issue #19).
//
// The error is returned rather than logged so the CALLER decides what a bad config
// means. main.go treats it as fatal before the listener binds: a half-configured
// firewall that answers requests is worse than one that refuses to start, because
// the developer on the other end cannot tell a misconfigured gate from a strict one.
func loadConfig() (Config, error) {
	var c configErrors
	ecosystem := c.enum("FW_ECOSYSTEM", "npm", "npm", "pypi", "oci", "maven")
	cfg := Config{
		ListenAddr:       c.str("FW_LISTEN_ADDR", ":8080"),
		Ecosystem:        ecosystem,
		UpstreamRegistry: c.str("FW_UPSTREAM", defaultUpstream(ecosystem)),
		// Default fail-CLOSED (block): unscorable packages are blocked and queued
		// for human review via the approval service. Deliberate posture as of
		// Phase 3 — safe now that there is a remembered human-approval path.
		UnscorablePolicy:        c.enum("FW_UNSCORABLE_POLICY", "block", "block", "allow"),
		ScoreThreshold:          c.number("FW_SCORE_THRESHOLD", 5.0, 0, scoreThresholdMax),
		ScorecardMode:           c.enum("FW_SCORECARD_MODE", "stub", "stub", "api", "local", "off"),
		ScorecardRequiredChecks: c.str("FW_SCORECARD_REQUIRED_CHECKS", ""),
		ScannerURL:              c.str("FW_SCANNER_URL", ""),
		ApprovalURL:             c.str("FW_APPROVAL_URL", ""),
		// How often traffic counters are flushed to the control plane, and therefore
		// also the BUCKET WIDTH of the capacity data (#32 Phase C). One minute is the
		// resolution "why is the pipe saturated right now" needs while keeping the row
		// count bounded; 0 disables emission entirely (the recorder still counts
		// locally). The real resolution/cardinality tradeoff gets measured against the
		// mock enterprise env before this default is treated as settled (D69).
		FlowFlushInterval: c.duration("FW_FLOW_FLUSH_INTERVAL", time.Minute),
		ScoreCacheTTL:     c.duration("FW_SCORE_CACHE_TTL", time.Hour),
		// 10,000 entries per cache: roughly a megabyte each at ~100 B/entry, and far
		// more than one build's working set, so the cap is a safety ceiling rather
		// than something a normal workload runs into.
		ScoreCacheMaxEntries:     c.integer("FW_SCORE_CACHE_MAX_ENTRIES", 10000, 0),
		ScoreL2TTL:               c.duration("FW_SCORE_L2_TTL", 0),
		RateLimitBackoffTTL:      c.duration("FW_RATELIMIT_BACKOFF_TTL", 10*time.Second),
		PendingRetryAfterSeconds: c.integer("FW_PENDING_RETRY_AFTER", 60, 0),
		PublicURL:                c.str("FW_PUBLIC_URL", ""),
		URLSigningKey:            c.str("FW_URL_SIGNING_KEY", ""),
		URLSigningKeyPrevious:    c.str("FW_URL_SIGNING_KEY_PREVIOUS", ""),
		FilesUpstream:            c.str("FW_FILES_UPSTREAM", "https://files.pythonhosted.org"),
		UpstreamAuth:             c.str("FW_UPSTREAM_AUTH", ""),
		UpstreamAuthFile:         c.str("FW_UPSTREAM_AUTH_FILE", ""),
		UpstreamCABundle:         c.str("FW_UPSTREAM_CA_BUNDLE", ""),
		InterceptListen:          c.str("FW_INTERCEPT_LISTEN", ""),
		InterceptCAFile:          c.str("FW_INTERCEPT_CA_FILE", ""),
		VerifyRepo:               c.boolean("FW_VERIFY_REPO", true),
		// Default fail-CLOSED on a durably unverified repo (D36 Ruling A). This
		// CHANGES D33's shipped behavior, which degraded open on a missing deps.dev
		// record — the brand-new-package (fresh typosquat) borrow path.
		UnverifiedPolicy:  c.enum("FW_UNVERIFIED_POLICY", unverifiedPolicyClosed, unverifiedPolicyClosed, unverifiedPolicyOpen),
		DepsDevBase:       c.str("FW_DEPSDEV_BASE", depsDevBaseURL),
		MaxReleaseAgeDays: c.integer("FW_MAX_RELEASE_AGE_DAYS", 0, 0),
		MinReleaseAgeDays: c.integer("FW_MIN_RELEASE_AGE_DAYS", defaultCooldownDays(ecosystem), 0),
		MalwareListPath:   c.str("FW_MALWARE_LIST", ""),
		MalwareFeedKey:    c.str("FW_MALWARE_FEED_KEY", ""),
		MalwareFeedURL:    c.str("FW_MALWARE_FEED_URL", ""),
		AllowListPath:     c.str("FW_ALLOW_LIST", ""),
		DenyListPath:      c.str("FW_DENY_LIST", ""),
		MaxConnsPerHost:   c.integer("FW_MAX_CONNS_PER_HOST", defaultMaxConnsPerHost, 0),
		// Default VISIBILITY-first, enforcement opt-in (D49). See the field
		// comment for the consequence this default deliberately accepts.
		ByteGate: c.enum("FW_BYTE_GATE", byteGateAllowButLog, byteGateAllowButLog, byteGateEnforce, byteGateOff),
		Mode:     c.enum("FW_MODE", modeEnforce, modeEnforce, modeReport),
		// Default BLOCK (D76: "everything should default to block"). Unlike
		// FW_BYTE_GATE — which defaults to visibility-first because it fires on
		// legitimate packages with thin metadata — an unrecognised request PATH is
		// not a noisy-but-benign case: it is the shape four separate bypasses used.
		UnknownPathPolicy: c.enum("FW_UNKNOWN_PATH_POLICY", unknownPathBlock, unknownPathBlock, unknownPathAllowButLog, unknownPathAllow),
		// Default BLOCK (#66). We are a pull-through gate; a write is a capability we
		// do not implement or test, and relaying one means judging a push by the
		// package's PULL score, which is the wrong question entirely.
		WritePolicy: c.enum("FW_WRITE_POLICY", writePolicyBlock, writePolicyBlock, writePolicyAllowButLog, writePolicyAllow),
		// Default EMPTY = trust no proxy (raw peer is the source IP). See the field
		// comment: only set behind a proxy you control.
		TrustedProxies: c.str("FW_TRUSTED_PROXIES", ""),
	}
	// Refuse BOTH forms of the same credential rather than silently preferring one.
	// They are not composable — one is a fixed value and the other rotates — so an
	// operator who sets both has a belief about which wins, and any choice we make is
	// wrong half the time. Worse, the wrong pick fails INVISIBLY: the static value
	// keeps working until the day it expires. Naming it at startup costs one restart;
	// guessing costs an outage nobody can attribute.
	if cfg.UpstreamAuth != "" && cfg.UpstreamAuthFile != "" {
		c.problems = append(c.problems,
			"FW_UPSTREAM_AUTH and FW_UPSTREAM_AUTH_FILE are both set; use exactly one "+
				"(the file form is the one that survives token rotation)")
	}
	// Absolute paths only, on the same reasoning as FW_MALWARE_LIST (#38 /
	// CVE-2025-64726): a relative path resolves against the working directory, so the
	// credential we present upstream would be chosen by wherever the process was
	// launched rather than by the operator. Here the stake is higher than for the
	// malware feed — this file holds a SECRET, so a working-directory-relative read is
	// a path an attacker who controls CWD could aim at a file of their choosing.
	//
	// Checked at startup rather than on first use so it fails before the listener
	// binds; a gate that starts and then cannot authenticate is the ambiguous state
	// loadConfig's doc comment exists to prevent.
	if cfg.UpstreamAuthFile != "" && !filepath.IsAbs(cfg.UpstreamAuthFile) {
		c.problems = append(c.problems, fmt.Sprintf(
			"FW_UPSTREAM_AUTH_FILE=%q must be an absolute path: a relative path resolves "+
				"against the working directory, so the credential is chosen by wherever the "+
				"process was launched rather than by the operator", cfg.UpstreamAuthFile))
	}
	// TLS interception (increment 7): the two knobs are a pair, the file is absolute for
	// the same reason FW_UPSTREAM_AUTH_FILE is — it holds a SIGNING KEY, so a CWD-relative
	// read would let whoever controls the working directory choose which CA we
	// impersonate registries with — and the scope is refused rather than silently partial.
	if (cfg.InterceptListen == "") != (cfg.InterceptCAFile == "") {
		c.problems = append(c.problems,
			"FW_INTERCEPT_LISTEN and FW_INTERCEPT_CA_FILE must be set together: the listener "+
				"cannot terminate TLS without a CA to sign with, and a CA with no listener does nothing")
	}
	if cfg.InterceptCAFile != "" && !filepath.IsAbs(cfg.InterceptCAFile) {
		c.problems = append(c.problems, fmt.Sprintf(
			"FW_INTERCEPT_CA_FILE=%q must be an absolute path: this file holds the key that signs "+
				"certificates for the registry, and a relative path resolves against wherever the "+
				"process was launched rather than where the operator put it", cfg.InterceptCAFile))
	}
	// The upstream CA bundle (#137) is absolute for the same reason as the two files
	// above, and it is RESOLVED here rather than on first use so that a bundle we cannot
	// use is one line at startup instead of an x509 failure on every upstream fetch — a
	// symptom that reads as "the registry is down" from every developer's terminal.
	// Reading it inside loadConfig also means there is exactly one path that produces
	// the pool, so a caller cannot construct a firewall that skipped it (#136's lesson:
	// a feature wired in only one of two configurations is a dead feature with green
	// tests).
	switch {
	case cfg.UpstreamCABundle != "" && !filepath.IsAbs(cfg.UpstreamCABundle):
		c.problems = append(c.problems, fmt.Sprintf(
			"FW_UPSTREAM_CA_BUNDLE=%q must be an absolute path: a relative path resolves against "+
				"the working directory, so which certificates we trust upstream would be chosen by "+
				"wherever the process was launched rather than by the operator", cfg.UpstreamCABundle))
	case cfg.UpstreamCABundle != "":
		roots, line, err := upstreamRoots(cfg.UpstreamCABundle)
		if err != nil {
			c.problems = append(c.problems, "FW_UPSTREAM_CA_BUNDLE="+err.Error())
		}
		cfg.upstreamRoots, cfg.upstreamTrustLine = roots, line
	}
	return cfg, c.err()
}

// The two enforcement modes (see Config.Mode). enforce is the default and the safe
// direction: an unrecognized value is refused at startup rather than read as report.
const (
	modeEnforce = "enforce"
	modeReport  = "report"
)

// reporting reports whether verdicts are computed but not enforced.
func (c Config) reporting() bool { return c.Mode == modeReport }

// The three byte-gate modes (see Config.ByteGate).
const (
	byteGateOff         = "off"
	byteGateAllowButLog = "allow-but-log"
	byteGateEnforce     = "enforce"
)

// byteGateMode normalizes cfg.ByteGate to one of the three modes. An unrecognized
// value resolves to the DEFAULT, never to "off": a typo must not silently drop the
// firewall back to the pre-#11 blind passthrough. (It can't resolve to "enforce"
// either — a typo turning on enforcement would break installs for a reason the
// operator never asked for.) main.go warns about an unrecognized value at startup.
func byteGateMode(v string) string {
	switch v {
	case byteGateOff, byteGateAllowButLog, byteGateEnforce:
		return v
	default:
		return byteGateAllowButLog
	}
}

// configErrors collects every FW_* value startup had to reject (issue #19).
//
// UNSET is not an error — it selects the documented default, which is the whole
// point of having defaults. SET-BUT-UNPARSEABLE is, and this is the behaviour
// change: these getters used to fall back silently, on the reasoning that "a typo
// can't crash startup". But silently substituting a different value is not
// safety — it is the operator not getting what they asked for, and never being
// told. `FW_VERIFY_REPO=ture` turned repo verification OFF and said nothing.
//
// It ACCUMULATES rather than returning on the first problem: an operator who
// mistyped three knobs should learn about three, not discover them one restart at
// a time. That fix-restart-fix loop is the same disease as the diagnostic cascade
// this issue is about, just spread over time instead of down the log.
type configErrors struct{ problems []string }

func (c *configErrors) reject(key, got, want string) {
	c.problems = append(c.problems, fmt.Sprintf("%s=%q is not %s", key, got, want))
}

// err returns ONE error naming every offending knob, or nil. One line, however
// many knobs are wrong — the requirement is that startup fails with a single
// actionable statement, not that it reports only the first thing it tripped over.
func (c *configErrors) err() error {
	if len(c.problems) == 0 {
		return nil
	}
	return errors.New(strings.Join(c.problems, "; "))
}

// str reads a plain string knob. Present for symmetry only — every value is
// legal, so it can never reject.
func (c *configErrors) str(key, fallback string) string { return getEnv(key, fallback) }

// enum reads a knob whose value must be one of a fixed set.
//
// These were the worst offenders, because they did not merely fall back — they
// SILENTLY SELECTED A MODE. A typo'd FW_BYTE_GATE resolved to allow-but-log and a
// typo'd FW_UNVERIFIED_POLICY to closed; two of them printed a warning at startup
// and then ran anyway, in a mode the operator did not choose. A warning is the
// wrong instrument for "your enforcement posture is not what you typed".
//
// The normalizers (byteGateMode, unknownPathMode, …) stay exactly as they are:
// they are the last line of defence for a Config built in code, and this validates
// the ENVIRONMENT before one is built. Belt and braces, not a replacement.
func (c *configErrors) enum(key, fallback string, allowed ...string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	c.reject(key, v, "one of "+strings.Join(allowed, ", "))
	return fallback
}

// number parses a float knob and holds it to [min,max]. The range matters as much
// as the syntax: FW_SCORE_THRESHOLD=50 parses fine and blocks every package in
// existence, which reads to a developer as a broken firewall, not a misconfigured one.
func (c *configErrors) number(key string, fallback, min, max float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		c.reject(key, v, "a number")
		return fallback
	}
	if f < min || f > max {
		c.reject(key, v, fmt.Sprintf("in range %g..%g", min, max))
		return fallback
	}
	return f
}

// integer parses an int knob and rejects anything below min (every int knob here
// is a count, a ceiling or a number of seconds — none has a meaning below zero).
func (c *configErrors) integer(key string, fallback, min int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		c.reject(key, v, "a whole number")
		return fallback
	}
	if n < min {
		c.reject(key, v, fmt.Sprintf("at least %d", min))
		return fallback
	}
	return n
}

// boolean parses a bool knob (strconv.ParseBool: "1"/"true"/"t" and "0"/"false"/"f",
// case-insensitive). This is the knob where silent fallback was most dangerous:
// FW_VERIFY_REPO governs whether the repo cross-check runs at all.
func (c *configErrors) boolean(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		c.reject(key, v, "a boolean (true/false)")
		return fallback
	}
	return b
}

// duration parses a Go duration string (e.g. "1h", "30m", "0"). Note "14d" is NOT
// valid Go — a trap worth naming in the error, because it is the single most common
// way this knob gets mistyped.
func (c *configErrors) duration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		c.reject(key, v, `a Go duration like "30m" or "24h" (note: "14d" is not valid Go)`)
		return fallback
	}
	if d < 0 {
		c.reject(key, v, "a non-negative duration")
		return fallback
	}
	return d
}

// defaultUpstream returns the public registry URL for an ecosystem, used when
// FW_UPSTREAM isn't explicitly set. Unknown ecosystems return "" — that surfaces
// as an error when the ecosystem is constructed, rather than silently using the
// wrong registry.
//
// Each of these must be the host the ecosystem's own client contacts unconfigured,
// not merely a host that serves the right bytes. Under interception the listener
// terminates TLS only for the configured upstream's hostname and refuses CONNECT to
// anything else without dialling it, so a default under a second name the client never
// says makes the mode refuse every request out of the box. That is pinned by
// TestTheShippedDefaultUpstreamIsAHostRealClientsContact, which carries the citation
// for each client's built-in name.
// cooldownDefaultDays is the shipped release cooldown (D335).
const cooldownDefaultDays = 14

// defaultCooldownDays is FW_MIN_RELEASE_AGE_DAYS when the operator sets nothing.
//
// OCI gets 0 rather than 14 because the window cannot be enforced there (no
// trustworthy release date, #127). A default of 14 would ALSO fire the startup
// warning "set but NOT ENFORCED -- remove it" on every image gate, telling an
// operator to remove a setting they never wrote. An operator who does write it on
// an OCI gate still gets that warning, which is then true.
//
// This list must agree with releaseWindowEnforced; TestDefaultCooldownFollowsEnforcement
// derives the expectation from that function so the two cannot drift.
func defaultCooldownDays(ecosystem string) int {
	if ecosystem == "oci" {
		return 0
	}
	return cooldownDefaultDays
}

func defaultUpstream(ecosystem string) string {
	switch ecosystem {
	case "npm":
		return "https://registry.npmjs.org"
	case "pypi":
		return "https://pypi.org"
	case "oci":
		return "https://registry-1.docker.io"
	case "maven":
		// Central under the name Maven's super-POM and Gradle's mavenCentral() use.
		// repo1.maven.org is the same repository under an older name — byte-identical
		// responses from the same address — but no unconfigured client ever says it.
		return "https://repo.maven.apache.org/maven2"
	default:
		return ""
	}
}

// getEnv returns the env var named by key, or fallback if it is unset/empty.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// publicURLWarning returns the operator warning for an unset FW_PUBLIC_URL, or ""
// when there is nothing to say (issue #19).
//
// WHY THIS IS A DEFAULT WORTH WARNING ABOUT. When FW_PUBLIC_URL is empty,
// relayRewritten mints artifact URLs from each request's Host header — "an address
// that routes back to this proxy", which is true and sufficient for the fetch to
// work. The problem is what happens NEXT: those URLs are written into the
// developer's lockfile as `resolved`. Reach the same firewall as localhost, as a
// service name, and through an ingress, and the same dependency records three
// different URLs. The lockfile stops being portable and starts churning in review
// — the Artifactory complaint a survey of comparable tools documents, shipped by default.
//
// It is NOT fatal, and that is measured rather than assumed: e2e/lockfile_test.go
// runs a firewall with FW_PUBLIC_URL deliberately unset as its CONTROL leg — the
// one that proves `resolved` follows the request host, and therefore that the
// setting does anything at all. Refusing to start would break the test that
// validates the feature. It is also legitimately absent in single-host dev.
//
// Scoped to npm and pypi because those are the only ecosystems whose bodies are
// rewritten (see rewriteMeta in proxy.go). Warning on OCI or Maven would describe
// a consequence that cannot occur there.
func publicURLWarning(cfg Config) string {
	if cfg.PublicURL != "" {
		return ""
	}
	if cfg.Ecosystem != "npm" && cfg.Ecosystem != "pypi" {
		return ""
	}
	return "FW_PUBLIC_URL is unset, so artifact URLs follow each request's Host header. " +
		"The same dependency then resolves differently per environment and lockfiles are NOT " +
		"portable across dev/CI/prod. Set FW_PUBLIC_URL to this proxy's externally reachable base URL."
}

// stubScoringNotice returns the line an operator needs when scoring is stubbed, or ""
// when it is not.
//
// ── WHY THIS IS NOT COSMETIC ─────────────────────────────────────────────────
//
// `stub` is the DEFAULT mode and it returns a fixed score for every repository. The
// default threshold is 5.0 and the fixed score is 7.5, so an out-of-the-box firewall
// ALLOWS EVERY PACKAGE on the score rule — and the banner said only "scorecard mode:
// stub", leaving the operator to know the fixed value, compare it to their threshold,
// and work out the consequence themselves. A gate that reports allow decisions with a
// plausible-looking score while scoring nothing is the false-confidence shape this
// project treats as worse than no check (CLAUDE.md), and it is the silent half of the
// readiness question left open (D217).
//
// ── WHY IT COMPUTES THE CONSEQUENCE RATHER THAN CAUTIONING ───────────────────
//
// "stub is not for production" is a sentence an operator skims. "Every package is
// scored 7.5, at or above your threshold of 5.0, so the score rule allows everything"
// is a statement about THEIR configuration that they can check against what they
// expected. It follows the OCI-plus-closed line in the banner, which names the exact
// consequence and the knob that changes it rather than describing the setting.
//
// ── WHY IT IS NOT A "WARNING:" ───────────────────────────────────────────────
//
// #19 asserts that a healthy boot emits no ERROR/WARN/FATAL, and every e2e rig runs in
// stub mode deliberately — so a severity token here would make the rigs' own healthy
// boots noisy, which is the failure #19 exists to prevent (Artifactory's healthy boot
// emitting 404s and "services missing or unhealthy" until nobody could tell healthy
// from broken). The banner's established shape for "loud, operator-facing, not a
// complaint" is the "***" line, which is what this uses and what startupNoise ignores.
func stubScoringNotice(cfg Config) string {
	if cfg.ScorecardMode != "stub" {
		return ""
	}
	effect := fmt.Sprintf("at or above your threshold of %.1f, so the score rule ALLOWS EVERY PACKAGE and the only "+
		"enforcement left is the operator lists and the known-malware feed", cfg.ScoreThreshold)
	if stubScore < cfg.ScoreThreshold {
		effect = fmt.Sprintf("below your threshold of %.1f, so the score rule REFUSES EVERY PACKAGE", cfg.ScoreThreshold)
	}
	return fmt.Sprintf("stub scoring: every package is scored %.1f, %s. Stub is for tests and demos; "+
		"set FW_SCORECARD_MODE=api or local to score packages for real.", stubScore, effect)
}

// scoreThresholdMax is the top of the OpenSSF Scorecard scale. A threshold above
// it can never be met, so every package would be blocked — indistinguishable, from
// the developer's side, from the firewall being broken.
const scoreThresholdMax = 10.0
