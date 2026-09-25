package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Decision is the result of evaluating a package — what the proxy acts on.
type Decision struct {
	Allowed  bool
	Score    float64
	HasScore bool // false when we couldn't obtain a score at all
	// Coverage says what Score was computed over (#154). Meaningful only when
	// HasScore; withCoverage is the one way it is set, and it refuses otherwise. A
	// pointer so Decision stays comparable (tests compare decisions with !=).
	Coverage *scoreCoverage
	// Unavailable means we could not consult our sources at all (registry
	// metadata or score source unreachable / rate-limited). This is NOT a
	// verdict on the package: the proxy surfaces it as a 503 so package
	// managers retry, instead of a 403 "blocked" (which npm clients do NOT
	// retry and humans read as "this package is bad").
	Unavailable bool
	// Pending means we don't have a score YET: this is the first (cold) pull of
	// an unscored package in async local mode (D18), so it is quarantined
	// immediately while a background scan runs. Like Unavailable it surfaces as a
	// 403 (D102) — but it is a DISTINCT outcome: Unavailable is "our sources are
	// down", Pending is "our sources are fine, the answer just isn't computed yet".
	//
	// Keeping them as separate fields is what makes that distinction expressible.
	// They used to be told apart by their Retry-After values; now both are 403 and
	// the ONLY thing separating them is the explanation writeDeferred picks, so
	// collapsing these two booleans into one would erase the difference entirely
	// rather than merely blur it.
	Pending bool
	Reason  string // human-readable explanation, surfaced to the user where possible
	// Deny classifies WHY a denial happened, when Allowed is false. Two different
	// things wear the same "blocked" clothes today, and the artifact byte gate has to
	// tell them apart (D72):
	//
	//   - a POSITIVE FINDING about the package — it scored below the threshold, or a
	//     human explicitly denied it. We looked and we found something.
	//   - an ABSENCE OF TRUST — we could not score it, or could not verify its repo,
	//     and policy defaults to blocking. We looked and found nothing to go on.
	//
	// The first is a verdict on the package and must hold on every path that can
	// deliver it, including a lockfile-driven tarball fetch. The second is the noisy
	// case whose default posture is visibility (D49), because it fires on
	// perfectly legitimate packages whose metadata is merely thin.
	//
	// Empty on an allow, and on Pending/Unavailable — neither is a denial.
	Deny denyKind
	// Rule and Source make a refusal attributable by construction (D182, #20). Rule is
	// the identifier of what fired -- an advisory ID, a deny-list entry, the name of the
	// policy rule -- and Source is where that rule lives: the known-malware feed, the
	// operator's deny list, the compiled policy (by digest), the approval service, the
	// release window. Both travel to the client (headers and body) and into the audit
	// record, so "why was this blocked, under which rule, from which policy" is a lookup,
	// not a log correlation. Empty on an allow.
	Rule   string
	Source string
	// Override records that this decision was made AGAINST a finding, on an explicit
	// operator instruction (D312). Empty on every ordinary decision, including an
	// ordinary allow: it means "a policy said no and a named instruction said yes".
	//
	// It travels into the audit record and the console for the reason D312 gives: the
	// administrator gets their way, the organisation still gets told. A string rather
	// than a bool because the useful question is never "was there an override" but
	// "which finding was overridden, for which release".
	Override string
}

// withCoverage attaches what a score was computed over to the decision that rests on
// it. A decision without a score (a human ruling, a malware refusal, an unscorable
// fallback) gets none, even when the caller had one: coverage describes a number, and
// there is no number on that record to describe.
func (d Decision) withCoverage(cov scoreCoverage) Decision {
	if d.HasScore {
		d.Coverage = &cov
	}
	return d
}

// The Source vocabulary. Each names the thing an operator would open to change the
// verdict, which is the question a structured reason exists to answer. No knob names:
// these strings reach the client, and a knob name describes the gate to whoever is
// probing it (the adversarial suite's disclosure rule). docs/SETUP.md maps each to its
// knob for the operator.
const (
	sourceMalwareFeed   = "known-malware feed"
	sourceDenyList      = "operator deny list"
	sourceApproval      = "approval service"
	sourceReleaseWindow = "release window"
	sourceIntegrity     = "byte integrity"
)

// policySource names the compiled policy in force, by the same digest the audit record
// and the startup line carry, so a ruleset refusal on the wire and the policy view an
// operator reads agree on which policy it was.
func (f *Firewall) policySource() string { return "policy " + f.policyDigestNow() }

// denyKind enumerates the reasons a Decision can be a denial. See Decision.Deny.
type denyKind string

const (
	denyNone       denyKind = ""
	denyScore      denyKind = "score-below-threshold"
	denyHuman      denyKind = "human-denied"
	denyUnscorable denyKind = "unscorable"
	denyUnverified denyKind = "unverified"
	// denyKnownMalware — the package is named in the operator's known-malware feed
	// (D172 layer 1). This is the STRONGEST positive finding the gate can make: not an
	// inference from repo hygiene, but a published advisory naming this package.
	denyKnownMalware denyKind = "known-malware"
	// denyOperator -- the package is named in the operator's OWN deny list
	// (FW_DENY_LIST, D193). Distinct from denyKnownMalware on purpose: that one
	// means "a published advisory names this", this one means "your organisation
	// decided this". They are actioned by different people, so a developer must be
	// able to tell them apart from the refusal alone.
	denyOperator denyKind = "operator-denied"
	// denyReleaseWindow -- every version of the package falls outside the operator's
	// release window (the cooldown FW_MIN_RELEASE_AGE_DAYS or the age floor
	// FW_MAX_RELEASE_AGE_DAYS, #26), or the registry gave no publish dates to judge by
	// while a window was active. A local policy, like denyOperator, but one that a
	// cooldown clears by itself with time -- which is why it needs its own next step.
	denyReleaseWindow denyKind = "release-window"
)

// hardDeny reports whether this decision denied on a POSITIVE FINDING about the
// package, rather than on an absence of trust. It is the predicate the artifact byte
// gate uses to decide whether "allow-but-log" still applies (D72).
//
// Deliberately a whitelist of the two finding-based kinds, not "anything that isn't
// unscorable": a denial reason added later defaults to the SOFT side, so a new kind
// cannot start silently blocking artifact fetches without someone choosing that here.
func (d Decision) hardDeny() bool {
	return hardDenyKind(d.Allowed, d.Deny)
}

// hardDenyKind is the predicate itself, taking the two fields it actually reads
// rather than a whole Decision.
//
// It exists because the byte gate's D72 carve-out is now expressed as a RULE
// (byteGateRuleset), whose condition sees a Facts, not a Decision. Writing the
// same `!allowed && (score || human)` test in both places would create exactly
// the drift this taxonomy exists to prevent: the rule could start disagreeing
// with hardDeny() about what "a positive finding" means, and the tests pinning
// hardDeny() would keep passing while the gate did something else. One owner,
// two callers.
// denyKnownMalware is added to the whitelist DELIBERATELY, which is exactly the
// choice the comment above demands of anyone adding a kind. A published advisory
// naming this package is the strongest positive finding available to us, so it must
// hold on every path that can deliver the package — including a lockfile-driven
// tarball fetch, which is how a blocked package gets installed anyway (#11). Leaving
// it on the soft side would mean the sharpest signal we have is the one the byte gate
// ignores by default.
//
// denyOperator is added to the whitelist for the same reason, and the comment above
// requires the choice to be stated rather than assumed. An operator who puts a package
// on FW_DENY_LIST has made a POSITIVE decision about it -- it is not an absence of
// trust like "unscorable" -- and the whole value of the list is that it holds. If it
// were soft, a denied package would still be delivered to anyone whose lockfile pins
// its tarball URL, which is exactly the #11 bypass, and the operator would have no way
// to tell from the console that their block was doing nothing.
func hardDenyKind(allowed bool, kind denyKind) bool {
	return !allowed && (kind == denyScore || kind == denyHuman ||
		kind == denyKnownMalware || kind == denyOperator)
}

// Firewall is the decision engine. It is deliberately its own type with its own
// dependencies (an HTTP client + config) so that later it can be lifted out into
// a separate microservice with almost no change to this code — the proxy would
// just call it over HTTP instead of calling its method.
type Firewall struct {
	cfg           Config
	client        *http.Client
	scannerClient *http.Client // separate, longer timeout: live scans are slow
	depsDevBase   string       // base URL for the deps.dev API; overridable in tests
	eco           Ecosystem
	cache         *scoreCache    // L1: in-memory, TTL-bounded score cache (fan-out guard)
	repos         *repoCache     // package -> normalized repo, same TTL as scores
	inflight      *inflightScans // async local mode: at-most-one background scan per repo
	backoff       *backoffCache  // D25: short-TTL 429 circuit breaker (re-probe fan-out guard)
	// depsDevOutage is the HOST-wide twin of backoff: armed when a deps.dev lookup fails
	// as unreachable/5xx, so an outage costs one timeout rather than one per cold package
	// (D342). Same TTL knob as backoff (FW_RATELIMIT_BACKOFF_TTL, default 10s); nil is a no-op.
	depsDevOutage *backoffCache
	// #153: what the control plane last ANSWERED to each of these senders, so a refusal
	// is logged once per change instead of never (before) or once per request.
	pendingOutcome outcomeLog
	scoreOutcome   outcomeLog
	audit          *auditEmitter // append-only audit log (D10 #3): best-effort, non-blocking
	// policyDigest fingerprints the policy in force, stamped onto every audit record
	// so an exported decision log says WHICH policy produced each verdict (#28).
	// Snapshotted at construction; see NewFirewall for why it is not per-request.
	policyDigest string
	// malware is D172's layer 1: the operator's known-malware feed as STARTUP loaded
	// it. nil when unconfigured, which every method on it tolerates — an absent feed
	// must be an inert gate, not a panic.
	//
	// ⚠️ NOT THE READ PATH. Since #160 the feed is re-read while the gate runs, so a
	// reader that takes this field sees the bytes from boot forever. Everything asks
	// malwareFeed(); malwarereload_test.go's source guard keeps it that way, because
	// the defect this field can cause is silent (an old feed, enforcing confidently).
	malware *malwareList
	// malwareSrc is the re-reading source when a feed is configured; nil means the
	// static field above, which is what every struct-literal Firewall in the tests is.
	malwareSrc   malwareSource
	malwareStale func() error

	// requiredChecks is the D271 coverage floor for a partial Scorecard report
	// (scorecardfloor.go), parsed once from FW_SCORECARD_REQUIRED_CHECKS.
	requiredChecks map[string]bool

	// allowList / denyList are the operator's own lists (D193, issue #58), read
	// through a SOURCE rather than held as a value (D195).
	//
	// A function, because D193 has the console editing these while the process runs:
	// a held pointer would go stale the moment someone saved, and the request path
	// would enforce a list the console no longer shows. Asking on every lookup lets
	// the source decide whether that means a re-read or the cached value. Both are
	// nil-safe end to end, so the unconfigured default still costs nothing.
	allowList listSource
	denyList  listSource
	// allowStale / denyStale report why the list in force is NOT the file on the mount
	// (a re-read that failed), or nil. Nil funcs for a static list. Read by readiness
	// (D165) and by nothing on the request path.
	allowStale, denyStale func() error

	// The cache key for policyDigest above: the two list content digests, which after
	// D195 are the only inputs to the view that can change while we run. Guarded because
	// the request path reads them from per-request goroutines while a reload can change
	// the lists underneath.
	digestMu    sync.Mutex
	digestAllow string
	digestDeny  string
	// Request coalescing for the two COLD paths the caches above can't help with —
	// the thundering-herd guard maven already had and npm/PyPI/deps.dev lacked
	// (issue #16). Both are nil-safe: a hand-built test Firewall simply doesn't
	// coalesce.
	//
	// These two CAN nest — a repoFlights leader whose verification refuses the repo
	// (a mismatch, or durably unverified under D36) goes on through unscorable /
	// unverified -> applyHumanRuling, which may getScore() a human-supplied repo and
	// so enter scoreFlights while still holding its repo
	// flight. That is safe, and deliberately so: they are separate groups keyed on
	// different things, do() never holds a group's mutex while running fn, and
	// nothing under scoreFlights re-enters repoFlights — so there is no lock cycle
	// to deadlock on. The only cost is that the repo flight's followers wait out the
	// score lookup too, which is bounded by the HTTP client timeout.
	repoFlights  *flightGroup[repoResolution] // one repo lookup+verify per package
	scoreFlights *flightGroup[cachedScore]    // one score lookup per repo

	// rules is the ordered, first-match-wins policy this firewall decides with
	// (D76, issue #58 — see policy.go). Built once at construction and never
	// mutated, so it is safe to read from every per-request goroutine without a
	// lock. A nil value means "use the default two-rule set": read it through
	// f.ruleset(), never directly, or a hand-built &Firewall{} literal would
	// block every package.
	rules Ruleset

	// classifyRules is the ordered policy for requests that carry NO package
	// identity — the classification half of the epic (issue #58 increment 2).
	// Same engine, separate ruleset, because the two answer different questions:
	// `rules` decides a verdict about a known package, this decides whether an
	// unidentified request is legitimate infrastructure at all. Nil means "use
	// the default"; read it through f.classifyRuleset().
	classifyRules Ruleset

	// byteRules is the ordered policy for the ARTIFACT BYTE route (issue #58
	// increment 4). Third ruleset, third question: `rules` decides what we think
	// of a package, `classifyRules` decides whether an unidentified request is
	// infrastructure, and this decides whether an already-evaluated package's
	// BYTES may be served — which FW_BYTE_GATE answers differently from the
	// metadata path on purpose (D49). Nil means "use the default"; read it
	// through f.byteRuleset().
	byteRules Ruleset
}

// NewFirewall constructs a Firewall with a sane HTTP client timeout so a slow
// upstream can never hang our request forever. It also resolves the configured
// ecosystem (npm/pypi); an unknown ecosystem is a fatal misconfiguration, so we
// return an error rather than starting in a broken state.
func NewFirewall(cfg Config) (*Firewall, error) {
	eco, err := newEcosystem(cfg.Ecosystem, cfg.UpstreamRegistry)
	if err != nil {
		return nil, err
	}
	// Scope any upstream credential (cfg.UpstreamAuth) to the registry host so it can
	// never leak to deps.dev or the approval service, which this same probe client also
	// calls. A bad UpstreamRegistry URL just yields an empty host → auth stays off.
	upstreamHost := ""
	if u, err := url.Parse(cfg.UpstreamRegistry); err == nil {
		upstreamHost = u.Host
	}
	// One reusable client for upstream probes AND approval/audit calls. Its
	// upstream credential is host-scoped (above), so it stays off requests to the
	// approval service; we pull it into a local so the audit emitter can share it.
	// ONE pooled transport shared by both clients below. Sharing is what we want: an
	// http.Transport's limits are applied PER HOST, so a single pool gives the
	// registry, deps.dev, the approval service and the scheduler each their own
	// connection budget, instead of two transports each granting every host its own.
	// Timeouts live on the Client, not the Transport, so the two clients keep their
	// very different deadlines. Without this, both clients fall through to
	// http.DefaultTransport, whose 2-idle-conns-per-host default turns a cold resolve
	// burst into a connection stampede against our own L2 (issue #1) — see
	// pooledTransport for the full account.
	maxConns := cfg.MaxConnsPerHost
	if maxConns == 0 {
		maxConns = defaultMaxConnsPerHost // zero value = "unset"; negative = unbounded
	}
	tr := newTransport(maxConns, cfg.upstreamRoots)
	// The credential is a SOURCE, not a value, so a short-lived upstream token can be
	// rotated under a running process (issue #53, D177). The file form is checked
	// first because loadConfig refuses both being set; a Config built in code that
	// sets neither yields a nil source, which withUpstreamAuth treats as "off".
	var upstreamCred credentialSource
	switch {
	case cfg.UpstreamAuthFile != "":
		upstreamCred = fileCredential(cfg.UpstreamAuthFile, log.Printf)
	case cfg.UpstreamAuth != "":
		upstreamCred = staticCredential(cfg.UpstreamAuth)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: withUpstreamAuth(withUserAgent(tr), upstreamHost, upstreamCred)}
	// An unset DepsDevBase means "the public API", not "no API". loadConfig already
	// defaults it, so this covers the other constructor path: the many tests (and any
	// future caller) that build a Config literal without naming every field. Getting
	// this wrong would not fail loudly — it would silently turn every deps.dev URL
	// into a relative one and make scoring/verification fail as "unavailable".
	depsDev := cfg.DepsDevBase
	if depsDev == "" {
		depsDev = depsDevBaseURL
	}
	// D172 layer 1. A configured feed that cannot be read is a STARTUP FAILURE, not a
	// warning: the alternative is a firewall that boots, answers /healthz, and
	// enforces nothing — the exact false-confidence shape this project treats as worse
	// than having no check at all. Unconfigured stays nil, and the gate is inert.
	//
	// The signing key is parsed FIRST, so a mistyped key is a startup error naming the
	// key rather than a confusing signature failure naming the feed (#157).
	feedKey, err := parseFeedKey(cfg.MalwareFeedKey)
	if err != nil {
		return nil, fmt.Errorf("FW_MALWARE_FEED_KEY %w", err)
	}
	if cfg.MalwareFeedURL != "" {
		// A pull that is not verified is a supply-chain hole in the thing whose job is
		// closing them, so the key is not optional here the way it is for a mounted file.
		if feedKey == nil {
			return nil, fmt.Errorf("FW_MALWARE_FEED_URL is set but FW_MALWARE_FEED_KEY is not: the gate refuses " +
				"to pull a snapshot it cannot verify")
		}
		if cfg.MalwareListPath == "" {
			return nil, fmt.Errorf("FW_MALWARE_FEED_URL is set but FW_MALWARE_LIST is not: the pulled snapshot " +
				"is installed at FW_MALWARE_LIST, so there is nowhere to put it")
		}
		if u, err := url.Parse(cfg.MalwareFeedURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, fmt.Errorf("FW_MALWARE_FEED_URL %q is not an http(s) URL", cfg.MalwareFeedURL)
		}
	}
	if feedKey != nil && cfg.MalwareListPath == "" {
		return nil, fmt.Errorf("FW_MALWARE_FEED_KEY is set but FW_MALWARE_LIST is not: a key with no feed " +
			"verifies nothing, and configuring one usually means the other was meant too")
	}
	// The pull (#157) is built before the first load, so a replica with an empty mount
	// can seed itself. Its own client: the gate's transport (proxy, CA bundle, user
	// agent) and NOTHING else -- not withUpstreamAuth, so the registry credential can
	// never be presented to the feed host.
	var fetcher *feedFetcher
	if cfg.MalwareFeedURL != "" {
		fetcher = &feedFetcher{
			url: cfg.MalwareFeedURL, path: cfg.MalwareListPath, key: feedKey,
			client:  &http.Client{Timeout: 2 * time.Minute, Transport: withUserAgent(tr)},
			logf:    log.Printf,
			inForce: func() *malwareList { return nil }, // nothing is in force yet
		}
		if err := fetcher.seedIfMissing(); err != nil {
			return nil, err
		}
	}
	var malware *malwareList
	if cfg.MalwareListPath != "" {
		malware, err = loadMalwareList(cfg.MalwareListPath, feedKey)
		if err != nil {
			return nil, err
		}
		// What the snapshot says it is, and how old that makes it. Logged at startup
		// whether or not a key is configured, because an operator who cannot see the
		// serial cannot tell a refreshed feed from a replayed one even by hand.
		if malware.header.Present {
			age := malware.header.age(time.Now())
			note := ""
			if age > feedMaxAge {
				note = fmt.Sprintf(" -- SECURITY: older than %s, so recent advisories are NOT in force; "+
					"the refresh has stopped", feedMaxAge)
			}
			log.Printf("known-malware feed %q: %s, %s old%s", cfg.MalwareListPath, malware.header,
				age.Round(time.Minute), note)
		}
		if feedKey != nil {
			log.Printf("known-malware feed %q: signature VERIFIED against FW_MALWARE_FEED_KEY", cfg.MalwareListPath)
		} else {
			log.Printf("known-malware feed %q: NOT verified -- no FW_MALWARE_FEED_KEY is configured, so a "+
				"tampered, truncated or replayed snapshot would load exactly like a good one", cfg.MalwareListPath)
		}
		// The gap is logged as a NUMBER rather than described in release notes.
		// It is scoped to THIS instance's ecosystem (#103): a pypi gate carrying npm
		// advisories is not failing to enforce them, it would never be asked.
		if g := malware.gap(cfg.Ecosystem); g > 0 {
			log.Printf("known-malware feed %q: %d package-wide advisories enforced, %d %s version-specific advisories loaded but NOT YET ENFORCED, %d records skipped",
				cfg.MalwareListPath, malware.enforced(), g, cfg.Ecosystem, malware.skipped)
		} else {
			log.Printf("known-malware feed %q: %d package-wide advisories enforced, version-specific advisories ENFORCED for %s, %d records skipped",
				cfg.MalwareListPath, malware.enforced(), cfg.Ecosystem, malware.skipped)
		}
	}

	// The feed is re-read while the gate runs (#160): the operator refreshes the file
	// on a schedule, and before this a refreshed file changed nothing until the process
	// restarted. Seeded with what startup just loaded, so the first interval re-parses
	// nothing and the feed in force never depends on who reads it first.
	var malwareSrc malwareSource
	var malwareStale func() error
	if cfg.MalwareListPath != "" {
		src := newReloadingFeed(cfg.MalwareListPath, cfg.Ecosystem, log.Printf, malware, feedKey)
		malwareSrc, malwareStale = src.current, src.stale
		if fetcher != nil {
			fetcher.inForce = src.current
			log.Printf("known-malware snapshot: pulling %q hourly into %q (verified before install)",
				cfg.MalwareFeedURL, cfg.MalwareListPath)
			go fetcher.run()
		}
	}

	// The operator's own lists (D193). Loaded the same way as the feed, and with the
	// same posture on failure: a list that cannot be read is a FATAL config error, not
	// a warning. Booting without the deny list an operator configured would enforce
	// nothing while looking healthy -- the false-confidence shape this project treats
	// as worse than no check at all.
	// Loaded ONCE here so a bad list is a startup failure (below), then handed to a
	// reloading source so later edits are picked up without a restart.
	var allowList, denyList listSource = staticList(nil), staticList(nil)
	var allowStale, denyStale func() error
	if cfg.AllowListPath != "" {
		first, err := loadOperatorList("allow", cfg.Ecosystem, cfg.AllowListPath)
		if err != nil {
			return nil, err
		}
		src := newReloadingList("allow", cfg.Ecosystem, cfg.AllowListPath, log.Printf, listReloadTTL, first)
		allowList, allowStale = src.current, src.stale
		// Logged as a COUNT so an operator can confirm the file they edited is the file
		// we read -- the cheapest possible answer to "why isn't my entry working?".
		log.Printf("operator allow-list %q: %d package(s) allowed without scoring [%s], re-read every %s",
			cfg.AllowListPath, first.count(), cfg.Ecosystem, listReloadTTL)
	}
	if cfg.DenyListPath != "" {
		first, err := loadOperatorList("deny", cfg.Ecosystem, cfg.DenyListPath)
		if err != nil {
			return nil, err
		}
		src := newReloadingList("deny", cfg.Ecosystem, cfg.DenyListPath, log.Printf, listReloadTTL, first)
		denyList, denyStale = src.current, src.stale
		log.Printf("operator deny-list %q: %d package(s) blocked outright [%s], re-read every %s",
			cfg.DenyListPath, first.count(), cfg.Ecosystem, listReloadTTL)
	}

	f := &Firewall{
		cfg:            cfg,
		client:         client,
		requiredChecks: parseRequiredChecks(cfg.ScorecardRequiredChecks),
		// A live Scorecard scan takes far longer than a normal upstream call, so the
		// scanner gets its own client with a generous timeout. In async local mode
		// (D18) this runs in a BACKGROUND goroutine (runBackgroundScan), so the long
		// timeout bounds the background work, never a client's request.
		scannerClient: &http.Client{Timeout: 4 * time.Minute, Transport: withUserAgent(tr)},
		depsDevBase:   depsDev,
		eco:           eco,
		cache:         newScoreCache(cfg.ScoreCacheTTL, cfg.ScoreCacheMaxEntries),
		repos:         newRepoCache(cfg.ScoreCacheTTL, cfg.ScoreCacheMaxEntries),
		inflight:      newInflightScans(),
		backoff:       newBackoffCache(cfg.RateLimitBackoffTTL),
		depsDevOutage: newBackoffCache(cfg.RateLimitBackoffTTL),
		repoFlights:   newFlightGroup[repoResolution](),
		scoreFlights:  newFlightGroup[cachedScore](),
		// The shipped default policy: allow at/above the threshold, block
		// everything else (D76). Snapshotting cfg here — rather than consulting
		// cfg on every decision — is what makes the ruleset immutable and
		// goroutine-safe. A later increment replaces these three constructors
		// with rulesets loaded from the operator's config (#32's console is the
		// surface); the shapes here are what that config must be able to express.
		rules: defaultRuleset(cfg),
		// The classification policy: allow this ecosystem's enumerated
		// control-plane endpoints, apply FW_UNKNOWN_PATH_POLICY to the rest, and
		// otherwise fall to the implicit terminal block (D76).
		classifyRules: defaultClassificationRuleset(cfg),
		// The artifact byte policy: FW_BYTE_GATE, as an ordered ruleset rather
		// than as a mode ladder. Unlike the two above, its terminal is an ALLOW
		// under the shipped default — visibility-first is D49's deliberate
		// exception to the epic's fail-closed thesis.
		byteRules: byteGateRuleset(cfg),
		// Best-effort, non-blocking audit of every terminal verdict. Disabled
		// automatically when no approval service is configured (ApprovalURL == "").
		audit:        newAuditEmitter(cfg.ApprovalURL, client, auditBufferSize),
		malware:      malware,
		malwareSrc:   malwareSrc,
		malwareStale: malwareStale,
		allowList:    allowList,
		denyList:     denyList,
		allowStale:   allowStale,
		denyStale:    denyStale,
	}
	// Warm the policy fingerprint every audit record carries (#28). It is CACHED, not
	// snapshotted — see policyDigestNow for why that distinction now matters.
	f.policyDigestNow()
	return f, nil
}

// policyDigestNow returns the fingerprint of the policy CURRENTLY in force (#28).
//
// This used to be computed once in NewFirewall, on a stated assumption: "policy is read
// from the environment at startup and never reloaded". D195 ended that — the operator
// allow/deny lists re-read from disk while the process runs. A snapshot would put the
// BOOT policy's digest on records produced under a later one, which for a compliance
// record (#28) is not a staleness annoyance but a false statement about what was enforced.
//
// CACHED RATHER THAN RECOMPUTED, because this runs once per package request and
// describePolicy is not free: measured 15.5 µs and 67 allocations per call on the dev
// host (BenchmarkDescribePolicy, 2026-09-05). The cache key is the two list content
// digests, because after D195 they are the ONLY inputs that can change while we run —
// everything else in the view is fixed at startup. So the steady state is two string
// compares, and a recompute happens only when an operator actually edits a list.
func (f *Firewall) policyDigestNow() string {
	a, d := listDigest(f.allow()), listDigest(f.deny())

	f.digestMu.Lock()
	defer f.digestMu.Unlock()
	if f.policyDigest != "" && f.digestAllow == a && f.digestDeny == d {
		return f.policyDigest
	}
	f.policyDigest = f.describePolicy().Digest
	f.digestAllow, f.digestDeny = a, d
	return f.policyDigest
}

// notReady lists why this gate must NOT take traffic (D165) -- today exactly one kind of
// reason: an operator list whose file on the deployment mount can no longer be read, so
// the list in force is the last good one rather than the deployed one. Empty means ready.
//
// Every check here is LOCAL and bounded, as D163 requires of liveness and D165 extends
// to readiness: nothing reaches a registry, deps.dev or the approval service. A registry
// outage must never make a gate unready, because every replica shares the registry and
// they would all leave rotation at once -- an outage turned into a route around the gate.
func (f *Firewall) notReady() []string {
	var out []string
	// `stub` is a DEVELOPMENT FIXTURE, not a configuration (D273). It does not decline
	// to score — it asserts a flat 7.5 it never measured, which is strictly worse than
	// not scoring, because the verdict looks like a measurement. Now that `off` exists
	// there is no legitimate reason to run `stub` in production, so failing readiness
	// here costs nothing real and closes the accident #141 was filed about.
	//
	// `off` is deliberately READY: it is a SUPPORTED configuration and, per D280, the
	// launch posture. Failing readiness on it would be the "nagging the user with a big
	// missing asset" the project explicitly ruled against.
	if f.cfg.ScorecardMode == "stub" {
		out = append(out, "FW_SCORECARD_MODE=stub is a development fixture that fabricates a passing "+
			"score for every package; set it to off, api or local before taking traffic")
	}
	for _, l := range []struct {
		what  string
		stale func() error
	}{
		{"operator allow-list", f.allowStale},
		{"operator deny-list", f.denyStale},
		{"known-malware feed", f.malwareStale},
	} {
		if l.stale == nil {
			continue
		}
		if err := l.stale(); err != nil {
			out = append(out, fmt.Sprintf("%s %v", l.what, err))
		}
	}
	return out
}

// malwareFeed is the feed in force RIGHT NOW: the re-reading source where one is
// configured (#160), otherwise the field startup loaded. Nil-safe in both directions —
// an unconfigured gate answers nil and every malwareList method tolerates it, which is
// what keeps a struct-literal Firewall usable.
func (f *Firewall) malwareFeed() *malwareList {
	if f.malwareSrc != nil {
		return f.malwareSrc()
	}
	return f.malware
}

// listDigest is the cache key for one list, nil-safe. An unconfigured list and an empty
// one must key differently, or configuring an empty list would not invalidate the cache.
func listDigest(l *operatorList) string {
	if l == nil {
		return "<none>"
	}
	return l.contentDigest
}

// auditVerdict records one terminal allow/block decision to the append-only audit
// log. It is called once per package request from the proxy's single control point
// (ServeHTTP), so there is exactly one event per requested package — the _files
// byte re-gate deliberately does not audit, to avoid two events per pull. Pending
// and Unavailable are not verdicts and are never routed here. The emit itself is
// fire-and-forget and never blocks the caller (see auditEmitter).
func (f *Firewall) auditVerdict(pkg, sourceIP string, d Decision) {
	action := auditActionAllow
	if !d.Allowed {
		action = auditActionBlock
	}
	// What was DONE is not always what was decided: report mode relays every verdict
	// (#114). The record carries both, and the mode that explains any difference.
	taken, mode := action, "enforce"
	if f.cfg.reporting() {
		taken, mode = auditActionAllow, modeReport
	}
	var score *float64
	if d.HasScore {
		s := d.Score // copy: never point at the caller's decision value
		score = &s
	}
	// The threshold is recorded only when a score was actually weighed against it.
	// Stamping it on every record would attach a scoring input to verdicts that never
	// scored anything — a known-malware refusal happens before any score is fetched —
	// and an auditor reading threshold 5.0 on such a record would reasonably conclude
	// the package had been scored and failed.
	var threshold *float64
	if d.HasScore {
		t := f.cfg.ScoreThreshold
		threshold = &t
	}
	var cov scoreCoverage
	if d.HasScore && d.Coverage != nil {
		cov = *d.Coverage
	}
	f.audit.Emit(auditEvent{
		Package:   pkg,
		Ecosystem: f.cfg.Ecosystem,
		Action:    action,
		Taken:     taken,
		Mode:      mode,
		Score:     score,
		Reason:    d.Reason,
		DenyKind:  string(d.Deny),
		// Coverage travels only with a score (#154); Decision.withCoverage already
		// enforces that, and an empty scoreCoverage marshals to no fields at all.
		ScoredChecks:    cov.ScoredChecks,
		TotalChecks:     cov.TotalChecks,
		ComputedWithout: cov.ComputedWithout,
		Rule:            d.Rule,
		Source:          d.Source,
		Override:        d.Override,
		SourceIP:        sourceIP, // observed connecting peer; "" when unobserved
		Threshold:       threshold,
		PolicyDigest:    f.policyDigestNow(),
	})
}

// PackageNameFromPath delegates to the active ecosystem's path parser, so the
// proxy doesn't need to know which ecosystem is in use.
func (f *Firewall) PackageNameFromPath(path string) string {
	return f.eco.PackageNameFromPath(path)
}

// ControlPlanePath delegates to the active ecosystem's control-plane enumeration,
// for the same reason PackageNameFromPath delegates: the proxy should not need to
// know which registry protocol is in use. See Ecosystem.ControlPlanePath — that
// enumeration is the whole fail-open surface of the classification gate.
func (f *Firewall) ControlPlanePath(escapedPath string) bool {
	return f.eco.ControlPlanePath(escapedPath)
}

// classifyRuleset returns the classification policy, falling back to the default
// when none was installed — the same nil-safety f.ruleset() needs, and for the
// same reason: a hand-built &Firewall{} literal would otherwise have a nil
// ruleset, which matches nothing, which the terminal rule turns into "refuse
// every infrastructure request".
func (f *Firewall) classifyRuleset() Ruleset {
	if f.classifyRules != nil {
		return f.classifyRules
	}
	return defaultClassificationRuleset(f.cfg)
}

// byteRuleset returns the artifact byte policy, falling back to the default when
// none was installed.
//
// The fallback matters MORE here than for the other two, and in the opposite
// direction. A nil ruleset elsewhere means "block everything", which is loud and
// gets noticed. Here the default is visibility-first, so a &Firewall{} literal
// with nil byteRules would fall to the implicit terminalRule and start REFUSING
// artifact bytes — the reverse of the shipped posture, and a change every
// hand-built test firewall would inherit. Read it through this accessor.
func (f *Firewall) byteRuleset() Ruleset {
	if f.byteRules != nil {
		return f.byteRules
	}
	return byteGateRuleset(f.cfg)
}

// transientReason builds the client-facing reason for a retryable 503, naming an
// upstream rate limit (HTTP 429) distinctly from a generic outage so a developer
// can tell "the registry is throttling us" from "the registry is down" (D25).
// subject is the thing we couldn't verify (e.g. `registry metadata for "left-pad"`).
// The D17 taxonomy is unchanged — both wordings are still retryable 503s.
func transientReason(subject string, err error) string {
	if errors.Is(err, errUpstreamRateLimited) {
		return subject + " temporarily unavailable: upstream rate limited (HTTP 429), retry shortly"
	}
	return subject + " temporarily unavailable"
}

// pinnedMalwareDecision applies version-pinned known-malware advisories to an
// identity that names its own version (issue #103). It reports blocked=false when
// there is nothing to say, so the caller falls through to the ordinary flow.
//
// THE UNKNOWN-VERSION BRANCH IS THE LOAD-BEARING ONE, and it is not symmetrical
// with the known one. It fires only where there is something to miss:
//
//   - No pinned advisory names this package? Then an unknown version hides nothing,
//     and refusing would deny a clean package for no reason.
//   - A pinned advisory DOES name it? Then whoever can stop us determining the
//     version gets exactly the release the advisory names. That is a bypass, not a
//     degradation, so it fails closed.
//
// The case is reachable: proxy.go falls back to the bare image name when a blob's
// digest matches no recorded manifest binding, and that identity carries no
// reference. Same posture as the unknown-age case in ageYankIndex (D100, #70) and
// as malwarePin.yankFor on the PyPI side — one rule, three control points.
func (f *Firewall) pinnedMalwareDecision(pkgName string) (Decision, bool) {
	if f.malwareFeed() == nil || !identityCarriesVersion(f.cfg.Ecosystem) {
		return Decision{}, false
	}
	version, known := identityVersion(f.cfg.Ecosystem, pkgName)
	return f.pinnedMalwareVerdict(pkgName, version, known)
}

// versionedPath is implemented by an ecosystem whose REQUEST PATH names the exact
// version even though its package IDENTITY does not. Maven is the case: its identity
// is "group:artifact" on purpose, so a human approves the library once rather than
// once per release — which is right for approvals and leaves a version-pinned
// advisory with nothing to match on.
//
// An optional interface rather than a method on Ecosystem, because three of the four
// ecosystems have nothing to say here and a required method would mean three
// implementations that return false — each of them a place for someone to later
// "implement properly" without the control point that would use it.
type versionedPath interface {
	VersionFromPath(path string) (string, bool)
}

// releaseDated is implemented by an ecosystem that can report WHEN the release named
// on a request path was published, so the operator's release window (#26 cooldown,
// D22 age floor) can apply to it.
//
// Optional for the same reason versionedPath is: npm and PyPI answer this from a
// metadata document they already fetch and rewrite, so they need no probe, and OCI
// deliberately does not implement it at all — see whyOCIHasNoReleaseWindow.
//
// The returned bool is "we have a time", NOT "allow". An ecosystem that answers
// (zero, false, nil) is saying the upstream gave no date, which the caller must treat
// as fail-closed while a bound is active, never as old enough to serve.
type releaseDated interface {
	mavenReleaseTime(c *http.Client, path string) (time.Time, bool, error)
}

// whyOCIHasNoReleaseWindow records a MEASURED decision, so the gap is not read as an
// oversight and quietly "fixed" with the wrong mechanism.
//
// OCI is the one ecosystem here with no trustworthy publish time:
//
//   - The registry supplies none. Measured 2026-09-12 against Docker Hub: a manifest
//     response carries docker-content-digest and etag and NO Last-Modified. The
//     distribution spec defines no push-time field.
//   - The only date in the pull path is `created` in the image config blob, and that
//     blob is content the PUBLISHER uploads. Demonstrated rather than asserted: taking
//     the real alpine:3.19 config, back-dating `created` to 2020 and recomputing its
//     digest yields a different but perfectly valid config blob, which the publisher
//     then references from their own manifest. The digest is a function of the bytes
//     they chose, and nothing the registry signs attests to when the push happened.
//   - `created` is ALREADY WRONG without anyone attacking it, in two distinct ways.
//     (a) Reproducible builds zero it on purpose: of 7 images sampled 2026-09-12, FOUR
//     report `created: 1970-01-01T00:00:00Z`, every gcr.io/distroless/* one — and this
//     repository ships gcr.io/distroless/static:nonroot in four Dockerfiles, so a
//     cooldown would compute our OWN base image as 56 years old. (b) Even where a real
//     date is present it runs early: measured 2026-09-16 across 18 Docker official
//     images against the registry's own push record, `created` was EARLIER than the
//     real push in 18 of 18, median 3.5 h, max 1,041 days (busybox:1.36), with FOUR of
//     the eighteen (22%) off by more than seven days — nginx:1.27 by 55.5 d,
//     registry:2 by 501 d, traefik:v3.1 by 14.6 d.
//
// The last bullet is the one to quote, because it survives the obvious objection to the
// one above it ("our publishers are trusted"). (a) is the loud failure and (b) the quiet
// one: a cooldown keyed on `created` is not merely forgeable by a hostile publisher, it
// is measurably vacuous for about a fifth of ordinary first-party images and absurd for
// every reproducibly-built one. It is also set by the party it restrains, so any image
// could clear a 7-day cooldown the moment it is pushed. Every way round it is strictly
// worse than not shipping one, because the operator would believe the window applied to
// containers. Implementing releaseDated for OCI therefore requires a NEW source of
// truth, not a new parser.
//
// On sources of truth, since the search is partly done (issue #127): Docker Hub's own
// non-spec API DOES return a registry-set push time, anonymously. It is not the answer.
// It is one registry's private API — registry:2, which the reference deployment ships
// as the customer stand-in, has nothing like it — and it lives on hub.docker.com, a
// DIFFERENT host from registry-1.docker.io. Increment 11 (!275) went to real trouble to
// add no new host under interception; reaching for the Hub API to date an image would
// undo that and needs its own entry in docs/EGRESS.md. A signed attestation (near #34),
// or a first-sight time we record ourselves from in front (D177), are the candidates
// that do not have those two problems.
func whyOCIHasNoReleaseWindow() {}

// pinnedMalwareOnPath is the second control point for version-pinned advisories
// (issue #103), for ecosystems that carry the version on the path instead of in the
// identity. It shares its verdict logic with pinnedMalwareDecision — the two differ
// ONLY in where the version comes from, and unifying them is deliberate: a separate
// copy would be a second place for the fail-closed rule to drift.
func (f *Firewall) pinnedMalwareOnPath(pkgName, path string) (Decision, bool) {
	if f.malwareFeed() == nil || !pinnedEnforcedIn(f.cfg.Ecosystem) {
		return Decision{}, false
	}
	vp, ok := f.eco.(versionedPath)
	if !ok {
		return Decision{}, false
	}
	version, known := vp.VersionFromPath(path)
	return f.pinnedMalwareVerdict(pkgName, version, known)
}

// D312's ruling, applied: *"if the administrator allows it, it is allowed."*
//
// An operator allow entry that NAMES A RELEASE outranks a known-malware advisory for that
// release. The administrator looked at that artifact and decided; we serve it, and we say
// so loudly — the organisation still gets told (D312's second condition), because an
// override that leaves no record is indistinguishable from a gate that missed something.
//
// ⚠️ THREE THINGS THIS DELIBERATELY DOES NOT DO, each of them the harm D312 itself names.
//
//  1. A NAME-scoped allow does not override an advisory. The administrator who wrote
//     "left-pad" in March judged what they could see in March; extending that to the
//     release hijacked in September attributes to them a decision they never made, and
//     then cites their authority as the reason to serve malware. The refusal tells them
//     to pin the release if that is what they mean. (D312 does not say this in so many
//     words, and it is the one reading in this file that is mine rather than his — put to
//     him as a question rather than assumed.)
//  2. It does not apply when the version is UNKNOWN. An override is an instruction about
//     one artifact; a request we cannot attribute to a release is not that artifact, and
//     failing open there would hand an attacker who can break the join exactly the
//     release the advisory names.
//  3. It does not override the OPERATOR'S OWN deny list. Two instructions from the same
//     authority, and the refusing one wins — unchanged from the name-scoped rule.
//
// The audit record and the console carry the override (Decision.Override), so "we block
// known malware" becomes "…unless an administrator has explicitly allowed that release",
// which is the bounded claim D312 asked to be written down before marketing writes the
// other one.
func (f *Firewall) adminAllowsRelease(pkgName, version string, known bool) bool {
	if !known || version == "" {
		return false
	}
	if !f.allow().hasVersion(f.cfg.Ecosystem, pkgName, version) {
		return false
	}
	// THE OPERATOR'S OWN DENY STILL WINS, and it has to be asked HERE rather than left to
	// Evaluate: the version-pinned control point runs before Evaluate's deny check, so an
	// override decided without this would invert the ordering for exactly the entries
	// this feature adds. Found by TestTheOperatorsOwnDenyStillOutranksTheirAllow, which
	// was red on the first run for this reason.
	deny := f.deny()
	if deny.has(f.cfg.Ecosystem, pkgName) || deny.hasVersion(f.cfg.Ecosystem, pkgName, version) {
		return false
	}
	return true
}

// overrideNote is the sentence that travels with an overriding decision: into the log, the
// audit record and the console. One place, so the three cannot describe it differently.
func overrideNote(pkgName, version, advisory string) string {
	return fmt.Sprintf("served by administrator override: version %q of %q is on this organisation's "+
		"allow list, which outranks the known-malware advisory %s naming it (D312). The advisory still "+
		"stands; the allow list entry is a local decision to install this release anyway",
		version, pkgName, advisory)
}

// pinnedMalwareVerdict is the shared rule: given a package and the version this
// request resolves to (and whether we could determine it at all), does a
// version-pinned known-malware advisory refuse it?
func (f *Firewall) pinnedMalwareVerdict(pkgName, version string, known bool) (Decision, bool) {
	if !known {
		if !f.malwareFeed().hasPinned(f.cfg.Ecosystem, pkgName) {
			return Decision{}, false
		}
		return Decision{
			Allowed: false,
			Deny:    denyKnownMalware,
			Rule:    "pinned-advisory:unknown-version",
			Source:  sourceMalwareFeed,
			Reason: fmt.Sprintf("a known-malware advisory names specific versions of %q and this "+
				"request's version could not be determined; refused without contacting upstream",
				pkgName),
		}, true
	}
	e, found := f.malwareFeed().pinnedFor(f.cfg.Ecosystem, pkgName, version)
	if !found {
		return Decision{}, false
	}
	// D312: the administrator's own instruction about THIS release outranks the advisory.
	if f.adminAllowsRelease(pkgName, version, true) {
		note := overrideNote(pkgName, version, e.ID)
		log.Printf("POLICY [administrator-override] %s", note)
		return Decision{Allowed: true, Override: note, Reason: note}, true
	}
	// A NAME-scoped allow reaching a version-pinned advisory: refused, and said out loud
	// with the way to say what they mean. Without this the operator sees their entry
	// ignored and nothing anywhere explains it — the package-wide branch's conflict line
	// cannot fire here, because this advisory names releases rather than the package.
	if f.allow().has(f.cfg.Ecosystem, pkgName) {
		log.Printf("POLICY %q is on the operator allow-list by NAME and version %q is named by the "+
			"known-malware advisory %s -- REFUSED: a name-scoped allow covers releases nobody has looked "+
			"at. Pin the release you judged (\"%s\") to override this advisory for it.",
			pkgName, version, e.ID, joinOperatorEntry(f.cfg.Ecosystem, pkgName, version))
	}
	return Decision{
		Allowed: false,
		Deny:    denyKnownMalware,
		Rule:    e.ID,
		Source:  sourceMalwareFeed,
		Reason: fmt.Sprintf("version %q of %q is listed as known malware (%s); refused without contacting upstream",
			version, pkgName, e.ID),
	}, true
}

// operatorVersionVerdict is the version-scoped DENY rule (#155/D312): given a package and
// the release this request resolves to, does the operator's own deny list refuse it?
//
// It is deliberately the same SHAPE as pinnedMalwareVerdict, including the fail-closed
// branch, and for the same reason: an entry that stops applying because we could not read
// a version is a deny that silently stops denying. What differs is the VOCABULARY, and
// that difference is the point (D193): "your own organisation blocked this release" and
// "this release is publicly reported as malware" are different facts, actioned by
// different people, and a developer must be able to tell them apart in the first sentence.
func (f *Firewall) operatorVersionVerdict(pkgName, version string, known bool) (Decision, bool) {
	deny := f.deny()
	if !deny.hasAnyVersion(f.cfg.Ecosystem, pkgName) {
		return Decision{}, false
	}
	if !known {
		return Decision{
			Allowed: false,
			Deny:    denyOperator,
			Rule:    "deny-list:unknown-version",
			Source:  sourceDenyList,
			Reason: fmt.Sprintf("this organisation's deny list names specific versions of %q and this "+
				"request's version could not be determined; refused without contacting upstream. This is a "+
				"local policy decision, not a published malware advisory -- ask whoever maintains the "+
				"firewall's deny list", pkgName),
		}, true
	}
	if !deny.hasVersion(f.cfg.Ecosystem, pkgName, version) {
		return Decision{}, false
	}
	entry := joinOperatorEntry(f.cfg.Ecosystem, pkgName, version)
	return Decision{
		Allowed: false,
		Deny:    denyOperator,
		Rule:    "deny-list:" + entry,
		Source:  sourceDenyList,
		Reason: fmt.Sprintf("version %q of %q is on this organisation's deny list; refused without "+
			"contacting upstream. Other versions of %q are not affected by this entry. This is a local "+
			"policy decision, not a published malware advisory -- ask whoever maintains the firewall's "+
			"deny list", version, pkgName, pkgName),
	}, true
}

// operatorVersionOnPath is operatorVersionVerdict for an ecosystem whose REQUEST PATH
// names the release although its identity does not -- Maven. Mirrors pinnedMalwareOnPath.
func (f *Firewall) operatorVersionOnPath(pkgName, path string) (Decision, bool) {
	vp, ok := f.eco.(versionedPath)
	if !ok {
		return Decision{}, false
	}
	version, known := vp.VersionFromPath(path)
	return f.operatorVersionVerdict(pkgName, version, known)
}

// operatorVersionInIdentity is operatorVersionVerdict for an ecosystem whose IDENTITY
// carries the release -- OCI. It fires only where an entry could exist; the parser does
// not produce version-scoped OCI entries today (#128's widening is unchanged), so this is
// inert there and stays correct if that changes.
func (f *Firewall) operatorVersionInIdentity(pkgName string) (Decision, bool) {
	if !identityCarriesVersion(f.cfg.Ecosystem) {
		return Decision{}, false
	}
	version, known := identityVersion(f.cfg.Ecosystem, pkgName)
	return f.operatorVersionVerdict(pkgName, version, known)
}

// Evaluate decides whether a given package should be allowed. The flow is
// ecosystem-agnostic: get the source repo (via the active ecosystem), score it,
// compare to the threshold; at any "can't get a score" point, fall back to the
// unscorable policy (which itself consults the approval service).
func (f *Firewall) Evaluate(pkgName string) Decision {
	// LAYER 1 FIRST (D172). This runs ahead of everything else in Evaluate — ahead of
	// the D25 backoff, the repo resolution and the score — for two reasons that are
	// both about ordering, not micro-optimisation:
	//
	//  1. It is the SHARPEST signal we have and the score is the fuzziest. Scorecard
	//     rates a repo's hygiene; this names this package in a published advisory.
	//     Leading with the fuzzy one and consulting the precise one afterwards is the
	//     inversion D172 found in our stack (companion issue: Scorecard's sequencing).
	//  2. It needs NO NETWORK. So a known-malicious package is still refused while
	//     upstream is down, while we are backing off a 429, and inside an air-gap —
	//     precisely the conditions under which every other layer degrades to
	//     "unavailable". A gate that stops gating during an outage is not a gate.
	if e, found := f.malwareFeed().lookupAll(f.cfg.Ecosystem, pkgName); found {
		// The one genuinely surprising outcome in this file, so it is said out loud:
		// the feed OUTRANKS the operator allow-list, because the allow-list is
		// consulted below this point and we return here. That is the safe default --
		// "we vouch for this" must not override "someone published an advisory naming
		// it" -- but from the outside it looks like the allow-list is broken, which is
		// how an operator ends up editing the wrong file for an afternoon.
		// Two shapes of allow entry reach here, and they are refused for DIFFERENT
		// reasons. Saying which is what stops an operator editing the wrong file.
		switch {
		case f.allow().has(f.cfg.Ecosystem, pkgName):
			// A NAME-scoped allow. D312 gives the administrator the last word about an
			// artifact they judged; a bare name judges every future release too, which
			// is the decision they did not make. Tell them how to say what they mean.
			log.Printf("POLICY %q is on the operator allow-list by NAME and in the known-malware feed "+
				"(%s) -- REFUSED: a name-scoped allow covers releases the advisory names that nobody has "+
				"looked at. Pin the release you judged (\"%s@<version>\") to override this advisory for "+
				"it, or remove the package from the feed if this is a false positive.", pkgName, e.ID, pkgName)
		case f.allow().hasAnyVersion(f.cfg.Ecosystem, pkgName):
			// A VERSION-scoped allow exists, and this control point has no version to
			// match it against: the advisory condemns every release, so the refusal is
			// decided on the package name before any release is named. Not silent — an
			// entry that appears to do nothing is the failure this whole file avoids.
			log.Printf("POLICY %q has a VERSION-SCOPED allow entry and the known-malware feed condemns "+
				"EVERY version (%s) -- REFUSED: the advisory is package-wide, so this decision is made "+
				"before any release is named and the entry has nothing to match. It still applies to a "+
				"version-pinned advisory for the same package.", pkgName, e.ID)
		}
		return Decision{
			Allowed: false,
			Deny:    denyKnownMalware,
			Rule:    e.ID,
			Source:  sourceMalwareFeed,
			Reason: fmt.Sprintf("package %q is listed as known malware (%s); refused without contacting upstream",
				pkgName, e.ID),
		}
	}
	// The VERSION-PINNED half of layer 1 (#103), for ecosystems whose identity names
	// the release. Kept here rather than on a byte path because for OCI there is
	// nothing to plumb: D164 already made the reference part of the package name, so
	// the version arrives with the identity and the verdict is version-keyed
	// everywhere downstream (score cache, approval queue, audit log) for free.
	//
	// This is the HIJACK case — a real, widely-used image with one poisoned release —
	// so it must condemn that release and leave its siblings installable. The
	// package-wide lookup above deliberately never fires for these advisories.
	if d, blocked := f.pinnedMalwareDecision(pkgName); blocked {
		return d
	}

	// THE OPERATOR'S OWN LISTS (D193, issue #58) -- second and third control points,
	// deliberately placed HERE: after the published-advisory feed, before everything
	// that needs the network.
	//
	// Why after the feed. If a package is on both, the feed's reason is the more
	// informative one -- it carries a MAL- advisory ID the operator can look up -- and
	// an operator who allow-listed something that is publicly reported as malware
	// should be told THAT, not quietly handed the package. See the log line below:
	// this combination is the one genuinely surprising outcome in the whole file, so
	// it is stated out loud rather than left to be discovered from a served pull.
	//
	// Why before the network. Both lists answer with NO EGRESS, which is what makes
	// them useful in exactly the conditions where every other layer degrades: upstream
	// down, deps.dev rate-limiting us, air-gapped. The same argument the feed makes
	// above, applied in both directions -- a deny that stops denying during an outage
	// is not a deny, and an allow-list that stops allowing during an outage is not an
	// allow-list, it is a suggestion.
	if f.deny().has(f.cfg.Ecosystem, pkgName) {
		// The same surprise the feed case logs above, one layer down, and it was SILENT
		// until #124. An operator adds a name to the allow list, the pull stays refused,
		// and the only trace that their entry was overridden is the rule NAME on the
		// 403 -- so greping the log for "allow" finds their own reload line and nothing
		// else. Two people editing two lists through the console (D193) is exactly how
		// a name ends up on both.
		//
		// Logged per pull rather than once, matching the feed case: the state is rare,
		// and a line that appears only on the first pull after a reload is a line
		// whoever is debugging has already scrolled past.
		if f.allow().has(f.cfg.Ecosystem, pkgName) {
			log.Printf("POLICY %q is on BOTH operator lists -- REFUSED: the deny list "+
				"outranks the allow list. Remove it from the deny list if the allow-list "+
				"entry is the intended one; re-adding it to the allow list cannot change "+
				"the verdict.", pkgName)
		}
		return Decision{
			Allowed: false,
			Deny:    denyOperator,
			Rule:    "deny-list:" + pkgName,
			Source:  sourceDenyList,
			// The reason names the ORGANISATION as the decider, not us, and points at
			// the file. A developer reading this needs to know it is an internal policy
			// call they can appeal to a colleague -- not a security finding about the
			// package, and not a bug in the proxy (D137).
			Reason: fmt.Sprintf("package %q is on this organisation's deny list; "+
				"refused without contacting upstream. This is a local policy decision, "+
				"not a published malware advisory -- ask whoever maintains the firewall's "+
				"deny list", pkgName),
		}
	}
	// The VERSION-SCOPED half of the deny list (#155), for an ecosystem whose identity
	// names the release. Placed with its name-scoped sibling above rather than on a byte
	// path, for the reason D164 gives: for OCI the reference is already part of the
	// identity, so the verdict is version-keyed everywhere downstream for free.
	if d, blocked := f.operatorVersionInIdentity(pkgName); blocked {
		return d
	}
	if f.allow().has(f.cfg.Ecosystem, pkgName) {
		return Decision{
			Allowed: true,
			Reason: fmt.Sprintf("package %q is on this organisation's allow list; "+
				"served without scoring", pkgName),
		}
	}

	// SCORING OFF (D273, launch requirement per D280). Everything above this line has
	// already run: the malware feed, the version-pinned feed, and both operator lists.
	// With no scorer configured there is nothing further to ask about this package, so
	// it is served.
	//
	// ⚠️ WHY THIS IS AN ALLOW AND NOT "unscorable". Reaching the unscorable path would
	// consult FW_UNSCORABLE_POLICY, whose default is `block` — so `off` would refuse
	// every package that is not explicitly allow-listed, which is not a gate anyone
	// can deploy. `off` means "we did not ask", and the honest verdict for a question
	// never asked is the one the other layers already gave.
	//
	// ⚠️ AND WHY IT SITS HERE, not in getScore. Returning a sentinel from the scorer
	// would leave the D25 backoff, the repo resolution and the deps.dev cross-check
	// upstream of it — network calls made to produce a number nobody will read. `off`
	// means no evaluation, so it must short-circuit BEFORE the first thing that
	// touches the network. That is also what makes it usable in an air-gap.
	//
	// D273: "many customers will find value in simply the ability to
	// blacklist/whitelist and package cooldown." Those are exactly the layers above,
	// plus the release-age window applied on the index path in proxy.go — none of
	// which is reached through here.
	if f.cfg.ScorecardMode == scorecardModeOff {
		return Decision{
			Allowed:  true,
			HasScore: false,
			Reason: fmt.Sprintf("package %q served: scoring is disabled (FW_SCORECARD_MODE=off), "+
				"and it is on neither operator list nor in the known-malware feed", pkgName),
		}
	}

	// D25 circuit breaker: a very recent 429 for this package means its scoring
	// sources are actively throttling us. Re-probing now would re-run the whole
	// fan-out (for Maven: metadata + POM + parent POMs) and amplify the storm, so
	// short-circuit to the SAME retryable 503 the probe would have produced — never
	// touching upstream — until the short TTL lapses. Backoff only, never a verdict.
	if f.backoff.active(pkgName) {
		return Decision{Unavailable: true, Reason: transientReason(fmt.Sprintf("scoring for %q", pkgName), errUpstreamRateLimited)}
	}

	// The identity the repo cache is keyed on. For an ecosystem whose package identity
	// can be MUTABLE (an OCI tag), this is the immutable identity behind it, obtained
	// by one revalidating request (ocirevalidate.go, #93/D164). For every other
	// ecosystem it is the package name. A revalidation failure is not a verdict: the
	// name cache is bypassed, the full resolve runs, and nothing is cached under the
	// tag -- the cost is one re-resolve, never a stale approval.
	cacheKey := pkgName
	if r, ok := f.eco.(cacheIdentityResolver); ok {
		if id, err := r.cacheIdentity(f.client, pkgName); err == nil {
			cacheKey = id
		} else {
			if errors.Is(err, errUpstreamUnavailable) || errors.Is(err, errPkgNotFound) {
				// Classified the same way resolveRepo's own failures are, below, so
				// a dead registry is "unavailable" and a missing tag passes through
				// -- rather than being re-fetched only to fail the same way.
				return f.repoLookupFailure(pkgName, err)
			}
			cacheKey = "" // cannot be revalidated: never read or write the name cache
			log.Printf("%s: cache identity for %q could not be revalidated (%v); resolving without the repo cache", f.eco.Name(), pkgName, err)
		}
	}

	repoURL, cached := "", false
	if cacheKey != "" {
		repoURL, cached = f.repos.get(cacheKey)
	}
	if !cached {
		// Cold package: resolve (and verify) its source repo. Coalesced per package
		// name (issue #16) so a cold install's concurrent requests for the SAME
		// package make one set of upstream calls between them, not N — see
		// resolveRepo and flightGroup. Followers share the leader's outcome,
		// including its error, and then each apply the switch below themselves
		// (backoff.mark and the log line are per-request and idempotent).
		res, err := f.repoFlights.do(pkgName, func() (repoResolution, error) {
			return f.resolveRepo(pkgName, cacheKey)
		})
		repoURL = res.repo
		switch {
		case errors.Is(err, errPkgNotFound), errors.Is(err, errUpstreamUnavailable):
			return f.repoLookupFailure(pkgName, err)
		case errors.Is(err, errUpstreamTooLarge):
			// #139: the document arrived intact and is simply bigger than we will buffer.
			// Logged as its own line, naming the cap, because "repo lookup failed" sent an
			// operator hunting a registry problem that does not exist — and because a cap
			// that is biting has to be COUNTABLE before anyone can decide whether it should
			// bite harder.
			//
			// ⚠️ The VERDICT is deliberately unchanged: still unscorable, so the shipped
			// byte-gate default still serves the artifact (D49). Whether an oversize
			// document should instead be a hard deny is a false-refusal trade — a
			// legitimately enormous package would stop installing — and firewall.go's
			// taxonomy requires that choice to be made explicitly rather than inherited.
			// #139 leaves it open. Until then this is visibility, not enforcement, and
			// saying so here keeps the next reader from assuming the gap is closed.
			log.Printf("evaluate %q: upstream metadata exceeds the inspection cap, so the package "+
				"could not be evaluated (served per the unscorable policy): %v", pkgName, err)
			return f.unscorable(pkgName, fmt.Sprintf("could not evaluate %q: its registry metadata is too large to inspect", pkgName))
		case err != nil:
			log.Printf("evaluate %q: repo lookup failed: %v", pkgName, err)
			return f.unscorable(pkgName, fmt.Sprintf("could not determine source repository for %q", pkgName))
		}
		if res.done {
			// Terminal outcome from verification (a borrow-a-score mismatch).
			return res.decision
		}
	}
	if repoURL == "" {
		return f.unscorable(pkgName, fmt.Sprintf("package %q does not declare a usable source repository", pkgName))
	}

	sc, outcome, scoreErr := f.scoreFor(pkgName, repoURL)
	switch outcome {
	case scoreUnavailable:
		if errors.Is(scoreErr, errUpstreamRateLimited) {
			f.backoff.mark(pkgName) // D25: a rate-limited score source backs the package off too
		}
		return Decision{Unavailable: true, Reason: transientReason(fmt.Sprintf("security score for %s", repoURL), scoreErr)}
	case scoreUnscorable:
		return f.unscorable(pkgName, fmt.Sprintf("no security score available for %s", repoURL))
	case scorePending:
		// Async local mode (D18): first (cold) pull of this repo. A background scan
		// is now running (or already was); quarantine THIS request as retryable
		// rather than block it for the whole scan. The next pull reads the cached
		// score (L1/L2) and gets a real verdict.
		return Decision{Pending: true, Reason: fmt.Sprintf("first request for %q; scanning %s in the background, retry shortly", pkgName, repoURL)}
	}
	return f.decideByScore(pkgName, sc.Score, "").withCoverage(sc.Coverage)
}

// repoResolution is what one cold repo lookup produces, bundled into a single
// value so the whole lookup can be shared between coalesced callers (flightGroup
// carries one T). It mirrors verifyRepo's (repo, decision, done) contract:
//
//   - done == false: `repo` is the repo to score (possibly "" — no usable repo).
//   - done == true:  `decision` is TERMINAL — stop and return it. The only such
//     case is a borrow-a-score mismatch (D33/D39).
type repoResolution struct {
	repo     string
	decision Decision
	done     bool
}

// resolveRepo does the actual cold work behind Evaluate's repoCache miss: ask the
// ecosystem for the package's self-declared source repo, cross-check it against
// deps.dev, and cache the result. It is ALWAYS called through f.repoFlights (issue
// #16), so on a cold install these upstream calls happen once per package rather
// than once per concurrent request.
//
// D33/D39: the repo from LookupRepo came from PUBLISHER-CONTROLLED metadata.
// Cross-check it against deps.dev's own package->project record before we cache or
// score it — closing the "borrow-a-score" hole where malware points its `repository`
// at a healthy repo to inherit its score. A mismatch is terminal (routed to
// unscorable/approval, never scored on the borrowed repo); otherwise verifyRepo
// returns the repo to score (the self-declared one, or deps.dev's own when the
// package declared none).
//
// THE VERIFY STEP'S POSITION IS LOAD-BEARING, and is what extends the check to local
// mode (D39) without restructuring the async path: it is upstream of BOTH
// `f.repos.put` below and `scoreFor`, and local mode launches its background scan
// inside scoreFor. So a mismatch returns before `inflight.begin` is ever reached —
// no scan goroutine is started against the borrowed repo — and an adopted deps.dev
// repo is the one that gets scanned and cached. Moving this into resolveRepo keeps
// that ordering exactly (it is still upstream of the put and of scoreFor); the only
// change is that concurrent callers now share one execution of it.
//
// Fan-out is bounded by construction: this runs only on a repoCache MISS, so
// verification costs its deps.dev calls once per package per ScoreCacheTTL, not
// once per pull — which matters more in local mode, where every cold pull of an npm
// tree would otherwise re-probe deps.dev.
//
// A mismatch is deliberately NOT cached, so a later human correction/approval takes
// effect immediately — same reasoning as repoCache not caching a verdict. Coalescing
// preserves that: a flight is dropped as soon as it completes, so only requests that
// overlapped in time share the mismatch, and the next one re-resolves.
//
// cacheKey is the identity the repo cache is read and written under (Evaluate computes
// it; for a mutable OCI tag it is image@digest). Empty means "do not touch the cache":
// the identity could not be revalidated, so a name-keyed entry would be exactly the
// stale approval #93 measured. BOTH read sites honour it -- this one and Evaluate's --
// because #93 recorded that patching one of the two is a silent no-op.
func (f *Firewall) resolveRepo(pkgName, cacheKey string) (repoResolution, error) {
	// Re-check the cache now that we hold the flight: a leader can have finished and
	// filled it between Evaluate's get and our arrival here. Turns that race into a
	// cache hit rather than a duplicate upstream call.
	if cacheKey != "" {
		if repo, ok := f.repos.get(cacheKey); ok {
			return repoResolution{repo: repo}, nil
		}
	}

	repoURL, err := f.eco.LookupRepo(f.client, pkgName)
	if err != nil {
		// Classification (not-found / transient / other) stays in Evaluate, which
		// owns the client-facing Decision; we just hand the error back.
		return repoResolution{}, err
	}

	if f.repoVerificationEnabled() {
		verified, dec, done := f.verifyRepo(pkgName, repoURL)
		if done {
			return repoResolution{decision: dec, done: true}, nil
		}
		repoURL = verified
	}
	if cacheKey != "" {
		f.repos.put(cacheKey, repoURL)
	}
	return repoResolution{repo: repoURL}, nil
}

// repoLookupFailure is Evaluate's classification of the two repo-lookup outcomes that
// are not verdicts, shared by the resolve path and the cache-identity revalidation so
// the two cannot drift apart.
func (f *Firewall) repoLookupFailure(pkgName string, err error) Decision {
	if errors.Is(err, errPkgNotFound) {
		// The package doesn't exist upstream. Not ours to gate: pass the request
		// through and let the registry's own 404 answer. (Blocking here would flood
		// the approval queue with every typo'd install and scanner probe.)
		// Deliberately not cached -- the tiny race where a package is published
		// mid-request resolves on the next request.
		return Decision{Allowed: true, Reason: fmt.Sprintf("package %q unknown upstream; passing through registry response", pkgName)}
	}
	if errors.Is(err, errUpstreamRateLimited) {
		f.backoff.mark(pkgName) // D25: throttle further probes of this package briefly
	}
	log.Printf("evaluate %q: metadata source unavailable: %v", pkgName, err)
	return Decision{Unavailable: true, Reason: transientReason(fmt.Sprintf("registry metadata for %q", pkgName), err)}
}

// scoreOutcome is the four-way result of scoreFor — richer than getScore's
// (float64, error) because async local mode adds a "not yet" state that is neither
// a score nor a failure.
type scoreOutcome int

const (
	scoreReady       scoreOutcome = iota // score is valid; decide on it
	scoreUnavailable                     // transient: sources down -> 403 unavailable, not a verdict (D102)
	scoreUnscorable                      // durable: no score obtainable -> unscorable/approval
	scorePending                         // local cold: a background scan was launched -> 403 pending, not a verdict (D102)
)

// scoreFor resolves a repo to a score for the HOT request path, without ever
// blocking on a live scan. It is the async counterpart to getScore:
//   - stub/api mode: reuse getScore (fast/synchronous — deps.dev + L1). A transient
//     failure maps to scoreUnavailable, any other failure to scoreUnscorable.
//   - local mode: the two-tier async model (D18). Check L1, then the durable L2
//     approval-DB cache. On an L2 hit return the score (or the negative marker ->
//     unscorable). On a cold miss, launch a deduped background scan and report
//     scorePending — the request is quarantined, not held for the scan.
//
// Only local mode is async: it's the slow path the whole feature exists for.
// deps.dev/api stays synchronous because it's already fast and L1-cached.
//
// The third return is the underlying transient error — non-nil only alongside
// scoreUnavailable — so the caller can name a rate limit (HTTP 429) distinctly in
// the client-facing reason (D25). It is otherwise nil.
func (f *Firewall) scoreFor(pkgName, repo string) (cachedScore, scoreOutcome, error) {
	if f.cfg.ScorecardMode != "local" {
		sc, err := f.getScored(repo)
		switch {
		case errors.Is(err, errUpstreamUnavailable):
			log.Printf("evaluate %q: score source unavailable for %s: %v", pkgName, repo, err)
			return cachedScore{}, scoreUnavailable, err
		case err != nil:
			log.Printf("evaluate %q: scorecard failed for %s: %v", pkgName, repo, err)
			return cachedScore{}, scoreUnscorable, nil
		}
		return sc, scoreReady, nil
	}

	// local mode: resolve from the async caches (L1 then durable L2) without
	// launching a scan. A definitive answer — a real score OR a negative marker —
	// short-circuits here.
	if sc, outcome, resolved := f.resolveCachedScore(pkgName, repo); resolved {
		return sc, outcome, nil
	}

	// Cold: no cached score and no durable marker. Launch AT MOST ONE background
	// scan for this repo.
	if f.inflight.begin(repo) {
		// Double-check now that we hold the slot. The cache resolution above and
		// this begin() are not atomic, so a scan for this repo can finish — writing
		// a score OR a durable negative marker — and release the slot in that gap.
		// Re-resolving with the SAME logic means we never re-scan on top of a result
		// that now exists (the single-install fan-out this guard exists to kill).
		// begin() happens-after that scan's done(), which happens-after its cache/L2
		// write, so this re-read is guaranteed to observe it. A transient-failure
		// scan writes nothing durable, so it stays cold and correctly re-triggers.
		if sc, outcome, resolved := f.resolveCachedScore(pkgName, repo); resolved {
			f.inflight.done(repo)
			return sc, outcome, nil
		}
		go f.runBackgroundScan(pkgName, repo)
	}
	return cachedScore{}, scorePending, nil
}

// resolveCachedScore answers a repo from the two async-mode caches WITHOUT
// launching a scan: L1 (per-replica) then the durable L2 approval-DB marker. It
// returns resolved=false only when the repo is genuinely cold — never scanned, or
// L2 unreachable — which is the one case scoreFor turns into a background scan.
// Factoring it out lets the cold path re-run the exact same resolution after
// winning the in-flight slot, closing the check-then-begin re-scan window for both
// a real score and a negative marker. When resolved is false the score/outcome are
// meaningless and must be ignored.
func (f *Firewall) resolveCachedScore(pkgName, repo string) (cachedScore, scoreOutcome, bool) {
	if s, ok := f.cache.get(repo); ok {
		return s, scoreReady, true
	}
	rec, found, err := f.lookupScoreRecord(repo)
	if err != nil {
		// L2 unreachable: we can't read (or later persist) a durable result, so
		// treat as cold and let a background scan try — its result caches in this
		// replica's L1 even if the durable write later fails. Degrades, not breaks.
		log.Printf("evaluate %q: L2 score lookup failed for %s: %v (treating as cold)", pkgName, repo, err)
		return cachedScore{}, 0, false
	}
	if found && f.l2Stale(rec.UpdatedAt) {
		// The row exists but is older than FW_SCORE_L2_TTL: its trust has expired
		// (issue #12 — a repo that later degraded, or a package hijacked after the
		// first scan, would otherwise keep its old verdict forever). Treat it EXACTLY
		// like cold so scoreFor launches one deduped background re-scan and quarantines
		// the pull as pending. We deliberately do NOT serve the stale score in the
		// meantime: this is security software and stale trust is the whole finding.
		// Applies to the negative marker too — a repo we once couldn't score may have
		// become scorable, so its marker also earns a re-scan when it ages out.
		log.Printf("evaluate %q: L2 score for %s is stale (age > %s), re-scanning", pkgName, repo, f.cfg.ScoreL2TTL)
		return cachedScore{}, 0, false
	}
	switch {
	case found && rec.Score != nil:
		sc := cachedScore{Score: *rec.Score, Coverage: rec.coverage()}
		f.cache.put(repo, sc) // warm L1 from L2 so siblings in this install skip it
		return sc, scoreReady, true
	case found:
		// The negative marker: a prior background scan could not score this repo.
		// Route to the unscorable/approval path WITHOUT launching another scan.
		return cachedScore{}, scoreUnscorable, true
	default: // cold: never scanned
		return cachedScore{}, 0, false
	}
}

// l2Stale reports whether a durable L2 row written at updatedAt has aged past the
// configured freshness window (FW_SCORE_L2_TTL). Two cases return false — meaning
// "still fresh, keep trusting it":
//   - TTL <= 0: freshness is disabled (the default), so a row is never stale. This
//     is the explicit opt-out that preserves the pre-#12 remember-forever behavior.
//   - updatedAt is zero: the row carried no timestamp (an older record, or a store
//     that doesn't stamp). We can't judge its age, so we don't force needless churn.
//
// Only a positive TTL with a real timestamp older than the window is stale.
func (f *Firewall) l2Stale(updatedAt time.Time) bool {
	if f.cfg.ScoreL2TTL <= 0 || updatedAt.IsZero() {
		return false
	}
	return time.Since(updatedAt) > f.cfg.ScoreL2TTL
}

// runBackgroundScan performs the live scan the hot path refused to wait for, and
// records the result durably (L2) so later pulls decide instantly. It is the ONLY
// place a scan blocks now — and it blocks a goroutine, never a client. Exactly one
// runs per repo at a time (inflight.begin gated the launch); done() releases the
// slot so a later pull can retry after a transient failure.
func (f *Firewall) runBackgroundScan(pkgName, repo string) {
	defer f.inflight.done(repo)
	score, cov, err := f.scanRepo(repo)
	switch {
	case err == nil:
		f.cache.put(repo, cachedScore{Score: score, Coverage: cov}) // L1: this replica decides instantly next pull
		f.recordScore(repo, score, cov)                             // L2: durable, shared across replicas/restarts
		log.Printf("background scan %q (%s) -> score %.1f (cached)", pkgName, repo, score)
	case errors.Is(err, errUpstreamUnavailable):
		// Our scanner/infra was unreachable — transient. Record NOTHING durable so
		// the next pull re-triggers a fresh scan instead of pinning a failure.
		log.Printf("background scan %q (%s): scanner unavailable, will retry on next pull: %v", pkgName, repo, err)
	default:
		// The scanner ran but could not score this repo (repo gone, no token, etc.).
		// Persist the NEGATIVE marker so we don't re-scan it on every pull forever;
		// the next pull reads it and routes to the unscorable/approval path.
		log.Printf("background scan %q (%s): unscorable, recording negative marker: %v", pkgName, repo, err)
		f.recordScoreUnscorable(repo)
	}
}

// decideByScore turns a score into a Decision. At/above the threshold -> allow
// (decideFinal). BELOW the threshold is deliberately NOT a hard block (D11,
// 2026-07-08): a false-low score is real — a healthy project whose package points
// at a mirror repo, or many packages published from one repo that has no Scorecard
// entry — and such a package must not be permanently uninstallable with no appeal
// (live testing made axios uninstallable over a 4.9-vs-5.0 dependency). So a
// below-threshold package routes through the SAME human-override path as an
// unscorable one (approve / deny / supply-repo / queue-pending); with no ruling it
// is recorded pending and blocked for now. The threshold thus becomes just the
// line above which no human is needed, not a contentious hard cutoff.
//
// It asks the POLICY RULESET for the verdict (via decideFinal), not the raw
// threshold. Under the shipped default ruleset those are the same test — that
// equivalence is pinned in policy_test.go — but routing through the engine is
// what lets increment 3 move this decision into configurable rules without
// touching the human-override flow below.
//
// D272 (2026-09-19) EXTENDS D11 in one direction and one only: asked whether a
// person's explicit block should override a package that passes on its score,
// The project said "yes". So the allow branch below now consults a RECORDED human deny
// before it returns. That is the whole of the change (#132) — D11's other half
// stands: with no ruling on record, a passing score is still an allow, and the
// human-override path is still where a REFUSED package goes to be appealed.
func (f *Firewall) decideByScore(pkgName string, score float64, source string) Decision {
	// One ruleset consult, reused for both branches. (This previously compared
	// the threshold here AND again inside decideFinal; the two could only ever
	// agree, so collapsing them is a simplification, not a behaviour change.)
	dec := f.decideFinal(pkgName, score, source)
	if dec.Allowed {
		if denied, isDeny := f.humanDenyOnRecord(pkgName, fmt.Sprintf(
			"overriding a passing score %.1f >= %.1f", score, f.cfg.ScoreThreshold)); isDeny {
			return denied
		}
		return dec
	}
	// Still names the configured threshold, because under the default ruleset
	// that IS why the package was refused. Increment 3 gives each rule its own
	// reason string and this becomes the matched rule's text.
	why := fmt.Sprintf("scored %.1f, below required %.1f", score, f.cfg.ScoreThreshold)
	if ruled, handled := f.applyHumanRuling(pkgName, why); handled {
		return ruled
	}
	return dec // the block, now recorded pending above
}

// decideFinal applies the POLICY RULESET with NO approval consult — the terminal
// decision. It is used for the allow path and for re-scoring a human-supplied
// repo, where re-entering the override logic would loop. The optional source
// annotates where the score came from, for the log/reason.
//
// The verdict comes from f.policyAllows (policy.go), which walks the ordered
// ruleset first-match-wins and falls through to an implicit block. Under the
// shipped default ruleset that is exactly the old `score >= threshold` test; the
// reason strings below are deliberately unchanged, because keeping them
// byte-identical is what makes this increment provably a no-op for existing
// deployers (pinned by TestDecideFinalMatchesLegacyDecision).
func (f *Firewall) decideFinal(pkgName string, score float64, source string) Decision {
	suffix := ""
	if source != "" {
		suffix = " [" + source + "]"
	}
	rule, allowed := f.policyAllows(pkgName, score)
	if allowed {
		return Decision{
			Allowed:  true,
			Score:    score,
			HasScore: true,
			Reason:   fmt.Sprintf("score %.1f >= threshold %.1f%s", score, f.cfg.ScoreThreshold, suffix),
		}
	}
	return Decision{
		Allowed:  false,
		Score:    score,
		HasScore: true,
		Deny:     denyScore,
		Rule:     f.ruleset().ruleID(chainVerdict, rule),
		Source:   f.policySource(),
		Reason:   fmt.Sprintf("BLOCKED: %q scored %.1f, below required %.1f%s", pkgName, score, f.cfg.ScoreThreshold, suffix),
	}
}

// humanDenyOnRecord asks the approval service whether a human has ALREADY recorded
// a "denied" ruling for pkgName, and nothing else. It is the allow path's consult
// (D272), deliberately narrower than applyHumanRuling in three ways, each of which
// is a reason a literal "move applyHumanRuling above the allow" would be wrong:
//
//  1. It never records the package PENDING. applyHumanRuling queues every package it
//     finds no ruling for, which is right on the refuse path (someone must decide)
//     and wrong on the allow path: every package the policy allows — nearly all
//     traffic — would land in the review queue. TestAnAllowedPackageIsNotQueued
//     pins that.
//  2. It ignores "approved". A package the policy already allows gains nothing from
//     an approval, and honouring one here would replace the policy's own reason
//     string with a human one in the audit trail for a decision nobody made.
//  3. It ignores a human-supplied repoUrl. Re-scoring a repo a human supplied is an
//     APPEAL against a refusal; applying it to a package that already passes could
//     only turn an allow into a block through a side door D272 did not open.
//
// Fail-safe, unchanged from the refuse path: an approval service that is disabled,
// unreachable, or erroring falls back to policy rather than breaking the pull. The
// consequence is worth naming rather than discovering — while approval is down, a
// recorded deny on an otherwise-passing package is NOT enforced. The deny list is
// the mechanism that survives an approval outage, and it is the one the console
// points at for exactly that reason.
func (f *Firewall) humanDenyOnRecord(pkgName, why string) (Decision, bool) {
	if f.cfg.ApprovalURL == "" {
		return Decision{}, false
	}
	d, found, err := f.lookupApproval(pkgName)
	if err != nil {
		log.Printf("evaluate %q: approval lookup failed on the allow path: %v "+
			"(serving per policy; a recorded human deny is NOT in force while approval is unreachable)", pkgName, err)
		return Decision{}, false
	}
	if !found || d.Verdict != "denied" {
		return Decision{}, false
	}
	return Decision{Allowed: false, Deny: denyHuman, Rule: "approval:denied", Source: sourceApproval,
		Reason: fmt.Sprintf("DENIED by human (%s)", why)}, true
}

// applyHumanRuling consults the approval service for a human decision on pkgName.
// Returns (decision, true) when a human ruling determines the outcome: denied ->
// block, approved -> allow, or a supplied repoUrl -> re-score THAT repo (via
// decideFinal, so we never re-enter approval and loop). Returns (_, false) when
// there is no ruling yet — recording the package as "pending" so it enters the
// review queue — or when approval is disabled/unreachable (fail-safe). The caller
// then applies its own default (a block for a below-threshold score;
// UnscorablePolicy for an unscorable package). This one path is shared by BOTH
// cases (D11), so a human override works identically whether a package scored too
// low or couldn't be scored at all.
func (f *Firewall) applyHumanRuling(pkgName, why string) (Decision, bool) {
	if f.cfg.ApprovalURL == "" {
		return Decision{}, false
	}
	d, found, err := f.lookupApproval(pkgName)
	switch {
	case err != nil:
		log.Printf("evaluate %q: approval lookup failed: %v (falling back to policy)", pkgName, err)
		return Decision{}, false
	case found && d.Verdict == "denied":
		return Decision{Allowed: false, Deny: denyHuman, Rule: "approval:denied", Source: sourceApproval,
			Reason: fmt.Sprintf("DENIED by human (%s)", why)}, true
	case found && d.Verdict == "approved":
		return Decision{Allowed: true, Reason: fmt.Sprintf("APPROVED by human (%s)", why)}, true
	case found && d.RepoURL != "":
		// Human corrected the package->repo association. Score THAT repo and take
		// it as final (decideFinal, not decideByScore) so we don't re-consult/loop.
		if repo := normalizeGitHub(d.RepoURL); repo != "" {
			if sc, serr := f.getScored(repo); serr == nil {
				return f.decideFinal(pkgName, sc.Score, "human-supplied repo "+repo).withCoverage(sc.Coverage), true
			} else {
				log.Printf("evaluate %q: scoring human-supplied repo %s failed: %v (falling back to policy)", pkgName, repo, serr)
			}
		} else {
			log.Printf("evaluate %q: human-supplied repo %q is not a usable GitHub URL", pkgName, d.RepoURL)
		}
		return Decision{}, false
	case !found:
		// First time we've needed a human on this package — queue it for review.
		f.recordPending(pkgName, why)
		return Decision{}, false
	}
	return Decision{}, false // already "pending" (no override yet), or fell through
}

// unverified handles a DURABLY unverified package->repo link (D36 Ruling A): deps.dev
// has no source-repo record for the package, or its record contradicts the repo the
// package claims. Like unscorable it consults the human-ruling path FIRST — so a
// reviewer can approve the package or supply the correct repo, and an un-ruled package
// lands in the review queue rather than vanishing — but with no ruling it BLOCKS.
//
// Why this is not just unscorable(): that defers to UnscorablePolicy, so a deployment
// running FW_UNSCORABLE_POLICY=allow (fail-open / monitoring mode) would get NO
// protection from the cross-check at all — a borrowed repo would be waved through with
// a log. Ruling A makes the unverified posture its own knob so "I accept unscorable
// packages" can't silently also mean "I accept unverifiable provenance claims".
//
// Fail-safe like unscorable: an unreachable approval service falls back to policy (here,
// the block) rather than breaking the pull with an error.
//
// MIGRATION NOTE (issue #58 increment 3). The unverified CATEGORY is now a rule in
// the ordered ruleset, but FW_UNVERIFIED_POLICY itself is NOT — it is consulted
// upstream in verifyRepo (depsdevrepo.go), where "open-with-visibility" proceeds on
// the self-declared repo and this function is never called. So the knob decides
// whether a package REACHES this category, not what happens once it has, and the
// rule is unconditionally reject to match. Moving that upstream branch onto a rule
// would change where the decision is made and is deliberately left to its own
// increment rather than smuggled in here.
func (f *Firewall) unverified(pkgName, why string) Decision {
	if dec, handled := f.applyHumanRuling(pkgName, why); handled {
		return dec
	}
	// Consulted for its side effect and for the ruleset's authority over the
	// verdict, even though the shipped rule always rejects: if an operator ever
	// reorders an allow above it, that must take effect here rather than being
	// silently overridden by a hardcoded block.
	rule, action := f.categoryAction(pkgName, denyUnverified)
	if action != ActionReject {
		return Decision{
			Allowed:  true,
			HasScore: false,
			Reason:   fmt.Sprintf("unverified (%s); allowed by policy rule", why),
		}
	}
	return Decision{
		Allowed:  false,
		HasScore: false, // never carries the score of the repo we refused to trust
		Deny:     denyUnverified,
		Rule:     f.ruleset().ruleID(chainVerdict, rule),
		Source:   f.policySource(),
		Reason: fmt.Sprintf("BLOCKED: unverified (%s); policy=%s — set FW_UNVERIFIED_POLICY=%s to proceed on the self-declared repo with a log instead",
			why, unverifiedPolicyClosed, unverifiedPolicyOpen),
	}
}

// unscorable handles the case where we cannot get a score at all. It routes
// through the same human-ruling path as a below-threshold score (approve / deny /
// supply-repo / queue-pending); with no human ruling it falls back to the
// configured UnscorablePolicy. Fail-safe: an unreachable approval service never
// breaks a pull.
func (f *Firewall) unscorable(pkgName, why string) Decision {
	if dec, handled := f.applyHumanRuling(pkgName, why); handled {
		return dec
	}
	// The posture now comes from the ordered ruleset's unscorable CATEGORY rule
	// (D76), not from a direct read of cfg. Under the shipped default that is the
	// same test — `UnscorablePolicy != "block"` — pinned by
	// TestUnscorableMatchesLegacyPolicy; what it buys is that an operator editing
	// one ordered list can see and move this line relative to the others.
	rule, action := f.categoryAction(pkgName, denyUnscorable)
	allowed := action != ActionReject
	kind := denyUnscorable
	ruleName, source := f.ruleset().ruleID(chainVerdict, rule), f.policySource()
	if allowed {
		kind = denyNone // an allow is not a denial at all
		ruleName, source = "", ""
	}
	return Decision{
		Allowed:  allowed,
		HasScore: false,
		Deny:     kind,
		Rule:     ruleName,
		Source:   source,
		Reason:   fmt.Sprintf("unscorable (%s); policy=%s", why, f.cfg.UnscorablePolicy),
	}
}

// ─────────────────── naming the coverage gap (issue #14) ───────────────────
//
// normalizeGitHub refuses every forge but GitHub, and that refusal is how a
// GitLab- or Bitbucket-hosted package becomes "unscorable". Until now the refusal
// was SILENT: the operator saw "does not declare a usable source repository",
// which reads as "this package declares nothing" when the truth is often "this
// package declares a repository we decline to normalise". Those are different
// facts and they call for different fixes.
//
// This does NOT change a single verdict. It changes what the log says, so the size
// of the gap becomes countable instead of arguable — issue #14's second bullet,
// which is the only part of it that needs no ruling.
//
// ── WHY THE FIX ITSELF IS NOT HERE, MEASURED 2026-09-15 ──────────────────────
//
// The obvious next step — "accept gitlab.com too" — is refuted for api mode and
// unfinished for local mode:
//
//   - deps.dev has NO Scorecard for GitLab. It knows the projects (stars, license,
//     description all come back on a 200) and simply carries no `scorecard` key,
//     where the GitHub record has one. Bitbucket 404s; Codeberg is rejected as a
//     malformed project key. So widening normalisation in api mode would turn
//     "unscorable because we declined" into "unscorable because deps.dev has no
//     score" — same verdict, one more upstream round-trip per package.
//   - Scorecard itself DOES score GitLab (v5.2.1 returned 4.8 for
//     gitlab.com/gitlab-org/gitlab-runner), so local mode is real work. But it
//     exits NON-ZERO while writing a complete report, which scanner/scorecard.go
//     currently discards (#133), it is never given a GITLAB_AUTH_TOKEN, and
//     Scorecard EXCLUDES errored checks from its aggregate rather than zeroing
//     them — that 4.8 came from 11 of 18 checks. Comparing a partial-coverage
//     score to FW_SCORE_THRESHOLD is comparing two different measurements, which
//     is a question about what the threshold MEANS, not a technique call.
//
// Full numbers are recorded on issue #14. Measure the gap first; that is what this
// code is for.

// forgeOf names the source forge in a repository URL we refused, or "" when the
// string is not a forge URL at all.
//
// The distinction is the whole point: a package with no `repository` field and a
// package whose repository is on GitLab both reach the unscorable branch today,
// and only the second one is evidence for widening forge support. A homepage like
// "https://lodash.com" is neither, and must stay silent or the signal drowns.
//
// It deliberately reuses normalizeGitHub's own prefix-stripping rather than
// url.Parse: these strings are the same publisher-written soup that function
// exists to survive (git+ssh, scm:git:, bare host/owner/name with no scheme), and
// two different parsers for one input is how the respelling bugs got in (#59).
//
// ⚠️ IT STILL CANNOT TELL A REPO FROM A DOCS SITE, AND IT NEVER WILL. Any "host/a/b"
// shape reads as a forge, and a documentation URL has that shape: nothing in the
// STRING separates docs.python.org/3/library from git.example.com/team/project. That
// is a property of the input, not a defect to fix here.
//
// What changed is WHO CALLS IT. When !289 shipped this, the PyPI caller passed every
// project_urls value, so "Documentation" entries were announced as unsupported forges
// — a caveat this comment carried rather than fixed, because the evidence to fix it
// did not exist yet. #134 supplied it: the LABEL is the discriminator, and
// pypiURLRank now encodes it. Every caller passes only source-ish candidates —
// PyPI's ranked ones, and for npm, Maven and OCI the single repository/SCM field,
// which is source-ish by definition.
//
// So the report now names the forge of a URL that WOULD have been chosen as the repo.
// Still an INDICATOR rather than a census — a package can name its source somewhere
// this code never looks — but no longer one that counts docs sites.
func forgeOf(raw string) string {
	s := stripRepoURLDecoration(raw)
	if s == "" {
		return ""
	}
	parts := strings.Split(s, "/")
	// host + owner + name. Fewer segments is a bare domain or a homepage, not a
	// repository, and naming it would report a gap that does not exist.
	if len(parts) < 3 || parts[1] == "" || parts[2] == "" {
		return ""
	}
	host := strings.ToLower(parts[0])
	// A host with no dot is not a forge (it is a relative path, or junk).
	if !strings.Contains(host, ".") {
		return ""
	}
	if host == "github.com" {
		return "" // supported; nothing to report
	}
	return host
}

// noteUnsupportedForge logs, at most once per lookup, that a package named a
// repository on a forge we do not score.
//
// Called ONLY where an ecosystem gives up — never per candidate. A PyPI project
// listing a GitHub repo in project_urls and a GitLab mirror in home_page resolves
// fine on the first, and must not be counted as a gap because of the second; that
// is why the candidates are passed here together instead of each being checked at
// its own normalizeGitHub call site.
func noteUnsupportedForge(eco, pkg string, candidates ...string) {
	for _, c := range candidates {
		if forge := forgeOf(c); forge != "" {
			log.Printf("coverage %s %q: source repository is on %s, which we do not score "+
				"(treated as unscorable; see #14)", eco, pkg, forge)
			return
		}
	}
}

// stripRepoURLDecoration removes the scheme/transport prefixes and any ref or
// query fragment from a publisher-written repository URL, leaving "host/path".
//
// Split out of normalizeGitHub so forgeOf sees EXACTLY the same string that the
// GitHub check saw. If these two ever drifted, a URL could be refused by one and
// unrecognised by the other, and the gap report would quietly stop matching the
// gap.
func stripRepoURLDecoration(raw string) string {
	if raw == "" {
		return ""
	}
	s := raw
	s = strings.TrimPrefix(s, "git+")
	s = strings.TrimPrefix(s, "git://")
	s = strings.TrimPrefix(s, "ssh://git@")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	// Drop any git ref/fragment or query (e.g. OCI source labels use a
	// "...repo.git#<commit>:<tag>" form): keep only the part before '#' or '?'.
	if i := strings.IndexAny(s, "#?"); i >= 0 {
		s = s[:i]
	}
	return s
}

// normalizeGitHub turns the many shapes of repository URL packages use
// (git+https://github.com/owner/name.git, git://..., https://github.com/owner/name)
// into the bare "github.com/owner/name" form. Returns "" if it isn't a
// recognizable GitHub URL — which is itself the signal to treat as unscorable.
func normalizeGitHub(raw string) string {
	if raw == "" {
		return ""
	}
	s := stripRepoURLDecoration(raw)
	if !strings.HasPrefix(s, "github.com/") {
		return "" // only GitHub is supported by the scorecard lookup for now
	}
	parts := strings.Split(s, "/")
	if len(parts) < 3 {
		return ""
	}
	owner := parts[1]
	name := parts[2]
	// The name segment may carry junk: a ".git" suffix, a ":tag" or "@ref". Cut
	// at the first ':' or '@', then strip a trailing ".git".
	if i := strings.IndexAny(name, ":@"); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimSuffix(name, ".git")
	if owner == "" || name == "" {
		return ""
	}
	if githubReservedOwner(owner) {
		return "" // not a repository at all — see below
	}
	// keep exactly github.com/owner/name, dropping any deeper path
	return "github.com/" + owner + "/" + name
}

// githubReservedOwner reports whether an "owner" segment is really one of
// GitHub's own reserved routes, so "github.com/<that>/<x>" is not a repository.
//
// MEASURED, not guessed (#134). Across 124 popular PyPI packages, five declared a
// Funding or Sponsor URL of the form github.com/sponsors/<user>, which normalised
// into a perfectly well-formed "repo" that does not exist: attrs, pydantic,
// starlette, uvicorn, hatchling. Scoring it cannot work, and it is worse than
// merely useless — deps.dev has no record for a Sponsors page, so verifyRepo saw a
// definite disagreement with the real source repo and fired the BORROW-A-SCORE
// tripwire, refusing a top-100 package and logging that it might be borrowing a
// score. The wrong repo produced a security accusation, not a missing number.
//
// THIS LIST IS THE ENTIRE SURFACE, in the sense !80 and !86 use: every name NOT on
// it is treated as a real owner. That is the safe direction here — a reserved name
// wrongly omitted keeps today's behaviour, while a real owner wrongly INCLUDED
// would make a legitimate package unscorable. So it holds only routes GitHub
// actually reserves at the top level, and `sponsors` is the only one measured in
// the wild. Deliberately NOT a general "does this repo exist" check: that is a
// network call on the metadata path, and the whole point is to decide from the
// string alone.
func githubReservedOwner(owner string) bool {
	switch strings.ToLower(owner) {
	case "sponsors", "orgs", "apps", "marketplace", "features",
		"about", "topics", "collections", "settings", "notifications":
		return true
	}
	return false
}

// smallJSONMaxBytes bounds every small JSON document this package reads over the
// network: deps.dev score and source-repo records, an OCI registry token, our own
// scheduler's scan result, and the approval service's decision records. All of them
// were unbounded (#135).
//
// Deliberately much smaller than the registry-metadata caps: these are records of a
// few hundred bytes, not package indexes, so a document anywhere near this size is
// already a sign something is wrong.
//
// The scheduler and the approval service are OUR OWN and still get the cap. They are
// reached over a network, and "we wrote the other end" has never been a reason to
// decode without a limit — it only changes who has to be compromised first.
const smallJSONMaxBytes = 8 << 20 // 8 MiB, matching mavenBodyMaxBytes

// depsDevResponse is the minimal slice of the deps.dev project API response
// that carries the OpenSSF Scorecard overall score. We declare only the field
// we need; encoding/json ignores the rest.
//
// OverallScore is a *pointer* on purpose: deps.dev may know a project but have
// no Scorecard for it, in which case the field is absent. A plain float64 would
// decode an absent field as 0.0 — indistinguishable from a genuine zero score,
// which would wrongly BLOCK the package. A nil pointer unambiguously means
// "no score data," which we route to the unscorable policy instead.
type depsDevResponse struct {
	Scorecard struct {
		OverallScore *float64 `json:"overallScore"`
	} `json:"scorecard"`
}

// getScore returns the OpenSSF Scorecard overall score for a
// github.com/owner/name repo, dispatching on the configured mode:
//
//	"stub"  - a fixed score, so the pipeline runs offline/deterministically
//	"api"   - the precomputed score from Google's deps.dev API (popular repos only)
//	"local" - a fresh scan from our own scanner service (any repo, but slower)
//
// It fronts both real modes with the L1 in-memory score cache: getScore runs on
// EVERY request for a package (metadata + each tarball/file), so without this a
// single `npm install`/`pip install` fans out into many identical scoring calls —
// D12's "9× in one install" (and, for deps.dev, the exact load that risks the
// rate-limit/403 we hit in Phase 2). Only a successful numeric score is cached; a
// lookup failure is deliberately NOT cached, so a transient outage or a
// "no score data" result is re-evaluated on the next pull rather than pinned.
//
// The cache alone only helps the SECOND lookup, so on a COLD repo those same
// concurrent requests all miss and all call deps.dev. scoreFlights (issue #16)
// closes that window: concurrent lookups of the same repo share one upstream call.
// It is coalescing, not caching — see flightGroup — so the "failures are not
// cached" contract above is unchanged: an error is shared with the callers that
// were already waiting, and the next request retries from scratch.
// stubScore is what "stub" mode returns for every repository. A named constant rather
// than a literal because the startup banner now states what it MEANS for the configured
// threshold (stubScoringNotice), and a banner that disagreed with the scorer would be
// worse than no banner at all.
const stubScore = 7.5

// scorecardModeOff disables scoring entirely (D273): the gate runs on the malware feed,
// the operator lists and the release-age window alone. Named rather than repeated as a
// literal because three places must agree on it — the Evaluate short-circuit, the
// readiness probe, and the startup banner — and a fourth spelling would be a silent
// downgrade in whichever one missed it.
const scorecardModeOff = "off"

func (f *Firewall) getScore(repo string) (float64, error) {
	sc, err := f.getScored(repo)
	return sc.Score, err
}

// getScored is getScore with the coverage the score was computed over (#154).
func (f *Firewall) getScored(repo string) (cachedScore, error) {
	if f.cfg.ScorecardMode == "stub" {
		return cachedScore{Score: stubScore}, nil // fixed, deterministic; never cached
	}
	if sc, ok := f.cache.get(repo); ok {
		return sc, nil
	}

	return f.scoreFlights.do(repo, func() (cachedScore, error) {
		// Re-check now that we hold the flight: a leader can have finished and
		// filled the cache in the gap between the get above and our arrival here.
		// Cheap (one map read) and it turns that race into a cache hit instead of
		// a redundant upstream call.
		if sc, ok := f.cache.get(repo); ok {
			return sc, nil
		}

		var (
			sc  cachedScore
			err error
		)
		switch f.cfg.ScorecardMode {
		case "local":
			sc.Score, sc.Coverage, err = f.scanRepo(repo)
		default: // "api"
			sc.Score, err = f.getScoreFromDepsDev(repo) // deps.dev reports no coverage: unknown, not partial
		}
		if err != nil {
			return cachedScore{}, err // failures are not cached — next pull retries
		}

		f.cache.put(repo, sc)
		return sc, nil
	})
}

// getScoreFromDepsDev reads the precomputed OpenSSF Scorecard score that Google
// serves via the free deps.dev API. Fast, but only covers repos deps.dev has
// already scored — the popular ones. Less-popular repos come back unscorable
// here, which is exactly what "local" mode (our own scanner) exists to cover.
func (f *Firewall) getScoreFromDepsDev(repo string) (float64, error) {
	// deps.dev exposes precomputed scorecard results at this endpoint. We use the
	// stable "v3" API (not "v3alpha"), and url.PathEscape turns "owner/name" into
	// the "owner%2Fname" form the API requires (escaped slashes).
	api := fmt.Sprintf("%s/v3/projects/%s", f.depsDevBase, url.PathEscape(repo))
	req, err := http.NewRequest(http.MethodGet, api, nil)
	if err != nil {
		return 0, err
	}
	// Identify ourselves. Public APIs/CDNs sometimes reject requests with a
	// missing or generic user agent (a likely cause of the earlier 403s). The const
	// is shared with the firewall's User-Agent transport (see useragent.go).
	req.Header.Set("User-Agent", userAgent)

	resp, err := f.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("deps.dev: %w: %v", errUpstreamUnavailable, err)
	}
	defer closeDrained(resp.Body)
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		// Rate-limited or erroring — transient, NOT "this repo has no score".
		// Routed to a 503 (client retries) instead of the unscorable policy. A 429
		// carries the rate-limited sentinel so the 503 reason can name it (D25);
		// both still wrap errUpstreamUnavailable, so the routing is identical.
		transient := errUpstreamUnavailable
		if resp.StatusCode == http.StatusTooManyRequests {
			transient = errUpstreamRateLimited
		}
		return 0, fmt.Errorf("deps.dev: %w (status %d)", transient, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		// Includes 404 (deps.dev doesn't know this project) — genuinely
		// "no score available", handled as unscorable.
		return 0, fmt.Errorf("deps.dev returned status %d", resp.StatusCode)
	}
	var dd depsDevResponse
	if err := decodeCapped(resp.Body, smallJSONMaxBytes, &dd); err != nil {
		return 0, err
	}
	if dd.Scorecard.OverallScore == nil {
		// Project is known to deps.dev but has no Scorecard — not a zero score.
		return 0, fmt.Errorf("deps.dev has no scorecard data for %s", repo)
	}
	return *dd.Scorecard.OverallScore, nil
}

// scannerResponse is the slice of the scheduler's /scan reply the firewall needs.
// The scan result also carries the full per-check breakdown; the decision only
// needs the aggregate score (persisting the breakdown for the review UI is later
// work).
type scannerResponse struct {
	Score float64 `json:"score"`

	// Coverage (#133). Scorecard EXCLUDES a check it could not evaluate from its
	// aggregate rather than zeroing it, so a report with errored checks carries a
	// score computed over a SUBSET. Without these two numbers the firewall cannot
	// tell such a score from a full one, and comparing it to FW_SCORE_THRESHOLD
	// silently changes what the threshold means.
	ScoredChecks int `json:"scoredChecks"`
	TotalChecks  int `json:"totalChecks"`

	// The per-check breakdown, decoded for ONE purpose: the required-check floor
	// (D271, scorecardfloor.go) needs to know WHICH checks errored, by name. A count
	// cannot tell losing Dangerous-Workflow from losing License. Score is -1 when
	// Scorecard could not evaluate the check, per the scanner's CheckResult contract.
	Checks []scannerCheck `json:"checks"`
}

type scannerCheck struct {
	Name  string `json:"name"`
	Score int    `json:"score"`
}

// getScoreFromScanner asks the scheduler to run OpenSSF Scorecard against the repo
// on demand (it launches a run-once scanner container per scan, D16) and returns
// the aggregate score. Unlike deps.dev, this can score any repo — at the cost of a
// live, slower scan. The HTTP contract (POST /scan {repo} → 200 {score…}, non-200
// → unscorable) is unchanged from the old persistent scanner, so no code changed
// here when the target became the scheduler.
func (f *Firewall) getScoreFromScanner(repo string) (float64, error) {
	score, _, err := f.scanRepo(repo)
	return score, err
}

// scanRepo is getScoreFromScanner with the report's COVERAGE alongside the score
// (#133): how many checks the aggregate was computed over, and which it was computed
// without. The hot path needs only the number; the background scan records both, so
// that a partial score which passed the D271 floor stays legible on the control plane
// and the console instead of being stored as a bare number indistinguishable from a
// full one.
func (f *Firewall) scanRepo(repo string) (float64, scoreCoverage, error) {
	var none scoreCoverage
	if f.cfg.ScannerURL == "" {
		return 0, none, fmt.Errorf("scorecard mode is 'local' but FW_SCANNER_URL is not set")
	}
	body, err := json.Marshal(map[string]string{"repo": repo})
	if err != nil {
		return 0, none, err
	}
	endpoint := strings.TrimRight(f.cfg.ScannerURL, "/") + "/scan"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, none, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := f.scannerClient.Do(req)
	if err != nil {
		// Can't reach our own scanner — transient infrastructure trouble, not a
		// verdict on the repo. 503 to the client rather than the unscorable path.
		return 0, none, fmt.Errorf("scanner: %w: %v", errUpstreamUnavailable, err)
	}
	defer closeDrained(resp.Body)
	if resp.StatusCode == http.StatusServiceUnavailable {
		// 503 is the scheduler saying "this is about US, not the repo". It now covers
		// three distinct causes (issue #69): at scan-concurrency cap (#13), the scanner
		// container could not be launched, and a report that carried neither a result
		// nor an error. None is a finding about the package, so none may reach the
		// unscorable policy — under the fail-closed default that would block a
		// perfectly good package for being unlucky, and under the default byte gate a
		// soft deny would SERVE its artifact.
		//
		// The reason is read from the scheduler's own JSON body rather than assumed:
		// this used to hard-code "at scan capacity", which silently mislabelled the
		// other two once they existed. An operator debugging a stuck pull needs to
		// know WHICH of the three it was.
		return 0, none, fmt.Errorf("scanner: %w: %s", errUpstreamUnavailable, schedulerReason(resp.Body, "unavailable"))
	}
	// 500 is the scheduler failing to PREPARE a scan (it could not mint a waiter or a
	// capability token). Nothing was ever asked about the repo, so this is our own
	// infrastructure failing and belongs on the transient path with the 503 above —
	// it was falling through to "unscorable" instead, which is a verdict about the
	// package, and under the default byte gate a soft deny SERVES the artifact.
	//
	// 429 is not emitted by the scheduler today, but a proxy or ingress in front of it
	// can produce one, and that is throttling rather than a finding.
	//
	// Deliberately NOT a blanket "5xx is transient": the scheduler answers 502 for two
	// opposite things — "failed to launch scanner" (ours) AND "scan failed: <reason>"
	// (the scan ran and the repo could not be scored). The status alone cannot tell
	// them apart, so reclassifying 502 would make a genuinely unscorable package retry
	// forever instead of reaching the approval path. 504 ("scan timed out") is
	// similarly ambiguous. That overloading is the real defect and it belongs in the
	// scheduler's protocol, not in a guess here.
	if resp.StatusCode == http.StatusInternalServerError || resp.StatusCode == http.StatusTooManyRequests {
		transient := errUpstreamUnavailable
		if resp.StatusCode == http.StatusTooManyRequests {
			transient = errUpstreamRateLimited
		}
		return 0, none, fmt.Errorf("scanner: %w (status %d)", transient, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		// The scanner replies non-200 with a reason when a scan fails (repo not
		// found, no token, timeout). Treat these as "couldn't get a score" so the
		// unscorable policy / approval path takes over.
		return 0, none, fmt.Errorf("scanner returned status %d", resp.StatusCode)
	}
	var sr scannerResponse
	if err := decodeCapped(resp.Body, smallJSONMaxBytes, &sr); err != nil {
		return 0, none, err
	}
	// ⚠️ A PARTIAL REPORT IS NOT AUTOMATICALLY A SCORE (#133, D271). Before the
	// salvage fix a non-zero scorecard exit reached us as a 502 and landed here as
	// "couldn't get a score". Salvaging the report must not quietly turn that into a
	// SCORED verdict: the aggregate is computed over only the checks that succeeded,
	// so an 11-of-18 score clearing the threshold would be a measurement the
	// threshold was never set against. That trade -- availability bought with
	// soundness -- is the one this project has refused before (#94, #60).
	//
	// D271 ruled the floor: the report is a score if and only if every check on the
	// required set (scorecardfloor.go) scored. A report missing only low-weight checks
	// is accepted, and the log names what it was computed without; one missing a
	// required check is unscorable, and the refusal names the check.
	//
	// Note this fires on a coverage shortfall however the run exited. A zero-exit run
	// with an errored check is just as incomparable, and keying off the exit status
	// would put the trust back in the signal that caused the bug.
	if err := partialReportVerdict(repo, sr, f.requiredChecks, f.cfg.ScoreThreshold); err != nil {
		return 0, none, err
	}
	if sr.Partial() {
		log.Printf("scanner: partial report for %s accepted: %.1f over %d of %d checks; every required check scored; "+
			"computed without: %s (#133)", repo, sr.Score, sr.ScoredChecks, sr.TotalChecks,
			strings.Join(erroredCheckNames(sr.Checks), ", "))
	}
	return sr.Score, coverageOf(sr), nil
}

// Partial mirrors scanner.ScanResult.Partial across the HTTP boundary: the score was
// computed over fewer checks than the run emitted. Each service owns its own DTO
// (the same rule as the firewall<->approval boundary), so the predicate is restated
// here rather than imported — and because it is restated, the two definitions are
// pinned to agree by a test rather than by the fact that they read alike.
//
// TotalChecks == 0 means the reply predates the coverage fields or the scanner sent
// none; that is NOT partial, because treating "no information" as "bad coverage"
// would make every older scanner in a rolling deploy start refusing scores.
func (sr scannerResponse) Partial() bool {
	return sr.TotalChecks > 0 && sr.ScoredChecks < sr.TotalChecks
}

// schedulerReason pulls the scheduler's own {"error":"…"} text out of a non-2xx body,
// so a transient failure names WHICH cause it was rather than a guess made at the call
// site. Falls back to def when the body is missing, malformed, or empty — a diagnostic
// string is never worth failing a request over.
//
// Bounded read: this is an error path, and an upstream that answers a scan request with
// an unbounded body must not be able to make us allocate it.
func schedulerReason(body io.Reader, def string) string {
	var e struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(body, 4<<10)).Decode(&e); err == nil {
		if msg := strings.TrimSpace(e.Error); msg != "" {
			return msg
		}
	}
	return def
}
