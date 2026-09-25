package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The release window (FW_MIN_RELEASE_AGE_DAYS cooldown, #26; FW_MAX_RELEASE_AGE_DAYS
// age floor, D22) for Maven.
//
// ── WHY THIS FILE EXISTS ─────────────────────────────────────────────────────
//
// Measured 2026-09-12: `maven.go` and `oci.go` referenced the cooldown ZERO times.
// The window was consulted only from `relayRewritten`, the metadata-REWRITE path,
// which exists for npm and PyPI alone — so "four ecosystems" was true of the CODE
// and false of the EFFECT. That is E25's pattern in a second control: E25 measured
// layer 1 covering 87.71% of corpus packages but ~2 for Maven and 0 for OCI.
//
// ── WHERE THE TIME COMES FROM, AND WHY NOT WHERE THE ISSUE SAID ──────────────
//
// The backlog row proposed reading the publish time from `maven-metadata.xml`.
// Measured against the live repository, that source cannot answer the question:
// guava's maven-metadata.xml lists 158 <version> entries and carries exactly ONE
// <lastUpdated>, describing the artifact as a whole. Dating every version by it
// would stamp 2011 releases with a 2026 timestamp — a cooldown that refuses the
// entire back catalogue, or passes all of it, depending on which way you read it.
// Wrong in a way that still produces a plausible-looking number, which is the
// failure this project keeps meeting.
//
// What DOES answer it is the per-file `Last-Modified` the repository serves, which
// is distinct per version (measured: guava 33.4.0-jre → 2024-12-16, 32.0.0-jre →
// 2023-05-26) and is set by the REPOSITORY when the file lands, not by the
// publisher inside the artifact. That distinction is the whole reason this is
// buildable for Maven and deliberately NOT built for OCI — see
// whyOCIHasNoReleaseWindow in firewall.go, which records that measurement.
//
// ── COST, STATED ─────────────────────────────────────────────────────────────
//
// This adds one HEAD per gated artifact URL, memoised for the life of the cache
// entry. It runs ONLY when a bound is configured, and both bounds default to 0
// (off), so the shipped default pays nothing. An operator who turns the cooldown on
// is choosing to spend one small request per artifact to get it.

// mavenReleaseTime reports when the repository says the artifact at `path` landed.
//
// Returns ok=false when the repository answered but named no time — a real state,
// distinct from an error, and one the caller must fail closed on rather than treat
// as "old enough".
func (e mavenEcosystem) mavenReleaseTime(c *http.Client, path string) (time.Time, bool, error) {
	if _, _, _, gav := mavenGAV(path); !gav {
		// Not a gated artifact request (maven-metadata.xml, a checksum, a signature).
		// Nothing to date and nothing to refuse.
		return time.Time{}, false, nil
	}
	url := strings.TrimRight(e.base, "/") + "/" + strings.TrimLeft(path, "/")

	if e.ages != nil {
		if t, ok, cached := e.ages.get(url); cached {
			return t, ok, nil
		}
	}

	// HEAD, not GET: we want one header and the artifact may be tens of megabytes.
	// A repository that refuses HEAD is handled below as "no time", not as an error,
	// because a 405 is a statement about the METHOD and says nothing about the file.
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("release-age probe: %w: %v", errUpstreamUnavailable, err)
	}
	resp, err := c.Do(req)
	if err != nil {
		// No answer at all is transient (D17), surfaced as a retryable 503 — never as
		// "this release is too new", which would turn an outage into a refusal an
		// operator cannot tell from a policy decision.
		return time.Time{}, false, fmt.Errorf("release-age probe: %w: %v", errUpstreamUnavailable, err)
	}
	defer closeDrained(resp.Body)

	if resp.StatusCode != http.StatusOK {
		if cerr := classifyStatus(resp.StatusCode); cerr != nil {
			return time.Time{}, false, fmt.Errorf("release-age probe: %w (status %d)", cerr, resp.StatusCode)
		}
		// Any other non-200 (405 Method Not Allowed on a repository that forbids HEAD,
		// for instance): we have no time. Not an error, and NOT permission to serve —
		// the caller's unknown-age rule decides, and it fails closed.
		return time.Time{}, false, nil
	}

	lm := resp.Header.Get("Last-Modified")
	if lm == "" {
		return e.rememberAge(url, time.Time{}, false), false, nil
	}
	t, perr := http.ParseTime(lm)
	if perr != nil {
		// A malformed date is an unknown date. Deliberately not an error: an upstream
		// with a broken clock format must not take the gate down, it must fall to the
		// fail-closed unknown-age branch.
		return e.rememberAge(url, time.Time{}, false), false, nil
	}
	return e.rememberAge(url, t.UTC(), true), true, nil
}

// rememberAge stores the outcome and returns the time, so the callers above read as
// one line each. A NEGATIVE result is cached too: an upstream that serves no
// Last-Modified will not start doing so within one cache window, and re-probing it
// per artifact is the fan-out D25 exists to prevent.
func (e mavenEcosystem) rememberAge(url string, t time.Time, ok bool) time.Time {
	if e.ages != nil {
		e.ages.put(url, t, ok)
	}
	return t
}

// mavenAgeCache memoises the release-time probe for the life of one resolve's burst.
//
// Separate from mavenFetchCache rather than reusing it, because the two hold
// different things (a parsed time plus a "there is no time" answer, versus a body)
// and folding a sentinel into a []byte cache to mean "known absent" is exactly the
// conflation ageYankIndex's comment warns about for unknown-vs-too-old.
type mavenAgeCache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]mavenAgeEntry
}

type mavenAgeEntry struct {
	t     time.Time
	known bool
	at    time.Time
}

func newMavenAgeCache(ttl time.Duration) *mavenAgeCache {
	return &mavenAgeCache{ttl: ttl, m: map[string]mavenAgeEntry{}}
}

// get reports the cached answer. `cached` says whether we have one at all; `ok` says
// whether that answer is a known time. The two are different questions and a single
// bool would force the caller to re-probe every URL we already know has no date.
func (c *mavenAgeCache) get(url string) (t time.Time, ok bool, cached bool) {
	if c == nil {
		return time.Time{}, false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, found := c.m[url]
	if !found || time.Since(e.at) > c.ttl {
		return time.Time{}, false, false
	}
	return e.t, e.known, true
}

func (c *mavenAgeCache) put(url string, t time.Time, known bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[url] = mavenAgeEntry{t: t, known: known, at: time.Now()}
}
