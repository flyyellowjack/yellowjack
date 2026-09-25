package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// This file closes the "borrow-a-score" hole (D33; hole identified in the D31
// review as issue #10): the repo we score comes from
// PUBLISHER-CONTROLLED metadata (npm `repository`, OCI source label, POM <scm>),
// with no check that the artifact actually came from that repo. An attacker can
// publish malware and point its `repository` at github.com/lodash/lodash to
// inherit lodash's ~9 score and be allowed. We can't fully verify provenance yet
// (that's a Sigstore/SLSA architecture decision flagged as a project decision), but deps.dev
// keeps its OWN package->project record, independent of the claim we just read
// from the live package. We cross-check the two.
//
// What happens when the cross-check doesn't confirm the link is a POSTURE, set by
// FW_UNVERIFIED_POLICY (D36 Ruling A — "real firewalls fail closed"). The split that
// matters, and the one this file exists to keep honest, is DURABLE vs TRANSIENT:
//
//   - DURABLE — deps.dev answered and the answer doesn't confirm the claim (no
//     source-repo mapping, or a definite contradiction). Retrying cannot change it, so
//     the default refuses the package and queues it for review. `open-with-visibility`
//     restores D33's degrade-open for the operator who chooses availability.
//   - TRANSIENT — deps.dev is unreachable / 5xx / rate-limiting us. We know NOTHING
//     about the link, so this is never a verdict: it is a retryable 503 (D17 taxonomy),
//     which clients retry, NOT a block. A deps.dev outage must not read as "all your
//     packages are malicious".
//
// Applies to api mode (D33) and local/async mode (D39) — see
// repoVerificationEnabled. stub mode is skipped because it is offline by design.
//
// Honest limitation (see DECISIONS D33): deps.dev's SOURCE_REPO relation is today
// itself `UNVERIFIED_METADATA` (derived from the package's published metadata),
// so this is NOT cryptographic provenance. Its value is a SECOND, independent
// record: it catches a live claim that diverges from deps.dev's recorded mapping
// (a hijacked/typosquatted package), and it stops the self-declared repo from
// being the sole, unchecked input to what we score.

// depsDevBaseURL is the public deps.dev API — the DEFAULT for Config.DepsDevBase
// (FW_DEPSDEV_BASE). Held in a Firewall field (f.depsDevBase) so tests can point the
// whole api-mode path at an httptest server, and so an operator can point a container
// at a mirror without a rebuild.
const depsDevBaseURL = "https://api.deps.dev"

// depsDevSourceRepoRelation is the relatedProjects.relationType value that marks a
// project as the package's source repository (as opposed to ISSUE_TRACKER, etc.).
const depsDevSourceRepoRelation = "SOURCE_REPO"

// The two FW_UNVERIFIED_POLICY values (D36 Ruling A). See Config.UnverifiedPolicy.
const (
	unverifiedPolicyClosed = "closed"
	unverifiedPolicyOpen   = "open-with-visibility"
)

// unverifiedFailsClosed reports whether a DURABLY unverified package->repo link
// should be refused (the default) rather than proceeding on the self-declared repo.
//
// Written as "not open" rather than "== closed" on purpose, matching the
// UnscorablePolicy idiom: an unset, misspelled, or otherwise unrecognized value
// resolves to the SAFE posture. Opening the gate must be a deliberate, exactly
// spelled act — a typo in a security default should never be the thing that
// silently disables it.
func (f *Firewall) unverifiedFailsClosed() bool {
	return f.cfg.UnverifiedPolicy != unverifiedPolicyOpen
}

// depsDevSystem maps our ecosystem name to the deps.dev "system" path segment.
// deps.dev covers npm/pypi/maven (and others) but NOT OCI/Docker, so oci returns
// "" — the caller treats an empty system as "durably unverifiable here": refused
// under FW_UNVERIFIED_POLICY=closed (D48, #33), or the self-declared repo logged
// unverified under open-with-visibility.
func depsDevSystem(ecosystem string) string {
	switch ecosystem {
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "maven":
		return "maven"
	default: // "oci" and anything else deps.dev doesn't index by package
		return ""
	}
}

// depsDevPackage is the slice of GetPackage we read: just the version list, so we
// can pick a version whose relatedProjects to inspect. We prefer the default
// version (isDefault) — the one deps.dev considers current.
type depsDevPackage struct {
	Versions []struct {
		VersionKey struct {
			Version string `json:"version"`
		} `json:"versionKey"`
		IsDefault bool `json:"isDefault"`
	} `json:"versions"`
}

// depsDevVersion is the slice of GetVersion we read: the related-projects list.
// Each entry names a project (projectKey.id, e.g. "github.com/owner/name"), the
// kind of relation (SOURCE_REPO / ISSUE_TRACKER / …), and where deps.dev learned
// it (relationProvenance) — which we log but do not gate on today (see file header).
type depsDevVersion struct {
	RelatedProjects []struct {
		ProjectKey struct {
			ID string `json:"id"`
		} `json:"projectKey"`
		RelationType       string `json:"relationType"`
		RelationProvenance string `json:"relationProvenance"`
	} `json:"relatedProjects"`
}

// repoVerificationEnabled reports whether the deps.dev cross-check should run for
// the active configuration. Two conditions, both required:
//
//   - FW_VERIFY_REPO is on (the operator escape hatch, default true).
//   - The scorecard mode is one that can reach deps.dev at all.
//
// The mode test is a deliberate ALLOWLIST, not `!= "stub"`, so a mode added later
// has to opt in explicitly rather than silently inherit a network call:
//
//   - "api"   — verified since D33.
//   - "local" — verified as of D39. The scan is asynchronous and the score comes
//     from our own scanner, but the REPO still comes from publisher-controlled
//     metadata, so the borrow-a-score hole is identical in local mode; only the
//     scoring engine differs. Verification stays SYNCHRONOUS on the hot path (it
//     decides what gets scanned, so it cannot be deferred into the background scan
//     it is meant to prevent) and is bounded by the repoCache TTL — see Evaluate.
//   - "stub"  — skipped: it is the offline/deterministic mode (no network by
//     design), so a deps.dev call would defeat its purpose and hang tests.
func (f *Firewall) repoVerificationEnabled() bool {
	if !f.cfg.VerifyRepo {
		return false
	}
	switch f.cfg.ScorecardMode {
	case "api", "local":
		return true
	default:
		return false
	}
}

// verifyRepo cross-checks a package's self-declared source repo against deps.dev's
// own package->project record, and returns the repo the caller should score.
//
// Returns (repo, decision, done):
//   - done == false: proceed to score `repo`. That is the self-declared repo when it
//     matches deps.dev (or when the policy is open-with-visibility and deps.dev had no
//     answer for us), or deps.dev's own source repo when the package declared none.
//   - done == true: STOP — `decision` is terminal, and is one of two KINDS:
//     a refusal (durably unverified: no mapping, or a mismatch) under the fail-closed
//     default, or a retryable 503 (deps.dev itself unreachable). Distinguishing those
//     two is the whole point — see the file header and D36.
//
// Called from Evaluate whenever repoVerificationEnabled() — api mode (D33) and local
// mode (D39). Note the cost of failing closed in LOCAL mode: a durable non-verification
// stops the background scan from ever being launched (verification sits upstream of
// scoreFor), which is the intent — we will not scan, cache, or serve a score for a repo
// we can't tie to the package. A deps.dev outage there stalls cold pulls behind retryable
// 503s until it recovers; the reason string names repo VERIFICATION specifically so that
// 503 is not mistaken for "the scanner is down", and an operator who prefers availability
// over the check sets FW_UNVERIFIED_POLICY=open-with-visibility.
func (f *Firewall) verifyRepo(pkg, selfRepo string) (string, Decision, bool) {
	system := depsDevSystem(f.cfg.Ecosystem)
	if system == "" {
		// deps.dev has no container index, so NO image's self-declared repo can ever be
		// cross-checked: for OCI the link is durably unverifiable by construction, not
		// merely unverified today. D48 rules that this fails CLOSED under the same
		// FW_UNVERIFIED_POLICY as every other durably unverifiable link -- knowing it
		// refuses every scored image pull until the operator sets the override (#33).
		// The friction is deliberate: it is the boundary the curated data fills. No
		// round-trip is spent discovering the gap; the answer is known from the
		// ecosystem alone.
		if selfRepo == "" {
			// No claim to verify. The unscorable path decides, as it does elsewhere.
			return selfRepo, Decision{}, false
		}
		if !f.unverifiedFailsClosed() {
			log.Printf("evaluate %q: repo %s unverified: %s not indexed by deps.dev (policy=%s, proceeding on self-declared repo)",
				pkg, selfRepo, f.cfg.Ecosystem, unverifiedPolicyOpen)
			return selfRepo, Decision{}, false
		}
		reason := fmt.Sprintf("self-declared repo %q for %q cannot be verified: deps.dev has no %s index, so no image's source repo can be cross-checked",
			selfRepo, pkg, f.cfg.Ecosystem)
		log.Printf("SECURITY evaluate %q: %s (failing closed per D48; set FW_UNVERIFIED_POLICY=%s to proceed on the self-declared repo with a log instead)",
			pkg, reason, unverifiedPolicyOpen)
		return "", f.unverified(pkg, reason), true
	}

	repos, found, err := f.depsDevSourceRepos(system, pkg)
	switch {
	case err != nil:
		// TRANSIENT (deps.dev unreachable / 5xx / 429). We do not KNOW anything about
		// this package's linkage — our own dependency is simply down. This must never
		// become a verdict in EITHER direction (D36's critical distinction):
		//   - fail-closed does NOT mean "block": a deps.dev hiccup would turn into a
		//     wall of 403s across every install. It means "ask again shortly" — the
		//     retryable 503 of the D17 taxonomy, which package managers retry.
		//   - degrading open here is what the operator opts into with
		//     open-with-visibility, accepting that an outage disables the check.
		if !f.unverifiedFailsClosed() {
			log.Printf("evaluate %q: repo %s unverified: deps.dev lookup failed: %v (policy=%s, proceeding on self-declared repo)",
				pkg, selfRepo, err, unverifiedPolicyOpen)
			return selfRepo, Decision{}, false
		}
		if errors.Is(err, errUpstreamRateLimited) {
			// D25: deps.dev is throttling us. Re-probing on the next pull of this
			// package amplifies the storm, so back it off briefly — the same circuit
			// breaker the scoring path uses, since in api mode this IS the same host.
			f.backoff.mark(pkg)
		}
		log.Printf("evaluate %q: repo verification for %s unavailable: deps.dev lookup failed: %v (retryable, not a verdict)", pkg, selfRepo, err)
		return "", Decision{Unavailable: true, Reason: transientReason(fmt.Sprintf("repo verification for %q", pkg), err)}, true

	case !found || len(repos) == 0:
		// DURABLE: deps.dev returned an answer and that answer gives us no usable
		// source-repo record — it never ingested this package (404), or it knows the
		// package but lists no repo our scorer can use. Retrying changes nothing, so
		// this is the branch the fail-closed default applies to. It is also exactly the
		// fresh-typosquat / new-malware profile: a package published minutes ago has no
		// deps.dev record, so pre-D36 it inherited the borrowed repo's score for free.
		if selfRepo == "" {
			// Nothing was claimed and nothing is known — there is no repo to score and
			// so no score to borrow. That is plain UNSCORABLE, not a broken linkage, and
			// it stays governed by FW_UNSCORABLE_POLICY: falling through returns "" and
			// Evaluate's "does not declare a usable source repository" path handles it.
			// Deliberately NOT escalated here — it is the ordinary messy-metadata case,
			// and overriding the operator's unscorable posture for it is beyond D36.
			log.Printf("evaluate %q: package declares no repo and deps.dev has no source-repo mapping", pkg)
			return selfRepo, Decision{}, false
		}
		if !f.unverifiedFailsClosed() {
			log.Printf("evaluate %q: repo %s unverified: deps.dev has no source-repo mapping (policy=%s, proceeding on self-declared repo)",
				pkg, selfRepo, unverifiedPolicyOpen)
			return selfRepo, Decision{}, false
		}
		reason := fmt.Sprintf("self-declared repo %q for %q could not be verified: deps.dev has no source-repo mapping for the package (a brand-new package is indistinguishable from one borrowing a repo)",
			selfRepo, pkg)
		log.Printf("SECURITY evaluate %q: %s (failing closed; set FW_UNVERIFIED_POLICY=%s to proceed with a log instead)", pkg, reason, unverifiedPolicyOpen)
		return "", f.unverified(pkg, reason), true
	}

	// deps.dev has an authoritative source repo (or several).
	if selfRepo == "" {
		// The package declared no repo of its own, but deps.dev knows one — adopt it
		// so we can score a package we'd otherwise have to treat as unscorable.
		log.Printf("evaluate %q: package declared no repo; scoring deps.dev source repo %s", pkg, repos[0])
		return repos[0], Decision{}, false
	}
	if reposContain(repos, selfRepo) {
		return selfRepo, Decision{}, false // verified: the claim agrees with deps.dev
	}

	// MISMATCH — the borrow-a-score tripwire, and the strongest signal this file can
	// produce: deps.dev gave a definite answer and it CONTRADICTS the live claim.
	// Terminal under either policy (this was never one of D33's degrade-open cases —
	// there is nothing missing to degrade over), but the posture differs:
	//   - closed:               refuse outright, queued for human review (D36).
	//   - open-with-visibility: the pre-D36 routing, which defers to UnscorablePolicy.
	// Either way we never score the claimed repo, and a human can still approve the
	// package or correct the association.
	reason := fmt.Sprintf("self-declared repo %q does not match deps.dev source repo(s) %s for %q (possible score-borrowing)",
		selfRepo, strings.Join(repos, ", "), pkg)
	log.Printf("SECURITY evaluate %q: %s", pkg, reason)
	if f.unverifiedFailsClosed() {
		return "", f.unverified(pkg, reason), true
	}
	return "", f.unscorable(pkg, reason), true
}

// depsDevSourceRepos resolves deps.dev's own source-repo record for a package:
// find its default version, then read that version's SOURCE_REPO related projects,
// normalized to the "github.com/owner/name" form we score (non-GitHub projects are
// dropped, since our scorer only understands GitHub).
//
// Returns (repos, found, err):
//   - err != nil: transient — deps.dev unreachable, 429, or 5xx (wraps
//     errUpstreamUnavailable). The caller degrades to the self-declared repo.
//   - found == false: deps.dev returned 404 — it doesn't know this package/version.
//   - found == true, len(repos) == 0: deps.dev knows the package but lists no usable
//     (GitHub) source repo.
func (f *Firewall) depsDevSourceRepos(system, pkg string) (repos []string, found bool, err error) {
	// The outage breaker (D342). While deps.dev is known to be down, answer with the same
	// TRANSIENT error a live probe would have produced, so both FW_UNVERIFIED_POLICY branches
	// behave exactly as they would after a real failure -- only without waiting out another
	// 10-second timeout per cold package. It is armed below, never by a verdict.
	if f.depsDevOutage.active(depsDevOutageKey) {
		return nil, false, fmt.Errorf("%w: deps.dev failed within the last %s, so it is not re-probed "+
			"until then (outage breaker)", errUpstreamUnavailable, f.depsDevOutage.ttl)
	}
	repos, found, err = f.depsDevSourceReposLive(system, pkg)
	// Armed on an outage (unreachable, 5xx) only. A 429 keeps D25's per-package backoff and
	// does not trip the host breaker: it is throttling, and the caller already handles it.
	if err != nil && errors.Is(err, errUpstreamUnavailable) && !errors.Is(err, errUpstreamRateLimited) {
		f.depsDevOutage.mark(depsDevOutageKey)
	}
	return repos, found, err
}

// depsDevOutageKey is the single key the host-wide breaker is kept under.
const depsDevOutageKey = "deps.dev"

// depsDevSourceReposLive is depsDevSourceRepos without the outage breaker: two live calls.
func (f *Firewall) depsDevSourceReposLive(system, pkg string) (repos []string, found bool, err error) {
	version, found, err := f.depsDevDefaultVersion(system, pkg)
	if err != nil || !found || version == "" {
		return nil, found, err
	}

	var v depsDevVersion
	verURL := fmt.Sprintf("%s/v3/systems/%s/packages/%s/versions/%s",
		f.depsDevBase, system, url.PathEscape(pkg), url.PathEscape(version))
	found, err = f.depsDevGet(verURL, &v)
	if err != nil || !found {
		return nil, found, err
	}

	seen := make(map[string]struct{})
	for _, rp := range v.RelatedProjects {
		if rp.RelationType != depsDevSourceRepoRelation {
			continue
		}
		repo := normalizeGitHub(rp.ProjectKey.ID)
		if repo == "" {
			continue // non-GitHub (gitlab/bitbucket) — our scorer can't use it
		}
		if _, dup := seen[repo]; dup {
			continue
		}
		seen[repo] = struct{}{}
		repos = append(repos, repo)
	}
	return repos, true, nil
}

// depsDevDefaultVersion fetches a package's version list and returns the version
// deps.dev marks as default (its current version). If none is marked default it
// falls back to the last-listed version (deps.dev lists oldest→newest, so the last
// entry is the newest known) so we can still inspect a mapping.
func (f *Firewall) depsDevDefaultVersion(system, pkg string) (version string, found bool, err error) {
	var p depsDevPackage
	pkgURL := fmt.Sprintf("%s/v3/systems/%s/packages/%s", f.depsDevBase, system, url.PathEscape(pkg))
	found, err = f.depsDevGet(pkgURL, &p)
	if err != nil || !found {
		return "", found, err
	}
	if len(p.Versions) == 0 {
		return "", true, nil
	}
	for _, ver := range p.Versions {
		if ver.IsDefault {
			return ver.VersionKey.Version, true, nil
		}
	}
	return p.Versions[len(p.Versions)-1].VersionKey.Version, true, nil
}

// depsDevGet performs one GET against the deps.dev API and decodes a 200 body into
// out. It maps status onto the same transient-vs-not taxonomy the rest of the
// firewall uses (D17/D25):
//   - 200 → decode, found=true
//   - 404 → found=false (deps.dev doesn't know it), no error
//   - 429 → errUpstreamRateLimited (wraps errUpstreamUnavailable)
//   - 5xx / network → errUpstreamUnavailable
//   - other non-200 → a plain error (treated as "couldn't verify" by the caller)
//
// Shares f.client (host-scoped upstream auth is NOT sent here — the deps.dev host
// differs from the upstream registry host), and sets our User-Agent, since public
// APIs reject generic/absent agents (the original Phase-2 403 cause).
func (f *Firewall) depsDevGet(rawURL string, out any) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := f.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("deps.dev: %w: %v", errUpstreamUnavailable, err)
	}
	defer closeDrained(resp.Body)

	switch {
	case resp.StatusCode == http.StatusOK:
		// decodeCapped so an overrun NAMES the cap in the log. The wrap stays %v on
		// purpose: errUpstreamTooLarge reaching Evaluate would be reported as "its
		// registry metadata is too large", and this is deps.dev's answer, not the
		// registry's. A flattened error is an ordinary lookup failure, which is what an
		// oversized service response is.
		if err := decodeCapped(resp.Body, smallJSONMaxBytes, out); err != nil {
			return false, fmt.Errorf("deps.dev: decode: %v", err)
		}
		return true, nil
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return false, fmt.Errorf("deps.dev: %w (status 429)", errUpstreamRateLimited)
	case resp.StatusCode >= 500:
		return false, fmt.Errorf("deps.dev: %w (status %d)", errUpstreamUnavailable, resp.StatusCode)
	default:
		return false, fmt.Errorf("deps.dev returned status %d", resp.StatusCode)
	}
}

// reposContain reports whether self is among repos, comparing case-insensitively:
// GitHub owner/name are case-insensitive, and the self-declared URL and deps.dev's
// id can differ only in case ("github.com/Owner/Repo" vs ".../owner/repo"). Folding
// avoids wrongly quarantining a legitimate package over a capitalization difference.
func reposContain(repos []string, self string) bool {
	for _, r := range repos {
		if strings.EqualFold(r, self) {
			return true
		}
	}
	return false
}
