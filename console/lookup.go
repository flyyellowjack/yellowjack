package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The developer-facing package lookup — "what do you know about this package?" without
// running an install and reading the error (#73, folded into #32).
//
// THREE RULINGS CONVERGE ON THIS ONE PAGE, which is why it is worth its own file:
//
//   - D135 pillar 4: a developer searches a package and sees its status. The project also
//     ruled the CLI "should ultimately hit the same API endpoints that the web app would
//     need", so this page is a CLIENT of /v1/packages and re-aggregates nothing.
//   - D137: the CLI dry-run is a second consumer of that same endpoint.
//   - D139: the stop-gap for the D102 gap — the first person ever to request a package
//     gets a plain refusal that nothing retries, and needs somewhere to look.
//
// D158 named this as the first step: we already speak the package-manager protocols, so
// harvest what they give us and render it.
//
// # THE ONE THING THIS PAGE MUST NOT DO
//
// The endpoint's own contract is emphatic, and it is a security property rather than a
// wording preference: we can report WHAT HAPPENED LAST TIME, we cannot report what the
// verdict IS. The live verdict is computed by the firewall at request time, against
// policy in force then, a score that may since have expired (D34) and a manual decision
// an admin may since have reversed.
//
// So this page says "last observed" everywhere, never "verdict"/"status"/"allowed", and
// states plainly that it is a report about the past. A console that renders a stale allow
// as though it were a promise is worse than no console: an operator would use it to decide
// whether to worry, which is exactly the decision it cannot support.
//
// # Exposure
//
// This is deliberately mounted INSIDE the console's existing auth gate, not beside
// /healthz. D139 ruled anonymous read-only access for developers, but the console
// exposure boundary is still an OPEN question (CONSOLE_MVP_SCOPE.md §4 Q3): anonymous
// read-only is a reconnaissance surface — who pulls what, what is blocked, and why.
// Widening it is a security decision to be taken deliberately and separately, not a side
// effect of adding a page. In the default deployment no credential is configured and the
// whole console is already open, so this costs the developer use case nothing today.

//go:embed templates/lookup.html
var lookupHTML string

var lookupTmpl = pageTemplate("lookup", lookupHTML, nil)

// packageStatus mirrors the approval service's response. Field names and the
// availability strings are part of that contract; see approval/packagestatus.go for why
// each "we do not have this" case is a distinct marker rather than an omitted field.
type packageStatus struct {
	Package   string `json:"package"`
	Ecosystem string `json:"ecosystem,omitempty"`

	Decision            *decision `json:"decision,omitempty"`
	DecisionGranularity string    `json:"decisionGranularity"`

	Score             *scoreRecord `json:"score,omitempty"`
	ScoreAvailability string       `json:"scoreAvailability"`

	LastObserved *event  `json:"lastObserved,omitempty"`
	RecentEvents []event `json:"recentEvents,omitempty"`

	// Upstream is the registry's OWN account of the package (D158). Nil unless the
	// approval service actually reached a registry — the marker in Upstream below says
	// which of the several "no data" cases applies, and they are not interchangeable.
	UpstreamHarvest *upstreamHarvest `json:"upstream,omitempty"`

	Upstream string `json:"upstreamMetadata"`
	Cache    string `json:"cacheStatus"`
}

// upstreamHarvest mirrors the approval service's projection of the registry's own
// metadata. Field names are part of that contract; see approval/upstream.go for why
// the projection is deliberately narrow.
type upstreamHarvest struct {
	LatestVersion string    `json:"latestVersion,omitempty"`
	PublishedAt   time.Time `json:"publishedAt,omitempty"`
	VersionCount  int       `json:"versionCount,omitempty"`
	Maintainers   int       `json:"maintainers,omitempty"`
	Deprecated    string    `json:"deprecated,omitempty"`
}

// scoreRecord is the cached OpenSSF result, repo-keyed. Its JSON keys are the approval
// service's ScoreRecord keys (approval/store.go), and scorewire_test.go holds them to
// that: until it did, this type named `hasScore` and `scoredAt`, keys the approval
// service never sends, so the page showed no number and a zero time for every scored
// package -- the same silent-drop class as the audit fields (#142).
type scoreRecord struct {
	Repo      string    `json:"repo"`
	Score     *float64  `json:"score"` // nil = scanned but could not be scored
	UpdatedAt time.Time `json:"updatedAt"`

	// Coverage (#133): what the score was computed over. Zero/empty = full report
	// or a row that predates the fields.
	ScoredChecks    int      `json:"scoredChecks"`
	TotalChecks     int      `json:"totalChecks"`
	ComputedWithout []string `json:"computedWithout"`
}

func (r scoreRecord) HasScore() bool { return r.Score != nil }

func (r scoreRecord) Value() float64 {
	if r.Score == nil {
		return 0
	}
	return *r.Score
}

// Partial mirrors the approval service's ScoreRecord.Partial: computed over fewer
// checks than the run emitted. A partial score reached the cache only because every
// required check scored (D271), so it is a real score -- but a reader comparing it to
// a full one must be told the denominator differs.
func (r scoreRecord) Partial() bool { return r.TotalChecks > 0 && r.ScoredChecks < r.TotalChecks }

// PackageStatus fetches the read-only aggregate for one package.
//
// A 404 is NOT an error here: the approval service answers 404 for a package it has
// never seen, and "never seen" is a legitimate, common, and informative answer — it is
// precisely the D139 stop-gap case. Turning it into an error would show the developer a
// service failure for the situation the page exists to explain.
func (c *approvalHTTPClient) PackageStatus(pkg, ecosystem string) (packageStatus, bool, error) {
	q := url.Values{}
	q.Set("package", pkg)
	if ecosystem != "" {
		q.Set("ecosystem", ecosystem)
	}
	endpoint := strings.TrimRight(c.baseURL, "/") + "/v1/packages?" + q.Encode()
	resp, err := c.http.Get(endpoint)
	if err != nil {
		return packageStatus{}, false, fmt.Errorf("contacting approval service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return packageStatus{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return packageStatus{}, false, fmt.Errorf("approval service returned status %d", resp.StatusCode)
	}
	var st packageStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return packageStatus{}, false, fmt.Errorf("decoding approval response: %w", err)
	}
	return st, true, nil
}

// lookupView is what the template renders.
type lookupView struct {
	Nav       navView
	Query     string
	Ecosystem string
	AuthUser  string

	// Searched distinguishes "the page just loaded" from "we searched and found
	// nothing" — two states that must not render identically, or an empty result reads
	// as a clean bill of health.
	Searched bool
	Found    bool
	Status   packageStatus

	// Explain renders the availability markers as sentences. Done in Go so the template
	// stays a dumb renderer, consistent with the other views.
	ScoreNote    string
	UpstreamNote string
	CacheNote    string
	DecisionNote string

	// ScoringOff hides the Score section entirely when the fleet runs with no scanner
	// (#151, D273 s5). Computed once per render from the replicas' reported policies.
	ScoringOff bool
}

// explainAvailability turns the endpoint's availability markers into operator English.
//
// The markers exist because "never requested" and "requested and could not be scored"
// are opposite operational situations that a boolean would flatten into the same false.
// The rendering must preserve that distinction rather than collapsing everything into a
// friendly dash — an absent field reads as "no problem found", which is the failure mode
// the API's author called out explicitly.
func explainAvailability(marker string) string {
	switch marker {
	case "present":
		return ""
	case "not-collected-by-this-service":
		return "Not collected by this service — the firewall fetches registry metadata, not the console."
	case "not-implemented":
		return "Not implemented yet. This is a seam, not a finding: nothing was checked."
	case "no-source-repo-known-for-this-package":
		return "No source repository is known for this package, so there is nothing to score. " +
			"This is the unscorable case, and how it is treated depends on the deployment's policy."
	case "repo-known-but-never-scanned":
		return "The source repository is known but has never been scanned."
	case "scanned-but-could-not-be-scored":
		return "The repository was scanned and no score could be produced."
	case "not-found-in-the-registry":
		return "The registry does not have a package by this name. If your install just failed, " +
			"check the spelling first — this is not a block, and nothing here refused it."
	case "upstream-registry-unreachable":
		return "We could not reach the registry to ask, so nothing below reflects what it currently " +
			"says. This is a fact about THIS deployment's connectivity, not about the package."
	case "upstream-registry-timed-out":
		return "The registry was reached but did not finish answering in the time this page waits, so " +
			"nothing below reflects it. Packages with a long release history have very large metadata " +
			"documents; over a slow link to the registry that can simply take too long. Try again, or " +
			"point this service at a nearer mirror. This is not a finding about the package."
	case "registry-metadata-too-large-to-read":
		return "The registry answered, but this package's metadata document is larger than this " +
			"service will read, so nothing below reflects it. That is a limit of THIS deployment, " +
			"not a finding about the package and not a connectivity problem: it affects large, " +
			"long-lived packages with many published versions."
	case "":
		return ""
	default:
		// An unrecognized marker is reported verbatim rather than swallowed. A new
		// availability case added upstream must not silently render as "fine".
		return "Reported as: " + marker
	}
}

func (s *server) handleLookup(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	pkg := strings.TrimSpace(q.Get("package"))
	eco := strings.TrimSpace(q.Get("ecosystem"))

	view := lookupView{Query: pkg, Ecosystem: eco, Nav: s.navFor(r, "lookup")}
	if u := s.currentUser(r); u != "" {
		view.AuthUser = u
	}
	if pkg == "" {
		// First load, or a cleared box. Render the form and nothing else.
		if err := lookupTmpl.Execute(w, view); err != nil {
			log.Printf("lookup: render: %v", err)
		}
		return
	}

	view.Searched = true
	st, found, err := s.approval.PackageStatus(pkg, eco)
	if err != nil {
		log.Printf("lookup: package status for %q: %v", pkg, err)
		http.Error(w, "Cannot reach the approval service. Is it running and is CONSOLE_APPROVAL_URL correct?", http.StatusBadGateway)
		return
	}
	view.Found = found
	view.ScoringOff = s.scoringOff()
	if found {
		view.Status = st
		view.ScoreNote = explainAvailability(st.ScoreAvailability)
		view.UpstreamNote = explainAvailability(st.Upstream)
		view.CacheNote = explainAvailability(st.Cache)
		view.DecisionNote = st.DecisionGranularity
	}
	if err := lookupTmpl.Execute(w, view); err != nil {
		log.Printf("lookup: render: %v", err)
	}
}
