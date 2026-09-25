package main

import (
	"log"
	"net/http"
	"strings"
)

// Package status — the read-only "what do we know about this package?" answer.
//
// # Why this exists, and why it is ONE endpoint rather than three
//
// D135 (2026-08-14) ruled that "ask us to check a package" is a web-GUI
// feature, and that any CLI "should ultimately hit the same API endpoints that the
// web app/operator console would need/have". So the console is a CLIENT of this, not
// a place where the aggregation is re-done in a template.
//
// Three separately-ruled features converge on this one read:
//
//   - D135's fourth console pillar — a developer searches a package and sees its status.
//   - D137's CLI dry-run — the wrapper asks "what do you say about these?" without
//     performing an install, for teams whose build tool already wraps pip/maven.
//   - D139's stop-gap for the D102 gap — the first person ever to request a package
//     gets a plain refusal that nothing retries, and needs somewhere to look.
//
// It is deliberately readable by ANYONE: D139 ruled anonymous read-only for developers
// and authenticated admins, so this path takes no credential. It is also strictly a
// READ — D140 ruled that unauthenticated callers must not be able to spend compute
// minutes, so nothing here launches a scan. The admin-only trigger is a separate,
// authenticated action and is deliberately NOT part of this handler.
//
// # The distinction this type exists to preserve
//
// We can report WHAT HAPPENED LAST TIME. We cannot report what the verdict IS.
//
// The verdict is computed by the firewall at request time, from the policy in force
// then, against a score that may since have changed or expired (D34's freshness TTL)
// and a manual decision an admin may since have reversed. A field called "verdict" on
// a status page would be read as "this is what you will get", and for a security
// console that is not a cosmetic difference — it is the difference between a report
// and a promise. So the observed history is named lastObserved, and nothing here is
// named as though it predicts the next answer.
//
// Everything we do NOT have is stated as an explicit availability marker rather than
// omitted. An absent field reads as "no problem found"; "notCollected" reads as "we
// did not look". For a gate, those must never be confusable.
type packageStatus struct {
	Package   string `json:"package"`
	Ecosystem string `json:"ecosystem,omitempty"`

	// Decision is the human ruling, if an admin has recorded one. Package-keyed only.
	Decision *Decision `json:"decision,omitempty"`

	// DecisionGranularity is load-bearing, not decoration. D135 asks for manual
	// verdicts at BOTH package and package+version granularity; the store is keyed by
	// package alone, so the version-level answer does not exist yet. Saying so is the
	// difference between "no version is blocked" and "we cannot tell you about
	// versions" — see the type comment.
	DecisionGranularity string `json:"decisionGranularity"`

	// Score is the cached OpenSSF result for the package's source repo, when we know
	// which repo that is. It is repo-keyed (ScoreRecord), while packages are
	// name-keyed, so this is only reachable when something has told us the mapping —
	// today, an admin-supplied RepoURL on the decision. ScoreAvailability says which
	// of the several "no score" cases applies.
	Score             *ScoreRecord `json:"score,omitempty"`
	ScoreAvailability string       `json:"scoreAvailability"`

	// LastObserved is the most recent gate decision actually taken for this package,
	// straight from the audit log. This is the honest core of the response: a fact
	// about the past, not a prediction. Nil when the package has never been requested
	// through this deployment.
	LastObserved *AuditEvent `json:"lastObserved,omitempty"`

	// RecentEvents is a short history so a developer can see "it was allowed on
	// Monday and blocked today", which is the question that actually gets asked when
	// a build breaks. Newest first.
	RecentEvents []AuditEvent `json:"recentEvents,omitempty"`

	// Cache is still a seam: in scope per D126, not built. Rendering it as an explicit
	// "not implemented" keeps the wire shape stable for the console and the CLI.
	//
	// ⚠️ Upstream is NO LONGER a seam, and this comment used to say "this service
	// fetches no registries (the firewall does)". That stopped being true when D158's
	// protocol-scraping step landed here — see approval/upstream.go for why it landed
	// here rather than in the firewall. Updated on purpose: a contract sentence that
	// quietly stops being true is worse than one that never was.
	//
	// It is OFF unless an operator configures a registry base URL, so the shipped
	// default still renders "not collected by this service" and makes no outbound call.
	// UpstreamHarvest is what the registry itself reports, fetched on demand and
	// never stored — registry metadata goes stale, and a cached answer presented as
	// current is the same failure mode the whole "report, not a promise" framing of
	// this endpoint exists to avoid. Nil unless Upstream == availPresent.
	UpstreamHarvest *upstreamHarvest `json:"upstream,omitempty"`
	Upstream        string           `json:"upstreamMetadata"`
	Cache           string           `json:"cacheStatus"`
}

// Availability markers. Strings rather than booleans because there are more than two
// answers and the difference between them is the whole point: "never requested" and
// "requested and could not be scored" are opposite operational situations that a
// boolean would flatten into the same false.
const (
	availNotCollected   = "not-collected-by-this-service"
	availNotImplemented = "not-implemented"
	availNoRepoKnown    = "no-source-repo-known-for-this-package"
	availNeverScanned   = "repo-known-but-never-scanned"
	availScoredNegative = "scanned-but-could-not-be-scored"
	availPresent        = "present"
	// Two outcomes the upstream harvest can reach that nothing else can, and they
	// must stay distinct: "we asked and the registry does not have it" is a real,
	// useful answer about the package, while "we could not ask" is a fact about US.
	// Collapsing either into an absent field would read as "no problem found".
	availNotInRegistry       = "not-found-in-the-registry"
	availUpstreamUnreachable = "upstream-registry-unreachable"
	// A third outcome, split out of "unreachable" by #139: the registry answered and the
	// document is larger than this service will read. It is a fact about OUR LIMIT, which
	// is neither of the two above, and the fix for a reader is different (nothing is
	// wrong with their network or the package).
	availUpstreamTooLarge = "registry-metadata-too-large-to-read"
	// And a fourth, split out by #152: the registry was reached and was answering, and
	// the answer did not FINISH inside upstreamFetchTimeout. Once the npm read streamed,
	// this became the outcome for the largest packuments on a slow link -- measured
	// 2026-09-21 from a residential line, `vite` (37 MB, 4.6 MB compressed) took 13.7 s.
	// "Unreachable" sends the reader to check connectivity that is working; this tells
	// them it is a matter of time and size, which has different remedies.
	availUpstreamTimedOut = "upstream-registry-timed-out"

	granularityPackageOnly = "package-only (version-level decisions are not stored)"
)

// recentEventLimit caps the history in the response. Small on purpose: this is a
// "why is my build broken" view, not the audit export (#28 streams that in full and
// without a limit, precisely because completeness is what makes an export worth
// having). A developer who needs more than this wants the audit view.
const recentEventLimit = 10

// getPackageStatus answers GET /v1/packages?package=NAME[&ecosystem=E].
//
// It returns 200 with an "everything we do not know" body for a package we have never
// seen, rather than 404. That is deliberate and it is the D102/D139 case: the person
// most likely to call this is someone whose install just failed on a package nobody
// has ever requested. A 404 would tell them "no such package", which is the exact
// misreading that made the pip block unactionable in the first place (#79). The body
// distinguishes "we have never seen this" from "we have nothing to say", which a bare
// status code cannot.
func (srv *server) getPackageStatus(w http.ResponseWriter, r *http.Request) {
	pkg := strings.TrimSpace(r.URL.Query().Get("package"))
	if pkg == "" {
		http.Error(w, "query parameter 'package' is required", http.StatusBadRequest)
		return
	}
	ecosystem := strings.TrimSpace(r.URL.Query().Get("ecosystem"))

	st := packageStatus{
		Package:             pkg,
		Ecosystem:           ecosystem,
		DecisionGranularity: granularityPackageOnly,
		ScoreAvailability:   availNoRepoKnown,
		Upstream:            availNotCollected,
		Cache:               availNotImplemented,
	}

	// D158's protocol-scraping step. Fetched on demand and never stored, because
	// registry metadata goes stale and a cached answer shown as current is the exact
	// "report vs promise" failure this endpoint is written around. Nil fetcher (the
	// shipped default, no registry configured) leaves Upstream at availNotCollected
	// and makes no outbound call at all.
	if srv.upstream != nil {
		st.UpstreamHarvest, st.Upstream = harvestUpstream(srv.upstream, pkg)
	}

	// The human ruling, if any. A missing decision is normal, not an error.
	if d, ok, err := srv.store.Get(pkg); err != nil {
		log.Printf("package status %q: decision lookup: %v", pkg, err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	} else if ok {
		st.Decision = &d
		// The admin-supplied repo is currently the only package -> repo mapping this
		// service holds, which is why a score is often unreachable even when one was
		// computed. Worth keeping in view: it is the argument for recording the
		// resolved repo on the audit event.
		if repo := strings.TrimSpace(d.RepoURL); repo != "" {
			st.ScoreAvailability = availNeverScanned
			rec, found, err := srv.store.GetScore(repo)
			if err != nil {
				log.Printf("package status %q: score lookup for %q: %v", pkg, repo, err)
				http.Error(w, "storage error", http.StatusInternalServerError)
				return
			}
			if found {
				st.Score = &rec
				if rec.Score == nil {
					// A durable NEGATIVE: we scanned and could not score it. Distinct
					// from "no row", and the distinction is why ScoreRecord.Score is a
					// pointer — see its comment in store.go.
					st.ScoreAvailability = availScoredNegative
				} else {
					st.ScoreAvailability = availPresent
				}
			}
		}
	}

	// What the gate actually did, most recent first. Package is a substring match in
	// EventFilter, so filter exactly here — a developer asking about "lodash" must not
	// be shown events for "lodash-es" and conclude their package was blocked.
	events, err := srv.store.ListEvents(EventFilter{Ecosystem: ecosystem, Package: pkg, Limit: 0})
	if err != nil {
		log.Printf("package status %q: event lookup: %v", pkg, err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	for _, e := range events {
		if !strings.EqualFold(e.Package, pkg) {
			continue
		}
		st.RecentEvents = append(st.RecentEvents, e)
		if len(st.RecentEvents) == recentEventLimit {
			break
		}
	}
	if len(st.RecentEvents) > 0 {
		st.LastObserved = &st.RecentEvents[0]
	}

	writeJSON(w, http.StatusOK, st)
}
