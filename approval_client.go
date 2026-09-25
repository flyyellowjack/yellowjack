package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// approvalDecision mirrors the subset of the approval service's response we need.
// Each service owns its own data-transfer type across the HTTP boundary — we
// deliberately do NOT share a Go type with the approval service, so the two can
// evolve independently. This is normal for microservices talking over REST.
type approvalDecision struct {
	Package string `json:"package"`
	Verdict string `json:"verdict"` // "pending" | "approved" | "denied"
	RepoURL string `json:"repoUrl,omitempty"`
}

// lookupApproval asks the approval service whether a human has ruled on pkg.
// found=false (no error) means no decision is recorded yet (HTTP 404).
//
// THE RESPONSE MUST BE ABOUT THE PACKAGE WE ASKED ABOUT. The request key says what was
// asked; it says nothing about what came back, and until now nothing checked. That is
// the confused-deputy shape issue #67 was: there, a URL prefix was treated as
// authoritative about which BYTES were served; here, the query string would be treated
// as authoritative about which RULING was returned. A record for another package is a
// fault in the control plane, not a decision about this one, so it is refused and named.
//
// This cannot break a correctly-behaving service: both stores key on an exact-match
// TEXT PRIMARY KEY (`s.decisions[pkg]`; `WHERE package = $1`) and return that stored
// key, so `d.Package == pkg` already holds by construction. What it catches is a
// mis-keyed cache or proxy between us and the service, a replaced implementation, and —
// measured, not hypothetical — a TEST STUB that answers every query with one fixed body,
// which is how e2e legs go silently vacuous (see startApprovalStub in e2e/harness.go).
//
// A mismatch returns an error rather than found=false so it is logged loudly. The
// caller (applyHumanRuling) already treats a lookup error as "no human ruling" and falls
// back to policy, so the blast radius is the same as an approval-service outage: a
// foreign APPROVAL can never open the gate, and a foreign DENIAL is not applied to a
// package it was never about.
func (f *Firewall) lookupApproval(pkg string) (approvalDecision, bool, error) {
	endpoint := fmt.Sprintf("%s/v1/decisions?package=%s",
		strings.TrimRight(f.cfg.ApprovalURL, "/"), url.QueryEscape(pkg))
	resp, err := f.client.Get(endpoint)
	if err != nil {
		return approvalDecision{}, false, err
	}
	defer closeDrained(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return approvalDecision{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return approvalDecision{}, false, fmt.Errorf("approval service returned status %d", resp.StatusCode)
	}
	var d approvalDecision
	if err := decodeCapped(resp.Body, smallJSONMaxBytes, &d); err != nil {
		return approvalDecision{}, false, err
	}
	// Strict, including the empty case: an absent `package` field is not evidence that
	// the record is ours. Treating empty as a pass is the same mistake as reading an
	// empty deny kind as "not a hard deny" (!91).
	if d.Package != pkg {
		return approvalDecision{}, false, fmt.Errorf(
			"approval service answered a query for %q with a record for %q; refusing to apply another package's ruling", pkg, d.Package)
	}
	return d, true, nil
}

// scoreRecord mirrors the subset of the approval /v1/scores response we need — the
// firewall's own DTO for the L2 durable score cache (D18), kept separate from the
// approval service's Go type so the two evolve independently. Score is a pointer:
// nil is the NEGATIVE marker ("scanned, could not score"), distinct from a 404
// ("never scanned" / cold).
type scoreRecord struct {
	Repo  string   `json:"repo"`
	Score *float64 `json:"score"`
	// UpdatedAt is when the approval service last wrote this row. The firewall reads
	// it to enforce the L2 freshness window (FW_SCORE_L2_TTL, issue #12): a row older
	// than the window is treated as cold and re-scanned. Zero (field absent) means
	// "age unknown" — the freshness check treats that as fresh, so an older record
	// without a timestamp never gets churned.
	UpdatedAt time.Time `json:"updatedAt"`

	// Coverage (#133): what the score was computed over. Zero/empty on a full report
	// and on rows written before these fields existed, so a reader treats "no
	// coverage" as "not partial", the same rule scannerResponse.Partial applies.
	ScoredChecks    int      `json:"scoredChecks,omitempty"`
	TotalChecks     int      `json:"totalChecks,omitempty"`
	ComputedWithout []string `json:"computedWithout,omitempty"`
}

// coverage is the record's coverage as the gate's own type (#154). Zero on a row that
// predates the fields, which reads as unknown, never as partial.
func (r scoreRecord) coverage() scoreCoverage {
	return scoreCoverage{ScoredChecks: r.ScoredChecks, TotalChecks: r.TotalChecks, ComputedWithout: r.ComputedWithout}
}

// lookupScore reads the L2 durable score cache for a repo. The three return shapes
// map to the three async outcomes the caller drives:
//
//	found=false            -> cold: no scan has run; the caller launches one.
//	found=true, hasScore=t -> a real numeric score to decide on.
//	found=true, hasScore=f -> the negative marker: scanned but unscorable; the
//	                          caller routes to the unscorable path, never re-scans.
//
// updatedAt is the row's write time (zero when found=false or absent), so the
// caller can apply the L2 freshness window (issue #12).
func (f *Firewall) lookupScore(repo string) (score float64, hasScore, found bool, updatedAt time.Time, err error) {
	rec, found, err := f.lookupScoreRecord(repo)
	if err != nil || !found {
		return 0, false, false, time.Time{}, err
	}
	if rec.Score == nil {
		return 0, false, true, rec.UpdatedAt, nil // negative marker
	}
	return *rec.Score, true, true, rec.UpdatedAt, nil
}

// lookupScoreRecord is lookupScore with the whole record, coverage included (#154).
// found=false with a nil error is cold; a nil rec.Score with found=true is the
// negative marker.
func (f *Firewall) lookupScoreRecord(repo string) (rec scoreRecord, found bool, err error) {
	if f.cfg.ApprovalURL == "" {
		return scoreRecord{}, false, nil // no L2 configured: treat as cold
	}
	endpoint := fmt.Sprintf("%s/v1/scores?repo=%s",
		strings.TrimRight(f.cfg.ApprovalURL, "/"), url.QueryEscape(repo))
	resp, err := f.client.Get(endpoint)
	if err != nil {
		return scoreRecord{}, false, err
	}
	defer closeDrained(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return scoreRecord{}, false, nil // cold
	}
	if resp.StatusCode != http.StatusOK {
		return scoreRecord{}, false, fmt.Errorf("approval scores returned status %d", resp.StatusCode)
	}
	if err := decodeCapped(resp.Body, smallJSONMaxBytes, &rec); err != nil {
		return scoreRecord{}, false, err
	}
	// Same identity rule as lookupApproval, and it matters more here: a score is the
	// number the whole verdict rests on, so accepting one recorded against a DIFFERENT
	// repo is borrow-a-score (#10/D33) arriving through our own control plane instead of
	// through publisher metadata. resolveCachedScore treats an error as cold, so the
	// cost of refusing is one re-scan — never a wrong number.
	if rec.Repo != repo {
		return scoreRecord{}, false, fmt.Errorf(
			"approval scores answered a query for %q with a record for %q; refusing to use another repo's score", repo, rec.Repo)
	}
	return rec, true, nil
}

// recordScore writes a successful background-scan result to the L2 cache.
// recordScoreUnscorable writes the negative marker. Both are best-effort: a failed
// write just means the next pull re-scans, never a broken pull. score==nil ->
// negative marker.
func (f *Firewall) recordScore(repo string, score float64, cov scoreCoverage) {
	f.putScore(repo, &score, cov)
}
func (f *Firewall) recordScoreUnscorable(repo string) { f.putScore(repo, nil, scoreCoverage{}) }

func (f *Firewall) putScore(repo string, score *float64, cov scoreCoverage) {
	if f.cfg.ApprovalURL == "" {
		return
	}
	body, _ := json.Marshal(scoreRecord{Repo: repo, Score: score,
		ScoredChecks: cov.ScoredChecks, TotalChecks: cov.TotalChecks, ComputedWithout: cov.ComputedWithout})
	endpoint := strings.TrimRight(f.cfg.ApprovalURL, "/") + "/v1/scores"
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		log.Printf("recordScore %q: build request: %v", repo, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		log.Printf("recordScore %q: %v", repo, err)
		return
	}
	status := resp.StatusCode
	closeDrained(resp.Body)
	if prev, changed := f.scoreOutcome.changed(status); changed {
		switch {
		case !accepted(status):
			log.Printf("recordScore: the control plane REFUSED a score (HTTP %d, first for %q). Scores refused this "+
				"way are not shared with other replicas or kept across a restart, so those repositories are "+
				"scanned again; verdicts are unaffected", status, repo)
		case prev != 0:
			log.Printf("recordScore: scores are being accepted again (HTTP %d)", status)
		}
	}
}

// recordPending tells the approval service we encountered an unscorable package
// so a human can review it later. Best-effort: failures are logged, never fatal —
// a missing audit note must not break a package pull.
func (f *Firewall) recordPending(pkg, why string) {
	body, _ := json.Marshal(map[string]string{
		"package": pkg,
		"verdict": "pending",
		"note":    why,
	})
	endpoint := strings.TrimRight(f.cfg.ApprovalURL, "/") + "/v1/decisions"
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		log.Printf("recordPending %q: build request: %v", pkg, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		log.Printf("recordPending %q: %v", pkg, err)
		return
	}
	status := resp.StatusCode
	closeDrained(resp.Body)
	// #153. This one has a consequence a person feels: the client has already been told
	// the package is awaiting approval, and a refusal here means it is NOT in the queue
	// anyone approves from. It re-records on the next request for the package, so it
	// heals by itself once the control plane recovers -- but until then the developer is
	// waiting on a decision nobody has been asked to make.
	if prev, changed := f.pendingOutcome.changed(status); changed {
		switch {
		case !accepted(status):
			log.Printf("recordPending: the control plane REFUSED a pending record (HTTP %d, first for %q). Packages "+
				"refused this way are NOT in the approval queue although the client was told they are pending; each "+
				"is re-recorded on its next request", status, pkg)
		case prev != 0:
			log.Printf("recordPending: pending records are being accepted again (HTTP %d)", status)
		}
	}
}
