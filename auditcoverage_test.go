package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

// #154: a partial score's coverage travels to the AUDIT EVENT, not only to the score
// cache and the lookup page (!363). An exported decision log that shows a 6.2 without
// saying it was computed over 15 of 18 checks is the #133 denominator trap one hop
// later: two records that read the same and were not the same measurement.

func partialCov() scoreCoverage {
	return scoreCoverage{ScoredChecks: 15, TotalChecks: 18, ComputedWithout: []string{"CI-Tests", "Contributors", "License"}}
}

func TestAuditVerdictCarriesWhatTheScoreWasComputedOver(t *testing.T) {
	a := &auditEmitter{ch: make(chan auditEvent, 4)}
	f := &Firewall{cfg: Config{Ecosystem: "npm", ScoreThreshold: 5.0}, audit: a}

	f.auditVerdict("lodash", "", Decision{Allowed: true, Score: 6.2, HasScore: true, Reason: "ok"}.withCoverage(partialCov()))
	e := <-a.ch
	if e.Score == nil || *e.Score != 6.2 {
		t.Fatalf("score missing from the event: %+v", e)
	}
	if e.ScoredChecks != 15 || e.TotalChecks != 18 || !reflect.DeepEqual(e.ComputedWithout, partialCov().ComputedWithout) {
		t.Errorf("the event does not say what 6.2 was computed over: %d of %d, without %v", e.ScoredChecks, e.TotalChecks, e.ComputedWithout)
	}

	// Control 1: a verdict WITHOUT a score gets no coverage even when the caller had
	// one -- there is no number on the record for it to describe.
	f.auditVerdict("evil", "", Decision{Allowed: false, Reason: "known malware", Deny: denyKnownMalware}.withCoverage(partialCov()))
	e = <-a.ch
	if e.Score != nil || e.ScoredChecks != 0 || e.TotalChecks != 0 || len(e.ComputedWithout) != 0 {
		t.Errorf("an unscored verdict carries coverage: %+v", e)
	}

	// Control 2: a full report records full coverage and nothing computed-without.
	f.auditVerdict("left-pad", "", Decision{Allowed: true, Score: 8.0, HasScore: true}.withCoverage(scoreCoverage{ScoredChecks: 18, TotalChecks: 18}))
	e = <-a.ch
	if e.ScoredChecks != 18 || e.TotalChecks != 18 || len(e.ComputedWithout) != 0 {
		t.Errorf("a full report recorded a shortfall: %+v", e)
	}
}

// TestWithCoverageRefusesAScorelessDecision pins withCoverage's own contract. It is
// NOT reachable through auditVerdict, which guards on HasScore a second time: with
// withCoverage's check removed, the control above stays green on the emitter's guard
// alone. Two guards on one property, each tested on its own.
func TestWithCoverageRefusesAScorelessDecision(t *testing.T) {
	if d := (Decision{Allowed: false, Reason: "known malware", Deny: denyKnownMalware}).withCoverage(partialCov()); d.Coverage != nil {
		t.Errorf("withCoverage attached coverage to a decision with no score: %+v", d.Coverage)
	}
	if d := (Decision{Allowed: true, Score: 6.2, HasScore: true}).withCoverage(partialCov()); d.Coverage == nil || d.Coverage.ScoredChecks != 15 {
		t.Errorf("withCoverage did not attach coverage to a scored decision: %+v", d.Coverage)
	}
}

// TestTheL2RecordsCoverageReachesTheDecision drives the async read path: the control
// plane answers /v1/scores with a partial record, and the decision the gate makes from
// it must carry that coverage -- and so must the L1 entry it warms, so the NEXT pull
// (an L1 hit) carries it too.
func TestTheL2RecordsCoverageReachesTheDecision(t *testing.T) {
	const repo = "gitlab.example/org/repo"
	ap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"repo":%q,"score":6.2,"updatedAt":%q,"scoredChecks":15,"totalChecks":18,"computedWithout":["CI-Tests","Contributors","License"]}`,
			repo, time.Now().UTC().Format(time.RFC3339))
	}))
	defer ap.Close()
	f := &Firewall{
		cfg:    Config{ScorecardMode: "local", ApprovalURL: ap.URL, ScoreThreshold: 5.0, ScoreL2TTL: time.Hour},
		client: ap.Client(),
		cache:  newScoreCache(time.Minute, 8),
	}

	sc, outcome, resolved := f.resolveCachedScore("pkg", repo)
	if !resolved || outcome != scoreReady || sc.Score != 6.2 {
		t.Fatalf("resolveCachedScore = (%+v, %v, %v)", sc, outcome, resolved)
	}
	if !reflect.DeepEqual(sc.Coverage, partialCov()) {
		t.Errorf("the L2 record's coverage was dropped on the way to the decision: %+v", sc.Coverage)
	}
	warmed, ok := f.cache.get(repo)
	if !ok || !reflect.DeepEqual(warmed.Coverage, partialCov()) {
		t.Errorf("L1 was warmed without the coverage, so the next pull would lose it: %+v (ok=%v)", warmed, ok)
	}

	// Through scoreFor (the L1 hit now) to a decision.
	got, outcome, err := f.scoreFor("pkg", repo)
	if err != nil || outcome != scoreReady {
		t.Fatalf("scoreFor = (%+v, %v, %v)", got, outcome, err)
	}
	d := f.decideByScore("pkg", got.Score, "").withCoverage(got.Coverage)
	if !d.Allowed || !d.HasScore || d.Coverage == nil || d.Coverage.ScoredChecks != 15 {
		t.Errorf("the decision lost the coverage: %+v", d)
	}
}

// TestAScoreWithoutCoverageIsUnknownNotPartial: deps.dev ("api" mode) reports no
// coverage, and an older L2 row has none. Both must read as unknown -- no fields on
// the event -- never as "0 of 0".
func TestAScoreWithoutCoverageIsUnknownNotPartial(t *testing.T) {
	a := &auditEmitter{ch: make(chan auditEvent, 2)}
	f := &Firewall{cfg: Config{Ecosystem: "npm", ScoreThreshold: 5.0}, audit: a}
	f.auditVerdict("lodash", "", Decision{Allowed: true, Score: 7.5, HasScore: true}.withCoverage(scoreCoverage{}))
	e := <-a.ch
	if e.ScoredChecks != 0 || e.TotalChecks != 0 || e.ComputedWithout != nil {
		t.Errorf("unknown coverage rendered as numbers: %+v", e)
	}
}
