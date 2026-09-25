package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// #151 / D273 s5: when no scanner is configured, the console must treat that as a
// configuration, not a gap -- no empty Score section, no columns of dashes implying
// something failed to run.
//
// The predicate is deliberately conservative, and each test below pins one edge of
// it. The dangerous direction is HIDING on thin evidence: a page that drops its
// scoring columns because a replica happened not to report is a page lying about
// what the fleet does, which is the failure /policy exists to prevent.

func fleet(modes ...string) []instanceHealth {
	var rows []instanceHealth
	for i, m := range modes {
		h := instanceHealth{Instance: "fw-" + string(rune('a'+i)), ReportedAt: time.Now().UTC()}
		switch m {
		case "": // reports a policy but not the mode -- a gate that predates the key
			h.Policy = &policyDoc{Values: map[string]string{"score_threshold": "5"}}
		case "nopolicy": // reports no policy at all
		default:
			h.Policy = &policyDoc{Values: map[string]string{"scorecard_mode": m, "score_threshold": "5"}}
		}
		rows = append(rows, h)
	}
	return rows
}

func TestScoringOffPredicate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rows  []instanceHealth
		err   error
		want  bool
		since string
	}{
		{"every replica off", fleet("off", "off"), nil, true, "the only case that hides"},
		{"single replica off", fleet("off"), nil, true, ""},
		{"a scoring replica", fleet("local"), nil, false, "scores exist somewhere in the fleet"},
		{"mixed fleet", fleet("off", "local"), nil, false, "a divergence the operator must SEE, not a reason to hide"},
		{"mode not reported", fleet(""), nil, false, "absent is not off -- a rolling deploy must not blank the page"},
		{"no policy reported", fleet("nopolicy"), nil, false, "same"},
		{"off beside an unreporting replica", fleet("off", ""), nil, true, "the unreporting one is unknown, not scoring"},
		{"empty fleet", nil, nil, false, "nothing reported means nothing is known -- the vacuous hide"},
		{"control plane unreachable", nil, errors.New("control plane unreachable"), false, "an error is not evidence scoring is off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &server{approval: &fakeApproval{health: tc.rows, healthErr: tc.err}}
			if got := s.scoringOff(); got != tc.want {
				t.Fatalf("scoringOff() = %v, want %v -- %s", got, tc.want, tc.since)
			}
		})
	}
}

// TestLookupHidesTheScoreSectionOnlyWhenTheFleetIsOff drives the page, because the
// predicate being right proves nothing about the template using it.
func TestLookupHidesTheScoreSectionOnlyWhenTheFleetIsOff(t *testing.T) {
	found := packageStatus{
		Package: "lodash", Ecosystem: "npm",
		ScoreAvailability: "no-source-repo-known-for-this-package",
		Upstream:          "not-collected-by-this-service",
		Cache:             "not-implemented",
		LastObserved:      &event{Action: "allow", Reason: "served: scoring is disabled", At: time.Now()},
	}

	// Control FIRST: with a scoring fleet the section renders. Without this the
	// assertion below is satisfied by a template that never had the section.
	fa := &fakeApproval{statusOK: true, status: found, health: fleet("local")}
	body := lookupGet(t, newTestServer(fa), "?package=lodash&ecosystem=npm").Body.String()
	if !strings.Contains(body, "<h2>Score</h2>") {
		t.Fatal("control: a scoring fleet must render the Score section, or the hide below proves nothing")
	}

	fa = &fakeApproval{statusOK: true, status: found, health: fleet("off")}
	body = lookupGet(t, newTestServer(fa), "?package=lodash&ecosystem=npm").Body.String()
	if strings.Contains(body, "<h2>Score</h2>") {
		t.Error("the fleet reports scoring off, yet /lookup still renders a Score section -- an empty " +
			"scanner panel is the 'big missing asset' nag D273 ruled against")
	}
	// The page must still be a page: the other sections are unaffected.
	for _, keep := range []string{"Last observed decision", "Recent history"} {
		if !strings.Contains(body, keep) {
			t.Errorf("hiding the Score section also lost %q", keep)
		}
	}
}

func TestAuditDropsScoreColumnsOnlyWhenTheFleetIsOff(t *testing.T) {
	score, threshold := 7.5, 5.0
	events := []event{{Package: "lodash", Ecosystem: "npm", Action: "allow", Score: &score,
		Threshold: &threshold, At: time.Now()}}
	get := func(fa *fakeApproval) string {
		rr := httptest.NewRecorder()
		newTestServer(fa).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/audit", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("/audit = %d", rr.Code)
		}
		return rr.Body.String()
	}

	// Control first, for the same reason as the lookup test.
	body := get(&fakeApproval{events: events, health: fleet("local")})
	if !strings.Contains(body, "<th>Score</th>") || !strings.Contains(body, "7.5") {
		t.Fatal("control: a scoring fleet must render the Score column and the value")
	}

	body = get(&fakeApproval{events: events, health: fleet("off")})
	if strings.Contains(body, "<th>Score</th>") || strings.Contains(body, "<th>Threshold</th>") {
		t.Error("the fleet reports scoring off, yet /audit still renders Score/Threshold columns")
	}
	// The row's OTHER cells survive: hiding two columns must not drop the event.
	if !strings.Contains(body, "lodash") || !strings.Contains(body, "allow") {
		t.Error("hiding the score columns lost the event row itself")
	}

	// And a mixed fleet keeps the columns: one replica still scores, and a page that
	// hid its scores while a replica produced them would be the wrong kind of quiet.
	body = get(&fakeApproval{events: events, health: fleet("off", "api")})
	if !strings.Contains(body, "<th>Score</th>") {
		t.Error("a mixed fleet (one off, one scoring) must keep the Score column")
	}
}

// TestScoringModeIsNotHiddenFromThePolicyPage: /policy is the provability surface
// (D136). Hiding scoring from lookup/audit is only honest if the policy page still
// shows WHY -- the reported value must appear there, not vanish with the columns.
func TestScoringModeIsNotHiddenFromThePolicyPage(t *testing.T) {
	fa := &fakeApproval{health: fleet("off")}
	rr := httptest.NewRecorder()
	newTestServer(fa).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/policy", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("/policy = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "scorecard_mode") {
		t.Error("/policy does not show scorecard_mode; the operator has no way to see WHY scores are absent elsewhere")
	}
}
