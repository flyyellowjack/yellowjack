package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The console decodes the control plane's tally with its own struct. This is the
// approval service's wire form written out literally (approval/eventsummary_test.go pins
// the same keys from the other side): a renamed key would decode to zero, and a zero on
// "stopped" reads as a quiet day.
func TestEventSummaryDecodesTheApprovalWireForm(t *testing.T) {
	wire := `{"since":"2026-09-22T12:00:00Z","allowed":2318,"blocked":14,"blocked_served":3,` +
		`"by_deny_kind":{"known-malware":9,"":5},"sources":41}`
	var s eventSummary
	if err := json.Unmarshal([]byte(wire), &s); err != nil {
		t.Fatal(err)
	}
	if s.Allowed != 2318 || s.Blocked != 14 || s.BlockedServed != 3 || s.Sources != 41 ||
		s.ByDenyKind["known-malware"] != 9 || s.ByDenyKind[""] != 5 || s.Since.IsZero() {
		t.Errorf("decoded %+v: a key did not map", s)
	}
}

func TestOverviewTiles(t *testing.T) {
	now := time.Now().UTC()
	f := &fakeApproval{
		decisions: []decision{
			{Package: "old", Verdict: "pending", FirstSeen: now.Add(-50 * time.Hour), UpdatedAt: now},
			{Package: "new", Verdict: "pending", FirstSeen: now.Add(-2 * time.Hour), UpdatedAt: now},
			{Package: "done", Verdict: "approved", FirstSeen: now.Add(-9 * time.Hour), UpdatedAt: now},
		},
		summary: eventSummary{Allowed: 2318, Blocked: 14, BlockedServed: 3, Sources: 41,
			ByDenyKind: map[string]int{"known-malware": 9, "score-below-threshold": 5}},
	}
	body := getPage(t, newTestServer(f), "/")

	for _, want := range []string{
		">2<",                   // two waiting, the settled one not counted
		"Oldest waiting 2 days", // the oldest, not the newest
		"past the one-day target",
		">14<", "9 known malware · 5 by policy",
		"3 more logged and served (report mode)", // served-anyway is its own number
		">2,318<", "From 41 hosts",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	// The tiles cover the last 24 hours, and say so.
	if age := now.Sub(f.summarySince); age < 23*time.Hour || age > 25*time.Hour {
		t.Errorf("overview asked for the tally since %s ago, want about 24h", age)
	}
	if !strings.Contains(body, "last 24 hours") {
		t.Errorf("the tiles do not say which window they cover")
	}
}

// An unreadable tally is "Unknown", never 0. A zero is a quiet day; this is not one.
func TestOverviewTallyFailureIsNotZero(t *testing.T) {
	// One waiting package, so the only tiles that could render a zero are the two the
	// failed tally feeds.
	f := &fakeApproval{summaryErr: errors.New("connection refused"),
		decisions: []decision{{Package: "p", Verdict: "pending", FirstSeen: time.Now(), UpdatedAt: time.Now()}}}
	body := getPage(t, newTestServer(f), "/")
	if strings.Count(body, `<span class="v unknown">Unknown</span>`) < 2 {
		t.Errorf("the stopped and allowed tiles do not both say Unknown when the tally fails")
	}
	if strings.Contains(body, `<span class="v">0</span>`) {
		t.Errorf("a failed tally rendered as a zero")
	}
}

// The feed tile states what the gates report, and flags disagreement or absence.
func TestOverviewFeedTile(t *testing.T) {
	now := time.Now().UTC()
	gate := func(name, feed string) instanceHealth {
		return instanceHealth{Instance: name, ReportedAt: now,
			Policy: &policyDoc{Digest: "d", Values: map[string]string{"known_malware_feed": feed}}}
	}
	cases := []struct {
		name string
		rows []instanceHealth
		want string
	}{
		{"count", []instanceHealth{gate("a", "1482 enforced (1482 package-wide, 0 version-pinned), sha256:abc")}, ">1,482<"},
		// A gate from before the count was split still reports a leading total, and parses.
		{"older gate", []instanceHealth{gate("a", "7 enforced incl. version-pinned, sha256:abc")}, ">7<"},
		{"off", []instanceHealth{gate("a", "off")}, ">Off<"},
		{"differs", []instanceHealth{gate("a", "10 enforced (10 package-wide, 0 version-pinned), sha256:a"), gate("b", "11 enforced (11 package-wide, 0 version-pinned), sha256:b")}, ">Differs<"},
		{"no gates", nil, "No gate is reporting its policy."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := getPage(t, newTestServer(&fakeApproval{health: c.rows}), "/")
			if !strings.Contains(body, c.want) {
				t.Errorf("feed tile lacks %q", c.want)
			}
		})
	}
}

func TestBreakdownGroupsByWhoToAsk(t *testing.T) {
	got := breakdown(map[string]int{"known-malware": 9, "unscorable": 1, "operator-denied": 3, "": 2, "unverified": 0})
	if got != "9 known malware · 3 on your block list · 3 by policy" {
		t.Errorf("breakdown = %q", got)
	}
	if got := breakdown(map[string]int{"known-malware": 1}); got != "1 known malware" {
		t.Errorf("single-kind breakdown = %q", got)
	}
}

func TestWhenLabelAcrossAMonthBoundary(t *testing.T) {
	now := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	for at, want := range map[time.Time]string{
		time.Date(2026, 10, 1, 8, 5, 0, 0, time.UTC):   "Today, 08:05",
		time.Date(2026, 9, 30, 23, 59, 0, 0, time.UTC): "Yesterday, 23:59",
		time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC):  "29 Sep, 12:00",
	} {
		if got := whenLabel(at, now); got != want {
			t.Errorf("whenLabel(%s) = %q, want %q", at, got, want)
		}
	}
}

// ── Decisions desk ──────────────────────────────────────────────────────────────

func deskFake(now time.Time) *fakeApproval {
	score, threshold := 3.8, 5.0
	return &fakeApproval{
		decisions: []decision{
			{Package: "axios", Verdict: "pending", Note: "scored 3.8, below required 5.0", FirstSeen: now.Add(-5 * time.Hour), UpdatedAt: now},
			{Package: "left-pad-utils", Verdict: "pending", Note: "no usable source repository", FirstSeen: now.Add(-30 * time.Hour), UpdatedAt: now},
		},
		events: []event{
			// Substring neighbour: the store's package filter would return it for "axios".
			{Package: "axios-retry", Ecosystem: "npm", Action: "block", DenyKind: "known-malware", SourceIP: "10.9.9.9", At: now.Add(-time.Hour)},
			{Package: "axios", Ecosystem: "npm", Action: "block", DenyKind: "score-below-threshold", Score: &score, Threshold: &threshold, SourceIP: "10.0.0.2", At: now.Add(-2 * time.Hour), Taken: "block"},
			{Package: "axios", Ecosystem: "npm", Action: "block", DenyKind: "score-below-threshold", Score: &score, Threshold: &threshold, SourceIP: "10.0.0.1", At: now.Add(-3 * time.Hour), Taken: "block"},
			{Package: "left-pad-utils", Ecosystem: "npm", Action: "allow", Reason: "unscorable; allowed by policy rule", SourceIP: "10.0.0.3", At: now.Add(-4 * time.Hour), Taken: "allow"},
		},
		status:   packageStatus{UpstreamHarvest: &upstreamHarvest{LatestVersion: "1.14.1", Maintainers: 3}},
		statusOK: true,
	}
}

// With nothing chosen, the desk opens on the package that has waited longest -- the one
// the queue's own order says to look at first.
func TestDecisionsSelectsLongestWaitingByDefault(t *testing.T) {
	body := getPage(t, newTestServer(deskFake(time.Now().UTC())), "/decisions")
	if !strings.Contains(body, `<h2 id="dt">left-pad-utils</h2>`) {
		t.Errorf("the detail pane does not open on the longest-waiting package")
	}
}

func TestDecisionsDetailForAScoreRefusal(t *testing.T) {
	f := deskFake(time.Now().UTC())
	body := getPage(t, newTestServer(f), "/decisions?pkg=axios")
	for _, want := range []string{
		`<h2 id="dt">axios</h2>`,
		"Its health score is 3.8, below your threshold of 5.0",
		"10.0.0.1, 10.0.0.2", // both hosts that asked for axios
		"1.14.1",             // the registry's account
	} {
		if !strings.Contains(body, want) {
			t.Errorf("axios detail lacks %q", want)
		}
	}
	// Exactly axios: the substring neighbour's host and malware finding are not its.
	if strings.Contains(body, "10.9.9.9") {
		t.Errorf("the detail borrowed a host from axios-retry, a different package")
	}
	if f.statusPkg != "axios" || f.statusEco != "npm" {
		t.Errorf("registry lookup asked for %q/%q, want axios/npm", f.statusPkg, f.statusEco)
	}
}

// A package the policy serves while it waits must not be described as blocked.
func TestDecisionsDetailSaysServedWhileWaiting(t *testing.T) {
	body := getPage(t, newTestServer(deskFake(time.Now().UTC())), "/decisions?pkg=left-pad-utils")
	if !strings.Contains(body, "It is being served and logged") || !strings.Contains(body, "whybox served") {
		t.Errorf("a package served under allow-but-log is not described as served")
	}
	if strings.Contains(body, "Blocked,") {
		t.Errorf("a served package is shown with a Blocked verdict")
	}
}

// The ruling form says what an approval covers, because the canvas it was drawn from
// said the opposite: approvals are per package name (D345).
func TestDecisionsFormSaysAnApprovalCoversEveryVersion(t *testing.T) {
	now := time.Now().UTC()
	srv := newAuthedServer(deskFake(now), "admin", "s3cret")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/decisions?pkg=axios", nil)
	req.SetBasicAuth("admin", "s3cret")
	srv.ServeHTTP(rr, req)
	body := rr.Body.String()
	for _, want := range []string{"Covers every version of this package", `name="verdict" value="approved"`, `name="verdict" value="denied"`, `name="note"`} {
		if !strings.Contains(body, want) {
			t.Errorf("ruling form lacks %q", want)
		}
	}
	if strings.Contains(body, "version only") {
		t.Errorf("the page claims a version-scoped approval, which the queue does not make")
	}
}

// A ruling given without a comment keeps the gate's own reason on the record.
func TestOverrideWithEmptyNoteKeepsTheRecordedNote(t *testing.T) {
	f := &fakeApproval{getResult: map[string]decision{
		"axios": {Package: "axios", Verdict: "pending", Note: "scored 3.8, below required 5.0"},
	}}
	srv := newAuthedServer(f, "admin", "s3cret")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, overrideRequest("admin", "s3cret", "",
		url.Values{"package": {"axios"}, "verdict": {"approved"}, "note": {"  "}}))
	if len(f.puts) != 1 || f.puts[0].Note != "scored 3.8, below required 5.0" {
		t.Fatalf("puts = %+v, want the recorded note kept", f.puts)
	}
	// And a real comment replaces it.
	srv.ServeHTTP(httptest.NewRecorder(), overrideRequest("admin", "s3cret", "",
		url.Values{"package": {"axios"}, "verdict": {"approved"}, "note": {"vendored by the platform team"}}))
	if len(f.puts) != 2 || f.puts[1].Note != "vendored by the platform team" {
		t.Errorf("a written note did not replace the recorded one: %+v", f.puts)
	}
}

// A tab's count is what clicking it shows: it honours the package filter.
func TestDecisionsTabsCountWithinThePackageFilter(t *testing.T) {
	body := getPage(t, newTestServer(queueFixture()), "/decisions?package=left")
	for _, want := range []string{`>All<span class="n">· 1</span>`, `>Allowed by a person<span class="n">· 1</span>`, `>Waiting<span class="n">· 0</span>`} {
		if !strings.Contains(body, want) {
			t.Errorf("tabs lack %q", want)
		}
	}
}
