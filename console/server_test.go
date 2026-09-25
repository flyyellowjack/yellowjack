package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeApproval is a stand-in for the approval REST client. Because handlers depend
// on the approvalClient interface, we can exercise the full read AND write paths
// with no approval service and no database. It records Put calls so tests can
// assert exactly what the override handler persisted.
type fakeApproval struct {
	decisions   []decision          // returned by List
	getResult   map[string]decision // returned by Get (found when the key is present)
	events      []event             // returned by ListEvents
	listErr     error
	getErr      error
	putErr      error
	eventsErr   error
	eventsLim   int               // records the limit the handler passed to ListEvents
	eventsFlt   eventFilter       // records the full filter the handler passed to ListEvents
	exportRaw   string            // NDJSON body ExportEvents streams back
	exportErr   error             // when set, ExportEvents fails before any bytes
	exportFlt   eventFilter       // records the filter the export handler passed
	ipRows      []ipCount         // returned by DownloadsByIP
	ipErr       error             // when set, DownloadsByIP fails
	ipFlt       eventFilter       // records the filter the downloads handler passed
	actRows     []packageActivity // returned by LastSeenByPackage
	actErr      error             // when set, LastSeenByPackage fails
	actFlt      eventFilter       // records the filter the activity handler passed
	health      []instanceHealth  // returned by ListInstanceHealth (#32 Phase D)
	healthErr   error             // when set, ListInstanceHealth fails
	puts        []decision        // every Put the handler made, in order
	fps         []falsePositive   // returned by ListFalsePositives (#142)
	fpsErr      error             // when set, ListFalsePositives fails
	fpReports   []falsePositive   // every ReportFalsePositive the handler made, in order
	fpErr       error             // when set, ReportFalsePositive fails
	status      packageStatus     // returned by PackageStatus (#73 lookup)
	statusOK    bool              // found flag PackageStatus returns
	statusErr   error             // when set, PackageStatus fails
	statusPkg   string            // records the package the lookup handler asked for
	statusCalls int               // how many times PackageStatus was invoked (not just its argument)
	statusEco   string            // records the ecosystem the lookup handler asked for

	// Capacity flow reads (#32 Pillar 2, D80/D81).
	flowSum    flowSummary   // returned by FlowSummary
	flowPkgs   []flowPackage // returned by FlowPackages
	flowErr    error         // when set, FlowSummary fails
	flowPkgErr error         // when set, FlowPackages fails -- SEPARATE from flowErr so a
	// test can fail one read and not the other; the handler must surface either as a 502,
	// and a single error field could not tell the two paths apart.
	summary      eventSummary // returned by SummarizeEvents (the Overview tiles)
	summaryErr   error
	summarySince time.Time  // records the window the Overview asked for
	flowFlt      flowFilter // records the filter the capacity handler passed to FlowSummary
	flowPFlt     flowFilter // and the one it passed to FlowPackages
}

func (f *fakeApproval) FlowSummary(flt flowFilter) (flowSummary, error) {
	f.flowFlt = flt
	return f.flowSum, f.flowErr
}

func (f *fakeApproval) FlowPackages(flt flowFilter) ([]flowPackage, error) {
	f.flowPFlt = flt
	return f.flowPkgs, f.flowPkgErr
}

func (f *fakeApproval) List() ([]decision, error) { return f.decisions, f.listErr }

func (f *fakeApproval) SummarizeEvents(since time.Time) (eventSummary, error) {
	f.summarySince = since
	return f.summary, f.summaryErr
}

func (f *fakeApproval) PackageStatus(pkg, eco string) (packageStatus, bool, error) {
	// statusCalls counts the CALL, not its argument. Recording only the argument makes
	// "was the backend contacted at all?" unanswerable whenever the argument is empty --
	// which is exactly the case the empty-search test needs to check.
	f.statusCalls++
	f.statusPkg, f.statusEco = pkg, eco
	return f.status, f.statusOK, f.statusErr
}

func (f *fakeApproval) ListInstanceHealth() ([]instanceHealth, error) {
	return f.health, f.healthErr
}

func (f *fakeApproval) LastSeenByPackage(flt eventFilter) ([]packageActivity, error) {
	f.actFlt = flt
	return f.actRows, f.actErr
}

func (f *fakeApproval) ListEvents(flt eventFilter) ([]event, error) {
	f.eventsFlt = flt
	f.eventsLim = flt.Limit
	return f.events, f.eventsErr
}

func (f *fakeApproval) ExportEvents(flt eventFilter) (io.ReadCloser, error) {
	f.exportFlt = flt
	if f.exportErr != nil {
		return nil, f.exportErr
	}
	return io.NopCloser(strings.NewReader(f.exportRaw)), nil
}

func (f *fakeApproval) DownloadsByIP(flt eventFilter) ([]ipCount, error) {
	f.ipFlt = flt
	return f.ipRows, f.ipErr
}

func (f *fakeApproval) Get(pkg string) (decision, bool, error) {
	if f.getErr != nil {
		return decision{}, false, f.getErr
	}
	d, ok := f.getResult[pkg]
	return d, ok, nil
}

func (f *fakeApproval) ListFalsePositives() ([]falsePositive, error) { return f.fps, f.fpsErr }

func (f *fakeApproval) ReportFalsePositive(r falsePositive) (falsePositive, error) {
	if f.fpErr != nil {
		return falsePositive{}, f.fpErr
	}
	r.ID = int64(len(f.fpReports) + 1)
	f.fpReports = append(f.fpReports, r)
	return r, nil
}

func (f *fakeApproval) Put(d decision) (decision, error) {
	if f.putErr != nil {
		return decision{}, f.putErr
	}
	f.puts = append(f.puts, d)
	return d, nil
}

// newTestServer builds a read-only console (no auth configured => writes disabled).
func newTestServer(f *fakeApproval) *server { return &server{approval: f} }

// newAuthedServer builds a console with overrides enabled behind basic auth.
func newAuthedServer(f *fakeApproval, user, pass string) *server {
	return &server{approval: f, auth: newBasicAuth(user, pass)}
}

// overrideRequest builds a POST /override form request. httptest gives it Host
// "example.com", so origin "http://example.com" is same-origin.
func overrideRequest(user, pass, origin string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/override", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	return req
}

func TestHealthz(t *testing.T) {
	rr := httptest.NewRecorder()
	newTestServer(&fakeApproval{}).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", rr.Code)
	}
	if strings.TrimSpace(rr.Body.String()) != "ok" {
		t.Fatalf("healthz body = %q, want ok", rr.Body.String())
	}
}

func TestQueueRendersEachVerdictGroup(t *testing.T) {
	f := &fakeApproval{decisions: []decision{
		{Package: "charset-normalizer", Verdict: "pending", Note: "no repo", UpdatedAt: time.Now()},
		{Package: "left-pad", Verdict: "approved", RepoURL: "https://github.com/stevemao/left-pad", DecidedBy: "alice", UpdatedAt: time.Now()},
		{Package: "evil-pkg", Verdict: "denied", Note: "typosquat", UpdatedAt: time.Now()},
	}}
	rr := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/decisions", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("queue status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"charset-normalizer", "left-pad", "evil-pkg",
		`https://github.com/stevemao/left-pad`,
		"3 decision(s)", // Total reflects the list length
	} {
		if !strings.Contains(body, want) {
			t.Errorf("queue page missing %q", want)
		}
	}
}

// queueFixture is the three-verdict decision set the filter tests share.
func queueFixture() *fakeApproval {
	return &fakeApproval{decisions: []decision{
		{Package: "charset-normalizer", Verdict: "pending", Note: "no repo", UpdatedAt: time.Now()},
		{Package: "left-pad", Verdict: "approved", RepoURL: "https://github.com/stevemao/left-pad", DecidedBy: "alice", UpdatedAt: time.Now()},
		{Package: "evil-pkg", Verdict: "denied", Note: "typosquat", UpdatedAt: time.Now()},
	}}
}

// The queue form filters by package substring: only the match is rendered, the count
// reads "matching", and the input stays populated.
func TestQueueFilterByPackage(t *testing.T) {
	rr := httptest.NewRecorder()
	newTestServer(queueFixture()).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/decisions?package=EVIL", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("filtered queue = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "evil-pkg") {
		t.Errorf("filtered queue missing the match evil-pkg")
	}
	for _, absent := range []string{"charset-normalizer", "left-pad"} {
		if strings.Contains(body, absent) {
			t.Errorf("filtered queue should not contain %q", absent)
		}
	}
	for _, want := range []string{`value="EVIL"`, "1 decision(s) matching"} {
		if !strings.Contains(body, want) {
			t.Errorf("filtered queue missing %q", want)
		}
	}
}

// A verdict filter shows only that bucket — the other verdict groups (and their
// headings) are not rendered at all.
func TestQueueFilterByVerdict(t *testing.T) {
	rr := httptest.NewRecorder()
	newTestServer(queueFixture()).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/decisions?verdict=pending", nil))
	body := rr.Body.String()
	if !strings.Contains(body, "charset-normalizer") || !strings.Contains(body, "Awaiting review") {
		t.Errorf("verdict=pending should show the pending group")
	}
	for _, absent := range []string{"Allowed by a human", "Blocked by a human", "left-pad", "evil-pkg"} {
		if strings.Contains(body, absent) {
			t.Errorf("verdict=pending should not render %q", absent)
		}
	}
	if !strings.Contains(body, `value="pending" selected`) {
		t.Errorf("verdict dropdown should remember the selection")
	}
}

// A filter that matches nothing shows the explicit empty-filter message, not a bare
// set of empty verdict groups.
func TestQueueFilterNoMatch(t *testing.T) {
	rr := httptest.NewRecorder()
	newTestServer(queueFixture()).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/decisions?package=zzz-nope", nil))
	body := rr.Body.String()
	if !strings.Contains(body, "No decisions match this filter") {
		t.Errorf("expected the no-match message")
	}
	if !strings.Contains(body, "0 decision(s) matching") {
		t.Errorf("expected a zero matching count")
	}
}

// A bad verdict filter is rejected with 400, mirroring the audit view's action guard.
func TestQueueRejectsUnknownVerdict(t *testing.T) {
	f := queueFixture()
	rr := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/decisions?verdict=bogus", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("queue ?verdict=bogus = %d, want 400", rr.Code)
	}
}

// A package name or note we did not author must not be able to inject markup.
// html/template escapes by context; this asserts we actually rely on that.
func TestQueueEscapesUntrustedInput(t *testing.T) {
	f := &fakeApproval{decisions: []decision{
		{Package: "<script>alert(1)</script>", Verdict: "pending", Note: "<b>bad</b>", UpdatedAt: time.Now()},
	}}
	rr := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/decisions", nil))

	body := rr.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("raw <script> leaked into output — escaping is not working")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("expected escaped package name in output")
	}
}

func TestQueueUpstreamDownReturns502(t *testing.T) {
	f := &fakeApproval{listErr: errors.New("connection refused")}
	rr := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/decisions", nil))

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("upstream-down status = %d, want 502", rr.Code)
	}
}

// The two buckets are ordered by DIFFERENT rules on purpose (#50).
//
// This test previously required newest-first everywhere. That is right for a feed of
// recent rulings and wrong for a queue you are trying to keep bounded: it puts the
// freshest arrival on top and pushes the package that has been waiting longest to the
// bottom, so a growing backlog becomes less visible exactly as it gets worse.
func TestGroupByVerdictOrdersPendingByLongestWait(t *testing.T) {
	now := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	oldWait := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	newWait := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)

	v := groupByVerdict([]decision{
		{Package: "arrived-recently", Verdict: "pending", FirstSeen: newWait, UpdatedAt: newWait},
		{Package: "waiting-longest", Verdict: "pending", FirstSeen: oldWait, UpdatedAt: oldWait},
		{Package: "ruled-early", Verdict: "approved", FirstSeen: oldWait, UpdatedAt: oldWait},
		{Package: "ruled-late", Verdict: "approved", FirstSeen: oldWait, UpdatedAt: newWait},
	}, now)

	pending := v.pendingItems()
	if len(pending) != 2 || pending[0].Package != "waiting-longest" {
		t.Fatalf("pending must lead with the longest wait, got %+v", pending)
	}
	// The settled bucket keeps newest-first: it is activity history, not a backlog.
	approved := v.Groups[1].Items
	if len(approved) != 2 || approved[0].Package != "ruled-late" {
		t.Fatalf("settled rows must stay newest-first, got %+v", approved)
	}
}

// A row with no enqueue time must not be treated as brand new and jump the queue.
// Rows written before #50 have no FirstSeen; sorting them as "waited zero seconds"
// would park them above packages whose long wait we can actually prove.
func TestGroupByVerdictSortsUnmeasurableRowsLast(t *testing.T) {
	now := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	v := groupByVerdict([]decision{
		{Package: "no-first-seen", Verdict: "pending", UpdatedAt: now},
		{Package: "waiting-3-days", Verdict: "pending", FirstSeen: now.Add(-72 * time.Hour), UpdatedAt: now},
	}, now)

	pending := v.pendingItems()
	if len(pending) != 2 || pending[0].Package != "waiting-3-days" {
		t.Fatalf("a row with no enqueue time displaced a measurable wait: %+v", pending)
	}
	if pending[1].Waiting != "" {
		t.Errorf("an unmeasurable row rendered a wait of %q — it must render blank, "+
			"because a confident wrong number in this column is worse than an admitted gap",
			pending[1].Waiting)
	}
}

// AGE is the number #50 is about, so the rendering gets its own assertions.
func TestQueueRowRendersWaitAndFlagsTheTarget(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	v := groupByVerdict([]decision{
		{Package: "fresh", Verdict: "pending", FirstSeen: now.Add(-2 * time.Hour), UpdatedAt: now},
		{Package: "stale", Verdict: "pending", FirstSeen: now.Add(-90 * 24 * time.Hour), UpdatedAt: now},
		{Package: "settled", Verdict: "approved", FirstSeen: now.Add(-48 * time.Hour), UpdatedAt: now},
	}, now)

	byName := map[string]queueRow{}
	for _, g := range v.Groups {
		for _, r := range g.Items {
			byName[r.Package] = r
		}
	}

	if got := byName["fresh"].Waiting; got != "2 hours" {
		t.Errorf("fresh wait = %q, want 2 hours", got)
	}
	if byName["fresh"].OverTarget {
		t.Error("a 2-hour wait was flagged as over target; the target is hours, so " +
			"flagging inside it trains the operator to ignore the flag")
	}
	// The issue's own comparator: an operator reported a three-month process.
	if got := byName["stale"].Waiting; got != "90 days" {
		t.Errorf("stale wait = %q, want 90 days", got)
	}
	if !byName["stale"].OverTarget {
		t.Error("a 90-day wait was NOT flagged — this is the exact case #50 exists for")
	}
	// A settled row reports how long it WAITED, not a still-growing age.
	if got := byName["settled"].WaitEnded; got != "2 days" {
		t.Errorf("settled WaitEnded = %q, want 2 days", got)
	}
	if byName["settled"].Waiting != "" {
		t.Error("a decided package still shows a live 'waiting' age, which reads as backlog")
	}
}

// An unrecognized verdict must not be silently dropped — it lands in pending so a
// reviewer still sees it.
func TestGroupByVerdictUnknownVerdictNotHidden(t *testing.T) {
	v := groupByVerdict([]decision{{Package: "weird", Verdict: "quarantined"}}, time.Now())
	if len(v.pendingItems()) != 1 {
		t.Fatalf("unknown verdict was hidden: %+v", v)
	}
}

// --- Part (b): override write path + basic gateway auth (D19) --------------------

// Without a configured credential the console is read-only: the override endpoint
// must refuse to act (so we never ship an open state-mutating endpoint).
func TestOverrideDisabledWithoutAuth(t *testing.T) {
	f := &fakeApproval{}
	rr := httptest.NewRecorder()
	form := url.Values{"package": {"left-pad"}, "verdict": {"approved"}}
	newTestServer(f).ServeHTTP(rr, overrideRequest("", "", "http://example.com", form))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("override without auth = %d, want 403", rr.Code)
	}
	if len(f.puts) != 0 {
		t.Fatalf("override without auth should not persist anything, got %d puts", len(f.puts))
	}
}

// The read-only page advertises how to turn overrides on and renders no forms.
func TestQueueReadOnlyShowsNoForms(t *testing.T) {
	f := &fakeApproval{decisions: []decision{{Package: "left-pad", Verdict: "pending", UpdatedAt: time.Now()}}}
	rr := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/decisions", nil))

	body := rr.Body.String()
	if strings.Contains(body, `action="/override"`) {
		t.Errorf("read-only page should not render override forms")
	}
	if !strings.Contains(body, "Read-only") {
		t.Errorf("read-only page should explain how to enable overrides")
	}
}

// With a credential configured, every non-health route requires it.
func TestAuthRequiredWhenConfigured(t *testing.T) {
	// Seed a decision so the authed page has a row to hang an override form on
	// (forms are per-row; an empty queue renders none).
	f := &fakeApproval{decisions: []decision{{Package: "left-pad", Verdict: "pending", UpdatedAt: time.Now()}}}
	srv := newAuthedServer(f, "admin", "s3cret")

	// No credentials -> 401.
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/decisions", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no creds = %d, want 401", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("401 should carry a WWW-Authenticate challenge")
	}

	// Wrong credentials -> 401.
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/decisions", nil)
	req.SetBasicAuth("admin", "wrong")
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong creds = %d, want 401", rr.Code)
	}

	// Correct credentials -> 200 and forms are rendered.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/decisions", nil)
	req.SetBasicAuth("admin", "s3cret")
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("correct creds = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `action="/override"`) {
		t.Errorf("authed page should render override forms")
	}
}

func TestOverrideApprovePersistsWithDecidedBy(t *testing.T) {
	f := &fakeApproval{}
	srv := newAuthedServer(f, "admin", "s3cret")
	rr := httptest.NewRecorder()
	form := url.Values{
		"package": {"axios"},
		"verdict": {"approved"},
		"repoUrl": {"https://github.com/axios/axios"},
		"note":    {"healthy project, override"},
	}
	srv.ServeHTTP(rr, overrideRequest("admin", "s3cret", "http://example.com", form))

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("override = %d, want 303 (POST-redirect-GET)", rr.Code)
	}
	if len(f.puts) != 1 {
		t.Fatalf("want 1 put, got %d", len(f.puts))
	}
	got := f.puts[0]
	if got.Package != "axios" || got.Verdict != "approved" {
		t.Errorf("put = %+v, want axios/approved", got)
	}
	if got.DecidedBy != "admin" {
		t.Errorf("decidedBy = %q, want the authenticated user 'admin'", got.DecidedBy)
	}
	if got.RepoURL != "https://github.com/axios/axios" || got.Note != "healthy project, override" {
		t.Errorf("repoUrl/note not persisted: %+v", got)
	}
}

func TestOverrideDenyPersists(t *testing.T) {
	f := &fakeApproval{}
	srv := newAuthedServer(f, "admin", "s3cret")
	rr := httptest.NewRecorder()
	form := url.Values{"package": {"evil-pkg"}, "verdict": {"denied"}, "note": {"typosquat"}}
	srv.ServeHTTP(rr, overrideRequest("admin", "s3cret", "http://example.com", form))

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("deny = %d, want 303", rr.Code)
	}
	if len(f.puts) != 1 || f.puts[0].Verdict != "denied" {
		t.Fatalf("deny not persisted: %+v", f.puts)
	}
}

// A deny used to be conditional (#132): the gate consulted a human ruling only on
// its refuse path (D11), so a deny recorded for a package the policy allows on its
// own was stored, displayed, and never enforced -- and the console graded HOW
// un-enforced it was by whether the package had a record before the write.
//
// D272 (2026-09-19) reversed that: a deny now reaches every path. So this test is a
// deliberate reversal too. The prior-record distinction is gone, and the assertion
// that replaces it is that the two cases produce the SAME notice -- which is the
// only way to catch the old branch surviving as dead code that still says
// "not in force" to somebody.
//
// What the notice must still carry is the reach that IS conditional: the ruling
// lives in the approval service, and a gate that cannot reach it falls back to
// policy. The deny list is the block that survives that.
func TestOverrideDenySaysWhatItReaches(t *testing.T) {
	// No prior record. Post-D272 this is not a weaker deny than any other.
	f := &fakeApproval{}
	srv := newAuthedServer(f, "admin", "s3cret")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, overrideRequest("admin", "s3cret", "http://example.com",
		url.Values{"package": {"is-number"}, "verdict": {"denied"}}))
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("deny = %d, want 303", rr.Code)
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil || loc.Path != "/decisions" {
		t.Fatalf("deny redirected to %q, want the queue", rr.Header().Get("Location"))
	}
	notice := loc.Query().Get("notice")
	for _, want := range []string{"is-number", "every path", "D272", "deny list", "approval service"} {
		if !strings.Contains(notice, want) {
			t.Errorf("deny notice lacks %q: %q", want, notice)
		}
	}
	// The pre-D272 wording must be gone, not merely outvoted by new text.
	for _, gone := range []string{"not in force", "D11"} {
		if strings.Contains(notice, gone) {
			t.Errorf("deny notice still carries the pre-D272 wording %q: %q", gone, notice)
		}
	}
	if got := loc.Query().Get("level"); got != "ok" {
		t.Errorf("deny notice level = %q, want ok -- the deny is enforced now", got)
	}

	// The notice must reach the page the redirect lands on, not only the URL.
	rr = httptest.NewRecorder()
	get := httptest.NewRequest(http.MethodGet, loc.String(), nil)
	get.SetBasicAuth("admin", "s3cret")
	srv.ServeHTTP(rr, get)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "every path") {
		t.Errorf("queue page after the deny does not carry the notice (status %d)", rr.Code)
	}

	// A prior record used to produce a DIFFERENT, milder notice. It must now produce
	// the same one, modulo the package name: whether the console has seen this
	// package before no longer bears on what a deny reaches.
	f = &fakeApproval{getResult: map[string]decision{"axios": {Package: "axios", Verdict: "approved"}}}
	srv = newAuthedServer(f, "admin", "s3cret")
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, overrideRequest("admin", "s3cret", "http://example.com",
		url.Values{"package": {"axios"}, "verdict": {"denied"}}))
	loc, _ = url.Parse(rr.Header().Get("Location"))
	if got, want := loc.Query().Get("notice"), strings.ReplaceAll(notice, "is-number", "axios"); got != want {
		t.Errorf("a previously-recorded package gets a different deny notice than a new one; the prior-record "+
			"branch should be gone.\n got: %q\nwant: %q", got, want)
	}
	if got := loc.Query().Get("level"); got != "ok" {
		t.Errorf("deny notice level for a recorded package = %q, want ok", got)
	}

	// An approve carries a notice too, and it is not a warning.
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, overrideRequest("admin", "s3cret", "http://example.com",
		url.Values{"package": {"axios"}, "verdict": {"approved"}}))
	loc, _ = url.Parse(rr.Header().Get("Location"))
	if loc.Query().Get("level") != "ok" || !strings.Contains(loc.Query().Get("notice"), "Approved axios") {
		t.Errorf("approve notice = %q level %q", loc.Query().Get("notice"), loc.Query().Get("level"))
	}
}

// The standing sentence on the write-enabled queue page says what a ruling reaches,
// so the reach is stated before the first click and not only after it.
func TestQueueWriteBannerSaysWhatARulingReaches(t *testing.T) {
	f := &fakeApproval{decisions: []decision{{Package: "left-pad", Verdict: "pending", UpdatedAt: time.Now()}}}
	srv := newAuthedServer(f, "admin", "s3cret")
	rr := httptest.NewRecorder()
	get := httptest.NewRequest(http.MethodGet, "/decisions", nil)
	get.SetBasicAuth("admin", "s3cret")
	srv.ServeHTTP(rr, get)
	body := rr.Body.String()
	for _, want := range []string{"What a ruling reaches", "every path", "D272", "deny list"} {
		if !strings.Contains(body, want) {
			t.Errorf("write-enabled queue page lacks %q", want)
		}
	}
	// The pre-D272 sentence promised the opposite and must be gone, not buried.
	if strings.Contains(body, "not blocked by a deny recorded here") {
		t.Error("write-enabled queue page still tells the operator a deny does not reach a package the policy allows (reversed by D272)")
	}
	// And the read-only page, which offers no ruling, does not lecture about one.
	rr = httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/decisions", nil))
	if strings.Contains(rr.Body.String(), "What a ruling reaches") {
		t.Errorf("read-only queue page carries the write-path sentence")
	}
}

// Read-modify-write: when the form omits repoUrl/note, the existing values must be
// preserved (the approval PUT is a whole-record upsert, so a naive write would wipe
// them).
func TestOverridePreservesExistingFields(t *testing.T) {
	f := &fakeApproval{getResult: map[string]decision{
		"eslint": {Package: "eslint", Verdict: "pending", RepoURL: "https://github.com/eslint/eslint", Note: "prior note"},
	}}
	srv := newAuthedServer(f, "admin", "s3cret")
	rr := httptest.NewRecorder()
	// Only package + verdict; no repoUrl/note fields at all.
	form := url.Values{"package": {"eslint"}, "verdict": {"approved"}}
	srv.ServeHTTP(rr, overrideRequest("admin", "s3cret", "http://example.com", form))

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("override = %d, want 303", rr.Code)
	}
	got := f.puts[0]
	if got.RepoURL != "https://github.com/eslint/eslint" {
		t.Errorf("existing repoUrl was wiped: %+v", got)
	}
	if got.Note != "prior note" {
		t.Errorf("existing note was wiped: %+v", got)
	}
	if got.Verdict != "approved" {
		t.Errorf("verdict not updated: %+v", got)
	}
}

func TestOverrideInvalidVerdictRejected(t *testing.T) {
	f := &fakeApproval{}
	srv := newAuthedServer(f, "admin", "s3cret")
	rr := httptest.NewRecorder()
	form := url.Values{"package": {"axios"}, "verdict": {"pending"}} // console never sets pending
	srv.ServeHTTP(rr, overrideRequest("admin", "s3cret", "http://example.com", form))

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid verdict = %d, want 400", rr.Code)
	}
	if len(f.puts) != 0 {
		t.Fatalf("invalid verdict should not persist")
	}
}

// A cross-origin form POST (with the browser replaying cached Basic creds) must be
// rejected — the CSRF guard.
func TestOverrideCrossOriginRejected(t *testing.T) {
	f := &fakeApproval{}
	srv := newAuthedServer(f, "admin", "s3cret")
	rr := httptest.NewRecorder()
	form := url.Values{"package": {"axios"}, "verdict": {"approved"}}
	srv.ServeHTTP(rr, overrideRequest("admin", "s3cret", "http://evil.example", form))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-origin = %d, want 403", rr.Code)
	}
	if len(f.puts) != 0 {
		t.Fatalf("cross-origin override should not persist")
	}
}

// The audit view renders each event with its verdict badge, formatted score, and
// reason; a nil score shows a dash, not a bare 0. It also passes the bounded limit.
func TestAuditRendersEvents(t *testing.T) {
	score := 7.5
	f := &fakeApproval{events: []event{
		{ID: 2, Package: "evil-pkg", Ecosystem: "npm", Action: "block", Reason: "score 2.0 < 6.0", SourceIP: "203.0.113.5", At: time.Now()},
		{ID: 1, Package: "left-pad", Ecosystem: "npm", Action: "allow", Score: &score, Reason: "score 7.5 >= 6.0", At: time.Now()},
	}}
	rr := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/audit", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("audit status = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"evil-pkg", "left-pad",
		`badge block`, `badge allow`, // verdict badges
		"7.5",                // the allow event's formatted score
		"score 2.0 &lt; 6.0", // reason, HTML-escaped by html/template
		"203.0.113.5",        // the block event's observed source IP (#41)
		"2 recent event(s)",  // Total
	} {
		if !strings.Contains(body, want) {
			t.Errorf("audit page missing %q", want)
		}
	}
	// The block event had no score: the row shows the dash, and there must be no
	// bare "0.0" masquerading as a real score.
	if !strings.Contains(body, "—") {
		t.Errorf("audit page should render a dash for the scoreless block event")
	}
	if f.eventsLim != auditViewLimit {
		t.Errorf("handler requested limit %d, want %d", f.eventsLim, auditViewLimit)
	}
}

// The /audit filter form (?package/?ecosystem/?action) is forwarded to the approval
// client and echoed back into the page so the inputs stay populated and the count
// reads "matching".
func TestAuditFilterPassthrough(t *testing.T) {
	f := &fakeApproval{events: []event{
		{ID: 2, Package: "evil-pkg", Ecosystem: "npm", Action: "block", Reason: "score 2.0 < 6.0", At: time.Now()},
	}}
	rr := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr,
		httptest.NewRequest(http.MethodGet, "/audit?package=evil&ecosystem=npm&action=block", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("audit filtered = %d, want 200", rr.Code)
	}
	// The handler forwarded the whole filter (plus the bounded limit) to the client.
	if f.eventsFlt.Package != "evil" || f.eventsFlt.Ecosystem != "npm" || f.eventsFlt.Action != "block" {
		t.Errorf("forwarded filter = %+v, want {evil npm block}", f.eventsFlt)
	}
	if f.eventsFlt.Limit != auditViewLimit {
		t.Errorf("forwarded limit = %d, want %d", f.eventsFlt.Limit, auditViewLimit)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`value="evil"`,           // package input stays filled
		`value="npm"`,            // ecosystem input stays filled
		`value="block" selected`, // the action dropdown remembers the choice
		"matching event(s)",      // count wording switches when filtered
	} {
		if !strings.Contains(body, want) {
			t.Errorf("filtered audit page missing %q", want)
		}
	}
}

// A bad action filter is rejected at the console edge with 400 — not forwarded (which
// would surface as a misleading 502) and not silently ignored.
func TestAuditRejectsUnknownAction(t *testing.T) {
	f := &fakeApproval{}
	rr := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/audit?action=blocked", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("audit ?action=blocked = %d, want 400", rr.Code)
	}
	// The bad request never reached the approval client.
	if f.eventsFlt.Action != "" {
		t.Errorf("handler forwarded a bad action %q, should have rejected it first", f.eventsFlt.Action)
	}
}

func TestAuditUpstreamDownReturns502(t *testing.T) {
	f := &fakeApproval{eventsErr: errors.New("connection refused")}
	rr := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/audit", nil))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("audit upstream-down = %d, want 502", rr.Code)
	}
}

// When a credential is configured, the audit view is protected too (not just the
// override endpoint): no creds => challenge, not data.
func TestAuditRequiresAuthWhenConfigured(t *testing.T) {
	f := &fakeApproval{events: []event{{Package: "left-pad", Action: "allow"}}}
	srv := newAuthedServer(f, "admin", "s3cret")

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/audit", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("audit without creds = %d, want 401", rr.Code)
	}

	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	req.SetBasicAuth("admin", "s3cret")
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("audit with creds = %d, want 200", rr.Code)
	}
}

// /audit/export streams the approval service's NDJSON through as a file download,
// forwarding the filter, and never buffering it into a Go type (it is opaque bytes).
func TestAuditExportStreamsWithFilter(t *testing.T) {
	ndjson := `{"package":"left-pad","action":"allow"}` + "\n" + `{"package":"evil","action":"block"}` + "\n"
	f := &fakeApproval{exportRaw: ndjson}
	rr := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/audit/export?ecosystem=npm&action=block", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("export = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("export Content-Type = %q, want application/x-ndjson", ct)
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".jsonl") {
		t.Errorf("export Content-Disposition = %q, want an attachment .jsonl", cd)
	}
	if rr.Body.String() != ndjson {
		t.Errorf("export body = %q, want the upstream NDJSON streamed through verbatim", rr.Body.String())
	}
	// The filter reached the client (Limit stays zero — an export is never capped).
	if f.exportFlt.Ecosystem != "npm" || f.exportFlt.Action != "block" || f.exportFlt.Limit != 0 {
		t.Errorf("forwarded export filter = %+v, want {npm block, no limit}", f.exportFlt)
	}
}

// A bad action is rejected before contacting the approval service; an upstream failure
// is a clean 502 (the client reports it before any bytes are streamed).
func TestAuditExportErrors(t *testing.T) {
	f := &fakeApproval{}
	rr := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/audit/export?action=blocked", nil))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("export ?action=blocked = %d, want 400", rr.Code)
	}
	if f.exportFlt.Action != "" {
		t.Errorf("a rejected export must not reach the client, got filter %+v", f.exportFlt)
	}

	f = &fakeApproval{exportErr: errors.New("connection refused")}
	rr = httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/audit/export", nil))
	if rr.Code != http.StatusBadGateway {
		t.Errorf("export upstream-down = %d, want 502", rr.Code)
	}
}

// The audit page shows an Export link, and it carries the active filter so you export
// exactly what you are viewing.
func TestAuditPageHasScopedExportLink(t *testing.T) {
	f := &fakeApproval{events: []event{{Package: "evil", Action: "block", At: time.Now()}}}
	rr := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/audit?action=block&package=evil", nil))
	body := rr.Body.String()
	if !strings.Contains(body, `/audit/export?`) {
		t.Errorf("audit page missing a scoped export link")
	}
	// The link must carry the filter (order-independent check on the two params).
	if !strings.Contains(body, "action=block") || !strings.Contains(body, "package=evil") {
		t.Errorf("export link does not carry the active filter")
	}
}

// The audit page cross-links to the downloads-by-IP view, carrying the active filter,
// so "who pulled this?" is one click from the scoped incident set you're viewing.
func TestAuditPageLinksToDownloads(t *testing.T) {
	f := &fakeApproval{events: []event{{Package: "evil", Action: "block", At: time.Now()}}}
	rr := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/audit?action=block&package=evil", nil))
	body := rr.Body.String()
	if !strings.Contains(body, `/downloads?`) {
		t.Errorf("audit page missing a downloads-by-IP link")
	}
	if !strings.Contains(body, "action=block") || !strings.Contains(body, "package=evil") {
		t.Errorf("downloads link does not carry the active filter")
	}
}

// The downloads view renders the per-IP tally: real IPs, the (unobserved) bucket, the
// total-pulls / distinct-sources summary — and it must request a COMPLETE count (no
// limit forwarded to the client).
func TestDownloadsRendersRows(t *testing.T) {
	now := time.Now()
	f := &fakeApproval{ipRows: []ipCount{
		{IP: "10.0.0.5", Count: 12, LastAt: now},
		{IP: "10.0.0.6", Count: 3, LastAt: now},
		{IP: "", Count: 2, LastAt: now}, // unobserved bucket
	}}
	rr := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/downloads?package=left-pad", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("downloads = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"10.0.0.5", "10.0.0.6", // the real sources
		"(unobserved)",      // the empty-IP bucket, labeled
		"12",                // a per-IP count
		"17</strong> pull",  // TotalPulls = 12+3+2
		"3</strong> source", // DistinctIPs = 3
		"left-pad",          // the scoped package echoed into the summary
	} {
		if !strings.Contains(body, want) {
			t.Errorf("downloads page missing %q", want)
		}
	}
	// COMPLETENESS: the handler must not cap the tally — no limit reaches the client.
	if f.ipFlt.Limit != 0 {
		t.Errorf("downloads forwarded limit %d, want 0 (the tally is complete)", f.ipFlt.Limit)
	}
	if f.ipFlt.Package != "left-pad" {
		t.Errorf("forwarded filter package = %q, want left-pad", f.ipFlt.Package)
	}
}

// The /downloads filter is forwarded to the client; a typo'd action is a 400 that never
// reaches the approval service; an unreachable upstream is a clean 502.
func TestDownloadsFilterAndErrors(t *testing.T) {
	f := &fakeApproval{ipRows: []ipCount{{IP: "10.0.0.9", Count: 1, LastAt: time.Now()}}}
	rr := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr,
		httptest.NewRequest(http.MethodGet, "/downloads?package=evil&ecosystem=npm&action=block", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("downloads filtered = %d, want 200", rr.Code)
	}
	if f.ipFlt.Package != "evil" || f.ipFlt.Ecosystem != "npm" || f.ipFlt.Action != "block" {
		t.Errorf("forwarded filter = %+v, want {evil npm block}", f.ipFlt)
	}

	f = &fakeApproval{}
	rr = httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/downloads?action=blocked", nil))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("downloads ?action=blocked = %d, want 400", rr.Code)
	}
	if f.ipFlt.Action != "" {
		t.Errorf("a rejected action must not reach the client, got %+v", f.ipFlt)
	}

	f = &fakeApproval{ipErr: errors.New("connection refused")}
	rr = httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/downloads", nil))
	if rr.Code != http.StatusBadGateway {
		t.Errorf("downloads upstream-down = %d, want 502", rr.Code)
	}
}

// The activity page renders per-package rows, marks the quiet ones, and reports the
// "N of M not seen in D+ days" summary that answers D81 Q3.
func TestActivityRendersRows(t *testing.T) {
	now := time.Now()
	f := &fakeApproval{actRows: []packageActivity{
		{Package: "forgotten-lib", Ecosystem: "npm", Events: 3, LastAt: now.AddDate(0, 0, -90)},
		{Package: "fresh-lib", Ecosystem: "npm", Events: 12, LastAt: now.AddDate(0, 0, -1)},
	}}
	rec := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/activity", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /activity = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"forgotten-lib", "fresh-lib", "<strong>1</strong> of <strong>2</strong> package(s) not seen in 30+ days"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	// The page must state its own scope: it is observed flow, not a repository inventory.
	// Without this the view silently overclaims coverage it does not have.
	if !strings.Contains(body, "not</strong> an inventory of your repository") {
		t.Error("activity page does not state that it is observed flow, not a repository inventory")
	}
	// Completeness: the handler must never send a limit — a windowed read would drop
	// exactly the quiet packages this page exists to surface.
	if f.actFlt.Limit != 0 {
		t.Errorf("handler sent Limit=%d to LastSeenByPackage, want 0 (the aggregation is complete)", f.actFlt.Limit)
	}
}

// The default filter is the load-bearing detail of this view, and it deliberately
// DIFFERS from the audit/downloads pages: with no ?action the page counts allows only,
// because it claims to show when a package was last PULLED. If this regresses to "any
// verdict", a package blocked every day renders as freshly used — the opposite of the
// truth, in the one view whose purpose is spotting disuse.
func TestActivityDefaultsToPullsOnly(t *testing.T) {
	f := &fakeApproval{}
	rec := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/activity", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /activity = %d, want 200", rec.Code)
	}
	if f.actFlt.Action != "allow" {
		t.Errorf("default action filter = %q, want \"allow\" (this page means last PULLED)", f.actFlt.Action)
	}

	// An EXPLICITLY empty ?action= is the opt-in to counting blocks too, and must be
	// distinguishable from the param being absent — q.Get alone cannot tell them apart.
	f2 := &fakeApproval{}
	rec2 := httptest.NewRecorder()
	newTestServer(f2).ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/activity?action=", nil))
	if f2.actFlt.Action != "" {
		t.Errorf("explicit ?action= gave %q, want \"\" (any verdict) — absent and empty must differ", f2.actFlt.Action)
	}
}

// Filter passthrough, the quiet-days threshold, and the error edges.
func TestActivityFilterAndErrors(t *testing.T) {
	now := time.Now()
	f := &fakeApproval{actRows: []packageActivity{
		{Package: "midway", Ecosystem: "npm", Events: 1, LastAt: now.AddDate(0, 0, -10)},
	}}
	rec := httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/activity?package=mid&ecosystem=npm&quiet_days=7", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("filtered GET = %d, want 200", rec.Code)
	}
	if f.actFlt.Package != "mid" || f.actFlt.Ecosystem != "npm" {
		t.Errorf("filter forwarded = %+v, want package=mid ecosystem=npm", f.actFlt)
	}
	// 10 days quiet against a 7-day threshold => counted as stale.
	if !strings.Contains(rec.Body.String(), "<strong>1</strong> of <strong>1</strong> package(s) not seen in 7+ days") {
		t.Errorf("quiet_days threshold not applied; body=%s", rec.Body.String())
	}

	// A typo'd action 400s rather than returning an unfiltered view that looks filtered.
	rec = httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/activity?action=allowed", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("?action=allowed = %d, want 400", rec.Code)
	}
	// Junk quiet_days 400s too — silently falling back to the default would misreport
	// the stale count against a threshold the operator did not ask for.
	rec = httptest.NewRecorder()
	newTestServer(f).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/activity?quiet_days=lots", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("?quiet_days=lots = %d, want 400", rec.Code)
	}

	// Approval unreachable => 502, not a page claiming nothing has been seen.
	fe := &fakeApproval{actErr: errors.New("boom")}
	rec = httptest.NewRecorder()
	newTestServer(fe).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/activity", nil))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("upstream down = %d, want 502", rec.Code)
	}
}
