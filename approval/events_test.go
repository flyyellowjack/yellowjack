package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The audit log is append-only and read newest-first: appending assigns a
// monotonic id, stamps the time, and never disturbs earlier events.
func TestMemStoreEventsAppendAndList(t *testing.T) {
	s := newMemStore()

	score := 7.5
	in := []AuditEvent{
		{Package: "left-pad", Ecosystem: "npm", Action: ActionAllow, Score: &score, Reason: "score 7.5 >= 6.0"},
		{Package: "evil-pkg", Ecosystem: "npm", Action: ActionBlock, Reason: "score 2.0 < 6.0"},
		{Package: "mystery", Ecosystem: "npm", Action: ActionBlock, Reason: "unscorable"},
	}
	for i, e := range in {
		saved, err := s.AppendEvent(e)
		if err != nil {
			t.Fatalf("AppendEvent %d: %v", i, err)
		}
		if saved.ID != int64(i+1) {
			t.Errorf("event %d got id %d, want %d (monotonic)", i, saved.ID, i+1)
		}
		if saved.At.IsZero() {
			t.Errorf("event %d: AppendEvent should stamp At", i)
		}
	}

	// Newest-first: the last appended event comes back first.
	all, err := s.ListEvents(EventFilter{})
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ListEvents returned %d events, want 3", len(all))
	}
	if all[0].Package != "mystery" || all[2].Package != "left-pad" {
		t.Errorf("ListEvents order = [%s ... %s], want newest-first [mystery ... left-pad]",
			all[0].Package, all[2].Package)
	}

	// The nil-score event and the present-score event round-trip distinctly.
	if all[0].Score != nil {
		t.Errorf("block event Score = %v, want nil (no score available)", *all[0].Score)
	}
	if all[2].Score == nil || *all[2].Score != 7.5 {
		t.Errorf("allow event Score = %v, want 7.5", all[2].Score)
	}

	// limit caps the read to the most recent N.
	recent, err := s.ListEvents(EventFilter{Limit: 1})
	if err != nil {
		t.Fatalf("ListEvents(Limit:1): %v", err)
	}
	if len(recent) != 1 || recent[0].Package != "mystery" {
		t.Errorf("ListEvents(Limit:1) = %+v, want just the newest (mystery)", recent)
	}
}

// The incident-response filters narrow the log by ecosystem, action, and (substring,
// case-insensitive) package. A zero-value filter matches everything.
func TestListEventsFilter(t *testing.T) {
	s := newMemStore()
	s.AppendEvent(AuditEvent{Package: "left-pad", Ecosystem: "npm", Action: ActionAllow})
	s.AppendEvent(AuditEvent{Package: "evil-pkg", Ecosystem: "npm", Action: ActionBlock})
	s.AppendEvent(AuditEvent{Package: "requests", Ecosystem: "pypi", Action: ActionAllow})
	s.AppendEvent(AuditEvent{Package: "Evil-Twin", Ecosystem: "pypi", Action: ActionBlock})

	cases := []struct {
		name string
		f    EventFilter
		want []string // expected packages, newest-first
	}{
		{"all", EventFilter{}, []string{"Evil-Twin", "requests", "evil-pkg", "left-pad"}},
		{"by ecosystem", EventFilter{Ecosystem: "npm"}, []string{"evil-pkg", "left-pad"}},
		{"by action", EventFilter{Action: ActionBlock}, []string{"Evil-Twin", "evil-pkg"}},
		{"by package substring (case-insensitive)", EventFilter{Package: "evil"}, []string{"Evil-Twin", "evil-pkg"}},
		{"combined", EventFilter{Ecosystem: "pypi", Action: ActionBlock}, []string{"Evil-Twin"}},
		{"no match", EventFilter{Ecosystem: "oci"}, nil},
	}
	for _, tc := range cases {
		got, err := s.ListEvents(tc.f)
		if err != nil {
			t.Fatalf("%s: ListEvents: %v", tc.name, err)
		}
		if !samePackages(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, packages(got), tc.want)
		}
	}
}

// Negative control for the cross-window guarantee: the filter must run over the WHOLE
// history, not a window pre-truncated to the newest Limit. Here the only block is the
// OLDEST event; asking for blocks with a small limit must still find it. A naive
// "take newest Limit, then filter" implementation returns nothing here — so this test
// fails if that regression is ever introduced.
func TestListEventsFilterAcrossWindow(t *testing.T) {
	s := newMemStore()
	s.AppendEvent(AuditEvent{Package: "old-evil", Ecosystem: "npm", Action: ActionBlock}) // oldest
	for i := 0; i < 4; i++ {
		s.AppendEvent(AuditEvent{Package: "safe", Ecosystem: "npm", Action: ActionAllow})
	}

	got, err := s.ListEvents(EventFilter{Action: ActionBlock, Limit: 2})
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(got) != 1 || got[0].Package != "old-evil" {
		t.Errorf("got %v, want the single older block [old-evil] found across the window", packages(got))
	}
}

// packages/samePackages are small test helpers for comparing result ordering by name.
func packages(events []AuditEvent) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.Package
	}
	return out
}

func samePackages(events []AuditEvent, want []string) bool {
	got := packages(events)
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// POST /v1/events appends and returns 201 with the assigned id; a malformed
// emitter is rejected rather than allowed to pollute the trail.
func TestAppendEventHTTP(t *testing.T) {
	srv := &server{store: newMemStore()}

	// Happy path: a valid block event -> 201 Created with an id. It carries a
	// source_ip (#41); the field must ingest and persist, not be dropped on the way in.
	rec := do(t, srv, http.MethodPost, "/v1/events",
		`{"package":"evil-pkg","ecosystem":"npm","action":"block","reason":"score 2.0 < 6.0","source_ip":"203.0.113.5"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST valid event = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var got AuditEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.ID == 0 || got.Action != ActionBlock {
		t.Errorf("stored event = %+v, want a non-zero id and action=block", got)
	}
	if got.SourceIP != "203.0.113.5" {
		t.Errorf("stored SourceIP = %q, want 203.0.113.5 (source_ip must survive ingest, #41)", got.SourceIP)
	}

	// Validation: missing package, unknown action, and malformed JSON are all 400,
	// and none of them lands a row.
	for _, tc := range []struct{ name, body string }{
		{"missing package", `{"action":"allow"}`},
		{"unknown action", `{"package":"x","action":"quarantine"}`},
		{"malformed json", `{`},
	} {
		r := do(t, srv, http.MethodPost, "/v1/events", tc.body)
		if r.Code != http.StatusBadRequest {
			t.Errorf("%s: POST = %d, want 400", tc.name, r.Code)
		}
	}

	// Exactly the one valid event should have persisted.
	if all, _ := srv.store.ListEvents(EventFilter{}); len(all) != 1 {
		t.Errorf("after 1 valid + 3 invalid posts, store has %d events, want 1", len(all))
	}
}

// GET /v1/events honours the ?ecosystem/?action/?package filters, and rejects an
// unknown action with 400 rather than silently returning unfiltered results.
func TestListEventsHTTPFilter(t *testing.T) {
	srv := &server{store: newMemStore()}
	srv.store.AppendEvent(AuditEvent{Package: "left-pad", Ecosystem: "npm", Action: ActionAllow})
	srv.store.AppendEvent(AuditEvent{Package: "evil-pkg", Ecosystem: "npm", Action: ActionBlock})
	srv.store.AppendEvent(AuditEvent{Package: "requests", Ecosystem: "pypi", Action: ActionAllow})

	get := func(query string) []AuditEvent {
		rec := do(t, srv, http.MethodGet, "/v1/events"+query, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200; body=%s", query, rec.Code, rec.Body.String())
		}
		var events []AuditEvent
		if err := json.Unmarshal(rec.Body.Bytes(), &events); err != nil {
			t.Fatalf("decode %s: %v", query, err)
		}
		return events
	}

	if ev := get("?action=block"); len(ev) != 1 || ev[0].Package != "evil-pkg" {
		t.Errorf("?action=block = %+v, want just evil-pkg", ev)
	}
	if ev := get("?ecosystem=npm"); len(ev) != 2 {
		t.Errorf("?ecosystem=npm returned %d events, want 2", len(ev))
	}
	if ev := get("?package=PAD"); len(ev) != 1 || ev[0].Package != "left-pad" {
		t.Errorf("?package=PAD = %+v, want just left-pad (case-insensitive substring)", ev)
	}

	// An unknown action is a loud 400, not a silently-unfiltered 200.
	if rec := do(t, srv, http.MethodGet, "/v1/events?action=blocked", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("?action=blocked = %d, want 400", rec.Code)
	}
}

// GET /v1/events lists newest-first and honours ?limit; unsupported methods 405.
func TestListEventsHTTP(t *testing.T) {
	srv := &server{store: newMemStore()}
	srv.store.AppendEvent(AuditEvent{Package: "first", Action: ActionAllow})
	srv.store.AppendEvent(AuditEvent{Package: "second", Action: ActionBlock})

	rec := do(t, srv, http.MethodGet, "/v1/events", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/events = %d, want 200", rec.Code)
	}
	var events []AuditEvent
	if err := json.Unmarshal(rec.Body.Bytes(), &events); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(events) != 2 || events[0].Package != "second" {
		t.Errorf("list = %+v, want 2 events newest-first (second, first)", events)
	}

	rec = do(t, srv, http.MethodGet, "/v1/events?limit=1", "")
	json.Unmarshal(rec.Body.Bytes(), &events)
	if len(events) != 1 || events[0].Package != "second" {
		t.Errorf("?limit=1 = %+v, want just the newest (second)", events)
	}

	// PUT/DELETE are not part of an append-only log's surface.
	if r := do(t, srv, http.MethodPut, "/v1/events", `{}`); r.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT /v1/events = %d, want 405", r.Code)
	}
}

// StreamEvents yields matching events oldest-first, applies the filter, and — the
// point of the export — is NOT capped. Appending more than defaultEventLimit and
// getting them all back is the completeness negative control: a bounded implementation
// (like ListEvents) would stop at the default and fail this.
func TestStreamEventsCompleteAndOrdered(t *testing.T) {
	s := newMemStore()
	total := defaultEventLimit + 5 // deliberately past the list default (200)
	for i := 0; i < total; i++ {
		action := ActionAllow
		if i%2 == 0 {
			action = ActionBlock
		}
		s.AppendEvent(AuditEvent{Package: "pkg", Ecosystem: "npm", Action: action})
	}

	var all []AuditEvent
	if err := s.StreamEvents(EventFilter{}, func(e AuditEvent) error {
		all = append(all, e)
		return nil
	}); err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}
	if len(all) != total {
		t.Fatalf("StreamEvents yielded %d events, want all %d (export must not be capped)", len(all), total)
	}
	// Oldest-first: ids ascend.
	if all[0].ID != 1 || all[len(all)-1].ID != int64(total) {
		t.Errorf("StreamEvents order = [id %d .. id %d], want ascending [1 .. %d]", all[0].ID, all[len(all)-1].ID, total)
	}

	// The filter still applies during a stream.
	blocks := 0
	s.StreamEvents(EventFilter{Action: ActionBlock}, func(e AuditEvent) error { blocks++; return nil })
	if blocks == 0 || blocks == total {
		t.Errorf("filtered stream yielded %d of %d, want a strict subset of blocks", blocks, total)
	}

	// A callback error stops iteration and propagates.
	calls := 0
	err := s.StreamEvents(EventFilter{}, func(e AuditEvent) error { calls++; return errStop })
	if err != errStop || calls != 1 {
		t.Errorf("callback error: got err=%v after %d calls, want errStop after 1", err, calls)
	}
}

var errStop = fmt.Errorf("stop")

// GET /v1/events/export streams complete NDJSON, oldest-first, with the provisional
// schema header; honours the filter; rejects a bad action; and — the compliance point
// — returns every event even past the list default.
func TestExportEventsHTTP(t *testing.T) {
	srv := &server{store: newMemStore()}
	srv.store.AppendEvent(AuditEvent{Package: "left-pad", Ecosystem: "npm", Action: ActionAllow})
	srv.store.AppendEvent(AuditEvent{Package: "evil-pkg", Ecosystem: "npm", Action: ActionBlock})

	rec := do(t, srv, http.MethodGet, "/v1/events/export", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("export Content-Type = %q, want application/x-ndjson", ct)
	}
	if sch := rec.Header().Get("X-Yellowjack-Schema"); !strings.Contains(sch, "provisional") {
		t.Errorf("export schema header = %q, want it marked provisional", sch)
	}
	lines := nonEmptyLines(rec.Body.String())
	if len(lines) != 2 {
		t.Fatalf("export returned %d NDJSON lines, want 2", len(lines))
	}
	// Oldest-first: first line is left-pad; each line is a standalone JSON object.
	var first AuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 0 is not valid JSON: %v", err)
	}
	if first.Package != "left-pad" {
		t.Errorf("export order: first line = %q, want left-pad (oldest-first)", first.Package)
	}

	// Filter narrows the export.
	rec = do(t, srv, http.MethodGet, "/v1/events/export?action=block", "")
	if l := nonEmptyLines(rec.Body.String()); len(l) != 1 {
		t.Errorf("?action=block export = %d lines, want 1", len(l))
	}
	// A bad action is a 400 before any streaming.
	if r := do(t, srv, http.MethodGet, "/v1/events/export?action=blocked", ""); r.Code != http.StatusBadRequest {
		t.Errorf("?action=blocked export = %d, want 400", r.Code)
	}
	// POST is not allowed (export is a read).
	if r := do(t, srv, http.MethodPost, "/v1/events/export", ""); r.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST export = %d, want 405", r.Code)
	}
}

// Completeness at the HTTP layer: the export must return every event even when there
// are more than the list default — otherwise "here is every component that entered"
// silently becomes "here are the most recent 200", which is not a due-diligence record.
func TestExportEventsIsComplete(t *testing.T) {
	srv := &server{store: newMemStore()}
	total := defaultEventLimit + 3
	for i := 0; i < total; i++ {
		srv.store.AppendEvent(AuditEvent{Package: "pkg", Action: ActionAllow})
	}
	rec := do(t, srv, http.MethodGet, "/v1/events/export", "")
	if l := nonEmptyLines(rec.Body.String()); len(l) != total {
		t.Errorf("export returned %d lines, want all %d (must not cap at the list default %d)", len(l), total, defaultEventLimit)
	}
}

// DownloadsByIP tallies matching pulls per source IP, most-frequent-first, tracks the
// most-recent time, and buckets unobserved-source pulls under "" so the totals stay
// honest.
func TestDownloadsByIP(t *testing.T) {
	s := newMemStore()
	early := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	late := time.Date(2026, 1, 1, 17, 0, 0, 0, time.UTC)
	// left-pad: 3 pulls from .5 (one later), 1 from .6, 1 unobserved.
	s.AppendEvent(AuditEvent{Package: "left-pad", Action: ActionAllow, SourceIP: "10.0.0.5", At: early})
	s.AppendEvent(AuditEvent{Package: "left-pad", Action: ActionAllow, SourceIP: "10.0.0.5", At: late})
	s.AppendEvent(AuditEvent{Package: "left-pad", Action: ActionBlock, SourceIP: "10.0.0.5", At: early})
	s.AppendEvent(AuditEvent{Package: "left-pad", Action: ActionAllow, SourceIP: "10.0.0.6", At: early})
	s.AppendEvent(AuditEvent{Package: "left-pad", Action: ActionAllow, SourceIP: "", At: early})
	// A different package must not leak into left-pad's tally.
	s.AppendEvent(AuditEvent{Package: "other", Action: ActionAllow, SourceIP: "10.0.0.5", At: late})

	rows, err := s.DownloadsByIP(EventFilter{Package: "left-pad"})
	if err != nil {
		t.Fatalf("DownloadsByIP: %v", err)
	}
	want := []IPCount{
		{IP: "10.0.0.5", Count: 3},
		{IP: "10.0.0.6", Count: 1},
		{IP: "", Count: 1},
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(rows), len(want), rows)
	}
	for i, w := range want {
		if rows[i].IP != w.IP || rows[i].Count != w.Count {
			t.Errorf("row %d = {%q,%d}, want {%q,%d} (most-frequent-first)", i, rows[i].IP, rows[i].Count, w.IP, w.Count)
		}
	}
	// Recency: .5's LastAt is the later of its two allow pulls.
	if !rows[0].LastAt.Equal(late) {
		t.Errorf("top IP LastAt = %v, want %v (the most recent matching pull)", rows[0].LastAt, late)
	}
	// The action filter composes: only .5 has a block.
	blocks, _ := s.DownloadsByIP(EventFilter{Package: "left-pad", Action: ActionBlock})
	if len(blocks) != 1 || blocks[0].IP != "10.0.0.5" || blocks[0].Count != 1 {
		t.Errorf("block tally = %+v, want one row {10.0.0.5, 1}", blocks)
	}
}

// NEGATIVE CONTROL for completeness — the reason the count is a store-level aggregation
// and not a client-side tally over the bounded list. More than defaultEventLimit pulls
// from one IP must ALL be counted; an implementation that reused the capped list path
// would report defaultEventLimit and silently undercount an incident.
func TestDownloadsByIPCompleteAcrossWindow(t *testing.T) {
	s := newMemStore()
	total := defaultEventLimit + 37
	for i := 0; i < total; i++ {
		s.AppendEvent(AuditEvent{Package: "left-pad", Action: ActionAllow, SourceIP: "10.0.0.9"})
	}
	rows, err := s.DownloadsByIP(EventFilter{Package: "left-pad"})
	if err != nil {
		t.Fatalf("DownloadsByIP: %v", err)
	}
	if len(rows) != 1 || rows[0].Count != total {
		t.Errorf("count = %+v, want one row with Count=%d (must not cap at the list default %d)", rows, total, defaultEventLimit)
	}
}

// The HTTP endpoint returns the tally as JSON, honours the filter, and rejects a bad
// action / wrong method — the same edge discipline as the list and export.
func TestDownloadsByIPHTTP(t *testing.T) {
	srv := &server{store: newMemStore()}
	srv.store.AppendEvent(AuditEvent{Package: "left-pad", Action: ActionAllow, SourceIP: "10.0.0.5"})
	srv.store.AppendEvent(AuditEvent{Package: "left-pad", Action: ActionAllow, SourceIP: "10.0.0.5"})
	srv.store.AppendEvent(AuditEvent{Package: "left-pad", Action: ActionBlock, SourceIP: "10.0.0.6"})

	rec := do(t, srv, http.MethodGet, "/v1/events/by-ip?package=left-pad", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("by-ip = %d, want 200", rec.Code)
	}
	var rows []IPCount
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if len(rows) != 2 || rows[0].IP != "10.0.0.5" || rows[0].Count != 2 {
		t.Errorf("rows = %+v, want top {10.0.0.5, 2}", rows)
	}
	// Filter composes over HTTP.
	rec = do(t, srv, http.MethodGet, "/v1/events/by-ip?package=left-pad&action=block", "")
	json.Unmarshal(rec.Body.Bytes(), &rows)
	if len(rows) != 1 || rows[0].IP != "10.0.0.6" {
		t.Errorf("block tally over HTTP = %+v, want one row {10.0.0.6,...}", rows)
	}
	// Bad action -> 400; POST -> 405.
	if r := do(t, srv, http.MethodGet, "/v1/events/by-ip?action=blocked", ""); r.Code != http.StatusBadRequest {
		t.Errorf("?action=blocked = %d, want 400", r.Code)
	}
	if r := do(t, srv, http.MethodPost, "/v1/events/by-ip", ""); r.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST by-ip = %d, want 405", r.Code)
	}
}

// nonEmptyLines splits an NDJSON body into its non-blank lines.
func nonEmptyLines(body string) []string {
	var out []string
	for _, ln := range strings.Split(body, "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}

// do is a tiny helper: run one request through the server and capture the response.
func do(t *testing.T, srv *server, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// LastSeenByPackage groups matching events by (package, ecosystem), quietest first,
// and tracks the most recent event per package — the "what has gone quiet" view
// (#32 Phase C, D81 Q3).
func TestLastSeenByPackage(t *testing.T) {
	s := newMemStore()
	oldest := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	middle := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	newest := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)

	s.AppendEvent(AuditEvent{Package: "quiet-pkg", Ecosystem: "npm", Action: ActionAllow, At: oldest})
	s.AppendEvent(AuditEvent{Package: "busy-pkg", Ecosystem: "npm", Action: ActionAllow, At: oldest})
	s.AppendEvent(AuditEvent{Package: "busy-pkg", Ecosystem: "npm", Action: ActionAllow, At: newest})
	s.AppendEvent(AuditEvent{Package: "mid-pkg", Ecosystem: "npm", Action: ActionAllow, At: middle})

	rows, err := s.LastSeenByPackage(EventFilter{})
	if err != nil {
		t.Fatalf("LastSeenByPackage: %v", err)
	}
	// Quietest first: quiet-pkg (Jan) then mid-pkg (Mar) then busy-pkg (Jun, its LATEST
	// event — not its first, or a busy package would masquerade as stale).
	want := []PackageActivity{
		{Package: "quiet-pkg", Events: 1, LastAt: oldest},
		{Package: "mid-pkg", Events: 1, LastAt: middle},
		{Package: "busy-pkg", Events: 2, LastAt: newest},
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(rows), len(want), rows)
	}
	for i, w := range want {
		if rows[i].Package != w.Package || rows[i].Events != w.Events || !rows[i].LastAt.Equal(w.LastAt) {
			t.Errorf("row %d = {%q, %d, %v}, want {%q, %d, %v} (quietest first)",
				i, rows[i].Package, rows[i].Events, rows[i].LastAt, w.Package, w.Events, w.LastAt)
		}
	}

	// The same NAME in two ecosystems is two different packages and must not merge —
	// one approval store serves a firewall instance per ecosystem.
	s2 := newMemStore()
	s2.AppendEvent(AuditEvent{Package: "requests", Ecosystem: "pypi", Action: ActionAllow, At: oldest})
	s2.AppendEvent(AuditEvent{Package: "requests", Ecosystem: "npm", Action: ActionAllow, At: newest})
	split, _ := s2.LastSeenByPackage(EventFilter{})
	if len(split) != 2 {
		t.Fatalf("same name in two ecosystems collapsed into %d row(s): %+v", len(split), split)
	}
	if split[0].Ecosystem != "pypi" || split[1].Ecosystem != "npm" {
		t.Errorf("ecosystem order = %q,%q, want pypi (quieter) then npm", split[0].Ecosystem, split[1].Ecosystem)
	}

	// Guard on the COMPOSITE KEY, not just on grouping: these two rows collide if the
	// key is built by concatenating package and ecosystem with a separator ("a"+"|"+"b|c"
	// == "a|b"+"|"+"c"), which would silently merge two unrelated packages into one row.
	s3 := newMemStore()
	s3.AppendEvent(AuditEvent{Package: "a", Ecosystem: "b|c", Action: ActionAllow, At: oldest})
	s3.AppendEvent(AuditEvent{Package: "a|b", Ecosystem: "c", Action: ActionAllow, At: newest})
	keyed, _ := s3.LastSeenByPackage(EventFilter{})
	if len(keyed) != 2 {
		t.Errorf("concatenation-colliding keys merged into %d row(s): %+v", len(keyed), keyed)
	}

	// The action filter composes, and it is how a caller asks for "last PULLED" rather
	// than "last seen": a package that is only ever blocked must not appear in the
	// allow-filtered view claiming freshness.
	s4 := newMemStore()
	s4.AppendEvent(AuditEvent{Package: "blocked-only", Ecosystem: "npm", Action: ActionBlock, At: newest})
	s4.AppendEvent(AuditEvent{Package: "pulled", Ecosystem: "npm", Action: ActionAllow, At: oldest})
	allows, _ := s4.LastSeenByPackage(EventFilter{Action: ActionAllow})
	if len(allows) != 1 || allows[0].Package != "pulled" {
		t.Errorf("allow-filtered rows = %+v, want only the actually-pulled package", allows)
	}
}

// NEGATIVE CONTROL for completeness. The quiet package is the OLDEST event in the log,
// so it is exactly what a recency-windowed implementation drops — and dropping it turns
// "this package went quiet six months ago" into "this package does not exist", the
// wrong answer in the more alarming direction. An implementation that reused the capped
// list path fails this.
func TestLastSeenByPackageCompleteAcrossWindow(t *testing.T) {
	s := newMemStore()
	old := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	s.AppendEvent(AuditEvent{Package: "long-forgotten", Ecosystem: "npm", Action: ActionAllow, At: old})
	// Bury it under more than a full window of newer traffic.
	for i := 0; i < defaultEventLimit+37; i++ {
		s.AppendEvent(AuditEvent{Package: "chatty", Ecosystem: "npm", Action: ActionAllow, At: old.AddDate(0, 0, i+1)})
	}
	rows, err := s.LastSeenByPackage(EventFilter{})
	if err != nil {
		t.Fatalf("LastSeenByPackage: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (the buried quiet package must survive the window): %+v", len(rows), rows)
	}
	if rows[0].Package != "long-forgotten" || !rows[0].LastAt.Equal(old) {
		t.Errorf("quietest row = %+v, want long-forgotten at %v — a windowed implementation loses it entirely", rows[0], old)
	}
}

// The last-seen endpoint returns per-package activity as JSON, honours the filter, and
// rejects a bad action / wrong method — same edge discipline as the list, export and
// by-ip tally.
func TestLastSeenByPackageHTTP(t *testing.T) {
	srv := &server{store: newMemStore()}
	old := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	srv.store.AppendEvent(AuditEvent{Package: "quiet-pkg", Ecosystem: "npm", Action: ActionAllow, At: old})
	srv.store.AppendEvent(AuditEvent{Package: "busy-pkg", Ecosystem: "npm", Action: ActionAllow, At: recent})
	srv.store.AppendEvent(AuditEvent{Package: "blocked-pkg", Ecosystem: "npm", Action: ActionBlock, At: recent})

	rec := do(t, srv, http.MethodGet, "/v1/events/last-seen", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("last-seen = %d, want 200", rec.Code)
	}
	var rows []PackageActivity
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if len(rows) != 3 || rows[0].Package != "quiet-pkg" {
		t.Errorf("rows = %+v, want 3 with quiet-pkg first (quietest leads)", rows)
	}

	// ?action=allow is how a caller asks for "last PULLED": the block-only package
	// must drop out rather than appear to be in active use.
	rec = do(t, srv, http.MethodGet, "/v1/events/last-seen?action=allow", "")
	json.Unmarshal(rec.Body.Bytes(), &rows)
	for _, r := range rows {
		if r.Package == "blocked-pkg" {
			t.Errorf("allow-filtered rows include a block-only package: %+v", rows)
		}
	}
	if len(rows) != 2 {
		t.Errorf("allow-filtered rows = %+v, want 2", rows)
	}

	// Bad action -> 400; POST -> 405.
	if r := do(t, srv, http.MethodGet, "/v1/events/last-seen?action=allowed", ""); r.Code != http.StatusBadRequest {
		t.Errorf("?action=allowed = %d, want 400", r.Code)
	}
	if r := do(t, srv, http.MethodPost, "/v1/events/last-seen", ""); r.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST last-seen = %d, want 405", r.Code)
	}
}
