package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeListStore stands in for the git store in handler tests.
//
// The git store has its own tests against a real repository (gitstore_test.go). What is
// under test HERE is the handler: who may write, what is refused, and what the operator
// is told -- none of which needs a git binary, and all of which would be slower and less
// legible if it did.
type fakeListStore struct {
	docs     map[string]string // kind -> file body
	applied  []fakeApply
	applyRes writeResult
	applyErr error
	loadErr  error
	history  []commitLine
}

type fakeApply struct {
	Kind, Entry, Actor string
	Add                bool
}

func newFakeListStore() *fakeListStore {
	return &fakeListStore{docs: map[string]string{listAllow: "", listDeny: ""}}
}

func (f *fakeListStore) Load(kind string) (*listDoc, error) {
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	return parseListDoc(kind, kind+".txt", "npm", []byte(f.docs[kind]))
}

func (f *fakeListStore) Apply(kind, entry, actor string, add bool) (writeResult, error) {
	f.applied = append(f.applied, fakeApply{kind, entry, actor, add})
	if f.applyErr != nil {
		return writeResult{}, f.applyErr
	}
	res := f.applyRes
	res.Kind, res.Entry = kind, entry
	if res.Detail == "" {
		res.Changed = true
		res.Detail = "Committed as abc123def456 and pushed to \"origin\"."
	}
	return res, nil
}

func (f *fakeListStore) History(kind string, n int) ([]commitLine, error) { return f.history, nil }
func (f *fakeListStore) Describe() string                                 { return "git /srv/policy, remote origin" }

// listsServer builds a console with list editing on, unless auth is empty.
func listsServer(t *testing.T, store listStore, user string, health []instanceHealth) *server {
	t.Helper()
	s := &server{
		approval:      &fakeApproval{health: health},
		lists:         store,
		listEcosystem: "npm",
	}
	if user != "" {
		s.auth = newBasicAuth(user, "secret")
	}
	return s
}

func getLists(t *testing.T, s *server) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/lists", nil)
	if s.auth != nil {
		r.SetBasicAuth(s.auth.user, s.auth.pass)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /lists = %d, want 200: %s", w.Code, w.Body.String())
	}
	return w.Body.String()
}

func postEdit(t *testing.T, s *server, form url.Values, auth bool) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/lists", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if auth && s.auth != nil {
		r.SetBasicAuth(s.auth.user, s.auth.pass)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// containsText reports whether the rendered page contains a phrase, ignoring how the
// HTML happens to be wrapped.
//
// Asserting on the raw body ties the test to the template's line breaks, so re-flowing a
// paragraph fails a test about MEANING. These assertions are about what the page tells an
// operator, not about where the newlines fell.
func containsText(body, want string) bool {
	return strings.Contains(strings.Join(strings.Fields(body), " "), strings.Join(strings.Fields(want), " "))
}

// --- the write path -----------------------------------------------------------------

func TestListEditAddsThroughTheStore(t *testing.T) {
	store := newFakeListStore()
	s := listsServer(t, store, "alice", nil)

	w := postEdit(t, s, url.Values{"kind": {listDeny}, "entry": {"left-pad"}, "action": {"add"}}, true)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("POST /lists = %d, want 303 (post-redirect-get): %s", w.Code, w.Body.String())
	}
	if len(store.applied) != 1 {
		t.Fatalf("store saw %d applies, want 1", len(store.applied))
	}
	got := store.applied[0]
	if got.Kind != listDeny || got.Entry != "left-pad" || !got.Add {
		t.Errorf("applied = %+v, want deny/left-pad/add", got)
	}
	// The ACTOR must reach the store, or the git commit cannot name who acted and the
	// audit trail D193 chose this mechanism for does not exist.
	if got.Actor != "alice" {
		t.Errorf("actor = %q, want alice — the commit would not name who made the change", got.Actor)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/lists?") {
		t.Errorf("redirect to %q, want back to /lists", loc)
	}
	if !strings.Contains(loc, "level=ok") {
		t.Errorf("redirect %q does not carry a success notice", loc)
	}
}

func TestListEditRemovePassesTheRemoveIntent(t *testing.T) {
	store := newFakeListStore()
	s := listsServer(t, store, "alice", nil)
	postEdit(t, s, url.Values{"kind": {listAllow}, "entry": {"lodash"}, "action": {"remove"}}, true)
	if len(store.applied) != 1 || store.applied[0].Add {
		t.Fatalf("applied = %+v, want a remove", store.applied)
	}
}

// TestListEditRejectsBadKind: the kind is a path into the store's file map, so it is
// validated rather than trusted.
func TestListEditRejectsBadKind(t *testing.T) {
	store := newFakeListStore()
	s := listsServer(t, store, "alice", nil)
	w := postEdit(t, s, url.Values{"kind": {"malware"}, "entry": {"x"}, "action": {"add"}}, true)
	if w.Code != http.StatusBadRequest {
		t.Errorf("editing an unknown list = %d, want 400", w.Code)
	}
	if len(store.applied) != 0 {
		t.Error("a bad kind still reached the store")
	}
}

// --- the guards ---------------------------------------------------------------------

// TestListEditRequiresACredential is the guard that keeps a second write endpoint from
// being the one without auth.
//
// The console's only access control is the shared credential (#13 item 2 is still
// awaiting a project decision), so a write path that works without one is an unauthenticated way to
// change what the firewall enforces.
func TestListEditRequiresACredential(t *testing.T) {
	store := newFakeListStore()
	s := listsServer(t, store, "", nil) // no credential => read-only console

	w := postEdit(t, s, url.Values{"kind": {listDeny}, "entry": {"left-pad"}, "action": {"add"}}, false)
	if w.Code != http.StatusForbidden {
		t.Errorf("unauthenticated edit = %d, want 403", w.Code)
	}
	if len(store.applied) != 0 {
		t.Error("an unauthenticated request reached the store — the firewall's policy is writable by anyone who can reach the console")
	}

	// And the credential must actually be CHECKED, not merely configured.
	s = listsServer(t, store, "alice", nil)
	w = postEdit(t, s, url.Values{"kind": {listDeny}, "entry": {"left-pad"}, "action": {"add"}}, false)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("edit with no credentials against an authenticated console = %d, want 401", w.Code)
	}
	if len(store.applied) != 0 {
		t.Error("a request with no credentials reached the store")
	}
}

// TestListEditRejectsCrossOrigin: a browser attaches Basic Auth to a cross-site form POST
// automatically, so without this an operator visiting any page could be made to change
// the firewall's policy.
func TestListEditRejectsCrossOrigin(t *testing.T) {
	store := newFakeListStore()
	s := listsServer(t, store, "alice", nil)

	r := httptest.NewRequest(http.MethodPost, "/lists",
		strings.NewReader(url.Values{"kind": {listDeny}, "entry": {"left-pad"}, "action": {"add"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.example")
	r.SetBasicAuth("alice", "secret")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("cross-origin edit = %d, want 403", w.Code)
	}
	if len(store.applied) != 0 {
		t.Error("a cross-origin request reached the store")
	}
}

// TestListEditRefusedWhenNoStoreConfigured: the read view must not be coupled to the
// write path, and the write must not half-work without somewhere to record it.
func TestListEditRefusedWhenNoStoreConfigured(t *testing.T) {
	s := listsServer(t, nil, "alice", nil)
	w := postEdit(t, s, url.Values{"kind": {listDeny}, "entry": {"x"}, "action": {"add"}}, true)
	if w.Code != http.StatusForbidden {
		t.Errorf("edit with no store = %d, want 403", w.Code)
	}
	// ...but the page still renders, because the enforced view is useful on its own.
	body := getLists(t, s)
	if !strings.Contains(body, "CONSOLE_LIST_REPO") {
		t.Error("the page does not say WHY editing is off; the operator is left guessing")
	}
}

// TestStoreFailureIsReportedNotSwallowed.
//
// A write that failed and a write that succeeded must not look the same. The specific
// failure that matters is the store refusing an entry the gate could not parse: the
// operator has to see the reason, or they will retype it and try again.
func TestStoreFailureIsReportedNotSwallowed(t *testing.T) {
	store := newFakeListStore()
	store.applyErr = errors.New("\"lodash@4.17.20\" looks like it names a version")
	s := listsServer(t, store, "alice", nil)

	w := postEdit(t, s, url.Values{"kind": {listDeny}, "entry": {"lodash@4.17.20"}, "action": {"add"}}, true)
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "level=err") {
		t.Errorf("a failed write redirected with %q; the operator is not told it failed", loc)
	}
	if !strings.Contains(loc, "names+a+version") {
		t.Errorf("the reason did not survive the redirect: %q", loc)
	}
}

// TestPushFailureIsAWarningNotASuccess.
//
// "Committed here" and "shared with the fleet" are different states. Reporting a failed
// push as success is the exact shape of a UI that says saved for something that did not
// fully happen -- and the half that failed is the half the operator was counting on.
func TestPushFailureIsAWarningNotASuccess(t *testing.T) {
	store := newFakeListStore()
	store.applyRes = writeResult{
		Changed: true,
		PushErr: "git push: permission denied",
		Detail:  "Committed locally as abc123, but the push to \"origin\" FAILED.",
	}
	s := listsServer(t, store, "alice", nil)

	w := postEdit(t, s, url.Values{"kind": {listDeny}, "entry": {"left-pad"}, "action": {"add"}}, true)
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "level=warn") {
		t.Errorf("a failed push redirected with %q, want level=warn", loc)
	}
	if !strings.Contains(loc, "FAILED") {
		t.Errorf("the push failure is not in the notice: %q", loc)
	}
}

// --- the page -----------------------------------------------------------------------

// TestPageShowsAuthoredAndEnforcedSeparately is the increment's display claim.
//
// If the page merged the two, an operator could not tell an edit that has reached the
// fleet from one that has not, and the lag between the gate's 5s re-read and the
// console's heartbeat would read as a bug rather than as the state of the rollout.
func TestPageShowsAuthoredAndEnforcedSeparately(t *testing.T) {
	store := newFakeListStore()
	store.docs[listDeny] = "left-pad\njust-authored\n"
	health := []instanceHealth{{
		Instance:   "fw-1",
		ReportedAt: time.Now().UTC(),
		Policy: &policyDoc{Lists: []policyList{
			{Kind: listDeny, Path: "/etc/yj/deny.txt", Names: []string{"left-pad"}, Digest: "aaaa"},
		}},
	}}
	s := listsServer(t, store, "alice", health)
	body := getLists(t, s)

	for _, want := range []string{"Authored", "Enforced by the fleet", "left-pad", "just-authored"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page is missing %q", want)
		}
	}
	// The entry the fleet has not picked up yet must be called out as pending, not shown
	// as though it were in force.
	if !containsText(body, "Not yet enforced:") {
		t.Error("an authored-but-not-enforced entry is not flagged; the operator would believe it is live")
	}
}

// TestPageWarnsWhenReplicasDisagree: divergence is the failure an editable list
// introduces, and D193 named it as the reason a plain local file was ruled out.
func TestPageWarnsWhenReplicasDisagree(t *testing.T) {
	now := time.Now().UTC()
	health := []instanceHealth{
		{Instance: "fw-1", ReportedAt: now, Policy: &policyDoc{Lists: []policyList{
			{Kind: listDeny, Names: []string{"left-pad"}, Digest: "aaaa"}}}},
		{Instance: "fw-2", ReportedAt: now, Policy: &policyDoc{Lists: []policyList{
			{Kind: listDeny, Names: []string{"left-pad", "is-odd"}, Digest: "bbbb"}}}},
	}
	s := listsServer(t, newFakeListStore(), "alice", health)
	if body := getLists(t, s); !containsText(body, "Replicas disagree") {
		t.Error("two replicas reporting different lists did not raise the divergence warning")
	}
}

// TestStaleReplicasDoNotRaiseDivergence: a warning that can never be cleared is one an
// operator learns to ignore, so a replica that died weeks ago must not light it forever.
func TestStaleReplicasDoNotRaiseDivergence(t *testing.T) {
	now := time.Now().UTC()
	health := []instanceHealth{
		{Instance: "fw-1", ReportedAt: now, Policy: &policyDoc{Lists: []policyList{
			{Kind: listDeny, Names: []string{"left-pad"}, Digest: "aaaa"}}}},
		{Instance: "fw-dead", ReportedAt: now.Add(-72 * time.Hour), Policy: &policyDoc{Lists: []policyList{
			{Kind: listDeny, Names: []string{"ancient"}, Digest: "cccc"}}}},
	}
	got := collectEnforcedLists(health, now)
	if got[listDeny] == nil {
		t.Fatal("no enforced list collected")
	}
	if got[listDeny].diverged {
		t.Error("a stale replica raised the divergence warning")
	}
	if got[listDeny].replicas != 1 {
		t.Errorf("replicas = %d, want 1 (the fresh one only)", got[listDeny].replicas)
	}
}

// TestControlPlaneOutageStillRendersTheAuthoredList.
//
// The write path does not depend on the control plane, so an outage there must not take
// the editing page with it. An operator responding to an incident is exactly who needs
// to add a deny entry, and exactly when the control plane is most likely to be unwell.
func TestControlPlaneOutageStillRendersTheAuthoredList(t *testing.T) {
	store := newFakeListStore()
	store.docs[listDeny] = "left-pad\n"
	s := &server{
		approval:      &fakeApproval{healthErr: errors.New("connection refused")},
		lists:         store,
		auth:          newBasicAuth("alice", "secret"),
		listEcosystem: "npm",
	}
	body := getLists(t, s)
	if !strings.Contains(body, "left-pad") {
		t.Error("the authored list vanished when the control plane was unreachable")
	}
	if !strings.Contains(body, "Fleet state unknown") {
		t.Error("the page does not say the fleet state is unknown")
	}
	if !containsText(body, "have not stopped gating traffic") {
		t.Error("the page does not reassure that the gate is still enforcing; an operator may take a drastic action")
	}
}

// TestPageSaysTheFeedOutranksTheAllowList.
//
// The single most confusing behaviour in this area: allow-listing a package the malware
// feed names does NOT serve it. If the page does not say so, the allow list reads as
// broken. It is the interaction the prototype was built to provoke, and it is a
// documented trap rather than a nicety.
func TestPageSaysTheFeedOutranksTheAllowList(t *testing.T) {
	s := listsServer(t, newFakeListStore(), "alice", nil)
	body := getLists(t, s)
	if !strings.Contains(body, "FW_MALWARE_LIST") {
		t.Error("the page does not name the feed")
	}
	if !containsText(body, "is consulted <em>before</em> these lists") {
		t.Error("the page does not state that the feed is consulted BEFORE the operator lists")
	}
	if !containsText(body, "allow-listing a package that a published advisory names does <em>not</em> serve it") {
		t.Error("the page does not spell out the consequence, which is the interaction operators get wrong")
	}
	if !containsText(body, "not editable here") {
		t.Error("the page does not say the feed cannot be edited here, so an operator will look for the button")
	}
}

// TestRemoveButtonsAbsentWithoutWrites: a control that cannot work must not be rendered.
func TestRemoveButtonsAbsentWithoutWrites(t *testing.T) {
	store := newFakeListStore()
	store.docs[listDeny] = "left-pad\n"
	s := listsServer(t, store, "", nil) // read-only console
	body := getLists(t, s)

	if strings.Contains(body, `name="action" value="remove"`) {
		t.Error("a read-only console rendered remove controls")
	}
	if !strings.Contains(body, "left-pad") {
		t.Error("a read-only console stopped showing the list; the read view must not depend on the write path")
	}
	if !strings.Contains(body, "CONSOLE_AUTH_USER") {
		t.Error("the page does not say which setting turns editing on")
	}
}

// TestUnparseableListIsSurfacedOnThePage: the state where the gate is refusing to boot
// is the one an operator most needs to be told about, and the console can see it.
func TestUnparseableListIsSurfacedOnThePage(t *testing.T) {
	store := newFakeListStore()
	store.loadErr = errors.New("deny-list deny.txt line 2: \"lodash 4.17.20\" contains whitespace")
	s := listsServer(t, store, "alice", nil)
	body := getLists(t, s)
	if !containsText(body, "could not be read") {
		t.Error("an unparseable list is not surfaced")
	}
	if !strings.Contains(body, "contains whitespace") {
		t.Error("the parse error's detail is not shown, so the operator cannot find the bad line")
	}
}

// --- the authored/enforced comparison -----------------------------------------------

// TestDiffListsDoesNotInventDifferencesFromNormalisation.
//
// Authored names are spelled by a human; enforced names come back normalised. A naive
// comparison would report a fleet divergence on every render for a list containing
// "LoDash", and a warning that is always on is one nobody reads.
func TestDiffListsDoesNotInventDifferencesFromNormalisation(t *testing.T) {
	pending, extra := diffLists("npm", []string{"LoDash", "@Acme/CLI"}, []string{"lodash", "@acme/cli"})
	if len(pending) != 0 || len(extra) != 0 {
		t.Errorf("case differences reported as a divergence: pending=%v extra=%v", pending, extra)
	}

	// PyPI folds '_' and '.' to '-' (PEP 503), so these are one package to the gate.
	pending, extra = diffLists("pypi", []string{"python_dateutil"}, []string{"python-dateutil"})
	if len(pending) != 0 || len(extra) != 0 {
		t.Errorf("PEP 503 punctuation reported as a divergence: pending=%v extra=%v", pending, extra)
	}

	// OCI reduces a reference to its repository (D164).
	pending, extra = diffLists("oci", []string{"library/nginx:1.25"}, []string{"library/nginx"})
	if len(pending) != 0 || len(extra) != 0 {
		t.Errorf("an oci tag reported as a divergence: pending=%v extra=%v", pending, extra)
	}

	// A REAL difference must still be reported, or the two assertions above would pass
	// for a function that always returned nothing.
	pending, extra = diffLists("npm", []string{"left-pad"}, []string{"is-odd"})
	if len(pending) != 1 || pending[0] != "left-pad" {
		t.Errorf("pending = %v, want [left-pad]", pending)
	}
	if len(extra) != 1 || extra[0] != "is-odd" {
		t.Errorf("extra = %v, want [is-odd]", extra)
	}
}

// TestTruncatedEnforcedListSuppressesTheDiff.
//
// A replica caps the names it reports at 200 and says how many it omitted. Diffing
// against a capped list would mark every unshown name "not yet enforced" -- turning a
// display cap into a fleet-wide false alarm on exactly the large deployments where the
// page matters most.
func TestTruncatedEnforcedListSuppressesTheDiff(t *testing.T) {
	store := newFakeListStore()
	store.docs[listDeny] = "left-pad\nis-odd\n"
	health := []instanceHealth{{
		Instance:   "fw-1",
		ReportedAt: time.Now().UTC(),
		Policy: &policyDoc{Lists: []policyList{
			{Kind: listDeny, Names: []string{"left-pad"}, Omitted: 199, Digest: "aaaa"},
		}},
	}}
	s := listsServer(t, store, "alice", health)
	body := getLists(t, s)

	if containsText(body, "Not yet enforced:") {
		t.Error("the diff ran against a truncated enforced list and raised a false alarm")
	}
	if !containsText(body, "199 more not shown") {
		t.Error("the page does not say the replica's list was truncated")
	}
}

// TestEveryConsolePageLinksToTheLists.
//
// A page nobody can reach is a page nobody uses. /lists was reachable only from itself
// for the whole of its first implementation -- every other page's nav went straight past
// it -- which is the operator-facing form of the same mistake as a correct filter that is
// never invoked.
//
// Asserted over the RENDERED pages rather than the template files, so it keeps holding if
// the nav is ever factored into a shared partial.
func TestEveryConsolePageLinksToTheLists(t *testing.T) {
	store := newFakeListStore()
	s := listsServer(t, store, "alice", []instanceHealth{{
		Instance: "fw-1", ReportedAt: time.Now().UTC(),
		Policy: &policyDoc{Values: map[string]string{"FW_ECOSYSTEM": "npm"}},
	}})

	for _, path := range []string{"/", "/audit", "/downloads", "/activity", "/policy", "/lookup", "/capacity", "/lists"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.SetBasicAuth("alice", "secret")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, w.Code)
			continue
		}
		if !strings.Contains(w.Body.String(), `href="/lists"`) {
			t.Errorf("%s does not link to /lists, so an operator cannot find the page that edits the lists", path)
		}
	}
}
