package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TIER 3 -- the adversarial pass over the console's list write path (#58 increment 3b).
//
// Tier 2 (the customer-shaped e2e leg) proves an operator can edit a list and the gate
// obeys it. That is the shape that structurally CANNOT find a bypass, because it only
// ever does what an operator would do. This file does what someone trying to get a
// package served would do instead.
//
// The write path is a good target and it is worth being explicit about why: it is the
// only place in the product where a request can CHANGE what the firewall enforces, it
// composes user text into a file that a separate process parses as policy, and it shells
// out to another program. Injection, confused-deputy and privilege questions all live
// here at once.

// --- injection into the FILE ---------------------------------------------------------

// TestEntryCannotInjectExtraListLines is the sharpest one.
//
// The list format is one name per line. If an entry may carry a newline, then adding
// "lodash" can also add a second line of the submitter's choosing -- and on the ALLOW
// list that second line is a package served WITHOUT SCORING. The console would show one
// chip; the gate would enforce two entries. Nothing in the UI would reveal the second.
func TestEntryCannotInjectExtraListLines(t *testing.T) {
	injections := []string{
		"lodash\nevil-pkg",
		"lodash\r\nevil-pkg",
		"lodash\revil-pkg",
		"lodash\n",
		"\nevil-pkg",
	}
	for _, entry := range injections {
		if err := validateEntry("npm", "deny", entry); err == nil {
			t.Errorf("validateEntry accepted %q — one add would author two entries", entry)
		}
	}

	// And the refusal must hold all the way through the store, not only at the validator.
	repo := newTestRepo(t)
	s := newTestStore(t, repo)
	if _, err := s.Apply(listAllow, "lodash\nevil-pkg", "mallory", true); err == nil {
		t.Fatal("the store committed an entry containing a newline")
	}
	if _, err := os.Stat(filepath.Join(repo, "allow.txt")); err == nil {
		body := readFile(t, filepath.Join(repo, "allow.txt"))
		if strings.Contains(body, "evil-pkg") {
			t.Errorf("an injected second entry reached the allow list:\n%s", body)
		}
	}
}

// TestEntryCannotSmuggleACommentOntoALine.
//
// The gate strips from the first '#'. So "evil-pkg # lodash" would be STORED as one
// thing and DISPLAYED (by anything echoing what was typed) as another -- the shape where
// a reviewer reading the file and the gate reading the file disagree.
func TestEntryCannotSmuggleACommentOntoALine(t *testing.T) {
	for _, entry := range []string{"evil-pkg # lodash", "#lodash", "lodash#", "lodash # ok"} {
		if err := validateEntry("npm", "deny", entry); err == nil {
			t.Errorf("validateEntry accepted %q — what the gate stores is not what was typed", entry)
		}
	}
}

// TestOversizedEntryIsRefused: the wrong paste, and the cheap way to bloat both the
// policy file and its git history.
func TestOversizedEntryIsRefused(t *testing.T) {
	if err := validateEntry("npm", "deny", strings.Repeat("a", maxEntryLen+1)); err == nil {
		t.Error("an over-long entry was accepted")
	}
	// The cap must not argue with a real name: a registry-qualified OCI reference and a
	// long Go module path are the longest legitimate shapes.
	for _, ok := range []struct{ eco, name string }{
		{"oci", "registry.example.com/some-team/a-fairly-long-service-name:v1.2.3-rc4"},
		{"go", "github.com/some-organisation/a-repository-with-a-long-name/submodule/v2"},
	} {
		if err := validateEntry(ok.eco, "deny", ok.name); err != nil {
			t.Errorf("the cap rejected a legitimate %s name %q: %v", ok.eco, ok.name, err)
		}
	}
}

// TestEntryCannotContainNUL: a NUL truncates the name for anything using C string
// semantics downstream, so what is stored and what is matched can differ.
func TestEntryCannotContainNUL(t *testing.T) {
	if err := validateEntry("npm", "deny", "lodash\x00evil"); err == nil {
		t.Error("an entry containing a NUL byte was accepted")
	}
}

// --- injection into GIT --------------------------------------------------------------

// TestEntryThatLooksLikeAGitOptionIsInert.
//
// The store shells out to git, so an entry resembling a flag is the obvious probe. It
// should be inert because the entry is never a bare argument -- it is a value of -m and
// a line in a file, and the file is passed after "--". This test is here to keep that
// true: it would start failing the moment someone interpolated the entry into an
// argument list.
func TestEntryThatLooksLikeAGitOptionIsInert(t *testing.T) {
	repo := newTestRepo(t)
	s := newTestStore(t, repo)

	// A name that is well-formed by the list's rules but reads like a flag.
	const flagish = "--upload-pack=echo"
	if err := validateEntry("npm", "deny", flagish); err != nil {
		t.Skipf("entry rejected before reaching git (%v) — the probe needs a name the validator allows", err)
	}
	res, err := s.Apply(listDeny, flagish, "mallory", true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Changed {
		t.Fatal("no change recorded")
	}
	// It landed as DATA: one line in the file, and the repository is still intact.
	body := readFile(t, filepath.Join(repo, "deny.txt"))
	if !strings.Contains(body, flagish) {
		t.Errorf("the entry was not stored verbatim:\n%s", body)
	}
	if out, err := s.git("status", "--porcelain"); err != nil || strings.TrimSpace(out) != "" {
		t.Errorf("the working tree is not clean after the commit (out=%q err=%v)", out, err)
	}
}

// TestCommitMessageCannotBeForgedByTheEntry.
//
// The audit trail is the justification for this mechanism, so the question is whether
// the thing an attacker controls (the entry) can rewrite the thing an auditor reads (the
// actor). It cannot: the actor comes from the authenticated credential and the message
// is built from separate fields. This pins that, because the natural "fix" for a
// formatting complaint later would be to interpolate one into the other.
func TestCommitMessageCannotBeForgedByTheEntry(t *testing.T) {
	subject, body := commitMessage(listDeny, "left-pad", true, 0, "alice", 0, 1)
	if !strings.Contains(body, "actor:   alice") {
		t.Fatalf("actor missing from the commit body:\n%s", body)
	}
	// An entry trying to overwrite the actor line. It cannot contain a newline (proven
	// above), so the worst it can do is appear inside the entry field.
	subject2, body2 := commitMessage(listDeny, "x-actor:-root", true, 0, "alice", 0, 1)
	// Counted LINE-ANCHORED, not as a substring. The entry may legitimately contain the
	// text "actor:" in the middle of its own line -- what would be a forgery is a second
	// line that BEGINS one, and that requires a newline, which validateEntry refuses.
	actorLines := 0
	for _, line := range strings.Split(body2, "\n") {
		if strings.HasPrefix(line, "actor:") {
			actorLines++
		}
	}
	if actorLines != 1 {
		t.Errorf("the commit body has %d actor lines, want 1:\n%s", actorLines, body2)
	}
	if !strings.Contains(body2, "actor:   alice") {
		t.Errorf("the recorded actor is no longer the authenticated one:\n%s", body2)
	}
	if subject == subject2 {
		t.Error("two different entries produced the same subject")
	}
}

// TestUnknownActorIsRecordedAsUnknown: the audit record must not invent a name.
func TestUnknownActorIsRecordedAsUnknown(t *testing.T) {
	_, body := commitMessage(listAllow, "lodash", true, 0, "  ", 0, 1)
	if !strings.Contains(body, "unknown-operator") {
		t.Errorf("an empty actor was not recorded as unknown:\n%s", body)
	}
}

// --- injection into the RESPONSE -----------------------------------------------------

// TestNoticeCannotInjectAResponseHeader.
//
// The store's error text reaches the operator through a redirect's query string. Error
// text contains the entry. If it were concatenated into the Location header unescaped,
// an entry carrying CRLF would split the response.
func TestNoticeCannotInjectAResponseHeader(t *testing.T) {
	store := newFakeListStore()
	s := listsServer(t, store, "alice", nil)

	w := postEdit(t, s, url.Values{
		"kind":   {listDeny},
		"entry":  {"x\r\nSet-Cookie: session=stolen"},
		"action": {"add"},
	}, true)

	loc := w.Header().Get("Location")
	if strings.ContainsAny(loc, "\r\n") {
		t.Errorf("the Location header carries a raw line break: %q", loc)
	}
	if _, ok := w.Result().Header["Set-Cookie"]; ok {
		t.Error("a header was injected through the notice")
	}
}

// TestNoticeIsEscapedIntoThePage: the notice is attacker-influenced text rendered back.
func TestNoticeIsEscapedIntoThePage(t *testing.T) {
	s := listsServer(t, newFakeListStore(), "alice", nil)
	r := httptest.NewRequest(http.MethodGet, "/lists?notice="+url.QueryEscape(`<script>alert(1)</script>`)+"&level=err", nil)
	r.SetBasicAuth("alice", "secret")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	body := w.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("the notice was rendered unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("the notice does not appear escaped either — it may have been dropped, which would " +
			"hide real error text from the operator")
	}
}

// TestListNamesAreEscapedIntoThePage.
//
// Entries reach the page from the FILE, which the console does not fully control: an
// operator may hand-edit it, and increment 3b's whole premise is that the file is
// authored elsewhere too. A name is not markup.
func TestListNamesAreEscapedIntoThePage(t *testing.T) {
	store := newFakeListStore()
	store.docs[listDeny] = "<img/src=x/onerror=alert(1)>\n"
	s := listsServer(t, store, "alice", nil)
	body := getLists(t, s)

	if strings.Contains(body, "<img/src=x/onerror=alert(1)>") {
		t.Error("a list entry was rendered as raw HTML")
	}
	if !strings.Contains(body, "&lt;img/src=x/onerror=alert(1)&gt;") {
		t.Error("the entry is neither escaped nor shown; an operator cannot see what is in their own file")
	}
}

// --- the deputy: who decides which file is written -----------------------------------

// TestKindCannotSelectAnArbitraryFile.
//
// kind indexes the store's file map. If it were used to build a path, it would be a
// traversal. The map lookup is what makes it safe; this asserts the property rather than
// the implementation, so replacing the map with a path join fails here.
func TestKindCannotSelectAnArbitraryFile(t *testing.T) {
	repo := newTestRepo(t)
	s := newTestStore(t, repo)

	for _, kind := range []string{
		"../../etc/passwd", "..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"/etc/passwd", "malware", "", "allow/../deny",
	} {
		if _, err := s.Apply(kind, "lodash", "mallory", true); err == nil {
			t.Errorf("the store wrote to an unknown list kind %q", kind)
		}
		if _, err := s.Load(kind); err == nil {
			t.Errorf("the store read an unknown list kind %q", kind)
		}
	}

	// The handler refuses before the store is even consulted.
	fake := newFakeListStore()
	h := listsServer(t, fake, "alice", nil)
	w := postEdit(t, h, url.Values{"kind": {"../../etc/passwd"}, "entry": {"x"}, "action": {"add"}}, true)
	if w.Code != http.StatusBadRequest {
		t.Errorf("traversal in kind = %d, want 400", w.Code)
	}
	if len(fake.applied) != 0 {
		t.Error("a traversal reached the store")
	}
}

// TestReadOnlyConsoleCannotBeTalkedIntoWriting.
//
// Every route to the write, tried against a console with writes disabled. The point is
// the ENUMERATION: a single check in one handler is a check someone can route around by
// finding the other entry point, and /lists is the console's second write endpoint.
func TestReadOnlyConsoleCannotBeTalkedIntoWriting(t *testing.T) {
	store := newFakeListStore()
	s := listsServer(t, store, "", nil) // read-only: no credential

	for _, tc := range []struct {
		name   string
		method string
		target string
	}{
		{"post to /lists", http.MethodPost, "/lists"},
		{"post with a query string", http.MethodPost, "/lists?kind=deny&entry=x&action=add"},
		{"put instead of post", http.MethodPut, "/lists"},
		{"get with the parameters in the query", http.MethodGet, "/lists?kind=deny&entry=x&action=add"},
	} {
		r := httptest.NewRequest(tc.method, tc.target,
			strings.NewReader(url.Values{"kind": {listDeny}, "entry": {"x"}, "action": {"add"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if len(store.applied) != 0 {
			t.Fatalf("%s reached the store on a read-only console", tc.name)
		}
	}
}

// TestGetDoesNotMutate: a GET carrying the form parameters must render, never write.
//
// It matters beyond HTTP correctness: a GET that mutates is reachable from an <img> tag,
// which sidesteps the same-origin check entirely because there is no form POST to guard.
func TestGetDoesNotMutate(t *testing.T) {
	store := newFakeListStore()
	s := listsServer(t, store, "alice", nil)

	r := httptest.NewRequest(http.MethodGet, "/lists?kind=deny&entry=evil&action=add", nil)
	r.SetBasicAuth("alice", "secret")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d, want 200", w.Code)
	}
	if len(store.applied) != 0 {
		t.Error("a GET mutated the list — that is reachable from an <img> tag and bypasses the CSRF check")
	}
}
