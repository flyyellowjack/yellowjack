package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Attribution under OIDC, everywhere — not just where it was checked first.
//
// WHAT WENT WRONG. `!330` routed the console's identity through one
// server.currentUser(r) and claimed "every identity site". It verified that by
// grepping **server.go** for `s.auth.user`, finding none left, and stopping. Two
// readers live in other files:
//
//   - console/lookup.go set the page's AuthUser from the static basic-auth name,
//     so an OIDC-only console showed nobody signed in. Cosmetic.
//   - console/lists.go's authUser() fed s.lists.Apply(..., actor, ...) — the
//     AUTHOR of an allow/deny-list edit. With OIDC configured and no shared
//     credential it returned "", so a list edit was committed **unattributed**.
//     That is exactly #41's defect ("a decision nobody can be asked about")
//     surviving in the console's OTHER write path, after the override path had
//     been fixed and declared done.
//
// The lesson is the grep, not the two lines: a claim of the form "every X now
// goes through Y" has to be checked against every FILE, and the cheapest way to
// keep it true is to let a test do the grepping.

// TestNoConsoleFileReadsTheStaticAuthUser is that test. It is source-derived on
// purpose: enumerating pages by hand is what produced the bug, and a new handler
// added next month would not be in a hand-written list.
func TestNoConsoleFileReadsTheStaticAuthUser(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	// ANTI-VACUITY: this whole test is a loop over files, and an empty glob passes
	// while reading nothing.
	if len(files) < 5 {
		t.Fatalf("only %d .go files found (%v) — this guard is not reading the package it protects", len(files), files)
	}

	// `s.auth.user` is legitimate in exactly one place: inside currentUser, which
	// is the reconciliation point every other reader must go through.
	reader := regexp.MustCompile(`s\.auth\.user`)
	var sawCurrentUser bool

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		// Strip // comments before scanning. A comment that NAMES the forbidden
		// pattern -- like the one above authUser explaining why it must not be used
		// -- is documentation, not a reader, and a guard that cannot tell them apart
		// pressures the next person into deleting the explanation to get green.
		text := stripLineComments(string(src))
		if strings.Contains(text, "func (s *server) currentUser(") {
			sawCurrentUser = true
		}
		for _, loc := range reader.FindAllStringIndex(text, -1) {
			// Which function is this in?
			start := strings.LastIndex(text[:loc[0]], "\nfunc ")
			if start < 0 {
				t.Errorf("%s: s.auth.user appears outside any function", f)
				continue
			}
			if !strings.Contains(text[start:start+80], "currentUser(") {
				line := 1 + strings.Count(text[:loc[0]], "\n")
				t.Errorf("%s:%d reads s.auth.user directly.\n"+
					"Every identity site must go through s.currentUser(r), or it returns the SHARED label when "+
					"both mechanisms are configured and an EMPTY string when only OIDC is — which is how a list "+
					"edit got committed with no author (#41, #148).", f, line)
			}
		}
	}

	if !sawCurrentUser {
		t.Fatal("currentUser is gone or renamed — this guard is no longer anchored to the thing it enforces")
	}
}

// TestListEditIsAttributedToTheSignedInPerson is the behavioural half: the guard
// above would pass if authUser() simply returned "" forever.
func TestListEditIsAttributedToTheSignedInPerson(t *testing.T) {
	f := newFakeIdP(t)
	store := &fakeListStore{}
	srv := &server{approval: &fakeApproval{}, lists: store, listEcosystem: "npm", oidc: newTestOIDC(t, f)}
	ck := signIn(t, srv.oidc, f, "/lists")

	form := strings.NewReader("kind=deny&entry=left-pad&action=add")
	req := httptest.NewRequest(http.MethodPost, "/lists", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://example.com")
	req.Host = "example.com"
	req.AddCookie(ck)

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusOK {
		t.Fatalf("list edit while signed in = %d; body %s", rr.Code, rr.Body.String())
	}
	if len(store.applied) != 1 {
		t.Fatalf("the list store saw %d edit(s), want 1 — the edit did not reach it, so the actor below "+
			"proves nothing", len(store.applied))
	}
	actor := store.applied[0].Actor
	if actor == "" {
		t.Fatal("the list edit was committed with an EMPTY author. An operator-list change is a policy decision, " +
			"and one nobody can be asked about is the defect #41 describes")
	}
	if actor != "dev@example.com" {
		t.Errorf("list edit actor = %q, want the signed-in person", actor)
	}
}

// stripLineComments blanks // comment text while preserving line numbering, so a
// reported line still points at the right place in the real file.
func stripLineComments(src string) string {
	lines := strings.Split(src, "\n")
	for i, l := range lines {
		if idx := strings.Index(l, "//"); idx >= 0 {
			lines[i] = l[:idx]
		}
	}
	return strings.Join(lines, "\n")
}
