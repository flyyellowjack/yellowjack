package main

import (
	_ "embed"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// The /lists page: the operator's own allow and deny lists, edited here (issue #58
// increment 3b, D193 QT2).
//
// WHY THIS IS A SEPARATE PAGE FROM /policy. /policy answers "what is my fleet
// enforcing?" and is a fleet-wide, read-only view grouped by replica. This page answers
// "what have we decided?" and is where a decision is made. They read the same lists from
// opposite ends, and merging them would have made the fleet view -- which is useful on
// its own and shipped two increments ago -- depend on a write path being configured.
//
// THE TWO COLUMNS ARE THE POINT. Authored is what the operator has written and committed;
// enforced is what replicas report they have loaded. They are NOT the same thing and they
// move on different clocks: the gate re-reads its file every listReloadTTL (5s) while the
// console renders whatever arrived in the last heartbeat (60s by default). A page that
// showed one number would be lying about the other, and the lag is not a defect to be
// hidden -- it is the only way an operator can see that an edit has, or has not, reached
// the fleet yet. Showing it is also what makes the store's documented case-folding gap
// self-correcting: a removal that did not take effect stays visible in the enforced
// column instead of being believed.

//go:embed templates/lists.html
var listsHTML string

var listsTmpl = pageTemplate("lists", listsHTML, nil)

// listsPageView is the whole page.
type listsPageView struct {
	Panels []listPanel
	Nav    navView

	// Editable is true only when BOTH a credential is configured (writes on) and a
	// store is available. Disabled says which is missing, in words: a UI that hides its
	// buttons without saying why is the operator-facing form of the unattributable
	// refusal D137 objects to.
	Editable  bool
	Disabled  string
	AuthUser  string
	StoreDesc string

	Notice      string
	NoticeLevel string // "ok" | "warn" | "err"

	// Err is a page-level failure to reach the control plane. It does not disable
	// editing: the store is local and the write path does not depend on the control
	// plane at all, so an operator can still act during an outage. They just cannot see
	// what the fleet has picked up.
	Err string

	StaleAfter string
}

// listPanel is one list, from both ends.
type listPanel struct {
	Kind string // "allow" | "deny"
	Var  string // the FW_* variable a deployer sets, so the page and the config agree
	Path string

	// Authored side.
	Authored    []string
	AuthoredErr string
	Rev         string
	History     []commitLine

	// Enforced side.
	Reported  bool // did any fresh replica report this list at all?
	Enforced  []string
	Omitted   int
	Replicas  int
	Diverged  bool
	EnfDigest string

	// The difference, which is the reason both sides are on the page.
	Pending []string // authored, not yet reported by any fresh replica
	Extra   []string // reported as enforced, but not in the authored file
}

// Title is a display helper so the template stays a dumb renderer.
func (p listPanel) Title() string {
	if p.Kind == listAllow {
		return "Allow list"
	}
	return "Deny list"
}

func (s *server) handleLists(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleListEdit(w, r)
		return
	}
	v := listsPageView{
		AuthUser:   s.authUser(r),
		StaleAfter: staleAfter.String(),
	}
	if q := r.URL.Query(); q.Get("notice") != "" {
		// Reflected into the page, but through html/template, which escapes it. It rides
		// the redirect because the console owns no session state -- that is the
		// architectural rule (it is an HTTP client of the control plane, nothing more),
		// and a flash message is not a good enough reason to break it.
		v.Notice = q.Get("notice")
		v.NoticeLevel = noticeLevel(q.Get("level"))
	}

	// Ordered most-blocking first. A missing binary outranks an unset repository
	// because no value of CONSOLE_LIST_REPO can fix it -- the fix is a different
	// image. Getting this order wrong is what made the default install (D199) tell
	// operators to set a variable that could not have worked.
	switch {
	case s.gitMissing:
		v.Disabled = "List editing is unavailable: this console image ships without git. " +
			"Build or pull the console-git image target to enable it. Setting " +
			"CONSOLE_LIST_REPO will not help on this image."
	case s.lists == nil:
		v.Disabled = "List editing is not configured: set CONSOLE_LIST_REPO to a git working tree containing the list files."
	case !s.writesEnabled():
		v.Disabled = "The console is running read-only. Set CONSOLE_AUTH_USER and CONSOLE_AUTH_PASS to enable edits."
	default:
		v.Editable = true
		v.StoreDesc = s.lists.Describe()
	}

	// The ENFORCED side comes from the control plane. A failure here is reported but
	// does not stop the page: the authored side is local and is still worth showing.
	enforced := map[string]*enforcedList{}
	rows, err := s.approval.ListInstanceHealth()
	if err != nil {
		log.Printf("lists: list instance health: %v", err)
		v.Err = "The control plane could not be reached, so what the fleet is enforcing is unknown. " +
			"The firewalls have not stopped gating traffic — they keep enforcing whatever they last loaded."
	} else {
		enforced = collectEnforcedLists(rows, time.Now().UTC())
	}

	for _, kind := range []string{listAllow, listDeny} {
		v.Panels = append(v.Panels, s.buildPanel(kind, enforced[kind]))
	}
	v.Nav = s.navFor(r, "lists")
	renderLists(w, v)
}

func (s *server) buildPanel(kind string, enf *enforcedList) listPanel {
	p := listPanel{Kind: kind, Var: "FW_" + strings.ToUpper(kind) + "_LIST"}

	if s.lists != nil {
		doc, err := s.lists.Load(kind)
		if err != nil {
			// Named, not swallowed. An unreadable or unparseable list is exactly the
			// state an operator needs to be told about: the gate is either refusing to
			// start on it or still enforcing an older copy of it.
			p.AuthoredErr = err.Error()
		} else {
			p.Authored = doc.Entries()
			p.Path = doc.Path
			p.Rev = shortRev(doc.Rev)
		}
		if h, err := s.lists.History(kind, 5); err == nil {
			p.History = h
		}
	}

	if enf != nil {
		p.Reported = true
		p.Enforced = enf.names
		p.Omitted = enf.omitted
		p.Replicas = enf.replicas
		p.Diverged = enf.diverged
		p.EnfDigest = enf.digest
		if p.Path == "" {
			p.Path = enf.path
		}
	}

	// The diff is computed only when BOTH sides are known and the enforced side is not
	// truncated. A capped list (listEntries caps at 200) would make every unshown name
	// look "pending", which would turn a display cap into a fake fleet-divergence alarm.
	if s.lists != nil && p.AuthoredErr == "" && p.Reported && p.Omitted == 0 {
		p.Pending, p.Extra = diffLists(s.listEcosystem, p.Authored, p.Enforced)
	}
	return p
}

// enforcedList is what the fleet reports for one list kind.
type enforcedList struct {
	names    []string
	omitted  int
	replicas int
	diverged bool
	digest   string
	path     string
}

// collectEnforcedLists reads the operator lists out of the fleet's heartbeats.
//
// FRESH replicas only, for the reason buildPolicyView already documents: a replica that
// died three weeks ago still carries whatever list it last loaded, and counting it would
// light a divergence warning that can never be cleared. A warning that cannot be cleared
// is one an operator learns to ignore.
func collectEnforcedLists(rows []instanceHealth, now time.Time) map[string]*enforcedList {
	out := map[string]*enforcedList{}
	digests := map[string]map[string]bool{}

	for _, h := range rows {
		if h.Policy == nil || now.Sub(h.ReportedAt) > staleAfter {
			continue
		}
		for _, l := range h.Policy.Lists {
			e, ok := out[l.Kind]
			if !ok {
				e = &enforcedList{path: l.Path, digest: l.Digest}
				out[l.Kind] = e
				digests[l.Kind] = map[string]bool{}
			}
			e.replicas++
			digests[l.Kind][l.Digest] = true
			// Names are taken from the FIRST fresh replica reporting this list. When
			// replicas disagree there is no single right answer to show, so the page
			// says they disagree rather than picking one and presenting it as the
			// fleet's policy.
			if len(e.names) == 0 {
				e.names = append([]string(nil), l.Names...)
				e.omitted = l.Omitted
			}
		}
	}
	for kind, e := range out {
		e.diverged = len(digests[kind]) > 1
	}
	return out
}

// diffLists reports what is authored but not enforced, and vice versa.
//
// The comparison key is DISPLAY-ONLY normalisation and is deliberately at least as
// aggressive as the gate's: authored names are spelled by a human while enforced names
// come back already normalised by malwareKey, so a naive comparison would flag "LoDash"
// against "lodash" as a fleet divergence on every render.
//
// Erring toward MATCHING (rather than toward showing a difference) is the right bias
// here even though it can hide one, because the noise it prevents is constant and the
// case it hides -- two spellings of one package in one file -- is already visible in the
// authored column itself, where both lines are listed.
func diffLists(ecosystem string, authored, enforced []string) (pending, extra []string) {
	inEnforced := map[string]bool{}
	for _, e := range enforced {
		inEnforced[compareKey(ecosystem, e)] = true
	}
	inAuthored := map[string]bool{}
	for _, a := range authored {
		inAuthored[compareKey(ecosystem, a)] = true
	}
	for _, a := range authored {
		if !inEnforced[compareKey(ecosystem, a)] {
			pending = append(pending, a)
		}
	}
	for _, e := range enforced {
		if !inAuthored[compareKey(ecosystem, e)] {
			extra = append(extra, e)
		}
	}
	sort.Strings(pending)
	sort.Strings(extra)
	return pending, extra
}

// compareKey folds a name for DISPLAY COMPARISON ONLY.
//
// It is not malwareKey and must never be used to decide policy. It exists because this
// page puts a human-spelled column next to a machine-normalised one, and the alternative
// -- importing the gate's normaliser -- is not available across the service boundary.
//
// The three rules mirror the ones that would otherwise produce constant false
// differences: case for every ecosystem, PEP 503's [-_.] folding for PyPI, and the
// reference for OCI, where a tag is part of what the operator may have written but the
// gate reduces to the repository (D164).
func compareKey(ecosystem, name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch ecosystem {
	case "pypi":
		var b strings.Builder
		lastDash := false
		for _, r := range n {
			if r == '-' || r == '_' || r == '.' {
				if !lastDash {
					b.WriteByte('-')
					lastDash = true
				}
				continue
			}
			b.WriteRune(r)
			lastDash = false
		}
		return b.String()
	case "oci":
		if i := strings.IndexByte(n, '@'); i >= 0 {
			n = n[:i]
		}
		// A colon separates a tag, but a registry host may carry a port: only the
		// segment after the last '/' can hold a tag.
		if i := strings.LastIndexByte(n, '/'); i >= 0 {
			if j := strings.IndexByte(n[i:], ':'); j >= 0 {
				n = n[:i+j]
			}
		} else if j := strings.IndexByte(n, ':'); j >= 0 {
			n = n[:j]
		}
		return n
	}
	return n
}

// handleListEdit is the write. POST only, credential required, same-origin required.
//
// It mirrors handleOverride's shape deliberately -- the same auth gate, the same CSRF
// check, the same POST-redirect-GET -- because this is the console's SECOND write
// endpoint and two write paths with two different sets of guards is how one of them ends
// up without a guard.
func (s *server) handleListEdit(w http.ResponseWriter, r *http.Request) {
	if s.lists == nil {
		http.Error(w, "list editing is not configured — set CONSOLE_LIST_REPO", http.StatusForbidden)
		return
	}
	if !s.writesEnabled() {
		// Defence in depth, exactly as in handleOverride: ServeHTTP would not have
		// demanded a credential without one configured, so the write endpoint refuses
		// on its own rather than relying on the router having done it.
		http.Error(w, "list edits are disabled — set CONSOLE_AUTH_USER and CONSOLE_AUTH_PASS to enable them", http.StatusForbidden)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	kind := strings.TrimSpace(r.PostForm.Get("kind"))
	if kind != listAllow && kind != listDeny {
		http.Error(w, "kind must be allow or deny", http.StatusBadRequest)
		return
	}
	entry := strings.TrimSpace(r.PostForm.Get("entry"))
	add := r.PostForm.Get("action") != "remove"

	res, err := s.lists.Apply(kind, entry, s.authUser(r), add)
	if err != nil {
		log.Printf("list edit %s %q (by %q): %v", kind, entry, s.authUser(r), err)
		redirectLists(w, r, err.Error(), "err")
		return
	}

	switch {
	case res.Existing, res.Absent:
		redirectLists(w, r, res.Detail, "warn")
	case res.PushErr != "":
		// A commit that did not reach the remote is reported as a WARNING rather than a
		// success. The edit is real and the local gate will see it, but "shared with the
		// fleet" has not happened, and that is the half the operator was counting on.
		log.Printf("list edit %s %q committed but push failed: %s", kind, entry, res.PushErr)
		redirectLists(w, r, res.Detail, "warn")
	default:
		verb := "Added"
		if !add {
			verb = "Removed"
		}
		log.Printf("list edit: %s %q on the %s list (by %q) — %s", strings.ToLower(verb), entry, kind, s.authUser(r), res.Detail)
		redirectLists(w, r, verb+" "+entry+". "+res.Detail+
			" Replicas pick this up on their own clock, so the enforced column may lag by a heartbeat.", "ok")
	}
}

// redirectLists is POST-redirect-GET so a refresh does not re-submit the edit.
func redirectLists(w http.ResponseWriter, r *http.Request, notice, level string) {
	q := url.Values{}
	q.Set("notice", notice)
	q.Set("level", level)
	http.Redirect(w, r, "/lists?"+q.Encode(), http.StatusSeeOther)
}

func noticeLevel(s string) string {
	switch s {
	case "ok", "warn", "err":
		return s
	}
	return "ok"
}

// authUser is who is acting, or "" when nobody is authenticated.
//
// ⚠️ IT TAKES THE REQUEST, and that is the whole point. It used to read the static
// basic-auth username, which silently became "" the moment OIDC was configured
// without a shared credential -- so a list edit was committed with an EMPTY author.
// That is #41's defect (a decision nobody can be asked about) surviving in the
// console's OTHER write path, after the override path had been fixed.
//
// Missed on the first pass because the OIDC change grepped server.go for
// `s.auth.user`, found none left, and stopped -- the readers in lists.go and
// lookup.go are in different files.
func (s *server) authUser(r *http.Request) string {
	return s.currentUser(r)
}

func renderLists(w http.ResponseWriter, v listsPageView) {
	if err := listsTmpl.Execute(w, v); err != nil {
		log.Printf("lists: render: %v", err)
	}
}
