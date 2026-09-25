package main

import (
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The Stopped pages (the design canvas's "Why this was blocked"): the gate's refusals as a
// list, and one refusal explained -- what happened, what to do instead, why the gate
// decided, who asked, and the override that applies to THAT kind of refusal.
//
// Read-only over the audit log. The only writes offered are the console's existing ones
// (a list edit, a ruling, a false-positive report), each posted to its own handler with
// its own guards, so this page adds no new way to change enforcement.

//go:embed templates/stopped.html
var stoppedHTML string

//go:embed templates/stoppedview.html
var stoppedViewHTML string

var (
	stoppedTmpl     = pageTemplate("stopped", stoppedHTML, nil)
	stoppedViewTmpl = pageTemplate("stoppedview", stoppedViewHTML, nil)
)

// stoppedListLimit is how many refusals the list shows. It is the audit page's window;
// the full history stays one click away on /audit.
const stoppedListLimit = auditViewLimit

// stoppedGroups are the list's tabs: the three kinds of refusal a person acts on
// differently. "policy" is every refusal that is neither an advisory nor the
// organisation's own list -- a score, an unscorable package, a release window, a ruling.
var stoppedGroups = []struct{ Key, Label string }{
	{"", "All"},
	{"known-malware", "Known malware"},
	{"operator", "Your block list"},
	{"policy", "By policy"},
}

func stoppedGroupOf(kind string) string {
	switch kind {
	case "known-malware":
		return "known-malware"
	case "operator-denied":
		return "operator"
	}
	return "policy"
}

// stoppedHref links one refusal. Both the event id and the package travel: the audit log
// is read by package (a bounded, indexed query) and the id picks the exact verdict.
func stoppedHref(e event) template.URL {
	q := url.Values{}
	q.Set("id", strconv.FormatInt(e.ID, 10))
	q.Set("package", e.Package)
	return template.URL("/stopped/view?" + q.Encode())
}

type stoppedTab struct {
	Label  string
	Count  int
	Href   template.URL
	Active bool
}

type stoppedRow struct {
	overviewBlock
	Reason string
}

type stoppedView struct {
	Nav   navView
	Tabs  []stoppedTab
	Rows  []stoppedRow
	Group string
}

func (s *server) handleStopped(w http.ResponseWriter, r *http.Request) {
	group := strings.TrimSpace(r.URL.Query().Get("kind"))
	known := false
	for _, g := range stoppedGroups {
		known = known || g.Key == group
	}
	if !known {
		http.Error(w, "kind must be known-malware, operator or policy", http.StatusBadRequest)
		return
	}
	evs, err := s.approval.ListEvents(eventFilter{Action: "block", Limit: stoppedListLimit})
	if err != nil {
		log.Printf("stopped: list events: %v", err)
		http.Error(w, "Cannot reach the approval service. Is it running and is CONSOLE_APPROVAL_URL correct?", http.StatusBadGateway)
		return
	}
	now := time.Now().UTC()
	v := stoppedView{Nav: s.navFor(r, "stopped"), Group: group}
	counts := map[string]int{}
	for _, e := range evs {
		g := stoppedGroupOf(e.DenyKind)
		counts[g]++
		if group != "" && g != group {
			continue
		}
		label, class := kindLabel(e.DenyKind)
		v.Rows = append(v.Rows, stoppedRow{
			overviewBlock: overviewBlock{Package: e.Package, Ecosystem: ecosystemLabel(e.Ecosystem), At: e.At,
				When: whenLabel(e.At, now), Label: label, Class: class, Served: e.Taken == "allow", Href: stoppedHref(e)},
			Reason: e.Reason,
		})
	}
	for _, g := range stoppedGroups {
		n := len(evs)
		if g.Key != "" {
			n = counts[g.Key]
		}
		href := "/stopped"
		if g.Key != "" {
			href += "?kind=" + g.Key
		}
		v.Tabs = append(v.Tabs, stoppedTab{Label: g.Label, Count: n, Href: template.URL(href), Active: g.Key == group})
	}
	if err := stoppedTmpl.Execute(w, v); err != nil {
		log.Printf("stopped: render: %v", err)
	}
}

// stoppedFact is one line of "Why the gate decided".
type stoppedFact struct{ Label, Value string }

type stoppedAttempt struct {
	Host string
	When string
}

type stoppedDetailView struct {
	Nav   navView
	Event event

	Ecosystem string
	KindLabel string
	KindClass string
	When      string
	Served    bool
	Hosts     int

	Happened string
	Instead  string
	// InsteadHref is the one link "what to do instead" points at, when there is one.
	InsteadHref  template.URL
	InsteadLabel string

	Facts    []stoppedFact
	Attempts []stoppedAttempt

	// Override is which of the console's existing writes fits this refusal, if any:
	// "pin" (a version-pinned allow entry outranks an advisory for that release, D312),
	// "unlist" (take it off the organisation's block list), or "rule" (a ruling in
	// Decisions). Empty when none applies, and the page says why.
	Override    string
	PinTemplate string // the entry, spelled for the ecosystem, with the version left to type
	CanEditList bool
	CanWrite    bool
	ListsNote   string
}

func (s *server) handleStoppedView(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	pkg := strings.TrimSpace(q.Get("package"))
	id, err := strconv.ParseInt(q.Get("id"), 10, 64)
	if pkg == "" || err != nil {
		http.Error(w, "a refusal is named by ?id= and ?package=", http.StatusBadRequest)
		return
	}
	evs, err := s.approval.ListEvents(eventFilter{Package: pkg, Action: "block", Limit: auditViewLimit})
	if err != nil {
		log.Printf("stopped view %q: list events: %v", pkg, err)
		http.Error(w, "Cannot reach the approval service. Is it running and is CONSOLE_APPROVAL_URL correct?", http.StatusBadGateway)
		return
	}
	// The store's package filter is a substring; the page is about exactly one name.
	var mine []event
	var found *event
	for i := range evs {
		if evs[i].Package != pkg {
			continue
		}
		mine = append(mine, evs[i])
		if evs[i].ID == id {
			found = &evs[i]
		}
	}
	if found == nil {
		http.Error(w, fmt.Sprintf("No refusal %d of %q is in the recent audit log. It may be older than the "+
			"%d most recent refusals of that name; the full history is on /audit.", id, pkg, auditViewLimit), http.StatusNotFound)
		return
	}

	now := time.Now().UTC()
	e := *found
	v := stoppedDetailView{Nav: s.navFor(r, "stopped"), Event: e, Ecosystem: ecosystemLabel(e.Ecosystem),
		When: whenLabel(e.At, now) + " UTC", Served: e.Taken == "allow", CanWrite: s.writesEnabled()}
	v.KindLabel, v.KindClass = kindLabel(e.DenyKind)

	seen := map[string]bool{}
	for _, m := range mine {
		if m.SourceIP != "" && !seen[m.SourceIP] {
			seen[m.SourceIP] = true
			if len(v.Attempts) < 8 {
				v.Attempts = append(v.Attempts, stoppedAttempt{Host: m.SourceIP, When: whenLabel(m.At, now) + " UTC"})
			}
		}
	}
	v.Hosts = len(seen)

	v.explain(e)
	v.Facts = stoppedFacts(e)

	v.CanEditList = s.lists != nil && s.writesEnabled()
	switch {
	case s.lists == nil:
		v.ListsNote = "List editing is not configured on this console, so the list-based override is not available here."
	case !s.writesEnabled():
		v.ListsNote = "This console is read-only, so no override is offered."
	}
	if err := stoppedViewTmpl.Execute(w, v); err != nil {
		log.Printf("stopped view: render: %v", err)
	}
}

// explain writes "What happened" and "What to do instead" for one refusal, and picks the
// override that fits it. Each branch says only what the refusal kind makes true: a score
// refusal says nothing about malware, and an advisory says nothing about the score.
func (v *stoppedDetailView) explain(e event) {
	name := e.Package
	switch e.DenyKind {
	case "known-malware":
		ref := ""
		if e.Rule != "" {
			ref = " (" + e.Rule + ")"
		}
		v.Happened = "This package is named on the known-malware list" + ref + ". The download stopped at the " +
			"gate, so nothing was installed."
		v.Instead = "Use a release the advisory does not name. Look the package up to see what the registry publishes."
		v.InsteadHref, v.InsteadLabel = template.URL("/lookup?package="+url.QueryEscape(name)), "Look up "+name
		v.Override, v.PinTemplate = "pin", pinTemplate(e.Ecosystem, name)
	case "operator-denied":
		v.Happened = "Your organisation put this package on its own block list. That is a local decision, not a " +
			"published advisory, and the gate refused it without contacting the registry."
		v.Instead = "Ask whoever maintains your block list, or use a different package."
		v.InsteadHref, v.InsteadLabel = "/lists", "See the allow & block lists"
		v.Override = "unlist"
	case "human-denied":
		v.Happened = "A person denied this package in Decisions, so the gate refuses it on every path."
		v.Instead = "Ask the person who ruled on it. The ruling and its note are on the Decisions page."
		v.InsteadHref, v.InsteadLabel = template.URL("/decisions?package="+url.QueryEscape(name)), "See the ruling"
		v.Override = "rule"
	case "score-below-threshold":
		if e.Score != nil && e.Threshold != nil {
			v.Happened = fmt.Sprintf("Its health score is %.1f, below your threshold of %.1f. The score measures how "+
				"the project is run, not whether this release is malicious.", *e.Score, *e.Threshold)
		} else {
			v.Happened = "Its health score is below your threshold. The score measures how the project is run, " +
				"not whether this release is malicious."
		}
		v.Instead = "A person can allow it in Decisions, where it is waiting."
		v.InsteadHref, v.InsteadLabel = template.URL("/decisions?pkg="+url.QueryEscape(name)), "Open it in Decisions"
		v.Override = "rule"
	case "unscorable", "unverified":
		v.Happened = "The gate could not judge this package: it has no source repository the gate can score and " +
			"trust. That is not a sign of malware, and your policy refuses packages like this until a person decides."
		v.Instead = "A person can allow it in Decisions, or give its source repository there so the gate can score it."
		v.InsteadHref, v.InsteadLabel = template.URL("/decisions?pkg="+url.QueryEscape(name)), "Open it in Decisions"
		v.Override = "rule"
	case "release-window":
		v.Happened = "Every version the registry offered is outside your release window: too new to trust yet, " +
			"or older than your age limit."
		v.Instead = "Wait for a release to age past the window, or pin a version inside it."
	default:
		v.Happened = "The gate refused this package. The audit record does not say which kind of refusal it was; " +
			"the gate's own words are below."
	}
}

// pinTemplate is an allow-list entry for one release of name, spelled the way the gate
// parses its ecosystem (#155), with the version left for the operator to type. The page
// cannot fill the version in: the audit record names the package, not the release.
func pinTemplate(ecosystem, name string) string {
	switch strings.ToLower(ecosystem) {
	case "pypi":
		return name + "=="
	case "maven":
		return name + ":"
	case "oci":
		return name + "@sha256:"
	}
	return name + "@"
}

func stoppedFacts(e event) []stoppedFact {
	var out []stoppedFact
	rule := e.Rule
	if e.Source != "" {
		if rule != "" {
			rule += " · "
		}
		rule += e.Source
	}
	if rule != "" {
		out = append(out, stoppedFact{"Rule that applied", rule})
	}
	if e.Score != nil {
		v := fmt.Sprintf("%.1f", *e.Score)
		if e.Threshold != nil {
			v += fmt.Sprintf(" against a threshold of %.1f", *e.Threshold)
		}
		if e.Partial() {
			v += fmt.Sprintf(" (partial: %d of %d checks)", e.ScoredChecks, e.TotalChecks)
		}
		out = append(out, stoppedFact{"Score", v})
	}
	switch e.DenyKind {
	case "known-malware", "operator-denied":
		out = append(out, stoppedFact{"Decided", "On the gate, without contacting the registry"})
	}
	if e.Taken == "allow" {
		out = append(out, stoppedFact{"Enforcement", "Report mode: logged, then served"})
	}
	if e.PolicyDigest != "" {
		out = append(out, stoppedFact{"Policy in force", shortDigest(e.PolicyDigest)})
	}
	return out
}
