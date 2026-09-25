package main

import (
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// layoutHTML is the shared shell: the stylesheet, the sidebar and the audit tabs. Every
// page is parsed together with it, so there is one navigation and one look rather than
// nine copies of each that drift -- the old per-page nav bars had already disagreed about
// which pages existed.
//
//go:embed templates/layout.html
var layoutHTML string

// pageTemplate parses one page with the shared layout. funcs may be nil.
func pageTemplate(name, page string, funcs template.FuncMap) *template.Template {
	t := template.New(name)
	if funcs != nil {
		t = t.Funcs(funcs)
	}
	return template.Must(template.Must(t.Parse(page)).Parse(layoutHTML))
}

// navItem is one sidebar entry, or a separator when Sep is set.
type navItem struct {
	Label, Href string
	Active      bool
	Count       int // a badge; 0 renders none
	Sep         bool
}

// gateCard is the sidebar's one-line answer to "are the gates up?".
type gateCard struct {
	Level    string // ok | warn | bad | "" (nothing to say yet)
	Headline string
	Detail   string
	Title    string // hover text: the replicas behind the headline
}

// navView is what the sidebar renders. Every page view carries one as .Nav.
type navView struct {
	Items      []navItem
	Gates      gateCard
	User       string
	CanSignOut bool
}

// navEntries is the sidebar, in order. The key is what a handler passes as "active".
//
// Pages reached from inside another page (downloads, activity and false positives sit
// under the audit log's tabs) are deliberately absent: the sidebar is the product's
// table of contents, and nine peers is the "technical settings panel" the redesign exists
// to replace.
var navEntries = []struct{ key, label, href string }{
	{"overview", "Overview", "/"},
	{"decisions", "Decisions", "/decisions"},
	{"stopped", "Stopped", "/stopped"},
	{"lookup", "Look up a package", "/lookup"},
	{"", "", ""},
	{"policy", "Policy", "/policy"},
	{"lists", "Allow & block lists", "/lists"},
	{"", "", ""},
	{"capacity", "Capacity", "/capacity"},
	{"audit", "Audit log", "/audit"},
}

// navFor builds the sidebar for one request. It asks the control plane two questions --
// how many packages wait on a person, and which gates are reporting -- concurrently,
// because a page whose control plane is slow should pay that wait once, not twice.
//
// Neither failure stops the page. The sidebar is chrome: a page that can render without
// the control plane (the lists page is one) must not start failing because its badge
// could not be fetched. An unknown count renders no badge rather than a zero, and an
// unreachable control plane says so in the gate card.
func (s *server) navFor(r *http.Request, active string) navView {
	var (
		wg       sync.WaitGroup
		pending  = -1
		health   []instanceHealth
		probeErr error
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if ds, err := s.approval.List(); err == nil {
			pending = 0
			for _, d := range ds {
				if d.Verdict == "pending" {
					pending++
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		health, probeErr = s.approval.ListInstanceHealth()
	}()
	wg.Wait()

	v := navView{User: s.currentUser(r), CanSignOut: s.oidc != nil}
	for _, e := range navEntries {
		if e.key == "" {
			v.Items = append(v.Items, navItem{Sep: true})
			continue
		}
		it := navItem{Label: e.label, Href: e.href, Active: e.key == active}
		if e.key == "decisions" && pending > 0 {
			it.Count = pending
		}
		v.Items = append(v.Items, it)
	}
	if probeErr != nil {
		v.Gates = gateCard{Level: "bad", Headline: "Control plane unreachable",
			Detail: "Gate status unknown. The gates keep enforcing what they last loaded."}
	} else {
		v.Gates = summarizeGates(health, time.Now().UTC())
	}
	return v
}

// ecosystemLabel is how an ecosystem is written for people.
func ecosystemLabel(e string) string {
	switch strings.ToLower(e) {
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "maven":
		return "Maven"
	case "oci":
		return "OCI"
	}
	return e
}

// summarizeGates reduces the replica heartbeats to the sidebar card.
//
// Freshness uses the policy page's staleAfter, so the card and that page never tell an
// operator different stories about the same replica. The card is WARN, not OK, whenever
// any gate runs in report mode: a report-mode gate logs its blocks and serves them, and
// a green "healthy" beside it would say the opposite.
func summarizeGates(rows []instanceHealth, now time.Time) gateCard {
	if len(rows) == 0 {
		return gateCard{Headline: "No gate has reported",
			Detail: "Nothing has sent a heartbeat to the control plane yet."}
	}
	fresh, report := 0, 0
	ecos := map[string]bool{}
	var titles []string
	for _, h := range rows {
		stale := now.Sub(h.ReportedAt) > staleAfter
		state := "reporting"
		if stale {
			state = "not reporting"
		} else {
			fresh++
			ecos[ecosystemLabel(h.Ecosystem)] = true
			if h.Policy != nil && h.Policy.Values["mode"] == "report" {
				report++
			}
		}
		titles = append(titles, fmt.Sprintf("%s (%s): %s", h.Instance, ecosystemLabel(h.Ecosystem), state))
	}
	sort.Strings(titles)
	names := make([]string, 0, len(ecos))
	for e := range ecos {
		names = append(names, e)
	}
	sort.Strings(names)

	c := gateCard{Title: strings.Join(titles, "\n"), Detail: strings.Join(names, " · ")}
	gates := func(n int) string {
		if n == 1 {
			return "1 gate"
		}
		return fmt.Sprintf("%d gates", n)
	}
	switch {
	case fresh == 0:
		c.Level, c.Headline = "bad", "No gate reporting"
		c.Detail = fmt.Sprintf("%s last reported more than %s ago.", gates(len(rows)), staleAfter)
	case fresh < len(rows):
		c.Level, c.Headline = "warn", fmt.Sprintf("%d of %s not reporting", len(rows)-fresh, gates(len(rows)))
	case report > 0:
		c.Level, c.Headline = "warn", fmt.Sprintf("%s in report mode", gates(report))
		c.Detail += " · blocks are logged, then served"
	default:
		c.Level = "ok"
		if fresh == 1 {
			c.Headline = "1 gate reporting"
		} else {
			c.Headline = fmt.Sprintf("All %d gates reporting", fresh)
		}
		c.Detail += " · enforcing"
	}
	return c
}
