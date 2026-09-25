package main

import (
	"fmt"
	"html/template"
	"log"
	"net/url"
	"sort"
	"strings"
	"time"
)

// The Decisions page (the design canvas's "what is waiting on you"): the queue as a list
// on the left and the selected package on the right, with everything a person needs to
// rule on it in one place -- why the gate stopped, who asked for it, what the registry
// says, and the two buttons.
//
// Everything here is ENRICHMENT of the queue the handler already renders. A failed read
// leaves a field blank and the page up: the ruling form works from the decision record
// alone, and an operator mid-incident must not lose the queue because the registry was
// slow.

// queueTab is one of the verdict tabs over the queue. They are the ?verdict= filter the
// page has always had, drawn as tabs.
type queueTab struct {
	Label  string
	Count  int
	Href   template.URL
	Active bool
}

// decisionDetail is the right-hand pane for one waiting package.
type decisionDetail struct {
	Row       queueRow
	Ecosystem string
	KindLabel string
	KindClass string

	// Why is the plain-language reason it is waiting. Served says the gate's policy let
	// it through while it waits (an allow-but-log category, or report mode): the page
	// must not describe a developer as blocked when they are not.
	Why    string
	Served bool

	LastVerdict string
	LastSeen    string
	Hosts       string

	Registry *upstreamHarvest
}

// queueHref is the Decisions URL for a filter and, optionally, a selected package.
func queueHref(f queueFilter, verdict, pkg string) template.URL {
	q := url.Values{}
	if f.Package != "" {
		q.Set("package", f.Package)
	}
	if verdict != "" {
		q.Set("verdict", verdict)
	}
	if pkg != "" {
		q.Set("pkg", pkg)
	}
	if len(q) == 0 {
		return "/decisions"
	}
	return template.URL("/decisions?" + q.Encode())
}

// queueTabs counts each verdict over the package-filtered list, so a tab's number is what
// clicking it will show.
func queueTabs(all []decision, f queueFilter) []queueTab {
	byPkg := filterDecisions(all, queueFilter{Package: f.Package})
	n := map[string]int{}
	for _, d := range byPkg {
		n[d.Verdict]++
	}
	return []queueTab{
		{"All", len(byPkg), queueHref(f, "", ""), f.Verdict == ""},
		{"Waiting", n["pending"], queueHref(f, "pending", ""), f.Verdict == "pending"},
		{"Allowed by a person", n["approved"], queueHref(f, "approved", ""), f.Verdict == "approved"},
		{"Denied by a person", n["denied"], queueHref(f, "denied", ""), f.Verdict == "denied"},
	}
}

// labelRows gives each pending row its selection link and, where the audit log knows it,
// the refusal kind and ecosystem.
func labelRows(v *queueView, latest map[string]event, selected string) {
	for gi := range v.Groups {
		for i := range v.Groups[gi].Items {
			row := &v.Groups[gi].Items[i]
			row.Href = queueHref(v.Filter, v.Filter.Verdict, row.Package)
			row.Selected = row.Package == selected
			if e, ok := latest[row.Package]; ok {
				row.Ecosystem = ecosystemLabel(e.Ecosystem)
				if e.DenyKind != "" {
					row.KindLabel, row.KindClass = kindLabel(e.DenyKind)
				} else if e.Action == "allow" {
					row.KindLabel = "Served while waiting"
				}
			}
		}
	}
}

// buildDetail assembles the right-hand pane for one pending row.
func (s *server) buildDetail(row queueRow, now time.Time) *decisionDetail {
	d := &decisionDetail{Row: row}

	// Every event for exactly this name. The store's package filter is a substring match
	// (an incident search), so "axios" also returns "axios-retry"; keep the exact ones.
	evs, err := s.approval.ListEvents(eventFilter{Package: row.Package, Limit: 200})
	if err != nil {
		log.Printf("decisions: events for %q: %v", row.Package, err)
	}
	var mine []event
	for _, e := range evs {
		if e.Package == row.Package {
			mine = append(mine, e)
		}
	}
	var last *event
	if len(mine) > 0 {
		last = &mine[0] // newest first
		d.Ecosystem = ecosystemLabel(last.Ecosystem)
		d.KindLabel, d.KindClass = kindLabel(last.DenyKind)
		d.Served = last.Action == "allow" || last.Taken == "allow"
		d.LastSeen = whenLabel(last.At, now) + " UTC"
		switch {
		case last.Action == "allow":
			d.LastVerdict = "Served and logged"
			d.KindLabel, d.KindClass = "Served while waiting", "allow"
		case last.Taken == "allow":
			d.LastVerdict = "Blocked by policy, served anyway (report mode)"
		default:
			d.LastVerdict = "Blocked"
		}
		d.Hosts = hostList(mine)
	}
	d.Why = whyWaiting(last, row.Note)

	eco := ""
	if last != nil {
		eco = last.Ecosystem
	}
	if st, found, err := s.approval.PackageStatus(row.Package, eco); err != nil {
		log.Printf("decisions: package status for %q: %v", row.Package, err)
	} else if found {
		d.Registry = st.UpstreamHarvest
	}
	return d
}

// hostList names the distinct source hosts that asked for a package, busiest first:
// "10.20.0.31, 10.20.0.14 and 3 more". Hosts, not people -- per-person attribution is
// #41, and the page must not imply an identity the gate never saw.
func hostList(evs []event) string {
	count := map[string]int{}
	for _, e := range evs {
		if e.SourceIP != "" {
			count[e.SourceIP]++
		}
	}
	if len(count) == 0 {
		return ""
	}
	ips := make([]string, 0, len(count))
	for ip := range count {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		if count[ips[i]] != count[ips[j]] {
			return count[ips[i]] > count[ips[j]]
		}
		return ips[i] < ips[j]
	})
	if len(ips) <= 2 {
		return strings.Join(ips, ", ")
	}
	return fmt.Sprintf("%s, %s and %d more", ips[0], ips[1], len(ips)-2)
}

// whyWaiting says in a sentence why a package is on a person's desk. It is written from
// the gate's structured refusal kind when the audit log has one, and falls back to the
// gate's own note -- which is always true, just terser -- rather than guessing.
func whyWaiting(last *event, note string) string {
	kind := ""
	if last != nil {
		kind = last.DenyKind
	}
	switch kind {
	case "score-below-threshold":
		if last.Score != nil && last.Threshold != nil {
			return fmt.Sprintf("Its health score is %.1f, below your threshold of %.1f. The score measures how "+
				"the project is run (code review, CI, maintenance), not whether this release is malicious, "+
				"so a person decides.", *last.Score, *last.Threshold)
		}
		return "Its health score is below your threshold. The score measures how the project is run, not " +
			"whether this release is malicious, so a person decides."
	case "unscorable":
		return "The gate could not score it, so it had nothing to judge it on. That is not a sign of malware. " +
			"Your policy sends packages like this to a person. The gate's note: " + note
	case "unverified":
		return "The source repository it names could not be confirmed as its own, so the gate would not " +
			"borrow that repository's score. The gate's note: " + note
	}
	if last != nil && last.Action == "allow" {
		return "The gate could not score it, and your policy lets packages like this through while a person " +
			"decides. It is being served and logged. The gate's note: " + note
	}
	if note != "" {
		return "The gate queued it with this note: " + note
	}
	return "The gate queued it for a person without a recorded reason."
}
