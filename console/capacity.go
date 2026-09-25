package main

import (
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
)

// The capacity view (#32 Pillar 2, D80/D81).
//
// ── WHY THIS PAGE IS BESPOKE AND NOT A GRAFANA LINK ─────────────────────────
//
// The scoping doc recommended exposing /metrics and letting the operator's existing
// Prometheus/Grafana do the charting. The project OVERRULED that in D80: build the bespoke,
// native, in-app dashboard: the hardest part of the puzzle is the dashboard itself, and
// an operator should not need a second system to see what their gate is doing.
//
// D81 sets the quality bar deliberately and it should stay there: "slightly easier
// than building it myself" -- better than an operator's DIY option, not a full
// analytics product. So: no gold-plating.
//
// ── D88 IS AN INSTRUCTION ABOUT THIS FILE ───────────────────────────────────
//
// "Anything computed on the customer's own hardware from data already in their instance
// — retention depth, dashboard views, export volume, history queries — is free by this
// rule", and the immediate build consequence D88 records is that Phase C carries NO TIER
// CHECK ANYWHERE IN ITS CODE PATH. There is none here, and none may be added: the whole
// page runs on the operator's own flow data. Recorded so nobody later "monetizes" it by
// reflex, which is the exact wording D88 uses.
//
// ── WHAT THIS INCREMENT ANSWERS ─────────────────────────────────────────────
//
// D81's seed question set, and which of the five this page covers:
//
//	Q1  what packages constitute the bulk of the data?   -> the ranking below
//	Q2  how much data is flowing through my system?      -> the totals below
//	Q3  how many packages are stale?                     -> /activity, already shipped
//	Q4  why is the pipe saturated RIGHT NOW?             -> NOT YET (needs the series)
//	Q5  failures to pull due to corruption?              -> the integrity row below
//
// Q4 is the one deliberately left out of this increment. It is a time series and wants a
// chart; the totals and the ranking are useful on their own the moment they render, and
// shipping them first means the seam is proven against real data before anything is
// drawn. Q3 is NOT missing: D-ruling on #32 Q2 settled that observed-flow staleness is
// the honest answer while we are unpaired with a customer registry, and that /activity's
// labelling ("packages seen passing through") is correct rather than provisional.

//go:embed templates/capacity.html
var capacityHTML string

var capacityTmpl = pageTemplate("capacity", capacityHTML, template.FuncMap{
	"bytes": humanBytes,
	"count": humanCount,
})

// capacityPageView is everything the template renders.
type capacityPageView struct {
	Filter    flowFilter
	Summary   flowSummary
	Packages  []flowPackage
	Integrity []integrityRow
	// HasFlow is false when nothing has been recorded in the window. The template shows
	// a stated empty state rather than a page of zeroes, because "0 bytes moved" and
	// "the firewall has never reported" look identical in tiles and mean very different
	// things — one is a quiet week, the other is a broken telemetry chain.
	HasFlow bool

	Nav navView
}

// integrityRow is one counter behind D81 Q5, "were there failures to pull packages due
// to file corruption?".
//
// Rendered as named rows rather than a single "errors" tile because the five counters
// have genuinely different operator responses: a truncated relay is our bug or a flaky
// upstream, an upstream status is the registry refusing us, a transport error is the
// network, and retries succeeding is the system working as designed. Collapsing them
// into one number would answer "is something wrong" while destroying "what".
type integrityRow struct {
	Label string
	Count int64
	// Meaning is shown next to the number. An operator who has never read our source
	// cannot act on a bare counter name, and this page's whole purpose is at-a-glance.
	Meaning string
	// Benign marks a counter that is NOT itself a failure. Retries are the retry logic
	// working; showing them in the same visual weight as a corruption count would
	// manufacture alarm, which is how a dashboard trains people to ignore it.
	Benign bool
}

func (s *server) handleCapacity(w http.ResponseWriter, r *http.Request) {
	f, err := parseFlowFilterFromQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sum, err := s.approval.FlowSummary(f)
	if err != nil {
		log.Printf("capacity: flow summary: %v", err)
		http.Error(w, "cannot reach the approval service", http.StatusBadGateway)
		return
	}
	pkgs, err := s.approval.FlowPackages(f)
	if err != nil {
		log.Printf("capacity: flow packages: %v", err)
		http.Error(w, "cannot reach the approval service", http.StatusBadGateway)
		return
	}

	view := capacityPageView{
		Filter:    f,
		Summary:   sum,
		Packages:  pkgs,
		Integrity: integrityRows(sum),
		HasFlow:   sum.Requests > 0,
		Nav:       s.navFor(r, "capacity"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := capacityTmpl.Execute(w, view); err != nil {
		log.Printf("capacity: render: %v", err)
	}
}

// integrityRows turns the summary's error counters into labelled rows (D81 Q5).
//
// The order is deliberate: the two that mean "bytes a developer received may be wrong"
// come first, then the ones that mean "the pull did not happen", then the benign one.
// An operator scanning top-to-bottom should hit the most alarming thing first.
func integrityRows(s flowSummary) []integrityRow {
	return []integrityRow{
		// First, because it is the only row on this page that means the bytes were
		// WRONG rather than the transfer broke, and it is the one with an outside
		// cause. Everything below it is our side or the link; this one says the
		// registry or something between it and us served content that did not match
		// the digest that same registry published (#64). Names the two artifact kinds
		// it can see, so nobody reads a zero as a claim about npm or Maven.
		{"Integrity mismatches", s.IntegrityMismatches,
			"a container layer, PyPI file or Maven file arrived complete but did not match the digest its registry published — we aborted the transfer", false},
		{"Truncated relays", s.Truncated,
			"a response ended early — the developer may hold an incomplete artifact", false},
		{"Relay errors", s.RelayErrors,
			"we failed while streaming the bytes back", false},
		{"Upstream refusals", s.UpstreamStatus,
			"the registry answered with an error status (rate limit, auth, gone)", false},
		{"Transport errors", s.TransportErrors,
			"we could not reach the registry at all", false},
		{"Metadata errors", s.MetaErrors,
			"the package's metadata could not be read, so it could not be scored", false},
		{"Retries", s.Retries,
			"a transient failure that we retried — the retry logic working, not a fault", true},
	}
}

// parseFlowFilterFromQuery reads the page's filter from the query string.
//
// Server-side filtering via query params, per the scope doc's stdlib-first constraint: a
// JS framework needs an explicit argument and "it's a dashboard" is not one. It also
// means every view of this page is a URL an operator can bookmark or paste into a ticket,
// which matters more for incident response than interactivity does.
func parseFlowFilterFromQuery(r *http.Request) (flowFilter, error) {
	q := r.URL.Query()
	f := flowFilter{
		Ecosystem: strings.TrimSpace(q.Get("ecosystem")),
		Instance:  strings.TrimSpace(q.Get("instance")),
		From:      strings.TrimSpace(q.Get("from")),
		To:        strings.TrimSpace(q.Get("to")),
	}
	// No ecosystem whitelist here, deliberately. The sibling views (/audit, /downloads)
	// pass the filter through and let the approval service decide what matches, and a
	// second list in the console would be a list that drifts from newEcosystem's. An
	// unknown value simply matches nothing, which is the honest result.
	return f, nil
}

// humanBytes renders a byte count the way an operator reads one.
//
// Base 1000, not 1024: this number sits next to a network pipe, and network capacity is
// quoted in decimal units. Using binary units here would make our "812 GB" disagree with
// the operator's own bandwidth graph by 7% for no reason they could see.
func humanBytes(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"kB", "MB", "GB", "TB", "PB"}
	v := float64(n)
	i := -1
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	if v >= 100 {
		return fmt.Sprintf("%.0f %s", v, units[i])
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// humanCount groups thousands so a six-digit request count is readable at a glance.
func humanCount(n int64) string {
	s := fmt.Sprintf("%d", n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}
