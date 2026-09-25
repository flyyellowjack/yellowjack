package main

import (
	_ "embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The Overview (the design canvas's home page): what the gates did in the last day and
// what is waiting on a person, on one screen. It is a READ of four things the console
// already reads elsewhere -- the queue, the verdict tally, the newest refusals, and the
// replicas' reported policy -- composed so the first page an operator opens answers "is
// anything on fire, and is anything waiting on me" without a click.

//go:embed templates/overview.html
var overviewHTML string

var overviewTmpl = pageTemplate("overview", overviewHTML, template.FuncMap{
	"count": func(n int) string { return humanCount(int64(n)) },
})

// overviewWindow is the span the "stopped" and "allowed" tiles cover. The last 24 hours,
// not "today": the page cannot know which midnight the reader means (see the approval
// service's defaultSummaryWindow), and the tile says which it is.
const overviewWindow = 24 * time.Hour

// overviewRecentBlocks is how many refusals the "Recently stopped" card lists.
const overviewRecentBlocks = 5

// overviewWaitingShown is how many waiting packages the "Needs your decision" card lists.
const overviewWaitingShown = 3

// denyKinds is how each of the gate's structured refusal kinds (D182, firewall.go's
// denyKind) is said to a person, and which badge colour it wears. One table, used by every
// page that labels a refusal, so the Overview and the Decisions page cannot call the same
// block two different things.
//
// Red is reserved for a positive finding (a published advisory). A local policy decision
// is blue and an inconclusive one is amber: colouring "we could not score it" the same as
// "this is malware" would teach an operator that red means nothing in particular.
var denyKinds = map[string]struct{ Label, Class string }{
	"known-malware":         {"Known malware", "block"},
	"operator-denied":       {"On your block list", "operator"},
	"human-denied":          {"Denied by a person", "operator"},
	"score-below-threshold": {"Below score threshold", "pending"},
	"unscorable":            {"Can't be scored", "pending"},
	"unverified":            {"Source not verified", "pending"},
	"release-window":        {"Outside release window", "pending"},
}

// kindLabel returns a refusal kind's label and badge class. An unknown or unrecorded
// kind is said as such rather than guessed at.
func kindLabel(kind string) (string, string) {
	if k, ok := denyKinds[kind]; ok {
		return k.Label, k.Class
	}
	if kind == "" {
		return "Reason not recorded", ""
	}
	return kind, ""
}

type overviewPending struct {
	Package    string
	Ecosystem  string
	Label      string // the refusal kind, when the audit log knows it
	Class      string
	Detail     string // the gate's own note on why it queued the package
	Waiting    string
	OverTarget bool
	Href       template.URL
}

type overviewBlock struct {
	Package   string
	Ecosystem string
	At        time.Time
	When      string
	Label     string
	Class     string
	Served    bool
	Href      template.URL
}

type overviewFact struct{ Label, Value, Title string }

type overviewView struct {
	Nav navView

	// Waiting on you.
	Waiting    int
	OldestWait string
	OverTarget bool
	QueueErr   bool
	Pending    []overviewPending

	// The last 24 hours. SummaryErr blanks the two tiles rather than showing zeros: a
	// zero is a quiet day, and an unreachable tally is not one.
	SummaryErr bool
	Stopped    int
	StoppedBy  string
	Served     int
	Allowed    int
	Sources    int

	// The known-malware feed as the gates report it.
	FeedValue string
	FeedSub   string
	FeedLevel string // "ok" | "warn"

	Recent    []overviewBlock
	RecentErr bool

	System []overviewFact
}

func (s *server) handleOverview(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	var (
		wg        sync.WaitGroup
		decisions []decision
		decErr    error
		sum       eventSummary
		sumErr    error
		blocks    []event
		blockErr  error
		health    []instanceHealth
		healthErr error
	)
	wg.Add(4)
	go func() { defer wg.Done(); decisions, decErr = s.approval.List() }()
	go func() { defer wg.Done(); sum, sumErr = s.approval.SummarizeEvents(now.Add(-overviewWindow)) }()
	go func() {
		defer wg.Done()
		blocks, blockErr = s.approval.ListEvents(eventFilter{Action: "block", Limit: overviewRecentBlocks})
	}()
	go func() { defer wg.Done(); health, healthErr = s.approval.ListInstanceHealth() }()
	wg.Wait()

	v := overviewView{Nav: s.navFor(r, "overview")}

	if decErr != nil {
		log.Printf("overview: list decisions: %v", decErr)
		v.QueueErr = true
	} else {
		v.fillWaiting(decisions, now, s.latestEvents())
	}

	if sumErr != nil {
		log.Printf("overview: summarize events: %v", sumErr)
		v.SummaryErr = true
	} else {
		v.Stopped, v.Served, v.Allowed, v.Sources = sum.Blocked, sum.BlockedServed, sum.Allowed, sum.Sources
		v.StoppedBy = breakdown(sum.ByDenyKind)
	}

	if blockErr != nil {
		log.Printf("overview: recent blocks: %v", blockErr)
		v.RecentErr = true
	}
	for _, e := range blocks {
		label, class := kindLabel(e.DenyKind)
		v.Recent = append(v.Recent, overviewBlock{
			Package: e.Package, Ecosystem: ecosystemLabel(e.Ecosystem), At: e.At,
			When: whenLabel(e.At, now), Label: label, Class: class,
			Served: e.Taken == "allow",
			Href:   stoppedHref(e),
		})
	}

	if healthErr != nil {
		log.Printf("overview: instance health: %v", healthErr)
	}
	v.fillFleet(health, s)

	if err := overviewTmpl.Execute(w, v); err != nil {
		log.Printf("overview: render: %v", err)
	}
}

// latestEvents indexes the newest audit event per package, from one bounded read. The
// Overview uses it only to LABEL waiting packages; a package whose last event is older
// than the read keeps its label-free row and the gate's own note, which is still true.
func (s *server) latestEvents() map[string]event {
	evs, err := s.approval.ListEvents(eventFilter{Limit: 1000})
	if err != nil {
		log.Printf("latest events: %v", err)
		return nil
	}
	out := make(map[string]event, len(evs))
	for _, e := range evs { // newest first, so the first seen per package wins
		if _, ok := out[e.Package]; !ok {
			out[e.Package] = e
		}
	}
	return out
}

func (v *overviewView) fillWaiting(ds []decision, now time.Time, latest map[string]event) {
	q := groupByVerdict(ds, now)
	pending := q.pendingItems()
	v.Waiting = len(pending)
	if len(pending) > 0 && pending[0].Waiting != "" {
		v.OldestWait, v.OverTarget = pending[0].Waiting, pending[0].OverTarget
	}
	for i, row := range pending {
		if i == overviewWaitingShown {
			break
		}
		p := overviewPending{
			Package: row.Package, Detail: row.Note, Waiting: row.Waiting, OverTarget: row.OverTarget,
			Href: template.URL("/decisions?pkg=" + url.QueryEscape(row.Package)),
		}
		if e, ok := latest[row.Package]; ok {
			p.Ecosystem = ecosystemLabel(e.Ecosystem)
			if e.DenyKind != "" {
				p.Label, p.Class = kindLabel(e.DenyKind)
			}
		}
		v.Pending = append(v.Pending, p)
	}
}

// breakdown renders the refusal split the way the canvas does and the Stopped page's tabs
// do: "9 known malware · 2 on your block list · 5 by policy". Three groups, because those
// are the three different people a refusal sends you to -- the advisory's publisher, your
// own list's owner, and whoever set the policy. Every kind lands in exactly one group, so
// the parts always add up to the tile.
func breakdown(by map[string]int) string {
	n := map[string]int{}
	for k, c := range by {
		n[stoppedGroupOf(k)] += c
	}
	var out []string
	for _, g := range []struct{ key, label string }{
		{"known-malware", "known malware"}, {"operator", "on your block list"}, {"policy", "by policy"},
	} {
		if n[g.key] > 0 {
			out = append(out, fmt.Sprintf("%d %s", n[g.key], g.label))
		}
	}
	return strings.Join(out, " · ")
}

// whenLabel is a refusal's time the way the canvas writes it: "Today, 14:02",
// "Yesterday, 09:15", or the date. UTC, and the page says so once rather than per row.
func whenLabel(t, now time.Time) string {
	t, now = t.UTC(), now.UTC()
	day := func(x time.Time) string { return x.Format("2006-01-02") }
	switch day(t) {
	case day(now):
		return "Today, " + t.Format("15:04")
	case day(now.AddDate(0, 0, -1)):
		return "Yesterday, " + t.Format("15:04")
	}
	return t.Format("2 Jan, 15:04")
}

// feedCount pulls the advisory count out of the gate's known_malware_feed value
// ("4 enforced (2 package-wide, 2 version-pinned), sha256:..."). The value is the gate's display
// string, so a format this does not recognise is shown whole rather than guessed at.
var feedCount = regexp.MustCompile(`^(\d+) enforced`)

func (v *overviewView) fillFleet(rows []instanceHealth, s *server) {
	now := time.Now().UTC()
	// PER ECOSYSTEM. Each gate fronts one ecosystem, and an npm gate and an OCI gate are
	// SUPPOSED to run different policies -- different feeds, lists, thresholds. Comparing
	// them as one fleet called every multi-ecosystem deployment "Differs", which is what
	// the first run of the demo stack (npm + OCI) showed. Disagreement is only a finding
	// between gates of the SAME ecosystem.
	type ecoState struct {
		feeds, digests map[string]bool
		allow, deny    string
	}
	ecos := map[string]*ecoState{}
	sorted := append([]instanceHealth(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Instance < sorted[j].Instance })
	fresh := 0
	for _, h := range sorted {
		if h.Policy == nil || now.Sub(h.ReportedAt) > staleAfter {
			continue
		}
		fresh++
		e := ecos[h.Ecosystem]
		if e == nil {
			e = &ecoState{feeds: map[string]bool{}, digests: map[string]bool{}}
			ecos[h.Ecosystem] = e
		}
		e.feeds[h.Policy.Values["known_malware_feed"]] = true
		d := h.PolicyDigest
		if d == "" {
			d = h.Policy.Digest
		}
		e.digests[d] = true
		e.allow, e.deny = h.Policy.Values["operator_allow_list"], h.Policy.Values["operator_deny_list"]
	}
	names := make([]string, 0, len(ecos))
	for k := range ecos {
		names = append(names, k)
	}
	sort.Strings(names)
	single := len(names) == 1

	var differs, on, off []string
	count := ""
	for _, k := range names {
		e := ecos[k]
		if len(e.feeds) > 1 {
			differs = append(differs, ecosystemLabel(k))
			continue
		}
		for f := range e.feeds {
			switch m := feedCount.FindStringSubmatch(f); {
			case m != nil:
				n, _ := strconv.Atoi(m[1])
				count = humanCount(int64(n))
				on = append(on, ecosystemLabel(k))
			case f == "" || f == "off":
				off = append(off, ecosystemLabel(k))
			default:
				on = append(on, ecosystemLabel(k))
			}
		}
	}
	switch {
	case fresh == 0:
		v.FeedValue, v.FeedSub, v.FeedLevel = "Unknown", "No gate is reporting its policy.", "warn"
	case len(differs) > 0:
		v.FeedValue, v.FeedLevel = "Differs", "warn"
		v.FeedSub = "Gates for " + strings.Join(differs, ", ") + " report different known-malware lists."
	case len(on) == 0:
		v.FeedValue, v.FeedSub, v.FeedLevel = "Off", "No known-malware list is loaded.", "warn"
	default:
		v.FeedLevel, v.FeedValue = "ok", count
		if count == "" {
			v.FeedValue = "Loaded"
		}
		v.FeedSub = "Advisories, checked on the gate itself."
		if !single {
			v.FeedSub = "Enforced on " + strings.Join(on, ", ")
			if len(off) > 0 {
				v.FeedSub += "; off on " + strings.Join(off, ", ")
			}
			v.FeedSub += "."
		}
	}

	policy := "No gate reporting"
	if fresh > 0 {
		var diverging []string
		var only string
		for _, k := range names {
			if len(ecos[k].digests) > 1 {
				diverging = append(diverging, ecosystemLabel(k))
			}
			for d := range ecos[k].digests {
				only = d
			}
		}
		switch {
		case len(diverging) > 0:
			policy = "Differs among " + strings.Join(diverging, ", ") + " gates"
		case single && fresh == 1:
			policy = "1 gate · " + shortDigest(only)
		case single:
			policy = fmt.Sprintf("All %d gates agree · %s", fresh, shortDigest(only))
		default:
			policy = fmt.Sprintf("%d gates · each ecosystem consistent", fresh)
		}
	}
	lists := func(pick func(*ecoState) string) string {
		var parts []string
		for _, k := range names {
			if n, ok := entriesOf(pick(ecos[k])); ok {
				if single {
					return entryCount(n)
				}
				parts = append(parts, ecosystemLabel(k)+" "+entryCount(n))
			}
		}
		if len(parts) == 0 {
			return "Not configured"
		}
		return strings.Join(parts, " · ")
	}
	source := "Read-only here (no list repository configured)"
	if s.lists != nil {
		source = s.lists.Describe()
	}
	v.System = []overviewFact{
		{Label: "Enforced policy", Value: policy},
		{Label: "Your allow list", Value: lists(func(e *ecoState) string { return e.allow })},
		{Label: "Your block list", Value: lists(func(e *ecoState) string { return e.deny })},
		{Label: "Lists are written to", Value: source, Title: source},
	}
}

func shortDigest(d string) string {
	if len(d) > 7 {
		return d[:7]
	}
	return d
}

// entryCount says a gate's "1 entries" the way a person would.
func entryCount(n string) string {
	if n == "1 entries" {
		return "1 entry"
	}
	return n
}
