package main

import (
	_ "embed"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The policy view (#32 Phase D / D4b): what each firewall replica reports it is ENFORCING.
//
// This page is READ-ONLY, and that is the increment, not a limitation. Storing and editing
// policy is D1/D5, which are blocked on an open design question (does an operator author ordered rules,
// or set values that produce them?) — see docs/POLICY_DISTRIBUTION.md §10. Rendering works
// under either answer, and is also how we find out whether rule names read well enough to
// be shown to an operator before anyone is asked to author them.
//
// The data comes from the CONTROL PLANE (GET /v1/health), not from asking a firewall. The
// firewall's own listener is the developer-facing one, so an introspection endpoint there
// would publish the gate's posture — the threshold, which categories are only watched, and
// whether the byte gate is enforcing — to the population most motivated to route around it.
// See docs/POLICY_DISTRIBUTION.md §6.1.

//go:embed templates/policy.html
var policyHTML string

var policyTmpl = pageTemplate("policy", policyHTML, template.FuncMap{"ecosystem": ecosystemLabel})

// staleAfter is how long a replica may go without a heartbeat before this page stops
// treating its report as current.
//
// DISPLAY ONLY. The authoritative staleness judgement is the approval service's alert
// (SilentAfter, C4b), and this is deliberately the same order of magnitude so the page and
// the alert do not tell an operator different stories about the same replica. It is not
// imported, because the console must not depend on the alerting package to render a page —
// and a console that silently changed its display when an alert threshold was tuned would
// be worse than one that is slightly out of step.
const staleAfter = 15 * time.Minute

// policyGroup is one DISTINCT policy and every replica reporting it.
//
// Grouping by digest is the whole point of the page. A single replica's policy is not very
// interesting — the operator configured it. What they cannot see any other way is whether
// their FLEET AGREES, and a rolling deploy, a failed restart, or a half-applied config
// change all show up here as two groups where there should be one.
type policyGroup struct {
	Digest   string
	Policy   *policyDoc
	Replicas []replicaLine
}

// replicaLine is one firewall as it appears under its policy group.
type replicaLine struct {
	Instance  string
	Ecosystem string
	LastSeen  time.Time
	Age       string
	Stale     bool
}

type policyPageView struct {
	Groups []policyGroup
	// Silent are replicas that have reported a heartbeat but NO policy. They are listed
	// separately rather than dropped: a replica that reports liveness without a policy is
	// running a build from before this feature, which is something an operator needs to
	// see rather than have quietly omitted from a page titled "what is being enforced".
	Silent []replicaLine
	// Diverged is true when FRESH replicas of the SAME ecosystem report different policies.
	// Gates of different ecosystems are meant to differ, so they are never compared.
	Diverged   bool
	DivergedIn string // the ecosystem whose gates disagree
	// FreshGroups counts the distinct policies among non-stale replicas — the number
	// Diverged is derived from, shown so the banner can be specific.
	FreshGroups int
	Total       int
	StaleAfter  string
	Err         string
	Nav         navView

	// Plain is the leading policy said in words (policyplain.go); the engine's own
	// chains stay below it for anyone who needs them.
	Plain plainPolicy
	// Where the lists are authored, and the newest change to each, when this console
	// edits them. Empty on a console with no list repository.
	ListSource  string
	ListChanges []listChange

	// The rules are one ecosystem's, chosen by tab when the deployment gates several.
	Eco     string
	EcoTabs []ecoTab
}

// ecoTab is one ecosystem's tab over the rules.
type ecoTab struct {
	Label  string
	Href   template.URL
	Active bool
}

// listChange is the newest commit to one list, for "where policy comes from".
type listChange struct {
	Kind string
	commitLine
}

// handlePolicy renders the enforced-policy view.
func (s *server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	rows, err := s.approval.ListInstanceHealth()
	if err != nil {
		// Rendered as a page-level error rather than a bare 502: the operator reaching
		// this page during an incident is better served by a page that says the control
		// plane is unreachable than by a browser error, and the nav stays available.
		log.Printf("policy: list instance health: %v", err)
		renderPolicy(w, policyPageView{Nav: s.navFor(r, "policy"), Err: "The control plane could not be reached, so the enforced policy is unknown. This does not mean the firewalls have stopped gating traffic — they keep enforcing whatever they last loaded."})
		return
	}
	v := buildPolicyView(rows, time.Now().UTC())
	v.Nav = s.navFor(r, "policy")
	v.choosePlain(strings.TrimSpace(r.URL.Query().Get("eco")))
	if s.lists != nil {
		v.ListSource = s.lists.Describe()
		for _, kind := range []string{listAllow, listDeny} {
			if h, err := s.lists.History(kind, 1); err == nil && len(h) > 0 {
				v.ListChanges = append(v.ListChanges, listChange{Kind: kind, commitLine: h[0]})
			}
		}
	}
	renderPolicy(w, v)
}

func renderPolicy(w http.ResponseWriter, v policyPageView) {
	v.StaleAfter = staleAfter.String()
	if err := policyTmpl.Execute(w, v); err != nil {
		log.Printf("policy: render: %v", err)
	}
}

// choosePlain picks the policy the plain-language rules describe: the chosen ecosystem's
// (?eco=), else npm's, else the first. Each ecosystem gets a tab when there is more than
// one, because one list of rules for an npm gate and an OCI gate would describe neither.
func (v *policyPageView) choosePlain(want string) {
	byEco := map[string]*policyDoc{}
	var ecos []string
	for _, g := range v.Groups {
		for _, r := range g.Replicas {
			if _, seen := byEco[r.Ecosystem]; !seen {
				byEco[r.Ecosystem] = g.Policy
				ecos = append(ecos, r.Ecosystem)
			}
		}
	}
	if len(ecos) == 0 {
		return
	}
	sort.Strings(ecos)
	eco := ecos[0]
	if _, ok := byEco["npm"]; ok {
		eco = "npm"
	}
	if _, ok := byEco[want]; ok {
		eco = want
	}
	v.Eco = eco
	v.Plain = buildPlainPolicy(byEco[eco])
	if len(ecos) > 1 {
		for _, e := range ecos {
			v.EcoTabs = append(v.EcoTabs, ecoTab{Label: ecosystemLabel(e),
				Href: template.URL("/policy?eco=" + url.QueryEscape(e)), Active: e == eco})
		}
	}
}

// buildPolicyView groups replicas by the policy they report.
//
// Divergence is computed over FRESH replicas only, and that asymmetry is deliberate. A
// replica that died three weeks ago still has a row in instance_health carrying whatever
// policy it last ran; counting it would leave the divergence banner lit forever, and a
// warning that can never be cleared is one an operator learns to ignore — the same reasoning
// that made the transfer-failure alert use a bounded window (approval/alerts.go). The dead
// replica is still LISTED, marked stale, because hiding it would be the opposite mistake.
func buildPolicyView(rows []instanceHealth, now time.Time) policyPageView {
	view := policyPageView{Total: len(rows)}

	byDigest := map[string]*policyGroup{}
	freshDigests := map[string]map[string]bool{} // ecosystem -> digests

	for _, h := range rows {
		line := replicaLine{
			Instance:  h.Instance,
			Ecosystem: h.Ecosystem,
			LastSeen:  h.ReportedAt,
			Age:       humanAge(now.Sub(h.ReportedAt)),
			Stale:     now.Sub(h.ReportedAt) > staleAfter,
		}
		if h.Policy == nil {
			view.Silent = append(view.Silent, line)
			continue
		}

		// Key on the digest the REPLICA computed, not on one recomputed here. The console
		// does not model the policy well enough to recompute it, and a second
		// implementation of "what makes two policies the same" would be a source of
		// phantom divergence.
		key := h.PolicyDigest
		if key == "" {
			key = h.Policy.Digest
		}
		g, ok := byDigest[key]
		if !ok {
			g = &policyGroup{Digest: key, Policy: h.Policy}
			byDigest[key] = g
		}
		g.Replicas = append(g.Replicas, line)
		if !line.Stale {
			if freshDigests[h.Ecosystem] == nil {
				freshDigests[h.Ecosystem] = map[string]bool{}
			}
			freshDigests[h.Ecosystem][key] = true
		}
	}

	for _, g := range byDigest {
		sort.Slice(g.Replicas, func(i, j int) bool { return g.Replicas[i].Instance < g.Replicas[j].Instance })
		view.Groups = append(view.Groups, *g)
	}
	// Largest group first, so the policy most of the fleet is running leads; digest as a
	// stable tiebreak so the page does not reshuffle between refreshes.
	sort.Slice(view.Groups, func(i, j int) bool {
		if len(view.Groups[i].Replicas) != len(view.Groups[j].Replicas) {
			return len(view.Groups[i].Replicas) > len(view.Groups[j].Replicas)
		}
		return view.Groups[i].Digest < view.Groups[j].Digest
	})
	sort.Slice(view.Silent, func(i, j int) bool { return view.Silent[i].Instance < view.Silent[j].Instance })

	// Divergence is a finding only among gates of one ecosystem: an npm gate and an OCI
	// gate run different policies by design. FreshGroups is the widest disagreement.
	ecos := make([]string, 0, len(freshDigests))
	for e := range freshDigests {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	for _, e := range ecos {
		if n := len(freshDigests[e]); n > view.FreshGroups {
			view.FreshGroups = n
			if n > 1 {
				view.DivergedIn = ecosystemLabel(e)
			}
		}
	}
	view.Diverged = view.FreshGroups > 1
	return view
}

// humanAge renders a heartbeat age the way an operator reads it.
//
// A NEGATIVE age reads as "just now" rather than as a nonsense future timestamp: the
// heartbeat's reported_at is stamped by the approval service's clock and rendered against
// this console's, and those are different processes. A second of skew must not produce
// "-1s ago", which looks like a bug in the data an operator is trying to trust.
func humanAge(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	return humanWait(d) + " ago"
}

// plural is "1 hour" / "5 hours".
func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

// humanWait renders a duration as a LENGTH rather than as a point in the past — "3
// days", not "3 days ago". The queue needs the former ("waiting 3 days") and the
// heartbeat the latter, and they share this bucketing deliberately: two independent
// duration renderers drift, and the operator ends up comparing a "2h" on one page
// against a "119m" on another and cannot tell whether they mean the same thing.
func humanWait(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		// Said in words, not as a Go duration: "45 minutes", never "45m0s".
		if n := int(d.Round(time.Minute).Minutes()); n < 60 {
			return plural(n, "minute")
		}
		return "1 hour"
	case d < 24*time.Hour:
		if n := int(d.Round(time.Hour).Hours()); n < 24 {
			return plural(n, "hour")
		}
		return "1 day"
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day"
		}
		return strconv.Itoa(days) + " days"
	}
}
