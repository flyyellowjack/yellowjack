package main

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// queueHTML is the single page this increment serves. Embedding it keeps the
// console a self-contained static binary (no template files to deploy beside it),
// matching the rest of the stack.
//
//go:embed templates/queue.html
var queueHTML string

// queueTmpl is parsed once at startup. html/template escapes every interpolated
// value for its HTML context, so untrusted strings (package names, human notes)
// cannot inject markup or script — important because this data originates from
// package metadata we do not control.
var queueTmpl = pageTemplate("queue", queueHTML, nil)

// auditHTML is the read-only audit view: the firewall's allow/block history. Same
// embedding and auto-escaping guarantees as the queue page.
//
//go:embed templates/audit.html
var auditHTML string
var auditTmpl = pageTemplate("audit", auditHTML, nil)

// downloadsHTML is the downloads-by-source-IP view (#41): "who pulled this package,
// how often". Same embedding and auto-escaping guarantees as the other pages.
//
//go:embed templates/downloads.html
var downloadsHTML string
var downloadsTmpl = pageTemplate("downloads", downloadsHTML, nil)

// activityHTML is the per-package activity view (#32 Phase C, D81 Q3): what the
// firewall has seen and what has gone quiet. Same embedding and auto-escaping
// guarantees as the other pages.
//
//go:embed templates/activity.html
var activityHTML string
var activityTmpl = pageTemplate("activity", activityHTML, nil)

// server holds the console's dependencies. It depends on the approvalClient
// interface, not the concrete HTTP client, so handlers are unit-testable with a
// fake. `auth` is nil when no credential is configured — which means read-only
// mode (the override endpoint is disabled). Mirrors the approval service's own
// `server` shape.
type server struct {
	approval approvalClient
	auth     *basicAuth // nil => no basic credential configured
	// oidc is per-user SSO (#148, D19's "eventual target", dated by D280). When
	// set it REPLACES basic auth as the identity source, and `decidedBy` on an
	// override becomes the actual person rather than a shared label -- which is
	// the first time this console can attribute a decision to a human at all (#41).
	oidc *oidcAuth

	// lists is where operator allow/deny-list edits are written (#58 increment 3b,
	// D193). nil => list editing is not configured and /lists renders read-only.
	//
	// It is an interface, and deliberately NOT the approval client: these lists are
	// not approval state. They are policy the FIREWALL reads from a file, so the
	// console authors them into git rather than into the control plane's database --
	// which is what keeps the enforcement plane free of the durable state D103
	// forbids it. See gitstore.go.
	lists listStore

	// gitMissing records that this IMAGE has no git binary. It is separate from
	// lists==nil because the two states need OPPOSITE advice: without git, setting
	// CONSOLE_LIST_REPO cannot help, and telling an operator to set it sends them
	// down a dead end. See errNoGitBinary.
	gitMissing bool

	// listEcosystem is the ecosystem the deployment gates, used to validate entries
	// and to compare authored names against the normalised ones replicas report.
	listEcosystem string
}

// writesEnabled reports whether override (write) actions are available. They are
// gated on a configured credential so we never expose an unauthenticated
// state-mutating endpoint, even on the loopback default (D19).
// writesEnabled reports whether overrides are available: they are, exactly when
// SOMEBODY is authenticated. Either identity source counts -- what makes an
// override safe is that it is attributable, not which mechanism produced the name.
func (s *server) writesEnabled() bool { return s.auth != nil || s.oidc != nil }

// scoringOff reports whether the fleet has scoring DISABLED (FW_SCORECARD_MODE=off),
// which is what lets /lookup and /audit drop their scoring surfaces (#151, D273 s5).
//
// The rule is deliberately conservative in both directions:
//
//   - TRUE only when at least one replica reports a policy AND every replica that
//     reports one says "off". A single scoring replica means the columns stay.
//   - ABSENT IS NOT OFF. A gate that predates the scorecard_mode key (a rolling
//     deploy) reports nothing, and hiding scores on missing information would blank
//     the page the day one replica lagged a release -- the same trap #133's coverage
//     fields avoided. Unknown means show.
//
// Any failure to reach the control plane also means show: the page is then honest
// about scores it cannot explain rather than silently pretending scoring is off.
func (s *server) scoringOff() bool {
	rows, err := s.approval.ListInstanceHealth()
	if err != nil {
		return false
	}
	reported := 0
	for _, h := range rows {
		if h.Policy == nil {
			continue
		}
		mode, ok := h.Policy.Values["scorecard_mode"]
		if !ok {
			continue
		}
		reported++
		if mode != "off" {
			return false
		}
	}
	return reported > 0
}

// currentUser is the authenticated identity for this request, or "". It is the one
// place the two mechanisms are reconciled, so no handler has to know which is in
// use, and a third could be added without touching any of them.
//
// OIDC wins when both are configured: an operator who has wired up SSO has said
// who their people are, and silently preferring a shared credential over that
// would put a generic name in the audit trail instead of a person's.
func (s *server) currentUser(r *http.Request) string {
	if s.oidc != nil {
		return s.oidc.check(r)
	}
	if s.auth != nil && s.auth.check(r) {
		return s.auth.user
	}
	return ""
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Liveness is always open (no auth): orchestrators probe it before the operator
	// has a credential in hand, and it reveals nothing.
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok\n")
		return
	}

	// The sign-in endpoints are the only other unauthenticated routes, and the set
	// is explicit rather than a "/auth/" prefix -- a prefix would open anything
	// anyone later hung underneath it.
	if s.oidc != nil && oidcOwnsPath(r.URL.Path) {
		switch r.URL.Path {
		case oidcLoginPath:
			s.oidc.startLogin(w, r)
		case oidcCallbackPath:
			s.oidc.completeLogin(w, r)
		case oidcLogoutPath:
			s.oidc.logout(w, r)
		}
		return
	}

	// When an identity source is configured, every other route requires it. The
	// console shows what is under review and (with writes on) can change verdicts,
	// so we protect the read view too, not just the override endpoint.
	if s.auth != nil || s.oidc != nil {
		if s.currentUser(r) == "" {
			if s.oidc != nil {
				// A browser gets sent to the IdP rather than a 401: the whole point of SSO
				// is that the operator never sees a credential prompt from us. `next`
				// brings them back to the page they asked for, reduced to a same-site
				// path by safeReturn so this cannot become an open redirect.
				http.Redirect(w, r, oidcLoginPath+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
				return
			}
			challenge(w)
			return
		}
	}

	switch r.URL.Path {
	case "/":
		s.handleOverview(w, r)
	case "/decisions":
		s.handleQueue(w, r)
	case "/stopped":
		s.handleStopped(w, r)
	case "/stopped/view":
		s.handleStoppedView(w, r)
	case "/audit":
		s.handleAudit(w, r)
	case "/audit/export":
		s.handleAuditExport(w, r)
	case "/downloads":
		s.handleDownloads(w, r)
	case "/activity":
		s.handleActivity(w, r)
	case "/lookup":
		s.handleLookup(w, r)
	case "/policy":
		s.handlePolicy(w, r)
	case "/lists":
		s.handleLists(w, r)
	case "/capacity":
		s.handleCapacity(w, r)
	case "/override":
		s.handleOverride(w, r)
	case "/false-positives":
		s.handleFalsePositives(w, r)
	case "/report-false-positive":
		s.handleReportFalsePositive(w, r)
	default:
		http.NotFound(w, r)
	}
}

// queueView is the shape handed to the template. Grouping by verdict happens here
// in Go so the template stays a dumb renderer. Rendering .Groups as one ordered
// list (rather than three named fields) lets each row reach the write-context via
// the template root ($.CanWrite / $.AuthUser) without threading it through a
// nested template.
type queueView struct {
	Groups   []groupView
	Total    int
	CanWrite bool        // render override forms only when writes are enabled
	AuthUser string      // who is acting — recorded as decidedBy on overrides
	Filter   queueFilter // echoed back so the form stays populated and the count reads honestly

	// Notice is a one-shot message carried through an override's POST-redirect-GET
	// (?notice=...&level=...), the mechanism /lists already uses. It exists because a
	// deny is not always what it looks like: the gate consults a human ruling only on
	// its refuse path -- which is what #132 reported and D272 reversed. Since D272 a
	// deny reaches every path, so the notice now states the reach that REMAINS
	// conditional: the ruling lives in the approval service, and a gate that cannot
	// reach it falls back to policy. The write says what it reaches at the moment it
	// happens, rather than leaving a `denied` badge to be believed.
	Notice      string
	NoticeLevel string // "ok" | "warn" | "err"

	// Decider is who is expected to act — the third thing #50 requires the queue to
	// expose. There is no assignment model yet (RBAC is #91), so the honest answer is
	// "whoever holds the console credential", and an EMPTY Decider is a finding in
	// itself: an unauthenticated console has no accountable decider at all. The
	// template says so in words rather than leaving the field blank.
	Decider string

	Nav    navView
	Tabs   []queueTab
	Detail *decisionDetail // the selected waiting package; nil when nothing waits
}

// queueFilter is the search an operator submitted via the queue form: a package
// substring and/or a verdict bucket. It exists because the unscorable problem is
// common, not rare — a real pending queue gets long, and "work the queue" first
// means finding the package you care about.
type queueFilter struct {
	Package string
	Verdict string // "pending" | "approved" | "denied" | "" (any)
}

// Active reports whether any filter field is set (exported for html/template).
func (f queueFilter) Active() bool { return f.Package != "" || f.Verdict != "" }

// filterDecisions narrows the decision list before it is grouped. Package is a
// case-insensitive substring; Verdict is exact.
//
// This filtering is done here in the console, over the WHOLE decision list — which
// is correct ONLY because the approval service's GET /v1/decisions returns every
// decision, with no limit/window. That is the opposite of the audit log (A1), where
// GET /v1/events is windowed and so filtering HAD to move into the store or a match
// older than the window would silently vanish. If /v1/decisions ever grows a limit,
// this must move server-side for the same reason — do not "align" the two blindly.
func filterDecisions(ds []decision, f queueFilter) []decision {
	if !f.Active() {
		return ds
	}
	out := make([]decision, 0, len(ds))
	for _, d := range ds {
		if f.Package != "" && !strings.Contains(strings.ToLower(d.Package), strings.ToLower(f.Package)) {
			continue
		}
		if f.Verdict != "" && d.Verdict != f.Verdict {
			continue
		}
		out = append(out, d)
	}
	return out
}

// groupView is one verdict bucket in display order.
type groupView struct {
	Verdict string // "pending" / "approved" / "denied" — also the badge CSS class
	Label   string // human heading, e.g. "Awaiting review"
	Items   []queueRow
}

// queueRow is one decision plus the things #50 requires the operator to be able to
// SEE — how long it has been waiting, and whether that wait has passed the target.
//
// The decision is embedded, so the template still reads .Package, .Note and the rest
// straight through; only the derived fields are new.
type queueRow struct {
	decision

	// Waiting is the age as a length ("3 days"), rendered for pending rows only.
	// An approved or denied row is not waiting for anything, and showing a growing
	// number beside a settled entry invites it to be read as a backlog.
	Waiting string

	// OverTarget marks a pending row that has waited longer than queueTargetWait.
	// It is the difference between a queue an operator can glance at and a list
	// they have to arithmetic their way through, which is how backlogs go unnoticed.
	OverTarget bool

	// Impossible marks an enqueue time so far in the future it cannot be clock skew.
	// The row renders as unmeasurable rather than as newly arrived — see
	// clockSkewTolerance for why that distinction is the whole point of the column.
	Impossible bool

	// WaitEnded is how long an already-decided package sat before someone acted. It
	// is the accountability half of #50 — "no timeline, no visibility, and no
	// accountability" — and it is only answerable because FirstSeen survives the
	// ruling that ends the wait.
	WaitEnded string

	// The Decisions page's list: the row's selection link, and what the audit log says
	// about it (see labelRows). Empty when the log has nothing on the package.
	Href      template.URL
	Selected  bool
	Ecosystem string
	KindLabel string
	KindClass string
}

// queueTargetWait is the bound #50 sets: "the target is a queue measured in HOURS,
// against the 3 months this operator reported". 24h is the first honest boundary
// past "hours" — a row that crosses it has left the regime the issue asks us to
// stay inside, and is flagged rather than left for someone to notice.
//
// It is not configurable yet on purpose. A knob here would let a deployment silence
// the warning by widening the target, which converts the one visible symptom of an
// unbounded queue into a setting (#51 also counts every new knob against us).
const queueTargetWait = 24 * time.Hour

// clockSkewTolerance is how far in the FUTURE an enqueue time may sit before we stop
// believing it.
//
// The console and the approval service are separate processes with separate clocks, so a
// FirstSeen a few seconds ahead of now is ordinary skew and is simply clamped to zero.
// Beyond this, it is not skew — it is corrupt or hostile data, and it must NOT be clamped.
//
// Found by attacking the feature rather than testing it (tier 3): the age is computed as
// now - FirstSeen, so a timestamp in the future goes negative, clamps to zero, and renders
// "under a minute". Crucially it renders that FOREVER, because the value never ages. A
// package parked with a far-future FirstSeen sits in the queue permanently while
// displaying as the newest arrival — which is the single most useful lie this page could
// be told, since the whole feature exists so a growing backlog cannot hide. PUT
// /v1/decisions decodes firstSeen straight from its body, so the timestamp is chosen by
// whoever can reach that endpoint, not derived by us.
const clockSkewTolerance = 5 * time.Minute

func (s *server) handleQueue(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := queueFilter{
		Package: strings.TrimSpace(q.Get("package")),
		Verdict: strings.TrimSpace(q.Get("verdict")),
	}
	// A present verdict filter must be a known bucket. Silently ignoring a typo would
	// return an unfiltered queue that looks filtered — the same trap as the audit
	// view's action guard.
	if v := filter.Verdict; v != "" && v != "pending" && v != "approved" && v != "denied" {
		http.Error(w, "verdict filter must be pending, approved, or denied", http.StatusBadRequest)
		return
	}

	decisions, err := s.approval.List()
	if err != nil {
		// The approval service is the source of truth; if we can't reach it, say so
		// plainly rather than showing an empty or stale queue. 502 = we are a healthy
		// gateway but our upstream failed.
		log.Printf("queue: list decisions: %v", err)
		http.Error(w, "Cannot reach the approval service. Is it running and is CONSOLE_APPROVAL_URL correct?", http.StatusBadGateway)
		return
	}

	now := time.Now().UTC()
	view := groupByVerdict(filterDecisions(decisions, filter), now)
	view.Filter = filter
	view.Tabs = queueTabs(decisions, filter)

	// The selected package is ?pkg= when it is waiting, else the one waiting longest --
	// the one the queue's own order says to look at first.
	if pending := view.pendingItems(); len(pending) > 0 {
		sel := pending[0]
		if want := strings.TrimSpace(q.Get("pkg")); want != "" {
			for _, row := range pending {
				if row.Package == want {
					sel = row
				}
			}
		}
		labelRows(&view, s.latestEvents(), sel.Package)
		view.Detail = s.buildDetail(sel, now)
	}
	if n := strings.TrimSpace(q.Get("notice")); n != "" {
		view.Notice = n
		view.NoticeLevel = noticeLevel(q.Get("level"))
	}
	view.CanWrite = s.writesEnabled()
	if u := s.currentUser(r); u != "" {
		view.AuthUser = u
		view.Decider = u
	}
	view.Nav = s.navFor(r, "decisions")
	if err := queueTmpl.Execute(w, view); err != nil {
		// A template execution error after headers may already be partially written;
		// there's little to do but log it.
		log.Printf("queue: render: %v", err)
	}
}

// auditViewLimit bounds how many recent events the audit page requests. A page is
// a reviewer's recent-history view, not an export, so a fixed window keeps the
// request cheap and the page fast; the approval service caps it again server-side.
const auditViewLimit = 200

// auditView is the shape handed to the audit template.
type auditView struct {
	Events   []eventRow
	Total    int
	AuthUser string      // shown in the header when auth is configured
	Filter   auditFilter // echoed back so the form stays populated and the count reads honestly
	// ScoringOff drops the Score/Threshold columns when the whole fleet runs with no
	// scanner (#151): a column of dashes on every row reads as "something failed to
	// run", and D273 ruled that an absent scanner is a configuration, not a gap.
	ScoringOff bool
	// CanReport shows the false-positive form on block rows (#142). It is the
	// writes-enabled predicate: a report must be attributable to a person.
	CanReport bool

	Nav navView
}

// auditFilter is the incident-response query the operator submitted via the /audit
// form. Echoed into the view so the inputs stay filled after a search and the header
// can say "matching" rather than "recent" when a filter is active.
type auditFilter struct {
	Ecosystem string
	Action    string
	Package   string
}

// Active reports whether any filter field is set — used by the template to switch
// the count wording and show a "clear" link. Exported because html/template can only
// call exported methods.
func (f auditFilter) Active() bool {
	return f.Ecosystem != "" || f.Action != "" || f.Package != ""
}

// queryString renders the filter as a URL query (no leading "?"). url.Values.Encode
// escapes every value, so the operator's search text is safe.
func (f auditFilter) queryString() string {
	q := url.Values{}
	if f.Package != "" {
		q.Set("package", f.Package)
	}
	if f.Ecosystem != "" {
		q.Set("ecosystem", f.Ecosystem)
	}
	if f.Action != "" {
		q.Set("action", f.Action)
	}
	return q.Encode()
}

// ExportHref is the full "/audit/export?…" link, carrying whatever the operator is
// currently viewing — so you export exactly the scoped set you see. It returns
// template.URL (not a plain string) because we build the query ourselves with
// url.Values.Encode; without that marker html/template treats the href as a URL
// context and percent-escapes our "&"/"=", corrupting the query. The value is
// trusted precisely because Encode already escaped every operator-supplied part.
func (f auditFilter) ExportHref() template.URL {
	href := "/audit/export"
	if q := f.queryString(); q != "" {
		href += "?" + q
	}
	return template.URL(href)
}

// DownloadsHref links from the audit view to the downloads-by-IP view carrying the
// same filter — so "who pulled this?" is one click from the scoped incident set you're
// already looking at. template.URL for the same reason as ExportHref.
func (f auditFilter) DownloadsHref() template.URL {
	href := "/downloads"
	if q := f.queryString(); q != "" {
		href += "?" + q
	}
	return template.URL(href)
}

// eventRow is one display row. Score is pre-formatted to a string here (in Go) so
// the template stays a dumb renderer and the "no score" case shows a clean dash
// rather than a bare 0.
type eventRow struct {
	Package   string
	Ecosystem string
	Action    string // "allow" | "block" — also the badge CSS class
	Score     string // formatted score, or "—" when none was available
	SourceIP  string // observed connecting-peer IP, or "" (template shows a dash)
	Reason    string
	At        time.Time
	// Threshold is the bar the score was weighed against (#28), pre-formatted like
	// Score. Shown BESIDE the score rather than only in the export, because "4.2" on
	// its own does not tell an operator whether that was a pass or a fail — which is
	// the first question anyone reading this table has.
	Threshold string // formatted threshold, or "—" when none was weighed
	// Coverage is non-empty when the score was a PARTIAL measurement (#154): "15 of
	// 18 checks; without CI-Tests, License". Shown beside the score so an operator
	// comparing two 6.2s can see that one was computed over a different denominator.
	Coverage string
	// The block's attribution (D182 via the control plane, #142), carried into the
	// report form so a false-positive report says which list or feed the block came
	// from. ID is the audit event's, so the report can point at the exact verdict.
	ID       int64
	DenyKind string
	Rule     string
	Source   string
	// Served is true when the verdict was "block" but the gate relayed the package
	// anyway (report mode, #114). The audit page must say so on the row: "block" alone
	// tells an operator a package was refused when it was delivered.
	Served bool
	// PolicyDigest identifies the policy in force for this verdict. Rendered short:
	// its job on this screen is to make two rows decided under DIFFERENT policies
	// visibly different, not to be read as a value.
	PolicyDigest string
}

// handleAudit renders the read-only audit view: the firewall's recent allow/block
// history, newest-first. It is read-only by construction — the console has no path
// to write an event; only the firewall appends to the log. Auth (when configured)
// is already enforced in ServeHTTP.
func (s *server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := auditFilter{
		Ecosystem: strings.TrimSpace(q.Get("ecosystem")),
		Action:    strings.TrimSpace(q.Get("action")),
		Package:   strings.TrimSpace(q.Get("package")),
	}
	// Reject an unknown action here at the console edge. If we forwarded it, the
	// approval service would answer 400 and our transport-error path below would
	// mis-report that as an unreachable-upstream 502 — a misleading error for
	// someone scoping an incident. A bad ecosystem/package simply matches nothing,
	// which is honest, so only action needs the guard.
	if filter.Action != "" && filter.Action != "allow" && filter.Action != "block" {
		http.Error(w, "action filter must be allow or block", http.StatusBadRequest)
		return
	}

	events, err := s.approval.ListEvents(eventFilter{
		Ecosystem: filter.Ecosystem,
		Action:    filter.Action,
		Package:   filter.Package,
		Limit:     auditViewLimit,
	})
	if err != nil {
		// Same posture as the queue: the approval service is the source of truth, so
		// an unreachable upstream is an honest 502, not an empty page.
		log.Printf("audit: list events: %v", err)
		http.Error(w, "Cannot reach the approval service. Is it running and is CONSOLE_APPROVAL_URL correct?", http.StatusBadGateway)
		return
	}

	view := auditView{Total: len(events), Filter: filter, ScoringOff: s.scoringOff(), CanReport: s.writesEnabled()}
	if u := s.currentUser(r); u != "" {
		view.AuthUser = u
	}
	for _, e := range events {
		row := eventRow{
			Package:   e.Package,
			Ecosystem: e.Ecosystem,
			Action:    e.Action,
			SourceIP:  e.SourceIP,
			Reason:    e.Reason,
			At:        e.At,
			Score:     "—",
			Threshold: "—",

			PolicyDigest: e.PolicyDigest,
			ID:           e.ID,
			DenyKind:     e.DenyKind,
			Rule:         e.Rule,
			Source:       e.Source,
			Served:       e.Action == "block" && e.Taken == "allow",
		}
		if e.Score != nil {
			row.Score = fmt.Sprintf("%.1f", *e.Score)
		}
		if e.Partial() {
			row.Coverage = fmt.Sprintf("%d of %d checks", e.ScoredChecks, e.TotalChecks)
			if len(e.ComputedWithout) > 0 {
				row.Coverage += "; without " + strings.Join(e.ComputedWithout, ", ")
			}
		}
		if e.Threshold != nil {
			row.Threshold = fmt.Sprintf("%.1f", *e.Threshold)
		}
		view.Events = append(view.Events, row)
	}
	view.Nav = s.navFor(r, "audit")
	if err := auditTmpl.Execute(w, view); err != nil {
		log.Printf("audit: render: %v", err)
	}
}

// handleAuditExport streams the complete decision-log export (NDJSON) as a file
// download, honouring the same filters as the audit view so "export what you're
// looking at" works. It is a read of the audit log — no auth beyond ServeHTTP's, and
// no write surface. The approval client checks the upstream status before any bytes,
// so a failure there is a clean 502; once io.Copy starts, the status is committed and
// a mid-stream error can only be logged.
func (s *server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := auditFilter{
		Ecosystem: strings.TrimSpace(q.Get("ecosystem")),
		Action:    strings.TrimSpace(q.Get("action")),
		Package:   strings.TrimSpace(q.Get("package")),
	}
	if filter.Action != "" && filter.Action != "allow" && filter.Action != "block" {
		http.Error(w, "action filter must be allow or block", http.StatusBadRequest)
		return
	}

	body, err := s.approval.ExportEvents(eventFilter{
		Ecosystem: filter.Ecosystem,
		Action:    filter.Action,
		Package:   filter.Package,
		// no Limit — the export is complete by design
	})
	if err != nil {
		log.Printf("audit export: %v", err)
		http.Error(w, "Cannot reach the approval service. Is it running and is CONSOLE_APPROVAL_URL correct?", http.StatusBadGateway)
		return
	}
	defer body.Close()

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="yellowjack-decisions.jsonl"`)
	if _, err := io.Copy(w, body); err != nil {
		// Status is already 200 and bytes are on the wire; the operator sees a
		// truncated download (dropped connection), which is more honest than pretending.
		log.Printf("audit export: streaming: %v", err)
	}
}

// downloadsView is the shape handed to the downloads template.
type downloadsView struct {
	Rows        []ipRow
	TotalPulls  int         // sum of all rows' counts — "how many times downloaded" (D83)
	DistinctIPs int         // number of rows (distinct observed sources, incl. the unobserved bucket)
	AuthUser    string      // shown in the header when auth is configured
	Filter      auditFilter // reused: the same ?package/?ecosystem/?action query, echoed back
	Nav         navView
}

// ipRow is one display row of the downloads-by-IP table. Source is pre-formatted so
// the template stays a dumb renderer: an unobserved source (empty IP) shows a clear
// label rather than a blank cell.
type ipRow struct {
	Source string    // the IP, or "(unobserved)" when the source was not attributed
	IsIP   bool      // true for a real IP (so the template can style/monospace it)
	Count  int       // pulls from this source matching the filter
	LastAt time.Time // most recent matching pull
}

// handleDownloads renders the downloads-by-source-IP view (#41, D83): for a scoped set
// of pulls, how many came from each observed host and when — the incident-response
// answer to "package X was flagged; who pulled it, and how often?". It is read-only
// (only the firewall ever writes events). The count is COMPLETE: the client sends no
// limit, so the tally reflects the whole matching history, not a recent window — a
// partial count would understate an incident.
func (s *server) handleDownloads(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := auditFilter{
		Ecosystem: strings.TrimSpace(q.Get("ecosystem")),
		Action:    strings.TrimSpace(q.Get("action")),
		Package:   strings.TrimSpace(q.Get("package")),
	}
	// Same edge as the audit view: a typo'd action must 400, not silently return an
	// unfiltered-but-filtered-looking tally to someone scoping an incident.
	if filter.Action != "" && filter.Action != "allow" && filter.Action != "block" {
		http.Error(w, "action filter must be allow or block", http.StatusBadRequest)
		return
	}

	rows, err := s.approval.DownloadsByIP(eventFilter{
		Ecosystem: filter.Ecosystem,
		Action:    filter.Action,
		Package:   filter.Package,
		// no Limit — the tally is complete by design
	})
	if err != nil {
		log.Printf("downloads: by ip: %v", err)
		http.Error(w, "Cannot reach the approval service. Is it running and is CONSOLE_APPROVAL_URL correct?", http.StatusBadGateway)
		return
	}

	view := downloadsView{Filter: filter, DistinctIPs: len(rows)}
	if u := s.currentUser(r); u != "" {
		view.AuthUser = u
	}
	for _, rc := range rows {
		view.TotalPulls += rc.Count
		row := ipRow{Source: rc.IP, IsIP: rc.IP != "", Count: rc.Count, LastAt: rc.LastAt}
		if !row.IsIP {
			row.Source = "(unobserved)"
		}
		view.Rows = append(view.Rows, row)
	}
	view.Nav = s.navFor(r, "audit")
	if err := downloadsTmpl.Execute(w, view); err != nil {
		log.Printf("downloads: render: %v", err)
	}
}

// defaultQuietDays is the "has this gone quiet?" threshold when the operator gives no
// ?quiet_days. 30 days is a starting point, not a tuned value — it is the rough scale
// at which a dependency nobody has pulled in a monthly release cycle becomes worth a
// look. It is a query param precisely because the right number is site-specific, and
// the mock enterprise env is where a real default gets picked (D69).
const defaultQuietDays = 30

// activityView is the /activity page model: per-package last-activity, quietest first.
type activityView struct {
	Rows       []activityRow
	Packages   int         // distinct (package, ecosystem) pairs seen
	StaleCount int         // how many crossed the quiet threshold — D81 Q3's "how many are stale"
	QuietDays  int         // the threshold in force, echoed so the page states its own definition
	AuthUser   string      // shown in the header when auth is configured
	Filter     auditFilter // the same ?package/?ecosystem/?action query, echoed back
	Nav        navView
}

// activityRow is one display row. DaysQuiet and Stale are computed here rather than in
// the template so the template stays a dumb renderer.
type activityRow struct {
	Package   string
	Ecosystem string
	Events    int
	LastAt    time.Time
	DaysQuiet int
	Stale     bool
}

// handleActivity renders per-package last-activity — the observed-flow half of D81 Q3
// ("how many packages are stale"), quietest first.
//
// HONESTY, and it is the reason this view is scoped the way it is: this is what the
// firewall HAS SEEN, not an inventory of a repository. We cannot list a package that
// exists upstream and was never pulled, which is what "published but not pulled"
// literally asks for — that needs a durable package inventory with publish dates which
// nothing in this system holds (docs/CAPACITY_INSTRUMENTATION.md §3.3). The template
// says so on the page; do not retitle it "packages in your repository".
func (s *server) handleActivity(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := auditFilter{
		Ecosystem: strings.TrimSpace(q.Get("ecosystem")),
		Action:    strings.TrimSpace(q.Get("action")),
		Package:   strings.TrimSpace(q.Get("package")),
	}
	// DELIBERATE DIFFERENCE from the audit and downloads views, which default to "any
	// verdict": here an ABSENT ?action defaults to "allow", because this page claims to
	// show when a package was last PULLED. Counting blocks as pulls would make a package
	// that is blocked every day look freshly used — the exact opposite of the truth, in a
	// view whose whole purpose is spotting disuse. An explicitly EMPTY ?action= still
	// means "any", so the operator can opt into counting blocks; q.Has distinguishes the
	// two, which q.Get alone cannot. Do not "align" this with the sibling views.
	if !q.Has("action") {
		filter.Action = "allow"
	}
	if filter.Action != "" && filter.Action != "allow" && filter.Action != "block" {
		http.Error(w, "action filter must be allow or block", http.StatusBadRequest)
		return
	}

	quietDays := defaultQuietDays
	if v := strings.TrimSpace(q.Get("quiet_days")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			http.Error(w, "quiet_days must be a non-negative whole number of days", http.StatusBadRequest)
			return
		}
		quietDays = n
	}

	rows, err := s.approval.LastSeenByPackage(eventFilter{
		Ecosystem: filter.Ecosystem,
		Action:    filter.Action,
		Package:   filter.Package,
		// no Limit — the aggregation is complete by design, and the quiet package is
		// exactly the one a window would drop.
	})
	if err != nil {
		log.Printf("activity: last seen by package: %v", err)
		http.Error(w, "Cannot reach the approval service. Is it running and is CONSOLE_APPROVAL_URL correct?", http.StatusBadGateway)
		return
	}

	view := activityView{Filter: filter, QuietDays: quietDays, Packages: len(rows)}
	if u := s.currentUser(r); u != "" {
		view.AuthUser = u
	}
	now := time.Now()
	for _, a := range rows {
		row := activityRow{
			Package:   a.Package,
			Ecosystem: a.Ecosystem,
			Events:    a.Events,
			LastAt:    a.LastAt,
			DaysQuiet: int(now.Sub(a.LastAt).Hours() / 24),
		}
		row.Stale = row.DaysQuiet >= quietDays
		if row.Stale {
			view.StaleCount++
		}
		view.Rows = append(view.Rows, row)
	}
	view.Nav = s.navFor(r, "audit")
	if err := activityTmpl.Execute(w, view); err != nil {
		log.Printf("activity: render: %v", err)
	}
}

// groupByVerdict splits a flat decision list into the three verdict buckets the
// template renders, in a fixed display order (pending first — that's the reviewer's
// work queue). Within each bucket we keep newest-first (the approval service already
// returns them ordered by updatedAt DESC, but we sort defensively so the view is
// correct regardless of backend ordering — the in-memory store, for instance, does
// not order).
func groupByVerdict(decisions []decision, now time.Time) queueView {
	buckets := map[string][]queueRow{}
	for _, d := range decisions {
		v := d.Verdict
		if v != "pending" && v != "approved" && v != "denied" {
			// Unknown verdicts shouldn't occur, but if the API ever adds one we put
			// it with pending so it is not silently hidden from a reviewer.
			v = "pending"
		}
		row := queueRow{decision: d}
		// A missing FirstSeen is left BLANK, never rendered as a wait of zero or as
		// an age since the epoch. Rows written before #50 have no enqueue time, and
		// inventing one would put a confident, wrong number in the column an
		// operator uses to decide whether the queue is healthy.
		if !d.FirstSeen.IsZero() {
			waited := now.Sub(d.FirstSeen)
			switch {
			case waited < -clockSkewTolerance:
				// Not measurable, and deliberately NOT rendered as a small number. Left as
				// the same blank the never-recorded case produces, so an impossible
				// timestamp reads as "we cannot tell you" rather than "this just arrived".
				row.Impossible = true
				waited = 0
			case waited < 0:
				waited = 0 // ordinary skew between two services' clocks
			}
			if v == "pending" && !row.Impossible {
				row.Waiting = humanWait(waited)
				row.OverTarget = waited > queueTargetWait
			} else if !row.Impossible && !d.UpdatedAt.Before(d.FirstSeen) {
				row.WaitEnded = humanWait(d.UpdatedAt.Sub(d.FirstSeen))
			}
		}
		buckets[v] = append(buckets[v], row)
	}
	groups := []groupView{
		{Verdict: "pending", Label: "Awaiting review", Items: buckets["pending"]},
		{Verdict: "approved", Label: "Allowed by a human", Items: buckets["approved"]},
		{Verdict: "denied", Label: "Blocked by a human", Items: buckets["denied"]},
	}
	for i := range groups {
		if groups[i].Verdict == "pending" {
			sortLongestWaitingFirst(groups[i].Items)
			continue
		}
		sortNewestFirst(groups[i].Items)
	}
	return queueView{Groups: groups, Total: len(decisions)}
}

// pendingItems is a small helper for tests/readability: the items in the pending
// bucket (always the first group).
func (v queueView) pendingItems() []queueRow { return v.Groups[0].Items }

func sortNewestFirst(ds []queueRow) {
	sort.Slice(ds, func(i, j int) bool { return ds[i].UpdatedAt.After(ds[j].UpdatedAt) })
}

// sortLongestWaitingFirst orders the PENDING bucket by how long each package has been
// waiting, oldest at the top.
//
// Newest-first is the right order for a feed of recent activity and the wrong one for
// a queue you are trying to keep bounded: it puts the freshest arrival at the top and
// buries the package that has been waiting three months at the bottom, below the fold,
// where the backlog #50 is about becomes invisible precisely as it grows. Rows with no
// enqueue time sort last — they are unmeasurable, not new, and must not displace a row
// whose wait we can actually prove.
func sortLongestWaitingFirst(ds []queueRow) {
	sort.SliceStable(ds, func(i, j int) bool {
		a, b := ds[i].FirstSeen, ds[j].FirstSeen
		if a.IsZero() != b.IsZero() {
			return b.IsZero()
		}
		if a.IsZero() {
			return ds[i].UpdatedAt.After(ds[j].UpdatedAt)
		}
		return a.Before(b)
	})
}

// handleOverride records a human's ruling on a package (the "approve anyway" /
// "deny" action). It is the write half of the console (D19 part b). Reached only
// when a credential is configured (writes enabled) and after Basic Auth passed in
// ServeHTTP.
//
// The write is READ-MODIFY-WRITE: the approval PUT is a whole-record upsert, so we
// fetch the current decision, overlay only the fields the form actually submitted,
// stamp decidedBy with the authenticated user, and PUT the merged record. This
// preserves fields the form doesn't expose and lets a repo association survive a
// verdict change.
func (s *server) handleOverride(w http.ResponseWriter, r *http.Request) {
	if !s.writesEnabled() {
		// Defence in depth: writes are gated on a configured credential. Without one
		// the override endpoint must not act, even though ServeHTTP wouldn't have
		// required auth to reach here.
		http.Error(w, "overrides are disabled — set CONSOLE_AUTH_USER and CONSOLE_AUTH_PASS to enable them", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// CSRF guard: the browser attaches Basic Auth credentials to any cross-site form
	// POST automatically, so a state-changing request needs an origin check. A full
	// CSRF token is future hardening; rejecting cross-origin POSTs is a cheap,
	// dependency-free first line. (Requests with no Origin header — e.g. curl — are
	// allowed; they aren't browser-driven CSRF.)
	if !sameOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	pkg := strings.TrimSpace(r.PostForm.Get("package"))
	verdict := strings.TrimSpace(r.PostForm.Get("verdict"))
	if pkg == "" {
		http.Error(w, "package is required", http.StatusBadRequest)
		return
	}
	// The console only lets a human approve or deny. "pending" is a machine state
	// (the firewall records it); a human ruling is always a definite verdict.
	if verdict != "approved" && verdict != "denied" {
		http.Error(w, "verdict must be approved or denied", http.StatusBadRequest)
		return
	}

	// Read: start from the current record (empty if none) so we don't clobber
	// fields the form doesn't carry.
	existing, _, err := s.approval.Get(pkg)
	if err != nil {
		log.Printf("override %q: get current: %v", pkg, err)
		http.Error(w, "cannot reach the approval service", http.StatusBadGateway)
		return
	}

	// Modify: overlay the verdict (always) plus repoUrl/note only if the form
	// actually submitted them, and stamp who decided.
	d := existing
	d.Package = pkg
	d.Verdict = verdict
	// The ACTUAL person when OIDC is on, the shared label when it is not. This is
	// the first time an override in this console can name a human (#41), and it is
	// the reason per-user SSO is worth more here than a stronger shared password.
	d.DecidedBy = s.currentUser(r)
	if r.PostForm.Has("repoUrl") {
		d.RepoURL = strings.TrimSpace(r.PostForm.Get("repoUrl"))
	}
	// An EMPTY note keeps the one on record. The Decisions form always posts the field,
	// and the record's note is usually the gate's own reason for queueing the package;
	// a ruling given without a comment must not erase why it was ever in the queue.
	if n := strings.TrimSpace(r.PostForm.Get("note")); n != "" {
		d.Note = n
	}

	// Write.
	if _, err := s.approval.Put(d); err != nil {
		log.Printf("override %q: put: %v", pkg, err)
		http.Error(w, "cannot reach the approval service", http.StatusBadGateway)
		return
	}
	log.Printf("override recorded: %s -> %s (by %q)", d.Package, d.Verdict, d.DecidedBy)

	// POST-redirect-GET: send the browser back to the queue so a refresh doesn't
	// re-submit the override -- carrying what the ruling REACHES (#132). Before D272
	// that meant warning that a deny might not be enforced at all, and the console
	// used "did this package have a record before this write?" as its only evidence.
	// D272 settled it: a deny reaches every path, so that distinction is gone and the
	// notice no longer depends on the prior record. What the notice still has to say
	// is the one limit that survives -- the ruling is enforced only while the gate can
	// reach the approval service, where a deny-list entry is not.
	http.Redirect(w, r, "/decisions?"+overrideNotice(d.Verdict, pkg).Encode(), http.StatusSeeOther)
}

// overrideNotice is the queue banner shown after an override, stating what the
// ruling reaches (#132). It no longer takes "did this package have a record before
// this write": that argument existed only to grade HOW un-enforced a deny was, and
// D272 made every deny enforced.
func overrideNotice(verdict, pkg string) url.Values {
	q := url.Values{}
	q.Set("level", "ok")
	if verdict != "denied" {
		q.Set("notice", fmt.Sprintf("Approved %s. The gate lets it through where its policy would have refused it.", pkg))
		return q
	}
	q.Set("notice", fmt.Sprintf("Denied %s. The gate refuses it on every path from now on -- including a package "+
		"its own policy would allow (D272). One limit worth knowing: this ruling lives in the approval service, "+
		"and a gate that cannot reach that service falls back to policy. Put %s on the deny list for a block that "+
		"survives an approval outage.", pkg, pkg))
	return q
}

// sameOrigin reports whether a mutating request is same-origin. If the browser
// sent an Origin header, its host must match the request Host. A missing Origin
// (non-browser clients) is treated as same-origin — CSRF is a browser attack.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}
