package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// decision mirrors the subset of the approval service's Decision that the console
// displays. We deliberately declare our OWN type here rather than importing the
// approval package's struct: the two services communicate over REST and must be
// free to evolve independently — the same boundary discipline as the firewall's
// approval_client.go. Field tags match the approval service's JSON exactly.
type decision struct {
	Package   string    `json:"package"`
	Verdict   string    `json:"verdict"` // "pending" | "approved" | "denied"
	RepoURL   string    `json:"repoUrl,omitempty"`
	Note      string    `json:"note,omitempty"`
	DecidedBy string    `json:"decidedBy,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
	// FirstSeen is when the package entered the queue, and is NOT UpdatedAt: see
	// approval.Decision.FirstSeen for why the distinction is load-bearing (#50).
	FirstSeen time.Time `json:"firstSeen"`
}

// event mirrors the subset of the approval service's AuditEvent the console
// displays — one immutable allow/block the firewall made. Our own type across the
// REST boundary, same discipline as decision above. Score is a pointer so a missing
// score (no value available) is distinct from a real 0.0.
type event struct {
	ID        int64     `json:"id"`
	Package   string    `json:"package"`
	Ecosystem string    `json:"ecosystem,omitempty"`
	Action    string    `json:"action"` // "allow" | "block"
	Score     *float64  `json:"score,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	SourceIP  string    `json:"source_ip,omitempty"` // observed connecting-peer IP (#41); rendered as "which host", not a person
	At        time.Time `json:"at"`
	// The verdict's inputs (#28). Threshold is a pointer for the same reason Score is:
	// nil means "no threshold was weighed" (a known-malware refusal decides before any
	// scoring), which must not render as a bar of 0.
	Threshold    *float64 `json:"threshold,omitempty"`
	PolicyDigest string   `json:"policy_digest,omitempty"`
	// The gate's structured attribution of a block (D182), stored by the control plane
	// since #142: what kind of denial, which rule, from which source. Empty on an
	// allow, and empty on events recorded before the control plane kept them.
	DenyKind string `json:"deny_kind,omitempty"`
	// Override: this verdict went against a finding on an explicit operator instruction
	// (D312). Rendered on the audit row, because an override the organisation cannot see
	// is the half of the ruling that would have been dropped.
	Override string `json:"override,omitempty"`
	Rule     string `json:"rule,omitempty"`
	Source   string `json:"source,omitempty"`
	// What the gate actually DID with the verdict, and why the two can differ (#114):
	// under report mode a "block" verdict is relayed anyway. Stored since #142.
	Taken string `json:"taken,omitempty"`
	Mode  string `json:"mode,omitempty"`
	// What the verdict's score was computed over (#154). 0/0/empty = full or unknown.
	ScoredChecks    int      `json:"scored_checks,omitempty"`
	TotalChecks     int      `json:"total_checks,omitempty"`
	ComputedWithout []string `json:"computed_without,omitempty"`
}

// Partial: the verdict rested on a score computed over fewer checks than the run
// emitted (#154). Same predicate as the lookup page's scoreRecord.
func (e event) Partial() bool { return e.TotalChecks > 0 && e.ScoredChecks < e.TotalChecks }

// packageActivity mirrors the approval service's PackageActivity — one row of the
// per-package last-activity aggregation (#32 Phase C, D81 Q3): how many matching
// events each package had and when the most recent was. Our own type across the REST
// boundary, same discipline as event/ipCount.
//
// OBSERVED FLOW ONLY: this describes packages this firewall has SEEN. It cannot know
// about a package that exists upstream and was never pulled, so it must never be
// rendered as "packages in your repository" — see docs/CAPACITY_INSTRUMENTATION.md §3.3.
type packageActivity struct {
	Package   string    `json:"package"`
	Ecosystem string    `json:"ecosystem,omitempty"`
	Events    int       `json:"events"`
	LastAt    time.Time `json:"last_at"`
}

// instanceHealth mirrors one row of the approval service's /v1/health: a firewall replica's
// heartbeat, plus the policy it reports it is ENFORCING (#32 Phase D / D4).
//
// Declared here rather than imported, the same REST-boundary discipline every other DTO in
// this file follows. Note the console models the policy MORE than the approval service
// does — approval stores the document opaquely because it never interprets it, while this
// service has to render it, so it needs the shape.
type instanceHealth struct {
	Instance     string     `json:"instance"`
	Ecosystem    string     `json:"ecosystem,omitempty"`
	ReportedAt   time.Time  `json:"reported_at"`
	StartedAt    time.Time  `json:"started_at,omitempty"`
	AuditDropped int64      `json:"audit_dropped"`
	FlowDropped  int64      `json:"flow_dropped"`
	Policy       *policyDoc `json:"policy,omitempty"`
	PolicyDigest string     `json:"policy_digest,omitempty"`
}

// policyDoc is the policy a replica reports. It mirrors the firewall's PolicyView.
//
// WHAT IS NOT HERE, AND CANNOT BE: a rule's CONDITION. Conditions are Go closures
// (`Match func(Facts) bool`), so they cannot be serialized — that is the crux of Phase D
// (docs/POLICY_DISTRIBUTION.md §2). This page therefore shows what each rule is CALLED and
// what it DOES, in order, which is what a firewall ACL listing shows too.
type policyDoc struct {
	Chains []policyChain     `json:"chains"`
	Values map[string]string `json:"values"`
	Lists  []policyList      `json:"lists,omitempty"`
	Digest string            `json:"digest"`
}

// policyList mirrors the firewall's ListView -- the operator's own allow/deny lists
// (D193, issue #58).
//
// Declared here rather than imported, like everything else in this file: the console is
// an HTTP client of the control plane, not a library user of it. The cost is that these
// json tags must match the firewall's, and the failure mode is silent -- a renamed tag
// decodes to an EMPTY list, which on this page reads as "the operator has not configured
// one" rather than as an error. policy_test.go pins the tags against a literal captured
// from the firewall's own encoder for exactly that reason.
type policyList struct {
	Kind    string   `json:"kind"`
	Path    string   `json:"path"`
	Names   []string `json:"names,omitempty"`
	Omitted int      `json:"omitted,omitempty"`
	Digest  string   `json:"digest"`
}

type policyChain struct {
	Name  string       `json:"name"`
	Rules []policyRule `json:"rules"`
	// DefaultAction is what the chain does to a request that matched no rule, as
	// reported by the firewall's own engine. It is NOT always the terminal reject: the
	// shipped byte chain ends in a match-all allow-but-log, so its terminal is
	// unreachable. Rendering the terminal instead would tell an operator their artifact
	// route is fail-closed when it is not.
	DefaultAction string `json:"default_action"`
}

type policyRule struct {
	Name     string `json:"name"`
	Action   string `json:"action"`
	Implicit bool   `json:"implicit,omitempty"`
}

// ipCount mirrors the approval service's IPCount — one row of the downloads-by-source-IP
// aggregation (#41): how many matching pulls came from each observed IP and when the
// most recent was. Our own type across the REST boundary, same discipline as event.
type ipCount struct {
	IP     string    `json:"ip"`      // observed source IP; "" = unobserved
	Count  int       `json:"count"`   // pulls from this IP matching the filter
	LastAt time.Time `json:"last_at"` // most recent matching pull
}

// eventSummary mirrors the approval service's EventSummary: the verdict tally since a
// point in time, for the Overview's "last 24 hours" tiles. Our own type across the REST
// boundary, like every DTO here; overview_test.go pins the tags against the approval
// service's literal wire form, because a renamed key decodes to a silent zero -- and a
// zero on "stopped" reads as a quiet day, not as a broken page.
type eventSummary struct {
	Since         time.Time      `json:"since"`
	Allowed       int            `json:"allowed"`
	Blocked       int            `json:"blocked"`
	BlockedServed int            `json:"blocked_served"`
	ByDenyKind    map[string]int `json:"by_deny_kind"`
	Sources       int            `json:"sources"`
}

// eventFilter narrows an audit-log read — the console's own type for the approval
// service's ?ecosystem/?action/?package query. Empty fields are wildcards; Limit
// bounds the result. Declared here (not shared with approval) for the same
// REST-boundary independence as event/decision above.
type eventFilter struct {
	Ecosystem string
	Action    string // "allow" | "block" | "" (any)
	Package   string
	Limit     int
}

// The approval API surface the console uses, split into read and write halves.
// Handlers depend on these interfaces, not the concrete HTTP client, so they can
// be tested with a fake (no running approval service, no DB).
type approvalReader interface {
	// List returns every recorded decision.
	List() ([]decision, error)
	// Get fetches one decision; found=false (no error) means none recorded yet.
	// Needed so an override is read-modify-write: the approval PUT is a whole-record
	// upsert, so we must start from the current record and merge, or we would wipe
	// fields the form doesn't carry (repoUrl/note/decidedBy).
	Get(pkg string) (decision, bool, error)
	// ListEvents returns recent audit events (the firewall's allow/block history),
	// newest-first, narrowed by the filter and capped at f.Limit. Read-only: the
	// console never writes events — only the firewall appends them, which is why
	// there is no write counterpart.
	ListEvents(f eventFilter) ([]event, error)
	// ExportEvents opens the COMPLETE decision-log export (NDJSON) for the filter and
	// returns the response body to stream to the operator. The caller must Close it.
	// It returns an error BEFORE any bytes are read (transport failure or a non-200
	// status), so the handler can send a clean 502 rather than a truncated download.
	// f.Limit is ignored — the export is complete by design.
	ExportEvents(f eventFilter) (io.ReadCloser, error)
	// DownloadsByIP returns the per-source-IP download tally for the filter (#41):
	// "who pulled this package, how often", most-frequent-first. Complete by design
	// (f.Limit ignored) — a partial count is a wrong count for incident response.
	DownloadsByIP(f eventFilter) ([]ipCount, error)
	// LastSeenByPackage returns per-package activity for the filter (#32 Phase C):
	// what the firewall has seen and when each package last came through, QUIETEST
	// FIRST. Complete by design (f.Limit ignored) — the package that went quiet
	// longest ago is exactly the one a recency window would drop.
	LastSeenByPackage(f eventFilter) ([]packageActivity, error)
	// ListInstanceHealth returns every firewall replica that has reported, newest
	// heartbeat first, each carrying the policy it says it is ENFORCING (#32 Phase D).
	// Read-only and deliberately unfiltered: a replica that stopped reporting is the
	// most interesting row on the page, so nothing here may hide a stale one.
	ListInstanceHealth() ([]instanceHealth, error)
	// PackageStatus returns the read-only aggregate for ONE package (#73 / D135 pillar
	// 4). found=false (nil error) means the package has never been requested through
	// this deployment -- a legitimate and informative answer, not a failure, and the
	// exact case D139's stop-gap exists for.
	PackageStatus(pkg, ecosystem string) (packageStatus, bool, error)
	// FlowSummary returns the capacity totals and error counters for the window
	// (#32 Pillar 2, D81 Q2 + Q5). Read-only: the FIREWALL posts flow buckets to the
	// control plane, the console only ever reads the aggregate back, which is why
	// there is no write counterpart here any more than there is for events.
	FlowSummary(f flowFilter) (flowSummary, error)
	// FlowPackages returns the per-package byte-volume ranking for the window
	// (D81 Q1: "what packages constitute the bulk of the data flowing through my
	// system?"), heaviest first. The approval service applies its own top-N cap;
	// this is a ranking, so a truncated tail is the intended answer rather than a
	// lost one -- unlike DownloadsByIP, where a partial count is a wrong count.
	FlowPackages(f flowFilter) ([]flowPackage, error)
	// ListFalsePositives returns the operator's false-positive reports, newest first
	// (#142). Read-only here; the write is ReportFalsePositive below.
	ListFalsePositives() ([]falsePositive, error)
	// SummarizeEvents returns the verdict tally since the given time (the Overview's
	// tiles). Complete, not a page: see the approval service's EventSummary.
	SummarizeEvents(since time.Time) (eventSummary, error)
}

// approvalWriter is the write half — used by the override, list and report handlers.
type approvalWriter interface {
	// Put upserts a decision and returns the saved record.
	Put(d decision) (decision, error)
	// ReportFalsePositive records that a block was wrong (#142) and returns the saved
	// report with its id.
	ReportFalsePositive(f falsePositive) (falsePositive, error)
}

// approvalClient is the full contract the server depends on.
type approvalClient interface {
	approvalReader
	approvalWriter
}

// approvalHTTPClient is the real implementation: it calls the approval service's
// REST API. It holds no state beyond its configuration.
type approvalHTTPClient struct {
	baseURL string
	http    *http.Client
}

// List fetches every recorded decision via GET /v1/decisions. The approval service
// returns them newest-first (its pgStore orders by updated_at DESC); we preserve
// whatever order it gives us.
func (c *approvalHTTPClient) List() ([]decision, error) {
	endpoint := strings.TrimRight(c.baseURL, "/") + "/v1/decisions"
	resp, err := c.http.Get(endpoint)
	if err != nil {
		// A transport error means the approval service is unreachable — surface it
		// as-is so the handler can render an honest "control plane unavailable" page.
		return nil, fmt.Errorf("contacting approval service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("approval service returned status %d", resp.StatusCode)
	}

	var ds []decision
	if err := json.NewDecoder(resp.Body).Decode(&ds); err != nil {
		return nil, fmt.Errorf("decoding approval response: %w", err)
	}
	return ds, nil
}

// ListEvents fetches recent audit events via GET /v1/events, forwarding the filter
// as query parameters. url.Values.Encode escapes every value, so an operator's
// search text can't break the URL. The approval service returns them newest-first
// (ORDER BY id DESC); we preserve that order.
func (c *approvalHTTPClient) ListEvents(f eventFilter) ([]event, error) {
	q := url.Values{}
	if f.Limit > 0 {
		q.Set("limit", strconv.Itoa(f.Limit))
	}
	if f.Ecosystem != "" {
		q.Set("ecosystem", f.Ecosystem)
	}
	if f.Action != "" {
		q.Set("action", f.Action)
	}
	if f.Package != "" {
		q.Set("package", f.Package)
	}
	endpoint := strings.TrimRight(c.baseURL, "/") + "/v1/events?" + q.Encode()
	resp, err := c.http.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("contacting approval service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("approval service returned status %d", resp.StatusCode)
	}
	var evs []event
	if err := json.NewDecoder(resp.Body).Decode(&evs); err != nil {
		return nil, fmt.Errorf("decoding approval response: %w", err)
	}
	return evs, nil
}

// ExportEvents opens the streaming NDJSON export via GET /v1/events/export. It checks
// the status here (closing the body on a non-200) and returns the still-open body on
// success, so the handler streams straight through with io.Copy — a large export never
// buffers in the console. No limit param: the export is complete.
func (c *approvalHTTPClient) ExportEvents(f eventFilter) (io.ReadCloser, error) {
	q := url.Values{}
	if f.Ecosystem != "" {
		q.Set("ecosystem", f.Ecosystem)
	}
	if f.Action != "" {
		q.Set("action", f.Action)
	}
	if f.Package != "" {
		q.Set("package", f.Package)
	}
	endpoint := strings.TrimRight(c.baseURL, "/") + "/v1/events/export?" + q.Encode()
	resp, err := c.http.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("contacting approval service: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("approval service returned status %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// DownloadsByIP fetches the per-source-IP tally via GET /v1/events/by-ip, forwarding
// the same filter as the list. No limit param — the tally is complete. The approval
// service already orders it most-frequent-first; we preserve that order.
func (c *approvalHTTPClient) DownloadsByIP(f eventFilter) ([]ipCount, error) {
	q := url.Values{}
	if f.Ecosystem != "" {
		q.Set("ecosystem", f.Ecosystem)
	}
	if f.Action != "" {
		q.Set("action", f.Action)
	}
	if f.Package != "" {
		q.Set("package", f.Package)
	}
	endpoint := strings.TrimRight(c.baseURL, "/") + "/v1/events/by-ip?" + q.Encode()
	resp, err := c.http.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("contacting approval service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("approval service returned status %d", resp.StatusCode)
	}
	var rows []ipCount
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("decoding approval response: %w", err)
	}
	return rows, nil
}

// SummarizeEvents fetches GET /v1/events/summary?since=. The since is always sent, so
// the window is the console's choice and is stated on the page, never the control
// plane's default silently standing in for it.
func (c *approvalHTTPClient) SummarizeEvents(since time.Time) (eventSummary, error) {
	endpoint := strings.TrimRight(c.baseURL, "/") + "/v1/events/summary?since=" +
		url.QueryEscape(since.UTC().Format(time.RFC3339))
	resp, err := c.http.Get(endpoint)
	if err != nil {
		return eventSummary{}, fmt.Errorf("contacting approval service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return eventSummary{}, fmt.Errorf("approval service returned status %d", resp.StatusCode)
	}
	var out eventSummary
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return eventSummary{}, fmt.Errorf("decoding approval response: %w", err)
	}
	return out, nil
}

// LastSeenByPackage fetches the per-package activity aggregation via GET
// /v1/events/last-seen, forwarding the same filter. No limit param — the aggregation
// is complete. The approval service already orders it quietest-first; we preserve that.
func (c *approvalHTTPClient) LastSeenByPackage(f eventFilter) ([]packageActivity, error) {
	q := url.Values{}
	if f.Ecosystem != "" {
		q.Set("ecosystem", f.Ecosystem)
	}
	if f.Action != "" {
		q.Set("action", f.Action)
	}
	if f.Package != "" {
		q.Set("package", f.Package)
	}
	endpoint := strings.TrimRight(c.baseURL, "/") + "/v1/events/last-seen?" + q.Encode()
	resp, err := c.http.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("contacting approval service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("approval service returned status %d", resp.StatusCode)
	}
	var rows []packageActivity
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("decoding approval response: %w", err)
	}
	return rows, nil
}

// Get fetches a single decision via GET /v1/decisions?package=NAME. A 404 means
// no decision is recorded yet (found=false, nil error) — the normal case for a
// first-time override.
// ListInstanceHealth fetches every replica's heartbeat via GET /v1/health, each carrying
// the policy that replica reports it is enforcing (#32 Phase D / D4).
//
// Unfiltered on purpose: the approval service returns stale replicas too, and this page
// exists partly to show them. A "recent only" filter here would hide exactly the replica an
// operator most needs to see — the one that stopped reporting while still gating traffic.
func (c *approvalHTTPClient) ListInstanceHealth() ([]instanceHealth, error) {
	endpoint := strings.TrimRight(c.baseURL, "/") + "/v1/health"
	resp, err := c.http.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("contacting approval service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("approval service returned status %d", resp.StatusCode)
	}
	var rows []instanceHealth
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("decoding approval response: %w", err)
	}
	return rows, nil
}

func (c *approvalHTTPClient) Get(pkg string) (decision, bool, error) {
	endpoint := fmt.Sprintf("%s/v1/decisions?package=%s",
		strings.TrimRight(c.baseURL, "/"), url.QueryEscape(pkg))
	resp, err := c.http.Get(endpoint)
	if err != nil {
		return decision{}, false, fmt.Errorf("contacting approval service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return decision{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return decision{}, false, fmt.Errorf("approval service returned status %d", resp.StatusCode)
	}
	var d decision
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return decision{}, false, fmt.Errorf("decoding approval response: %w", err)
	}
	return d, true, nil
}

// Put upserts a decision via PUT /v1/decisions and returns the saved record.
// The approval service sets updatedAt server-side, so we ignore any value we send.
func (c *approvalHTTPClient) Put(d decision) (decision, error) {
	body, err := json.Marshal(d)
	if err != nil {
		return decision{}, fmt.Errorf("encoding decision: %w", err)
	}
	endpoint := strings.TrimRight(c.baseURL, "/") + "/v1/decisions"
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return decision{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return decision{}, fmt.Errorf("contacting approval service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return decision{}, fmt.Errorf("approval service returned status %d", resp.StatusCode)
	}
	var saved decision
	if err := json.NewDecoder(resp.Body).Decode(&saved); err != nil {
		return decision{}, fmt.Errorf("decoding approval response: %w", err)
	}
	return saved, nil
}
