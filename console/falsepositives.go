package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The false-positive report path (#142).
//
// Every block on /audit gets a "report false positive" form when writes are enabled;
// submitting it records the report on the control plane -- package, ecosystem, the
// reason the developer saw, the gate's structured attribution of the block (advisory vs
// operator list), the operator's note and identity -- and /false-positives lists them.
// Local first: the operator's own history is the product, and it works with no egress.
// Forwarding, if the control plane is configured for it, happens THERE, not here.

//go:embed templates/falsepositives.html
var falsePositivesHTML string
var falsePositivesTmpl = pageTemplate("falsepositives", falsePositivesHTML, nil)

// falsePositive mirrors the approval service's FalsePositiveReport across the REST
// boundary -- our own type, same discipline as event and decision.
type falsePositive struct {
	ID         int64     `json:"id"`
	EventID    int64     `json:"event_id,omitempty"`
	Package    string    `json:"package"`
	Ecosystem  string    `json:"ecosystem,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Source     string    `json:"source,omitempty"`
	DenyKind   string    `json:"deny_kind,omitempty"`
	Rule       string    `json:"rule,omitempty"`
	Note       string    `json:"note,omitempty"`
	ReportedBy string    `json:"reported_by,omitempty"`
	At         time.Time `json:"at"`
}

// SourceKind is the operator-facing classification. It is computed HERE as well as on
// the control plane (the same three words) because this page renders what it reads and
// must not depend on a field the control plane might not send.
func (f falsePositive) SourceKind() string {
	switch strings.TrimSpace(f.Source) {
	case "known-malware feed":
		return "advisory"
	case "operator deny list", "approval service":
		return "operator"
	case "":
		return "unattributed"
	}
	return f.Source
}

// ── client ───────────────────────────────────────────────────────────────────────

func (c *approvalHTTPClient) ListFalsePositives() ([]falsePositive, error) {
	resp, err := c.http.Get(strings.TrimRight(c.baseURL, "/") + "/v1/false-positives")
	if err != nil {
		return nil, fmt.Errorf("contacting approval service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("approval service returned status %d", resp.StatusCode)
	}
	var out []falsePositive
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding false positives: %w", err)
	}
	return out, nil
}

func (c *approvalHTTPClient) ReportFalsePositive(f falsePositive) (falsePositive, error) {
	body, err := json.Marshal(f)
	if err != nil {
		return falsePositive{}, err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(c.baseURL, "/")+"/v1/false-positives", bytes.NewReader(body))
	if err != nil {
		return falsePositive{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return falsePositive{}, fmt.Errorf("contacting approval service: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return falsePositive{}, fmt.Errorf("approval service returned status %d", resp.StatusCode)
	}
	var saved falsePositive
	if err := json.NewDecoder(resp.Body).Decode(&saved); err != nil {
		return falsePositive{}, fmt.Errorf("decoding approval response: %w", err)
	}
	return saved, nil
}

// ── handlers ─────────────────────────────────────────────────────────────────────

type falsePositivesView struct {
	Nav      navView
	Reports  []falsePositive
	AuthUser string
	// Saved is the id just recorded, carried on the redirect so the page can confirm
	// the specific report landed rather than saying "done" in the abstract.
	Saved int64
	// WritesEnabled tells the page whether the /audit form exists at all, so it can
	// explain an empty list correctly: "nothing reported" and "reporting is off"
	// are different empty states.
	WritesEnabled bool
}

func (s *server) handleFalsePositives(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reports, err := s.approval.ListFalsePositives()
	if err != nil {
		log.Printf("false positives: %v", err)
		http.Error(w, "cannot reach the approval service", http.StatusBadGateway)
		return
	}
	view := falsePositivesView{Reports: reports, AuthUser: s.currentUser(r), WritesEnabled: s.writesEnabled()}
	view.Nav = s.navFor(r, "audit")
	view.Saved, _ = strconv.ParseInt(r.URL.Query().Get("saved"), 10, 64)
	var buf bytes.Buffer
	if err := falsePositivesTmpl.Execute(&buf, view); err != nil {
		log.Printf("render false positives: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// handleReportFalsePositive is the write. Same gating as /override and /lists: writes
// need a configured identity (so the report is attributed), and a browser POST must be
// same-origin. It is deliberately a form POST from the audit row, not a JSON API: the
// console is the operator's tool, and the control plane already has the API.
func (s *server) handleReportFalsePositive(w http.ResponseWriter, r *http.Request) {
	if !s.writesEnabled() {
		http.Error(w, "reporting is disabled — configure a console credential or OIDC to enable it", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
	f := falsePositive{
		Package:    strings.TrimSpace(r.PostForm.Get("package")),
		Ecosystem:  strings.TrimSpace(r.PostForm.Get("ecosystem")),
		Reason:     strings.TrimSpace(r.PostForm.Get("reason")),
		Source:     strings.TrimSpace(r.PostForm.Get("source")),
		DenyKind:   strings.TrimSpace(r.PostForm.Get("deny_kind")),
		Rule:       strings.TrimSpace(r.PostForm.Get("rule")),
		Note:       strings.TrimSpace(r.PostForm.Get("note")),
		ReportedBy: s.currentUser(r),
	}
	f.EventID, _ = strconv.ParseInt(r.PostForm.Get("event_id"), 10, 64)
	if f.Package == "" {
		http.Error(w, "package is required", http.StatusBadRequest)
		return
	}
	// Only a BLOCK can be a false positive. The form only exists on block rows, but a
	// hand-made POST must not be able to file a report against an allow.
	if r.PostForm.Get("action") != "" && r.PostForm.Get("action") != "block" {
		http.Error(w, "only a block can be reported as a false positive", http.StatusBadRequest)
		return
	}
	saved, err := s.approval.ReportFalsePositive(f)
	if err != nil {
		log.Printf("report false positive %q: %v", f.Package, err)
		http.Error(w, "cannot reach the approval service", http.StatusBadGateway)
		return
	}
	log.Printf("false positive reported: %s (%s, %s) by %q", saved.Package, saved.Ecosystem, saved.SourceKind(), saved.ReportedBy)
	http.Redirect(w, r, "/false-positives?saved="+strconv.FormatInt(saved.ID, 10), http.StatusSeeOther)
}
