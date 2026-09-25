package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// The console's read model for the capacity flow data (#32 Pillar 2, D80/D81).
//
// These mirror approval/flowstore.go's FlowSummary / FlowPackage / FlowSource, but they
// are DECLARED SEPARATELY rather than imported, for the same reason every other type in
// this package is: the console is an HTTP client of the control plane, not a library user
// of it (CLAUDE.md's microservice rule — components talk over a standard protocol with a
// configurable interface). Sharing the struct would make a wire-format change a
// compile-time coupling and quietly delete the seam.
//
// The cost of that choice is real and worth naming: the JSON tags below must match the
// approval service's. A field renamed on one side and not the other decodes to zero and
// renders as "0 B", which looks like a quiet week rather than a bug. flowclient_test.go
// pins the tags against a literal captured from the approval service's own encoder so the
// drift is caught at test time rather than on the page.

// flowFilter is the query contract shared by every /v1/flow* read.
//
// From/To are strings, not time.Time, because this page's filter arrives from a URL and
// leaves as a URL: parsing to a time and formatting back would silently normalise an
// operator's "2026-09-01" into something they did not type, and reject-with-a-message is
// the approval service's job (it already answers 400 "from/to must be RFC3339
// timestamps"). Passing the text through means one validator, not two that can disagree.
type flowFilter struct {
	Ecosystem string
	Instance  string
	From      string
	To        string
}

// query renders the filter as a URL query string, omitting empty fields so a bare page
// load asks for the service's own default window rather than pinning one here.
func (f flowFilter) query() string {
	v := url.Values{}
	for name, val := range map[string]string{
		"ecosystem": f.Ecosystem,
		"instance":  f.Instance,
		"from":      f.From,
		"to":        f.To,
	} {
		if val != "" {
			v.Set(name, val)
		}
	}
	if len(v) == 0 {
		return ""
	}
	return "?" + v.Encode()
}

// flowSummary answers D81 Q2 ("how much data is flowing through my system?") and Q5
// ("were there failures to pull packages due to file corruption?").
type flowSummary struct {
	Requests      int64 `json:"requests"`
	BytesUpstream int64 `json:"bytes_upstream"`
	BytesClient   int64 `json:"bytes_client"`

	Truncated       int64 `json:"truncated"`
	RelayErrors     int64 `json:"relay_errors"`
	TransportErrors int64 `json:"transport_errors"`
	UpstreamStatus  int64 `json:"upstream_status"`
	MetaErrors      int64 `json:"meta_errors"`
	Retries         int64 `json:"retries"`
	// #64. No omitempty: a zero is the informative "checked, all matched", and must
	// not read on the wire like a gate too old to check.
	IntegrityMismatches int64 `json:"integrity_mismatches"`

	Packages int64 `json:"packages"`
}

// flowPackage is one row of the per-package ranking (D81 Q1).
type flowPackage struct {
	Package       string `json:"package,omitempty"` // "" = the unattributed bucket
	Ecosystem     string `json:"ecosystem"`
	Requests      int64  `json:"requests"`
	BytesUpstream int64  `json:"bytes_upstream"`
	BytesClient   int64  `json:"bytes_client"`
}

// Display returns the name to show for a package row.
//
// The approval service returns "" for traffic it could not attribute to a package, and
// an empty cell in a ranking reads as a rendering bug. Naming it makes the unattributed
// share visible, which is itself worth seeing: if it dominates, the ranking above it is
// not describing the traffic.
func (p flowPackage) Display() string {
	if strings.TrimSpace(p.Package) == "" {
		return "(unattributed)"
	}
	return p.Package
}

func (c *approvalHTTPClient) FlowSummary(f flowFilter) (flowSummary, error) {
	var out flowSummary
	err := c.getFlowJSON("/v1/flow/summary", f, &out)
	return out, err
}

func (c *approvalHTTPClient) FlowPackages(f flowFilter) ([]flowPackage, error) {
	var out []flowPackage
	err := c.getFlowJSON("/v1/flow/packages", f, &out)
	return out, err
}

// getFlowJSON is the one place the flow reads talk to the control plane.
//
// Shared because the three reads differ only in path and result type, and because a
// per-endpoint copy is how one of them ends up not checking the status code — the
// failure that returns an empty page instead of an error, and so reports "no traffic"
// when the truth is "we could not ask".
func (c *approvalHTTPClient) getFlowJSON(path string, f flowFilter, out any) error {
	endpoint := strings.TrimRight(c.baseURL, "/") + path + f.query()
	resp, err := c.http.Get(endpoint)
	if err != nil {
		return fmt.Errorf("contacting approval service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("approval service returned status %d for %s", resp.StatusCode, path)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding approval response for %s: %w", path, err)
	}
	return nil
}
