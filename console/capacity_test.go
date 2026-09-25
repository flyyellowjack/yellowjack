package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Tests for the capacity view (#32 Pillar 2, D80/D81).
//
// The failure this file is most concerned with is NOT a crash. It is the page rendering
// cleanly with zeroes in it. "0 B moved" is indistinguishable, at a glance, from a quiet
// week — so every way the numbers can silently become zero needs a test that fails:
//
//	a JSON tag drifts from the approval service's       -> decodes to zero, renders "0 B"
//	the handler swallows a backend error                -> empty page, reads as "no traffic"
//	the filter is dropped on the way to the backend     -> right numbers, wrong window
//
// A dashboard that lies quietly is worse than one that is down, because nobody
// investigates it.

// errBoom is any backend failure. The message is deliberately not asserted anywhere --
// what matters is that the handler refuses to render, not what it logged.
var errBoom = errors.New("approval service unreachable")

func getCapacity(t *testing.T, f *fakeApproval, query string) *httptest.ResponseRecorder {
	t.Helper()
	srv := &server{approval: f}
	req := httptest.NewRequest(http.MethodGet, "/capacity"+query, nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestCapacityPageRendersTheTotalsAndTheRanking(t *testing.T) {
	f := &fakeApproval{
		flowSum: flowSummary{
			Requests: 4102, BytesClient: 812_000_000_000, BytesUpstream: 44_000_000_000,
			Packages: 317, Truncated: 3,
		},
		flowPkgs: []flowPackage{
			{Package: "typescript", Ecosystem: "npm", BytesClient: 700_000_000, Requests: 91},
			{Package: "", Ecosystem: "npm", BytesClient: 12_000_000, Requests: 4},
		},
	}
	rec := getCapacity(t, f, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /capacity = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	// D81 Q2: how much data is flowing through my system.
	for _, want := range []string{"812 GB", "44.0 GB", "4,102", "317"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not show %q — D81 Q2 (how much data is flowing) is "+
				"unanswered by this render", want)
		}
	}
	// D81 Q1: what packages constitute the bulk of it.
	if !strings.Contains(body, "typescript") {
		t.Error("the heaviest package is not on the page — D81 Q1 is unanswered")
	}
	// The unattributed bucket must be NAMED, not left as an empty cell that reads as a
	// rendering bug. If it ever dominates, the ranking above it is not describing the
	// traffic, and an operator can only notice that if it is visible.
	if !strings.Contains(body, "(unattributed)") {
		t.Error("the empty-package row renders as a blank cell rather than a named bucket")
	}
	// D81 Q5: failures to pull due to corruption.
	if !strings.Contains(body, "Truncated relays") {
		t.Error("the integrity counters are absent — D81 Q5 is unanswered")
	}
}

// TestCapacityPageSaysWhenThereIsNoTrafficAtAll is the honesty check.
//
// An all-zero page and a page reporting a genuinely quiet window look identical. The
// difference matters — one means "nothing happened", the other can mean "the firewall is
// not reporting and you are flying blind" — so the page must say which it is rather than
// showing a wall of zeroes and letting the operator assume.
func TestCapacityPageSaysWhenThereIsNoTrafficAtAll(t *testing.T) {
	rec := getCapacity(t, &fakeApproval{}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /capacity = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No traffic recorded") {
		t.Error("an empty window renders as zeroes with no explanation. A dashboard that " +
			"cannot distinguish 'quiet' from 'not reporting' trains people to ignore it.")
	}
}

// TestCapacityFailsLoudlyWhenTheControlPlaneIsUnreachable — both reads, separately.
//
// The tempting shape is to render whatever succeeded and leave the rest at zero. That is
// the exact defect this file exists to prevent: a partial page is read as a complete one.
func TestCapacityFailsLoudlyWhenTheControlPlaneIsUnreachable(t *testing.T) {
	for _, tc := range []struct {
		name string
		fake *fakeApproval
	}{
		{"summary read fails", &fakeApproval{flowErr: errBoom}},
		{"package ranking read fails", &fakeApproval{flowPkgErr: errBoom}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := getCapacity(t, tc.fake, "")
			if rec.Code != http.StatusBadGateway {
				t.Errorf("GET /capacity = %d, want 502. A backend failure rendered as a "+
					"page means the operator reads zeroes as 'no traffic' when the truth "+
					"is 'we could not ask'.", rec.Code)
			}
		})
	}
}

// TestCapacityPassesTheFilterThroughToBothReads.
//
// Without this, the page can show the right-looking numbers for the WRONG WINDOW — the
// most expensive kind of wrong, because nothing about it looks broken. Both reads must
// receive the same filter, or the ranking describes a different period than the totals.
func TestCapacityPassesTheFilterThroughToBothReads(t *testing.T) {
	f := &fakeApproval{}
	getCapacity(t, f, "?ecosystem=npm&instance=fw-1&from=2026-09-01T00:00:00Z&to=2026-09-02T00:00:00Z")

	want := flowFilter{Ecosystem: "npm", Instance: "fw-1",
		From: "2026-09-01T00:00:00Z", To: "2026-09-02T00:00:00Z"}
	if f.flowFlt != want {
		t.Errorf("FlowSummary got filter %+v, want %+v", f.flowFlt, want)
	}
	if f.flowPFlt != want {
		t.Errorf("FlowPackages got filter %+v, want %+v — the totals and the ranking would "+
			"be describing different windows on the same page", f.flowPFlt, want)
	}
}

// TestFlowFilterQueryOmitsEmptyFields — a bare page load must not pin a window.
//
// Sending `?from=&to=` is not the same as sending nothing: it asks the approval service to
// parse empty strings as timestamps rather than to apply its own default window.
func TestFlowFilterQueryOmitsEmptyFields(t *testing.T) {
	if got := (flowFilter{}).query(); got != "" {
		t.Errorf("empty filter produced %q, want an empty query string", got)
	}
	got := flowFilter{Ecosystem: "npm"}.query()
	if got != "?ecosystem=npm" {
		t.Errorf("filter query = %q, want ?ecosystem=npm", got)
	}
}

// TestTheWireFormatMatchesTheApprovalService is the drift guard, and the reason this file
// is not just a rendering test.
//
// console/flowclient.go declares its own structs rather than importing the approval
// service's, deliberately — the console is an HTTP client of the control plane, not a
// library user of it, and sharing the type would delete that seam. The cost is that the
// JSON tags must agree, and a rename on one side decodes to ZERO on the other. It does not
// error. It renders "0 B" and looks like a quiet week.
//
// So this pins the tags against a literal payload in the approval service's own encoding.
// If someone renames bytes_client, this fails here rather than on an operator's screen.
func TestTheWireFormatMatchesTheApprovalService(t *testing.T) {
	// Every field non-zero and distinct, so a MISWIRING (two fields swapped) is caught as
	// well as a missing one. All-1s would pass a swapped pair.
	const payload = `{
	  "requests": 11, "bytes_upstream": 22, "bytes_client": 33,
	  "truncated": 44, "relay_errors": 55, "transport_errors": 66,
	  "upstream_status": 77, "meta_errors": 88, "retries": 99,
	  "packages": 111
	}`
	var got flowSummary
	if err := json.Unmarshal([]byte(payload), &got); err != nil {
		t.Fatalf("decoding the approval service's summary shape: %v", err)
	}
	want := flowSummary{
		Requests: 11, BytesUpstream: 22, BytesClient: 33,
		Truncated: 44, RelayErrors: 55, TransportErrors: 66,
		UpstreamStatus: 77, MetaErrors: 88, Retries: 99,
		Packages: 111,
	}
	if got != want {
		t.Errorf("summary decoded as %+v, want %+v.\nA field that decodes to zero renders "+
			"as '0 B' and reads as a quiet week rather than as a bug — which is why this "+
			"is pinned rather than trusted.", got, want)
	}

	const pkgPayload = `[{"package":"left-pad","ecosystem":"npm",
	  "requests":7,"bytes_upstream":8,"bytes_client":9}]`
	var pkgs []flowPackage
	if err := json.Unmarshal([]byte(pkgPayload), &pkgs); err != nil {
		t.Fatalf("decoding the package ranking shape: %v", err)
	}
	wantPkg := flowPackage{Package: "left-pad", Ecosystem: "npm",
		Requests: 7, BytesUpstream: 8, BytesClient: 9}
	if len(pkgs) != 1 || pkgs[0] != wantPkg {
		t.Errorf("package row decoded as %+v, want [%+v]", pkgs, wantPkg)
	}
}

// TestHumanBytesUsesDecimalUnits.
//
// Base 1000, not 1024, and it is a deliberate choice rather than an oversight: this number
// sits next to a network pipe, and network capacity is quoted in decimal units. Binary
// units here would disagree with the operator's own bandwidth graph by 7% for no reason
// they could see from the page.
func TestHumanBytesUsesDecimalUnits(t *testing.T) {
	for _, tc := range []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{999, "999 B"},
		{1000, "1.0 kB"},
		{1024, "1.0 kB"}, // NOT "1.0 KiB" and not "1024 B"
		{812_000_000_000, "812 GB"},
		{1_500_000, "1.5 MB"},
	} {
		if got := humanBytes(tc.in); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHumanCountGroupsThousands(t *testing.T) {
	for _, tc := range []struct {
		in   int64
		want string
	}{{0, "0"}, {999, "999"}, {1000, "1,000"}, {4102, "4,102"}, {1234567, "1,234,567"}} {
		if got := humanCount(tc.in); got != tc.want {
			t.Errorf("humanCount(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestIntegrityRowsSeparateFaultsFromRetries.
//
// Retries are the retry logic WORKING. Showing them at the same visual weight as a
// corruption count manufactures alarm, and a dashboard that cries wolf is one people stop
// reading — the same failure this project has already fixed twice in its CI gate.
func TestIntegrityRowsSeparateFaultsFromRetries(t *testing.T) {
	rows := integrityRows(flowSummary{Truncated: 1, Retries: 900})
	var sawBenignRetry, sawFaultTruncated bool
	for _, r := range rows {
		if strings.Contains(strings.ToLower(r.Label), "retr") && r.Benign {
			sawBenignRetry = true
		}
		if strings.Contains(strings.ToLower(r.Label), "truncated") && !r.Benign {
			sawFaultTruncated = true
		}
		if r.Meaning == "" {
			t.Errorf("counter %q has no explanation. A bare counter name is not actionable "+
				"by an operator who has never read our source.", r.Label)
		}
	}
	if !sawBenignRetry {
		t.Error("retries are not marked benign — 900 successful retries would render as " +
			"alarming as 900 corrupted transfers")
	}
	if !sawFaultTruncated {
		t.Error("truncated relays are marked benign — that is the one counter meaning a " +
			"developer may be holding an incomplete artifact")
	}
}

// TestCapacityIsReachableWithoutCredentials pins the tier/auth posture.
//
// D88 is explicit that anything computed on the customer's own hardware from data already
// in their instance is FREE, and names Phase C as carrying no tier check anywhere in its
// code path. This page is also a READ, so it must behave like the other reads: available
// without the override credential, which only gates writes.
func TestCapacityIsReachableWithoutCredentials(t *testing.T) {
	srv := &server{approval: &fakeApproval{}} // no auth configured
	req := httptest.NewRequest(http.MethodGet, "/capacity", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Errorf("GET /capacity = %d without credentials. Reads are unauthenticated on "+
			"this console by design, and D88 forbids gating this page at all.", rec.Code)
	}
}
