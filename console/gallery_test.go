package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// galleryFake is a console backend with a realistic day in it: a queue with the three
// kinds of wait, blocks of every attribution, a fleet with one quiet replica. It exists
// so every page is rendered against data shaped like production rather than against the
// one-row fixtures the focused tests use -- which is where a template that only breaks
// on a populated field hides.
func galleryFake(now time.Time) *fakeApproval {
	f64 := func(v float64) *float64 { return &v }
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	policy := &policyDoc{
		Digest: "4f2a91c0d1e2",
		Chains: []policyChain{
			{Name: "verdict", DefaultAction: "reject", Rules: []policyRule{
				{Name: "allow: OSSF score at or above threshold", Action: "allow"},
				{Name: "block everything", Action: "reject"},
				{Name: "terminal: block everything (implicit)", Action: "reject", Implicit: true},
			}},
		},
		Values: map[string]string{
			"mode": "enforce", "score_threshold": "5", "unscorable_policy": "block",
			"min_release_age_days": "7", "scorecard_mode": "scanner",
			"known_malware_feed":  "1482 enforced (1482 package-wide, 0 version-pinned), sha256:9c1d2e3f4a5b",
			"operator_allow_list": "12 entries, sha256:aa11bb22cc33",
			"operator_deny_list":  "4 entries, sha256:dd44ee55ff66",
		},
		Lists: []policyList{
			{Kind: "allow", Path: "/etc/yj/allow.txt", Names: []string{"lodash@4.17.21", "left-pad"}, Digest: "aa11bb22cc33dd44"},
			{Kind: "deny", Path: "/etc/yj/deny.txt", Names: []string{"colorama-helper"}, Digest: "dd44ee55ff66aa77"},
		},
	}
	return &fakeApproval{
		decisions: []decision{
			{Package: "left-pad-utils", Verdict: "pending", Note: "package \"left-pad-utils\" does not declare a usable source repository", FirstSeen: ago(2 * time.Hour), UpdatedAt: ago(2 * time.Hour)},
			{Package: "pandas-profiler-lite", Verdict: "pending", Note: "scored 3.8, below required 5.0", FirstSeen: ago(5 * time.Hour), UpdatedAt: ago(5 * time.Hour)},
			{Package: "com.acme:json-helpers", Verdict: "pending", Note: "no security score available for github.com/acme/json-helpers", FirstSeen: ago(30 * time.Hour), UpdatedAt: ago(30 * time.Hour)},
			{Package: "tiny-invariant", Verdict: "approved", DecidedBy: "priya", Note: "vendored by the design system", FirstSeen: ago(72 * time.Hour), UpdatedAt: ago(70 * time.Hour)},
			{Package: "event-streamer", Verdict: "denied", DecidedBy: "priya", Note: "abandoned; use eventemitter3", FirstSeen: ago(96 * time.Hour), UpdatedAt: ago(95 * time.Hour)},
		},
		events: []event{
			{ID: 41, Package: "reqeusts", Ecosystem: "npm", Action: "block", DenyKind: "known-malware", Rule: "MAL-2026-1181", Source: "known-malware feed", Reason: "package \"reqeusts\" is listed as known malware (MAL-2026-1181); refused without contacting upstream", SourceIP: "10.20.0.14", At: ago(20 * time.Minute), PolicyDigest: "4f2a91c0d1e2", Taken: "block"},
			{ID: 40, Package: "axios", Ecosystem: "npm", Action: "block", DenyKind: "known-malware", Rule: "MAL-2026-0990", Source: "known-malware feed", Reason: "axios@1.14.1 is listed as known malware (MAL-2026-0990)", SourceIP: "10.20.0.31", At: ago(2 * time.Hour), PolicyDigest: "4f2a91c0d1e2", Taken: "block"},
			{ID: 39, Package: "colorama-helper", Ecosystem: "pypi", Action: "block", DenyKind: "operator-denied", Rule: "deny-list:colorama-helper", Source: "deny list", Reason: "package \"colorama-helper\" is on this organisation's deny list", SourceIP: "10.20.0.8", At: ago(4 * time.Hour), PolicyDigest: "4f2a91c0d1e2", Taken: "block"},
			{ID: 38, Package: "pandas-profiler-lite", Ecosystem: "pypi", Action: "block", DenyKind: "score-below-threshold", Rule: "verdict#2", Source: "policy 4f2a91c0d1e2", Score: f64(3.8), Threshold: f64(5), ScoredChecks: 15, TotalChecks: 18, ComputedWithout: []string{"CI-Tests", "License"}, Reason: "BLOCKED: \"pandas-profiler-lite\" scored 3.8, below required 5.0", SourceIP: "10.30.1.2", At: ago(5 * time.Hour), PolicyDigest: "4f2a91c0d1e2", Taken: "block"},
			{ID: 37, Package: "lodash", Ecosystem: "npm", Action: "allow", Score: f64(8.1), Threshold: f64(5), Reason: "score 8.1 >= threshold 5.0", SourceIP: "10.20.0.14", At: ago(6 * time.Hour), PolicyDigest: "4f2a91c0d1e2", Taken: "allow"},
			{ID: 36, Package: "left-pad-utils", Ecosystem: "npm", Action: "block", DenyKind: "unscorable", Rule: "verdict#3", Source: "policy 4f2a91c0d1e2", Reason: "BLOCKED: unscorable", SourceIP: "10.20.0.31", At: ago(2 * time.Hour), PolicyDigest: "4f2a91c0d1e2", Taken: "block"},
		},
		ipRows:  []ipCount{{IP: "10.20.0.14", Count: 812, LastAt: ago(20 * time.Minute)}, {IP: "10.30.1.2", Count: 377, LastAt: ago(5 * time.Hour)}, {IP: "", Count: 4, LastAt: ago(90 * 24 * time.Hour)}},
		actRows: []packageActivity{{Package: "moment", Ecosystem: "npm", Events: 12, LastAt: ago(61 * 24 * time.Hour)}, {Package: "lodash", Ecosystem: "npm", Events: 2318, LastAt: ago(6 * time.Hour)}},
		health: []instanceHealth{
			{Instance: "gate-npm-1", Ecosystem: "npm", ReportedAt: ago(20 * time.Second), Policy: policy, PolicyDigest: policy.Digest},
			{Instance: "gate-pypi-1", Ecosystem: "pypi", ReportedAt: ago(40 * time.Second), Policy: policy, PolicyDigest: policy.Digest},
			{Instance: "gate-maven-1", Ecosystem: "maven", ReportedAt: ago(35 * time.Second), Policy: policy, PolicyDigest: policy.Digest},
			{Instance: "gate-oci-1", Ecosystem: "oci", ReportedAt: ago(50 * time.Second), Policy: policy, PolicyDigest: policy.Digest},
		},
		fps: []falsePositive{{ID: 1, EventID: 39, Package: "colorama-helper", Ecosystem: "pypi", DenyKind: "operator-denied", Rule: "deny-list:colorama-helper", Note: "internal fork, not the typosquat", ReportedBy: "dana", At: ago(3 * time.Hour)}},
		status: packageStatus{
			Package: "axios", Ecosystem: "npm", DecisionGranularity: "package name, every version",
			LastObserved:    &event{Action: "block", At: ago(2 * time.Hour), Reason: "axios@1.14.1 is listed as known malware"},
			UpstreamHarvest: &upstreamHarvest{LatestVersion: "1.14.1", PublishedAt: ago(26 * time.Hour), VersionCount: 112, Maintainers: 3},
		},
		statusOK: true,
		summary: eventSummary{Since: ago(24 * time.Hour), Allowed: 2318, Blocked: 14, BlockedServed: 0, Sources: 47,
			ByDenyKind: map[string]int{"known-malware": 9, "score-below-threshold": 3, "operator-denied": 2}},
		flowSum:  flowSummary{Requests: 2318, BytesUpstream: 3 << 30, BytesClient: 3 << 30, Packages: 412, Retries: 3},
		flowPkgs: []flowPackage{{Package: "typescript", Ecosystem: "npm", Requests: 88, BytesUpstream: 1 << 29, BytesClient: 1 << 29}},
	}
}

// galleryRoutes is every page a person can open. A page added to the console belongs
// here, so it is rendered against production-shaped data at least once.
var galleryRoutes = map[string]string{
	"overview":        "/",
	"decisions":       "/decisions",
	"decision-score":  "/decisions?pkg=pandas-profiler-lite",
	"stopped":         "/stopped",
	"stopped-malware": "/stopped/view?id=40&package=axios",
	"stopped-score":   "/stopped/view?id=38&package=pandas-profiler-lite",
	"audit":           "/audit",
	"downloads":       "/downloads",
	"activity":        "/activity",
	"false-positives": "/false-positives",
	"policy":          "/policy",
	"lists":           "/lists",
	"lookup":          "/lookup?package=axios&ecosystem=npm",
	"capacity":        "/capacity",
}

// TestGalleryRendersEveryPage renders every page, signed in with writes on, and fails on
// the three ways html/template degrades silently instead of erroring: a missing field
// renders "<no value>", an unsafe URL renders "ZgotmplZ", and an execution error after
// the first byte leaves a page cut off before its closing tag.
//
// With CONSOLE_GALLERY_DIR set it also writes each page there, which is how the redesign
// is looked at in a browser without a running control plane.
func TestGalleryRendersEveryPage(t *testing.T) {
	now := time.Now().UTC()
	s := &server{approval: galleryFake(now), auth: &basicAuth{user: "priya", pass: "pw"}}
	dir := os.Getenv("CONSOLE_GALLERY_DIR")
	for name, route := range galleryRoutes {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, route, nil)
			req.SetBasicAuth("priya", "pw")
			rr := httptest.NewRecorder()
			s.ServeHTTP(rr, req)
			body := rr.Body.String()
			if rr.Code != http.StatusOK {
				t.Fatalf("GET %s = %d: %.300s", route, rr.Code, body)
			}
			for _, bad := range []string{"<no value>", "ZgotmplZ"} {
				if strings.Contains(body, bad) {
					i := strings.Index(body, bad)
					t.Errorf("GET %s rendered %q near: %q", route, bad, body[max(0, i-120):i])
				}
			}
			if !strings.Contains(body, "</html>") {
				t.Errorf("GET %s stops before </html>: the template failed part-way", route)
			}
			if !strings.Contains(body, `class="sidebar"`) {
				t.Errorf("GET %s has no sidebar: the page is not on the shared shell", route)
			}
			if dir != "" {
				if err := os.WriteFile(filepath.Join(dir, name+".html"), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
