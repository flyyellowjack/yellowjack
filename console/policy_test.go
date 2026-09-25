package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func shippedPolicyDoc(digest string) *policyDoc {
	return &policyDoc{
		Digest: digest,
		Chains: []policyChain{
			{
				Name:          "verdict",
				DefaultAction: "reject",
				Rules: []policyRule{
					{Name: "allow: OSSF score at or above threshold", Action: "allow"},
					{Name: "block everything", Action: "reject"},
					{Name: "terminal: block everything (implicit)", Action: "reject", Implicit: true},
				},
			},
			{
				Name:          "bytes",
				DefaultAction: "allow-but-log",
				Rules: []policyRule{
					{Name: "reject: denied on a positive finding", Action: "reject"},
					{Name: "allow-but-log: byte gate is in visibility mode", Action: "allow-but-log"},
					{Name: "terminal: block everything (implicit)", Action: "reject", Implicit: true},
				},
			},
		},
		Values: map[string]string{"score_threshold": "5", "byte_gate": "allow-but-log"},
	}
}

func getPolicyPage(t *testing.T, f *fakeApproval) *httptest.ResponseRecorder {
	t.Helper()
	srv := &server{approval: f}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/policy", nil))
	return rec
}

// The page renders the rules, in order, with their actions.
func TestPolicyPageRendersRules(t *testing.T) {
	f := &fakeApproval{health: []instanceHealth{{
		Instance: "fw-1", Ecosystem: "npm", ReportedAt: time.Now().UTC(),
		PolicyDigest: "abc", Policy: shippedPolicyDoc("abc"),
	}}}

	rec := getPolicyPage(t, f)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /policy = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"fw-1", "allow: OSSF score at or above threshold", "verdict", "bytes", "score_threshold"} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not mention %q", want)
		}
	}
}

// THE MISLEADING-RENDER TRAP, at the last mile.
//
// The firewall computes the byte chain's true default (allow-but-log, because the shipped
// chain ends in a match-all — D49's visibility-first posture). That correctness is worth
// nothing if the PAGE prints the terminal rule's action instead. An operator who reads
// "reject" believes their artifact route is fail-closed when it is not, and this is the
// last place that belief can be introduced.
//
// Sabotage check: render the last rule's action instead of .DefaultAction and this fails.
func TestPolicyPageShowsTheChainsRealDefault(t *testing.T) {
	f := &fakeApproval{health: []instanceHealth{{
		Instance: "fw-1", ReportedAt: time.Now().UTC(),
		PolicyDigest: "abc", Policy: shippedPolicyDoc("abc"),
	}}}

	body := getPolicyPage(t, f).Body.String()

	// The bytes chain's stated default must appear. Both chains render their default in
	// the same sentence, so find the one after the bytes heading.
	i := strings.Index(body, ">bytes<")
	if i < 0 {
		t.Fatal("no bytes chain rendered")
	}
	tail := body[i:]
	j := strings.Index(tail, "matching no rule above is")
	if j < 0 {
		t.Fatal("bytes chain does not state a default action")
	}
	stmt := tail[j : j+120]
	if !strings.Contains(stmt, "allow-but-log") {
		t.Errorf("bytes chain default rendered as %q — an operator would read their artifact route as fail-closed when D49 leaves it visibility-first", stmt)
	}
}

// DIVERGENCE IS THE POINT OF THE PAGE. Two fresh replicas on different policies must be
// called out, or the one thing an operator cannot learn any other way stays invisible.
func TestPolicyPageWarnsWhenReplicasDiverge(t *testing.T) {
	now := time.Now().UTC()
	f := &fakeApproval{health: []instanceHealth{
		{Instance: "fw-1", ReportedAt: now, PolicyDigest: "aaa", Policy: shippedPolicyDoc("aaa")},
		{Instance: "fw-2", ReportedAt: now, PolicyDigest: "bbb", Policy: shippedPolicyDoc("bbb")},
	}}

	body := getPolicyPage(t, f).Body.String()
	if !strings.Contains(body, "different policies") {
		t.Errorf("two replicas on different policies produced no divergence warning:\n%s", body)
	}
}

// ...and an agreeing fleet must NOT be warned about, or the warning means nothing.
func TestPolicyPageQuietWhenReplicasAgree(t *testing.T) {
	now := time.Now().UTC()
	f := &fakeApproval{health: []instanceHealth{
		{Instance: "fw-1", ReportedAt: now, PolicyDigest: "aaa", Policy: shippedPolicyDoc("aaa")},
		{Instance: "fw-2", ReportedAt: now, PolicyDigest: "aaa", Policy: shippedPolicyDoc("aaa")},
	}}

	body := getPolicyPage(t, f).Body.String()
	if strings.Contains(body, "different policies") {
		t.Errorf("a fleet in agreement was warned about divergence:\n%s", body)
	}
}

// A RETIRED REPLICA MUST NOT LIGHT THE WARNING FOREVER.
//
// instance_health keeps a row for every replica that ever reported, carrying whatever
// policy it last ran. Counting a long-dead one toward divergence would leave the banner
// permanently lit, and a warning that can never be cleared is one an operator learns to
// ignore — taking the real one with it. Same reasoning as the bounded window on the
// transfer-failure alert.
//
// Sabotage check: count every replica instead of only fresh ones, and this fails.
func TestStaleReplicaDoesNotTriggerDivergence(t *testing.T) {
	now := time.Now().UTC()
	f := &fakeApproval{health: []instanceHealth{
		{Instance: "fw-live", ReportedAt: now, PolicyDigest: "aaa", Policy: shippedPolicyDoc("aaa")},
		{Instance: "fw-retired", ReportedAt: now.Add(-30 * 24 * time.Hour), PolicyDigest: "old", Policy: shippedPolicyDoc("old")},
	}}

	body := getPolicyPage(t, f).Body.String()
	if strings.Contains(body, "different policies") {
		t.Errorf("a replica retired a month ago lit the divergence warning — it can never be cleared:\n%s", body)
	}
	// ...but it must still be LISTED. Hiding it would be the opposite mistake: a replica
	// that stopped reporting while still serving traffic is the row worth seeing.
	if !strings.Contains(body, "fw-retired") {
		t.Error("the stale replica was hidden; a replica that stopped reporting is exactly what an operator needs to see")
	}
}

// A replica reporting liveness but no policy is listed, not dropped — it is running a
// build from before policy reporting, which the operator needs to know.
func TestReplicaWithoutPolicyIsListed(t *testing.T) {
	now := time.Now().UTC()
	f := &fakeApproval{health: []instanceHealth{
		{Instance: "fw-new", ReportedAt: now, PolicyDigest: "aaa", Policy: shippedPolicyDoc("aaa")},
		{Instance: "fw-old-build", ReportedAt: now},
	}}

	body := getPolicyPage(t, f).Body.String()
	if !strings.Contains(body, "fw-old-build") {
		t.Errorf("a replica reporting no policy was silently omitted from a page titled 'what is being enforced':\n%s", body)
	}
	if !strings.Contains(body, "no policy") {
		t.Error("the page does not explain why that replica has no policy shown")
	}
}

// A control-plane outage must render as a page that says so — not a bare error, and
// emphatically not an empty page that reads as "no policy is in force".
func TestPolicyPageSurfacesAControlPlaneOutage(t *testing.T) {
	f := &fakeApproval{healthErr: errNotReachable}

	rec := getPolicyPage(t, f)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /policy = %d, want 200 with an explanation", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "could not be reached") {
		t.Errorf("outage not explained on the page:\n%s", body)
	}
	// The reassurance matters: an operator seeing this page blank during an incident must
	// not conclude the gate has stopped enforcing.
	if !strings.Contains(body, "keep enforcing") {
		t.Error("the outage message does not say the firewalls keep enforcing what they last loaded")
	}
}

// Grouping keys on the digest the REPLICA reported. Recomputing "sameness" here would be a
// second implementation of what makes two policies equal, and a source of phantom
// divergence.
func TestReplicasGroupByReportedDigest(t *testing.T) {
	now := time.Now().UTC()
	rows := []instanceHealth{
		{Instance: "a", ReportedAt: now, PolicyDigest: "same", Policy: shippedPolicyDoc("same")},
		{Instance: "b", ReportedAt: now, PolicyDigest: "same", Policy: shippedPolicyDoc("same")},
		{Instance: "c", ReportedAt: now, PolicyDigest: "other", Policy: shippedPolicyDoc("other")},
	}
	v := buildPolicyView(rows, now)

	if len(v.Groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(v.Groups))
	}
	// Largest first, so the policy most of the fleet runs leads.
	if len(v.Groups[0].Replicas) != 2 {
		t.Errorf("groups not ordered largest-first: got %d replicas in the first group", len(v.Groups[0].Replicas))
	}
	if !v.Diverged {
		t.Error("two distinct fresh policies did not set Diverged")
	}
}

// Clock skew between the approval service and this console must not render as a negative
// age, which reads as corrupt data in a view an operator is being asked to trust.
func TestFutureHeartbeatRendersAsJustNow(t *testing.T) {
	if got := humanAge(-2 * time.Second); got != "just now" {
		t.Errorf("humanAge(-2s) = %q, want %q — clock skew must not print a negative age", got, "just now")
	}
}

var errNotReachable = &notReachable{}

type notReachable struct{}

func (*notReachable) Error() string { return "dial tcp: connection refused" }
