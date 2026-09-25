package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// #153: a gate-to-control-plane sender must read the ANSWER.
//
// The defect was uniform across three senders -- handle the transport error, then
// closeDrained(resp.Body) without a look at the status -- and the serious instance is the
// audit trail: with the approval service UP and its database DOWN, /v1/events answers 500
// for every event, the gate logged nothing, and the drop counter the console relies on to
// say "this record is incomplete" stayed at ZERO throughout.

// answering returns a control-plane stub whose status the test can change between calls.
func answering(t *testing.T) (*httptest.Server, func(int), *int64) {
	t.Helper()
	var status atomic.Int32
	status.Store(http.StatusCreated)
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(int(status.Load()))
	}))
	t.Cleanup(srv.Close)
	return srv, func(s int) { status.Store(int32(s)) }, &hits
}

func TestARefusedAuditEventIsCountedAsDropped(t *testing.T) {
	srv, answer, hits := answering(t)
	a := &auditEmitter{endpoint: srv.URL + "/v1/events", client: srv.Client()}
	buf := captureStdLog(t)
	ev := auditEvent{Package: "left-pad", Ecosystem: "npm", Action: auditActionBlock}

	// CONTROL: an accepted event is not a drop and says nothing. Without this, the count
	// below would also be satisfied by a sender that counts EVERY post.
	a.post(ev)
	a.post(ev)
	if got := a.Dropped(); got != 0 || strings.Contains(buf.String(), "audit emit") {
		t.Fatalf("CONTROL: two accepted events gave dropped=%d and logged %q", got, buf.String())
	}

	answer(http.StatusInternalServerError) // approval is up, its store is failing
	for i := 0; i < 5; i++ {
		a.post(ev)
	}
	if got := a.Dropped(); got != 5 {
		t.Errorf("five events answered 500 gave dropped=%d, want 5. Those records were NOT stored; a counter "+
			"that stays at 0 tells the console the audit trail is complete while all of it is being lost", got)
	}
	if n := strings.Count(buf.String(), "REFUSED a decision record"); n != 1 {
		t.Errorf("five refusals logged %d line(s), want exactly 1: never is the bug, and one per event is how "+
			"the fix gets filtered out\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "AUDIT TRAIL IS INCOMPLETE") || !strings.Contains(buf.String(), "Enforcement is unaffected") {
		t.Errorf("the line must say what is broken (the record) and what is not (enforcement):\n%s", buf.String())
	}

	buf.Reset()
	answer(http.StatusCreated)
	a.post(ev)
	if !strings.Contains(buf.String(), "accepted again") || !strings.Contains(buf.String(), "5 were lost") {
		t.Errorf("recovery must be logged WITH the total lost, or the last line in the log still says REFUSED:\n%s", buf.String())
	}
	if got := a.Dropped(); got != 5 {
		t.Errorf("an accepted event moved the drop count to %d", got)
	}
	if atomic.LoadInt64(hits) != 8 {
		t.Fatalf("the stub saw %d posts, want 8; the assertions above did not exercise what they claim", atomic.LoadInt64(hits))
	}
}

// TestRefusedAuditEventsReachTheHeartbeat asserts the wiring rather than assuming it: the
// count is only useful because the console reads it from the beat as audit_dropped.
func TestRefusedAuditEventsReachTheHeartbeat(t *testing.T) {
	srv, answer, _ := answering(t)
	answer(http.StatusInternalServerError)
	a := &auditEmitter{endpoint: srv.URL + "/v1/events", client: srv.Client()}
	captureStdLog(t)
	for i := 0; i < 3; i++ {
		a.post(auditEvent{Package: "p", Action: auditActionAllow})
	}

	e := newFlowEmitter("", "fw-test", srv.Client(), newFlowRecorder("npm"), time.Hour, a)
	body, err := e.heartbeatBody()
	if err != nil {
		t.Fatal(err)
	}
	var beat struct {
		AuditDropped int64 `json:"audit_dropped"`
	}
	if err := json.Unmarshal(body, &beat); err != nil {
		t.Fatal(err)
	}
	if beat.AuditDropped != 3 {
		t.Errorf("the heartbeat reports audit_dropped=%d after 3 refused events, want 3", beat.AuditDropped)
	}
}

func TestARefusedPendingRecordOrScoreIsLogged(t *testing.T) {
	srv, answer, _ := answering(t)
	f := &Firewall{cfg: Config{ApprovalURL: srv.URL}, client: srv.Client()}
	buf := captureStdLog(t)

	// CONTROL: accepted writes are quiet.
	f.recordPending("left-pad", "unscorable")
	f.recordScore("github.com/a/b", 7.5, scoreCoverage{})
	if s := buf.String(); strings.Contains(s, "recordPending") || strings.Contains(s, "recordScore") {
		t.Fatalf("CONTROL: accepted writes logged:\n%s", s)
	}

	answer(http.StatusBadRequest)
	f.recordPending("left-pad", "unscorable")
	f.recordPending("right-pad", "unscorable")
	f.recordScore("github.com/a/b", 7.5, scoreCoverage{})
	f.recordScore("github.com/c/d", 1.0, scoreCoverage{})
	s := buf.String()
	if n := strings.Count(s, "REFUSED a pending record"); n != 1 {
		t.Errorf("two refused pending records logged %d line(s), want 1:\n%s", n, s)
	}
	// The consequence is the point of this line: the developer was told "pending".
	if !strings.Contains(s, "NOT in the approval queue") {
		t.Errorf("a refused pending record must say the package is NOT queued although the client was told it is:\n%s", s)
	}
	if n := strings.Count(s, "REFUSED a score"); n != 1 {
		t.Errorf("two refused scores logged %d line(s), want 1:\n%s", n, s)
	}

	buf.Reset()
	answer(http.StatusOK)
	f.recordPending("left-pad", "unscorable")
	f.recordScore("github.com/a/b", 7.5, scoreCoverage{})
	if s := buf.String(); strings.Count(s, "accepted again") != 2 {
		t.Errorf("recovery of both senders must be logged:\n%s", s)
	}
}

// ── the guard: the fourth such sender must not be written next month ────────────────

// statusBlindSenderAllowlist holds functions that make an HTTP call and never read
// StatusCode ON PURPOSE, keyed by file and function, with the reason.
var statusBlindSenderAllowlist = map[string]string{
	"proxy.go:doWithRetry": "returns the *http.Response to its caller, which is where the status is read; " +
		"reading it here too would be a second, divergent policy",
}

// statusBlindSenders returns "file:func" for every function that performs an HTTP client
// call and never mentions StatusCode.
func statusBlindSenders(files map[string]*ast.File) (blind []string, senders int) {
	for path, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			calls, reads := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.AssignStmt:
					if isHTTPCallAssignment(x) {
						calls = true
					}
				case *ast.SelectorExpr:
					if x.Sel.Name == "StatusCode" {
						reads = true
					}
				}
				return true
			})
			if !calls {
				continue
			}
			senders++
			if !reads {
				blind = append(blind, fmt.Sprintf("%s:%s", filepath.ToSlash(filepath.Base(path)), fn.Name.Name))
			}
		}
	}
	sort.Strings(blind)
	return blind, senders
}

// isHTTPCallAssignment recognises an HTTP round trip by its SHAPE, not by what the client
// happens to be called: `resp, err := X.Do|Get|Post|Head(...)` -- two results from a
// method with one of those names.
//
// The first version keyed on the receiver's NAME ("client", "http") and silently skipped
// eight call sites where the client is a parameter called `c` (ecosystem.go, maven.go,
// mavenage.go, oci.go): it examined 12 functions and looked healthy. Found by listing
// every call site with grep and comparing the two numbers, which is the only way a
// recogniser's blind spot shows up -- from the inside it just reports a smaller total.
// The two-result shape is what excludes the lookalikes: sync.Once.Do, Header.Get and
// url.Values.Get all return one value or none.
func isHTTPCallAssignment(as *ast.AssignStmt) bool {
	if len(as.Lhs) != 2 || len(as.Rhs) != 1 {
		return false
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "Do", "Get", "Post", "Head", "PostForm":
		return true
	}
	return false
}

func TestNoGateSenderIgnoresTheControlPlanesAnswer(t *testing.T) {
	files := map[string]*ast.File{}
	for _, path := range firewallPackageFiles(t) {
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		files[path] = f
	}
	blind, senders := statusBlindSenders(files)
	// COVERAGE FLOOR, one below the current count and meant to be edited deliberately: if a
	// sender was removed, lower it and say why. It exists because a recogniser that loses
	// sight of half the package reports a smaller total and an equally clean result.
	const minSendersExamined = 18
	if senders < minSendersExamined {
		t.Fatalf("recognised only %d HTTP-calling function(s) in the gate; the recogniser is broken and a "+
			"clean result would mean nothing", senders)
	}
	seen := map[string]bool{}
	for _, s := range blind {
		seen[s] = true
		if _, ok := statusBlindSenderAllowlist[s]; !ok {
			t.Errorf("%s makes an HTTP call and never reads resp.StatusCode, so a 4xx or 5xx is treated as success. "+
				"That is how refused audit events went uncounted (#153). Read the status; if ignoring it is "+
				"deliberate, add the function to statusBlindSenderAllowlist WITH the reason.", s)
		}
	}
	for s := range statusBlindSenderAllowlist {
		if !seen[s] {
			t.Errorf("statusBlindSenderAllowlist names %s, which no longer ignores the status (or no longer "+
				"exists). Remove the entry.", s)
		}
	}
	t.Logf("examined %d HTTP-calling functions in the gate", senders)
}

func TestTheStatusBlindSenderGuardCanFail(t *testing.T) {
	const src = `package p

func blind(c *http.Client, req *http.Request) { resp, _ := c.Do(req); closeDrained(resp.Body) }
func reads(c *http.Client, req *http.Request) { resp, _ := c.Do(req); _ = resp.StatusCode }
func notASender(h http.Header, o *sync.Once) { _ = h.Get("x"); o.Do(func() {}) }
`
	f, err := parser.ParseFile(token.NewFileSet(), "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
	blind, senders := statusBlindSenders(map[string]*ast.File{"fixture.go": f})
	if senders != 2 || len(blind) != 1 || blind[0] != "fixture.go:blind" {
		t.Fatalf("senders=%d blind=%v, want 2 senders and exactly [fixture.go:blind]: `reads` looks at the "+
			"status, and neither Header.Get nor Once.Do is an HTTP round trip", senders, blind)
	}
}

// TestAnUndeliverableAuditEventIsCountedAsDropped covers the commonest outage: the
// approval service is simply down. The connection is REFUSED quickly, so the queue drains
// and the buffer-full path never fires -- before #153 every such event was logged and none
// was counted, which made docs/FAILURE_MODES.md's "lost events are counted" false for the
// case an operator is most likely to meet.
func TestAnUndeliverableAuditEventIsCountedAsDropped(t *testing.T) {
	srv, _, _ := answering(t)
	a := &auditEmitter{endpoint: srv.URL + "/v1/events", client: srv.Client()}
	buf := captureStdLog(t)

	// CONTROL: while the service is up, nothing is dropped.
	a.post(auditEvent{Package: "p", Action: auditActionAllow})
	if a.Dropped() != 0 {
		t.Fatalf("CONTROL: a delivered event counted as dropped (%d)", a.Dropped())
	}

	srv.Close() // the service goes away
	for i := 0; i < 4; i++ {
		a.post(auditEvent{Package: "p", Action: auditActionAllow})
	}
	if got := a.Dropped(); got != 4 {
		t.Errorf("four undeliverable events gave dropped=%d, want 4", got)
	}
	if n := strings.Count(buf.String(), "cannot be DELIVERED"); n != 1 {
		t.Errorf("four undeliverable events logged %d line(s), want exactly 1:\n%s", n, buf.String())
	}
}
