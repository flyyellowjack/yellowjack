package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// #139, the heartbeat: a cap that, when hit, turned a HEALTHY firewall into a DEAD one --
// silently, on both sides.
//
// The control plane refuses a beat over maxHealthBytes (64 KiB). The policy view inside
// the beat grows with the operator's lists, and measured 2026-09-20 two 200-name lists of
// ~160-character entries put it at 62.5 KB on their own. When that happened the control
// plane answered "invalid JSON body" -- to a sender that never read the status -- and the
// console showed a stale replica with no line anywhere saying why.
//
// Three properties, each with its control:
//
//	1. the sender's budget sits under the receiver's cap  (derived across the binaries)
//	2. an over-budget report sheds NAMES, never the beat   (control: a small one is whole)
//	3. a refusal is LOGGED, once per change of outcome     (control: acceptance is quiet)

// controlPlaneHeartbeatCap reads maxHealthBytes out of the approval service's source. The
// two are separate `package main` binaries with no shared constant, so this number is a
// wire contract nothing at compile time connects -- the older budget test in
// policyview_test.go carried a hand-copied `8 << 10` that went stale when the cap was
// raised to 64 KiB, which is the failure this derivation exists to make impossible.
func controlPlaneHeartbeatCap(t *testing.T) int {
	t.Helper()
	src, err := os.ReadFile("approval/healthhttp.go")
	if err != nil {
		t.Fatalf("read the control plane's heartbeat handler: %v", err)
	}
	m := regexp.MustCompile(`(?m)^const maxHealthBytes = (\d+) << (\d+)\s*$`).FindSubmatch(src)
	if m == nil {
		t.Fatal("could not find `const maxHealthBytes = N << M` in approval/healthhttp.go; this test is reading nothing")
	}
	n, _ := strconv.Atoi(string(m[1]))
	shift, _ := strconv.Atoi(string(m[2]))
	return n << shift
}

func TestTheHeartbeatBudgetIsBelowTheControlPlanesCap(t *testing.T) {
	limit := controlPlaneHeartbeatCap(t)
	if limit < 8<<10 {
		t.Fatalf("derived a control-plane cap of %d bytes, which is implausibly small; the pattern matched the wrong thing", limit)
	}
	// A quarter of the cap as margin: the receiver counts the WHOLE body, and anything
	// added to the beat later (a new counter, a longer instance name) lands in it.
	if heartbeatBudget > limit*3/4 {
		t.Errorf("heartbeatBudget is %d, the control plane refuses anything over %d. A beat built to the budget "+
			"must still be accepted with margin, because a refused beat reads as a DEAD replica", heartbeatBudget, limit)
	}
}

// longListView builds the worst case the reporting cap allows: maxListNamesReported names
// of nameLen characters each.
func longListView(kind string, nameLen int) ListView {
	names := make([]string, maxListNamesReported)
	for i := range names {
		names[i] = fmt.Sprintf("registry.example.com/%s/img%04d", strings.Repeat("a", nameLen-30), i)
	}
	return ListView{Kind: kind, Path: "/etc/yellowjack/" + kind + ".txt", Names: names, Omitted: 7, Digest: "sha256:" + kind}
}

func emitterReporting(view *PolicyView, url string, client *http.Client) *flowEmitter {
	e := newFlowEmitter(url, "fw-test", client, newFlowRecorder("oci"), time.Hour, nil)
	e.policy = func() *PolicyView { return view }
	return e
}

func TestAnOversizePolicyReportShedsNamesInsteadOfLosingTheBeat(t *testing.T) {
	decode := func(t *testing.T, body []byte) PolicyView {
		t.Helper()
		var beat struct {
			Instance string      `json:"instance"`
			Policy   *PolicyView `json:"policy"`
		}
		if err := json.Unmarshal(body, &beat); err != nil || beat.Policy == nil || beat.Instance != "fw-test" {
			t.Fatalf("the beat does not decode to an identified report: %v\n%s", err, body[:min(len(body), 200)])
		}
		return *beat.Policy
	}

	// CONTROL: a report that fits is sent WHOLE. Without this, "names were shed" below
	// would also pass for a sender that strips them from every beat.
	small := &PolicyView{Digest: "d1", Lists: []ListView{longListView("allow", 40)}}
	body, err := emitterReporting(small, "", http.DefaultClient).heartbeatBody()
	if err != nil {
		t.Fatal(err)
	}
	if got := decode(t, body); len(got.Lists) != 1 || len(got.Lists[0].Names) != maxListNamesReported || got.Lists[0].Omitted != 7 {
		t.Fatalf("CONTROL: a %d-byte report (budget %d) did not arrive whole: %d names, omitted %d",
			len(body), heartbeatBudget, len(got.Lists[0].Names), got.Lists[0].Omitted)
	}

	big := &PolicyView{Digest: "d2", Values: map[string]string{"mode": "enforce"},
		Lists: []ListView{longListView("allow", 200), longListView("deny", 200)}}
	whole, _ := json.Marshal(big)
	if len(whole) <= controlPlaneHeartbeatCap(t) {
		t.Fatalf("the fixture is only %d bytes and would be ACCEPTED as it stands, so this test exercises nothing", len(whole))
	}

	body, err = emitterReporting(big, "", http.DefaultClient).heartbeatBody()
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > heartbeatBudget {
		t.Fatalf("the beat is %d bytes, over the %d-byte budget: the control plane refuses it and this "+
			"healthy replica reads as DEAD", len(body), heartbeatBudget)
	}
	got := decode(t, body)
	if got.Digest != "d2" || got.Values["mode"] != "enforce" {
		t.Errorf("shedding changed what the control plane DECIDES on: digest %q, values %v", got.Digest, got.Values)
	}
	if len(got.Lists) != 2 {
		t.Fatalf("shedding dropped a list entirely (%d left); the page would show a configured list as absent", len(got.Lists))
	}
	for _, l := range got.Lists {
		if len(l.Names) != 0 || l.Omitted != maxListNamesReported+7 {
			t.Errorf("%s list: %d names, omitted %d; want 0 names and omitted %d, so the page says "+
				"TRUNCATED rather than EMPTY", l.Kind, len(l.Names), l.Omitted, maxListNamesReported+7)
		}
		if l.Digest != "sha256:"+l.Kind || l.Path == "" {
			t.Errorf("%s list lost its digest or path (%q, %q); divergence detection depends on them", l.Kind, l.Digest, l.Path)
		}
	}
	// The source view must be untouched: it is shared with the /policy handler, and a
	// sender that mutated it would blank the names for every other reader.
	if len(big.Lists[0].Names) != maxListNamesReported || big.Lists[0].Omitted != 7 {
		t.Error("heartbeatBody MUTATED the policy view it was given")
	}
}

func TestARefusedHeartbeatIsLoggedOncePerChange(t *testing.T) {
	status := http.StatusAccepted
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		defer mu.Unlock()
		w.WriteHeader(status)
	}))
	defer srv.Close()
	set := func(s int) { mu.Lock(); status = s; mu.Unlock() }
	e := emitterReporting(nil, srv.URL, srv.Client())
	// captureStdLog(t) is the package's existing helper (npmversion_test.go). heartbeat()
	// logs on the calling goroutine, so reading the buffer between calls is race-free.
	buf := captureStdLog(t)
	logged := func(fn func()) string { buf.Reset(); fn(); return buf.String() }

	// CONTROL: acceptance from the first beat is QUIET. A line per healthy beat would bury
	// the one that matters.
	if out := logged(func() { e.heartbeat(); e.heartbeat() }); strings.Contains(out, "flow heartbeat") {
		t.Fatalf("CONTROL: accepted beats logged something:\n%s", out)
	}

	set(http.StatusRequestEntityTooLarge)
	out := logged(func() { e.heartbeat(); e.heartbeat(); e.heartbeat() })
	if n := strings.Count(out, "REFUSED as too large"); n != 1 {
		t.Errorf("three refused beats logged the refusal %d time(s), want exactly 1: silence is the bug "+
			"being fixed, and a line per interval is how the fix gets muted\n%s", n, out)
	}
	if !strings.Contains(out, "STALE") || !strings.Contains(out, "enforcement is unaffected") {
		t.Errorf("the refusal must say what the operator will SEE (a stale replica) and what is NOT "+
			"affected (enforcement):\n%s", out)
	}

	set(http.StatusInternalServerError)
	if out := logged(e.heartbeat); !strings.Contains(out, "HTTP 500") {
		t.Errorf("a change from 413 to 500 was not logged:\n%s", out)
	}
	set(http.StatusAccepted)
	if out := logged(e.heartbeat); !strings.Contains(out, "accepted again") {
		t.Errorf("recovery was not logged, so the last line in the log still says REFUSED:\n%s", out)
	}
}
