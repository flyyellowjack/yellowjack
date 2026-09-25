package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Page-level tests for #50: the queue must expose STATE, AGE and DECIDER, and say what
// happens next and who decides it.
//
// The failure these guard against is not a crash. It is a queue page that looks fine
// and answers none of the three questions an operator asks when a developer is blocked
// — how long has this been sitting, what is supposed to happen now, and whose job is
// it. The issue traces that gap to observed behaviour: three independent bypass
// mechanisms, and teams hand-rolling the functionality rather than waiting.

func queueGet(t *testing.T, srv *server, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if srv.auth != nil {
		req.SetBasicAuth("admin", "secret")
	}
	srv.ServeHTTP(rec, req)
	return rec
}

func pendingFor(d time.Duration) decision {
	now := time.Now().UTC()
	return decision{
		Package:   "unscorable-thing",
		Verdict:   "pending",
		Note:      "no source repo",
		FirstSeen: now.Add(-d),
		UpdatedAt: now.Add(-d),
	}
}

// TestQueueShowsHowLongAPackageHasWaited — AGE, on the page, not just in a struct.
func TestQueueShowsHowLongAPackageHasWaited(t *testing.T) {
	fa := &fakeApproval{decisions: []decision{pendingFor(72 * time.Hour)}}
	body := queueGet(t, newTestServer(fa), "/decisions").Body.String()

	if !strings.Contains(body, "3 days") {
		t.Error("the queue does not show how long the package has been waiting — AGE is " +
			"the number the whole issue turns on")
	}
	// On the ROW, not merely somewhere on the page: the tab strip says "Waiting" too, so
	// the bare word would pass with no age rendered at all.
	if !strings.Contains(body, "Waiting 3 days") {
		t.Error(`the waiting row does not read "Waiting 3 days"`)
	}
}

// TestQueueFlagsAWaitPastTheTarget: #50's target is a queue measured in HOURS.
func TestQueueFlagsAWaitPastTheTarget(t *testing.T) {
	long := queueGet(t, newTestServer(&fakeApproval{decisions: []decision{pendingFor(90 * 24 * time.Hour)}}), "/decisions").Body.String()
	if !strings.Contains(long, `class="wait over"`) {
		t.Error("a 90-day wait is not flagged. This is the case the issue was filed from — " +
			"an operator reporting a three-month approval process.")
	}

	// The control: flagging everything is the same as flagging nothing.
	short := queueGet(t, newTestServer(&fakeApproval{decisions: []decision{pendingFor(2 * time.Hour)}}), "/decisions").Body.String()
	if strings.Contains(short, `class="wait over"`) {
		t.Error("a 2-hour wait was flagged as over target, but the target IS hours — " +
			"a warning that fires on healthy rows is one operators learn to ignore")
	}
}

// TestQueueSaysWhatHappensNextAndWhoDecides — the half of #50 that is not a column.
func TestQueueSaysWhatHappensNextAndWhoDecides(t *testing.T) {
	fa := &fakeApproval{decisions: []decision{pendingFor(2 * time.Hour)}}
	body := queueGet(t, newAuthedServer(fa, "admin", "secret"), "/decisions").Body.String()

	if !strings.Contains(body, "What happens next") {
		t.Error("the queue never says what happens next; a blocked developer's package " +
			"sits here with no stated process")
	}
	if !strings.Contains(body, "Who decides") {
		t.Error("the queue never says who decides")
	}
	if !strings.Contains(body, "admin") {
		t.Error("the decider is not named, so no one is accountable for the wait")
	}
	// The honest part: nothing retries and nothing expires (D102 made the two
	// non-verdict states plain 403s). Saying "we'll get to it" would be a lie.
	if !strings.Contains(body, "Nothing retries on its own") {
		t.Error("the page does not say that nothing retries or expires on its own, which " +
			"is what makes the wait unbounded rather than merely slow")
	}
}

// TestQueueWithNoCredentialSaysNoOneIsAccountable.
//
// An unauthenticated console cannot name a decider — and that absence IS the finding,
// not a blank to leave empty. Rendering nothing here would let a deployment with no
// accountable owner look identical to one with a named reviewer.
func TestQueueWithNoCredentialSaysNoOneIsAccountable(t *testing.T) {
	fa := &fakeApproval{decisions: []decision{pendingFor(2 * time.Hour)}}
	body := queueGet(t, newTestServer(fa), "/decisions").Body.String()

	if !strings.Contains(body, "no one is accountable") {
		t.Error("with no credential configured the queue does not say that nobody is " +
			"accountable for working it — the deployment looks the same as one that has " +
			"a named reviewer")
	}
	if !strings.Contains(body, "CONSOLE_AUTH_USER") {
		t.Error("the page does not say how to name a decider, so the finding is not actionable")
	}
}

// TestSettledRowsDoNotShowALiveWait: an approved package is not a backlog item.
func TestSettledRowsDoNotShowALiveWait(t *testing.T) {
	now := time.Now().UTC()
	fa := &fakeApproval{decisions: []decision{{
		Package: "approved-thing", Verdict: "approved", DecidedBy: "admin",
		FirstSeen: now.Add(-50 * time.Hour), UpdatedAt: now.Add(-2 * time.Hour),
	}}}
	body := queueGet(t, newTestServer(fa), "/decisions").Body.String()

	if !strings.Contains(body, "Waited") {
		t.Error(`the settled table should head its age column "Waited" (past tense), not "Waiting"`)
	}
	if strings.Contains(body, "What happens next") {
		t.Error("the next-step banner rendered with nothing pending — it tells the operator " +
			"to act on an empty queue")
	}
	// It waited ~2 days before someone ruled; that number is the accountability record.
	if !strings.Contains(body, "2 days") {
		t.Error("the settled row does not report how long it waited before being decided")
	}
}

// TestQueueRendersUnknownRatherThanZeroForLegacyRows.
//
// Rows written before this change carry no enqueue time. Rendering "under a minute"
// or "just now" for them would be a confident, wrong answer in the one column an
// operator uses to judge whether the queue is healthy.
func TestQueueRendersUnknownRatherThanZeroForLegacyRows(t *testing.T) {
	fa := &fakeApproval{decisions: []decision{{
		Package: "legacy", Verdict: "pending", UpdatedAt: time.Now().UTC(),
	}}}
	body := queueGet(t, newTestServer(fa), "/decisions").Body.String()

	if !strings.Contains(body, "unknown") {
		t.Error("a row with no enqueue time did not render as unknown")
	}
	for _, wrong := range []string{"under a minute", "just now"} {
		if strings.Contains(body, wrong) {
			t.Errorf("a row with no enqueue time rendered as %q — an unmeasurable wait "+
				"must not be reported as a short one", wrong)
		}
	}
}
