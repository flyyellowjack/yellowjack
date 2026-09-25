package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// Tests for #50 acceptance item 2: a block must name what happens next and who decides.
//
// The gap this closes is narrow but expensive. A block already said WHY ("score 2.1 <
// threshold 5.0"), which tells a developer they are stuck without telling them how to
// get unstuck. #50 records what people do at that point: they route around the control
// — shadow SaaS, personal devices, or hand-rolling the dependency, which is more
// dangerous than the vetted package they were denied.

func decodeBlock(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("block body is not the JSON shape npm parses: %v (body=%s)", err, rec.Body)
	}
	return body
}

// TestNextStepNeverLeaksIntoTheMachineReason is the property most likely to be broken
// later, and the one with the least visible consequence when it is.
//
// `reason` is what the audit log stores and what the console renders in the queue. If
// the guidance sentence is appended there too, every stored decision record grows a
// paragraph of advice — and advice ages: it will still be telling an auditor in 2028 to
// ask a reviewer about a package decided in 2026.
func TestNextStepNeverLeaksIntoTheMachineReason(t *testing.T) {
	rec := httptest.NewRecorder()
	writeBlockDecision(rec, "npm", "evil-pkg", Decision{
		Reason: "score 2.1 < threshold 5.0",
		Deny:   denyScore,
	})

	body := decodeBlock(t, rec)
	if body["reason"] != "score 2.1 < threshold 5.0" {
		t.Errorf("the machine reason was rewritten to %q — it must stay exactly what the "+
			"gate decided, because it is what the audit log keeps", body["reason"])
	}
	if body["nextStep"] == "" {
		t.Fatal("nextStep is empty for a queued denial")
	}
	if strings.Contains(body["reason"], body["nextStep"]) {
		t.Error("the guidance was folded into the machine reason")
	}
	// The header carries the same split.
	if got := rec.Header().Get("X-Yellowjack-Reason"); got != "score 2.1 < threshold 5.0" {
		t.Errorf("X-Yellowjack-Reason = %q, want the bare reason", got)
	}
	if rec.Header().Get("X-Yellowjack-Next-Step") == "" {
		t.Error("X-Yellowjack-Next-Step is unset, so body-less clients get no guidance")
	}
}

// TestBlockedPackagePrintsTheNextStepWhereNpmShowsIt.
//
// npm prints ONLY the "error" field. Guidance carried anywhere else reaches the operator
// log and never the developer — the same defect the e2e ladder caught for the reason
// itself, so it gets the same assertion rather than the same rediscovery.
func TestBlockedPackagePrintsTheNextStepWhereNpmShowsIt(t *testing.T) {
	rec := httptest.NewRecorder()
	writeBlockDecision(rec, "npm", "evil-pkg", Decision{Reason: "score 2.1 < threshold 5.0", Deny: denyScore})

	printed := decodeBlock(t, rec)["error"]
	if !strings.Contains(printed, "score 2.1 < threshold 5.0") {
		t.Error(`the printed message lost the reason`)
	}
	if !strings.Contains(printed, "approval queue") {
		t.Error("the printed message does not say what happens next; the developer sees " +
			"only that they are blocked, which is the state that gets routed around")
	}
}

// TestWaitingHelpsOnlyWhereItActuallyHelps is the distinction the whole feature turns on.
func TestWaitingHelpsOnlyWhereItActuallyHelps(t *testing.T) {
	// Queued kinds: a person must act, and re-running never will.
	for _, kind := range []denyKind{denyScore, denyUnscorable, denyUnverified} {
		step := nextStepFor(kind)
		if !strings.Contains(step, "Nothing retries on its own") {
			t.Errorf("%s: does not say that nothing retries, so re-running looks worth trying", kind)
		}
		if !strings.Contains(step, "approval queue") {
			t.Errorf("%s: never mentions the queue the package is actually sitting in", kind)
		}
	}

	// Already ruled: waiting is not just useless, someone has already decided.
	if step := nextStepFor(denyHuman); !strings.Contains(step, "already reviewed") {
		t.Error("a human denial does not say a person already ruled on it")
	}

	// Malware: must NOT invite an override. Offering an approval path here reads as
	// "ask nicely and this malware will be let through".
	mal := nextStepFor(denyKnownMalware)
	if strings.Contains(mal, "approval queue") || strings.Contains(mal, "can approve it") {
		t.Errorf("the known-malware step points at an approval path: %q. That invites a "+
			"request to override a published advisory.", mal)
	}
	if !strings.Contains(mal, "advisory") {
		t.Error("the known-malware step does not say this is a published advisory, which " +
			"is what distinguishes it from a policy threshold the operator could relax")
	}
}

// TestIntegrityRefusalsDoNotPromiseAReview.
//
// A path/filename/signature mismatch writes no pending record. Telling the developer a
// reviewer will look at it would be a promise nothing keeps — and worse, it invites an
// override request, where an override would clear a package/artifact mismatch: the
// confused-deputy bypass #67 closed.
func TestIntegrityRefusalsDoNotPromiseAReview(t *testing.T) {
	rec := httptest.NewRecorder()
	writeBlock(rec, "npm", "lodash", "artifact-binding", "artifact path does not belong to the requested package", notAReviewItem)

	body := decodeBlock(t, rec)
	if strings.Contains(body["nextStep"], "approval queue") {
		t.Errorf("an integrity refusal promises a review that will never happen: %q", body["nextStep"])
	}
	if !strings.Contains(body["nextStep"], "no approval will clear this") {
		t.Error("the integrity refusal does not say that an approval will not help, so the " +
			"developer's next move is to go and ask for exactly the override that would " +
			"reopen the confused-deputy bypass")
	}
}

// TestOciBlocksCarryTheNextStepToo: OCI has its own body shape, and it drifted from the
// npm branch once before (only the npm branch was dropping the reason).
func TestOciBlocksCarryTheNextStepToo(t *testing.T) {
	rec := httptest.NewRecorder()
	writeBlockDecision(rec, "oci", "evil/img", Decision{Reason: "score 1.0 < threshold 5.0", Deny: denyScore})

	if !strings.Contains(rec.Body.String(), "approval queue") {
		t.Errorf("the OCI error body carries no next step: %s", rec.Body)
	}
	if rec.Header().Get("X-Yellowjack-Next-Step") == "" {
		t.Error("OCI responses do not set the next-step header")
	}
}

// TestNoNextStepIsInventedForAnUnknownKind.
//
// A denial kind added later must render NO guidance rather than falling through to a
// message written for a different situation. Wrong advice on a security refusal is worse
// than none: it sends the developer down a path that cannot resolve their block.
func TestNoNextStepIsInventedForAnUnknownKind(t *testing.T) {
	if got := nextStepFor(denyKind("some-kind-added-later")); got != "" {
		t.Errorf("an unrecognized denial kind produced guidance %q, which was written for "+
			"a different case", got)
	}
	if got := nextStepFor(denyNone); got != "" {
		t.Errorf("denyNone produced %q; it is not a denial at all", got)
	}
}
