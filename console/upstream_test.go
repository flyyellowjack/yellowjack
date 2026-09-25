package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// The registry's own metadata on the developer lookup page (D158's protocol-scraping
// step). These are page-level: the approval-service tests prove the harvest is correct,
// these prove an operator can actually see it and cannot misread it.

func TestUpstreamHarvestReachesThePage(t *testing.T) {
	fa := &fakeApproval{
		statusOK: true,
		status: packageStatus{
			Package:   "lodash",
			Ecosystem: "npm",
			Upstream:  "present",
			UpstreamHarvest: &upstreamHarvest{
				LatestVersion: "4.17.21",
				PublishedAt:   time.Date(2021, 2, 20, 15, 42, 16, 0, time.UTC),
				VersionCount:  114,
				Maintainers:   2,
			},
			ScoreAvailability: "no-source-repo-known-for-this-package",
			Cache:             "not-implemented",
		},
	}
	body := lookupGet(t, newTestServer(fa), "?package=lodash&ecosystem=npm").Body.String()

	for _, want := range []string{"4.17.21", "114", "What the registry says"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not carry %q — the harvest was fetched and then not rendered", want)
		}
	}
	// The one line that keeps this section honest: everything else on this page is
	// historical, and a reader who takes the registry data as equally stale would draw
	// the wrong conclusion about a package that was just published.
	if !strings.Contains(body, "current rather than historical") {
		t.Error("the page does not distinguish the live registry read from the historical " +
			"record around it")
	}
}

// TestADeprecationIsNotBuriedInFootnotes. A maintainer saying "do not use this" is the
// most actionable line the page can carry, and rendering it in the muted availability
// style would make it quieter than our own footnotes.
func TestADeprecationIsNotBuriedInFootnotes(t *testing.T) {
	fa := &fakeApproval{
		statusOK: true,
		status: packageStatus{
			Package:         "left-pad",
			Upstream:        "present",
			UpstreamHarvest: &upstreamHarvest{LatestVersion: "1.3.0", Deprecated: "use String.padStart"},
		},
	}
	body := lookupGet(t, newTestServer(fa), "?package=left-pad").Body.String()

	if !strings.Contains(body, "use String.padStart") {
		t.Fatal("the maintainer's deprecation message is absent from the page")
	}
	if !strings.Contains(body, `class="deprecated"`) {
		t.Error("the deprecation is not rendered in its own callout — in the muted .avail style " +
			"it reads as a footnote rather than as the maintainer's warning")
	}
	// NOT an error state. Deprecated is not blocked, and colouring it as a refusal
	// would tell the developer their build was stopped when it was not.
	if strings.Contains(body, "This is a report about the past, not a live verdict") == false {
		t.Error("the report/promise banner vanished, which is a regression from #73")
	}
}

// TestAnUnreachableRegistryDoesNotRenderAsAHealthyPackage is the page-level twin of the
// approval service's test, and it is the misreading that actually costs something: a
// section that silently renders nothing reads as "we checked and it was fine".
func TestAnUnreachableRegistryDoesNotRenderAsAHealthyPackage(t *testing.T) {
	fa := &fakeApproval{
		statusOK: true,
		status: packageStatus{
			Package:  "lodash",
			Upstream: "upstream-registry-unreachable",
		},
	}
	body := lookupGet(t, newTestServer(fa), "?package=lodash").Body.String()

	if !strings.Contains(body, "could not reach the registry") {
		t.Error("an unreachable registry rendered with no explanation — an empty section reads " +
			"as 'we checked and found no problem'")
	}
	// And it must be framed as OUR connectivity, not as a finding about the package.
	if !strings.Contains(body, "not about the package") {
		t.Error("the page does not say the failure is about this deployment rather than about " +
			"the package, which is how a developer concludes their dependency is broken")
	}
}

// TestNotInTheRegistryIsSaidPlainly — the most common real cause of a failed install is
// a typo, and this is the page that should say so.
func TestNotInTheRegistryIsSaidPlainly(t *testing.T) {
	fa := &fakeApproval{
		statusOK: true,
		status:   packageStatus{Package: "lodahs", Upstream: "not-found-in-the-registry"},
	}
	body := lookupGet(t, newTestServer(fa), "?package=lodahs").Body.String()

	if !strings.Contains(body, "does not have a package by this name") {
		t.Error("a package the registry has never heard of is not stated plainly")
	}
	if !strings.Contains(body, "this is not a block") {
		t.Error("the page does not say we did NOT refuse it — otherwise a developer reads a " +
			"typo as an enforcement action by us")
	}
}

// TestAHostileRegistryStringCannotInjectMarkup — the adversarial tier. The deprecation
// message is attacker-controlled: anyone who can publish a package chooses that text,
// and it lands on an operator's authenticated console page.
func TestAHostileRegistryStringCannotInjectMarkup(t *testing.T) {
	const payload = `<img src=x onerror=alert(1)>`
	fa := &fakeApproval{
		statusOK: true,
		status: packageStatus{
			Package:         "evil",
			Upstream:        "present",
			UpstreamHarvest: &upstreamHarvest{LatestVersion: payload, Deprecated: payload},
		},
	}
	rec := lookupGet(t, newTestServer(fa), "?package=evil")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	// Assert on LIVE MARKUP, not on the substring: the payload's text is expected to
	// appear, escaped. An earlier version of this check looked for "onerror=" and
	// passed on `&#39;&gt;&lt;img` — escaped text that is perfectly safe.
	if strings.Contains(body, "<img src=x") {
		t.Errorf("a registry-supplied string reached the page as live markup. Whoever publishes " +
			"a package chooses that text, so this is stored XSS against the operator console.")
	}
	// Anti-vacuity: the value must actually be on the page, escaped. Without this the
	// assertion above passes for a page that dropped the field entirely.
	if !strings.Contains(body, "onerror") {
		t.Error("the payload is absent altogether, so the escaping assertion proves nothing")
	}
}
