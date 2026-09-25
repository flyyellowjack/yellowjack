package main

import (
	"strings"
	"testing"
)

// A PyPI yank on the operator's page.
//
// The harvest field is shared with npm's deprecation, which is what makes this worth
// a test rather than an assumption: the two signals mean different things, and the
// page must not describe one as the other.

// TestAYankIsNotDescribedAsAWholePackageDeprecation.
//
// PEP 592 yanks a RELEASE. The callout used to lead with "The maintainer has
// deprecated this package", which for a yanked latest release is simply untrue — the
// other releases are unaffected. An operator acting on that would pull a dependency
// that did not need pulling, from the page whose whole job is to be trustworthy.
func TestAYankIsNotDescribedAsAWholePackageDeprecation(t *testing.T) {
	fa := &fakeApproval{
		statusOK: true,
		status: packageStatus{
			Package:   "evil",
			Ecosystem: "pypi",
			Upstream:  "present",
			UpstreamHarvest: &upstreamHarvest{
				LatestVersion: "1.0.1",
				Deprecated:    "the latest release was yanked: ships a backdoor",
			},
		},
	}
	body := lookupGet(t, newTestServer(fa), "?package=evil&ecosystem=pypi").Body.String()

	if strings.Contains(body, "has deprecated this package") {
		t.Error("a per-release yank is rendered as a whole-package deprecation; the other " +
			"releases are unaffected, so the page is making a false claim")
	}
	// The maintainer's own words still have to reach the page, and still in the
	// callout rather than the muted availability style.
	if !strings.Contains(body, "ships a backdoor") {
		t.Error("the yank reason is absent from the page")
	}
	if !strings.Contains(body, `class="deprecated"`) {
		t.Error("the yank is not in its own callout — in the muted .avail style it reads as " +
			"a footnote rather than as the maintainer's warning")
	}
}

// TestTheWarningLeadStillReadsCorrectlyForNpm is the other half. Making the lead
// scope-neutral must not turn npm's deprecation into something vague: the detail line
// carries the specific claim, and it still has to be there.
func TestTheWarningLeadStillReadsCorrectlyForNpm(t *testing.T) {
	fa := &fakeApproval{
		statusOK: true,
		status: packageStatus{
			Package:   "left-pad",
			Ecosystem: "npm",
			Upstream:  "present",
			UpstreamHarvest: &upstreamHarvest{
				LatestVersion: "1.3.0",
				Deprecated:    "use String.padStart",
			},
		},
	}
	body := lookupGet(t, newTestServer(fa), "?package=left-pad&ecosystem=npm").Body.String()

	if !strings.Contains(body, "use String.padStart") {
		t.Error("the npm deprecation message no longer reaches the page")
	}
	if !strings.Contains(body, "published a warning") {
		t.Error("there is no warning lead at all now, so the deprecation has no heading and " +
			"reads as loose prose next to the version numbers")
	}
}

// TestAHealthyPackageHasNoWarningCallout — the NEGATIVE CONTROL for both above. Each
// would pass against a page that rendered the callout unconditionally.
func TestAHealthyPackageHasNoWarningCallout(t *testing.T) {
	fa := &fakeApproval{
		statusOK: true,
		status: packageStatus{
			Package:         "requests",
			Ecosystem:       "pypi",
			Upstream:        "present",
			UpstreamHarvest: &upstreamHarvest{LatestVersion: "2.31.0", VersionCount: 3},
		},
	}
	body := lookupGet(t, newTestServer(fa), "?package=requests&ecosystem=pypi").Body.String()

	if strings.Contains(body, "published a warning") || strings.Contains(body, `class="deprecated"`) {
		t.Error("a package with no maintainer warning still renders the warning callout")
	}
	// Anti-vacuity: the harvest must actually be on the page, or the assertion above
	// is satisfied by a section that rendered nothing.
	if !strings.Contains(body, "2.31.0") {
		t.Error("the harvest is absent from the page, so the assertion above proves nothing")
	}
}
