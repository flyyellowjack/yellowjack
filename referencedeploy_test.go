package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The reference deployment is the file an evaluator RUNS and then COPIES. That makes it
// worse than documentation when it rots: a stale paragraph wastes someone's afternoon,
// but a stale compose file becomes somebody's deployment.
//
// Two gates already cover parts of it and were widened to reach it when it was written:
// scripts/pinned-images.sh (every image pinned by digest, #22) and
// scripts/exposed-ports.sh (only front doors on all interfaces). Both were sabotaged
// against this exact file to prove the widening works.
//
// What neither can see is whether the settings it names still EXIST, and whether the
// walkthrough still shows the product doing its job. That is what this file asserts.

const (
	referenceComposePath = "deploy/reference/docker-compose.yml"
	referenceDocPath     = "docs/REFERENCE_DEPLOYMENT.md"
)

// TestReferenceDeploymentOnlyNamesRealSettings is the drift guard that matters most.
//
// A renamed FW_* var does not break this compose file loudly -- the container starts,
// the demo appears to work, and whichever control the old name carried is simply OFF.
// FW_MIN_RELEASE_AGE_DAYS is the sharp case: silently losing it means the deployment
// stops gating on release age while still reporting a healthy boot.
func TestReferenceDeploymentOnlyNamesRealSettings(t *testing.T) {
	inCode := configVarsIn(t, configSourcePath)
	for _, path := range []string{referenceComposePath, referenceDocPath} {
		inFile := configVarsIn(t, path)
		if len(inFile) == 0 {
			t.Fatalf("no FW_* settings found in %s -- either it stopped configuring anything "+
				"or the extraction broke, and both make this test vacuous", path)
		}
		for _, v := range sorted(inFile) {
			if !inCode[v] {
				t.Errorf("%s names %s, which does not appear in %s. A setting that no longer "+
					"exists is silently ignored: the container starts, the demo looks fine, and "+
					"whatever that knob controlled is off.", path, v, configSourcePath)
			}
		}
	}
}

// TestReferenceDeploymentKeepsItsShape pins what the example is FOR, not how it is worded.
//
// The failure this prevents is the example decaying into a plain stack definition -- the
// thing README's old "Quick start" already was, which built three binaries and never
// showed a verdict.
func TestReferenceDeploymentKeepsItsShape(t *testing.T) {
	compose := readTextFile(t, referenceComposePath)
	doc := readTextFile(t, referenceDocPath)

	for _, want := range []struct{ in, needle, why string }{
		{compose, "FW_DENY_LIST", "the demo runs on a signal that needs no account, no scanner and no network call of ours"},
		{compose, ":ro", "the list directory is mounted read-only: the gate reads an injected list and never writes one (D103)"},
		{compose, "FW_PUBLIC_URL", "unset, artifact URLs are minted from the request Host and land in lockfiles that way (#19)"},
		// Three ecosystems, one topology. The example was npm-only for its first two
		// weeks and an evaluator with a Python or Docker shop could not use it; these pin
		// that the second and third gate stay, each with its own registry stand-in.
		{compose, `FW_ECOSYSTEM: "pypi"`, "the PyPI gate is part of the example, not a footnote"},
		{compose, `FW_ECOSYSTEM: "oci"`, "the OCI gate is part of the example, not a footnote"},
		{compose, "REGISTRY_PROXY_REMOTEURL", "the OCI stand-in is a pull-through cache of the public registry, which is the shape a customer registry takes"},
		{compose, "nginx-pypi.conf", "the PyPI stand-in proxies the public index the way a Nexus/Artifactory remote does"},
		{doc, "403", "the walkthrough must show a refusal, not just a stack that starts"},
		{doc, "200", "and something being allowed -- a gate that blocks everything is not a gate"},
		{doc, "X-Yellowjack-Kind", "the refusal is machine-readable, and someone integrating us needs to see that"},
		{doc, "report", "report mode is the answer to 'nobody switches a blocking gate on cold', and it belongs on this page"},
		// D192 trims the launch core to time-gating + lists + a UI. The walkthrough
		// demonstrated the lists and the console and never the time gate -- the half
		// named FIRST -- which is why this leg exists.
		{doc, "YJ_MIN_RELEASE_AGE_DAYS", "the release-age floor is the only control here needing neither a list nor a scanner"},
		// Steps 8 and 9: the other two ecosystems, each shown REFUSING and ALLOWING, and
		// PyPI shown in its own shape -- a yanked index, not a 403 -- with the honest
		// statement of what reached the registry, which differs from npm's.
		{doc, "data-yanked", "PyPI's refusal is a PEP 592 yank carrying the reason, and the page must show that rather than pretend it is a 403"},
		{doc, "no artifact bytes were", "the PyPI reason must say what the yank transport actually did -- measured to fetch the index and not the bytes, where the old wording claimed neither"},
		{doc, "docker pull", "the OCI gate must be exercised by the real client, not only by curl"},
		{doc, "curl -I", "docker resolves tags with HEAD, so the reason lives only in headers and the page has to show how to read them"},
		{doc, "pip install", "the PyPI gate must be exercised by the real client, not only by curl"},
		{doc, "withheld", "the time gate's observable is versions being WITHHELD from the packument, not a 403; a reader who expects a refusal will think it is broken"},
	} {
		if !strings.Contains(want.in, want.needle) {
			t.Errorf("%q is gone: %s", want.needle, want.why)
		}
	}

	// The topology claim is the reason this example exists, and it is expressed by an
	// ABSENCE -- the registry publishes no host port, so no route reaches it except
	// through the gate. An absence is exactly what a reader will "tidy up", so it is
	// pinned here: the registry service must not gain a ports: entry.
	for _, reg := range []string{"custreg", "custreg-pypi", "custreg-oci"} {
		if strings.Contains(serviceBlock(t, compose, reg), "ports:") {
			t.Errorf("the %s service now publishes a host port. That reopens the bypass the "+
				"in-front topology exists to close: a developer could reach the registry without "+
				"passing the gate, and every refusal in %s becomes optional.", reg, referenceDocPath)
		}
	}
}

// TestReferenceDeploymentContainerLegPinsItsAbsences pins what the container gate
// deliberately does NOT do. An absence is what a reader "completes" -- the reason the
// no-ports check above exists -- and both of these were expensive to establish.
//
// FW_MIN_RELEASE_AGE_DAYS is absent from firewall-oci on purpose (#127): a registry
// publishes no push time, the only date in the pull path is written by whoever built
// the image, and 4 of 7 real images sampled report the 1970 epoch. The gate does not
// apply the release window to OCI at all (whyOCIHasNoReleaseWindow in firewall.go),
// so the knob here would look armed and refuse nothing. When #127 lands a trustworthy
// time, this test is what says the example should now set it.
func TestReferenceDeploymentContainerLegPinsItsAbsences(t *testing.T) {
	compose := readTextFile(t, referenceComposePath)
	doc := readTextFile(t, referenceDocPath)

	oci := serviceBlock(t, compose, "firewall-oci")
	if len(oci) < 200 {
		t.Fatalf("serviceBlock returned %d bytes for firewall-oci; every check below would pass on nothing", len(oci))
	}
	// Read over the SETTINGS, not the raw block: the compose file explains the absence
	// in a comment that names the variable, and the first version of this check fired on
	// its own explanation. A guard that cannot tell a setting from prose about a setting
	// is the shape #122 and #128 were both made of.
	if strings.Contains(withoutComments(oci), "FW_MIN_RELEASE_AGE_DAYS") {
		t.Errorf("firewall-oci now sets FW_MIN_RELEASE_AGE_DAYS. There is no trustworthy " +
			"publication time for a container image -- the only date is publisher-written " +
			"`created`, and real images already report the epoch -- and the gate does not " +
			"apply the window to OCI, so this would appear armed and refuse nothing (#127). " +
			"Remove it, or close #127 first.")
	}
	// And the explanation must stay beside the absence, or the next reader adds the knob.
	if !strings.Contains(oci, "#127") {
		t.Errorf("firewall-oci no longer explains, next to its settings, why it has no " +
			"release window (#127); an unexplained absence gets 'completed'")
	}

	for _, want := range []struct{ needle, why string }{
		{"every tag", "an OCI operator-list entry is repository-wide (#128), the one rule that surprises people"},
		{"names a tag or digest", "and the page shows the gate's own warning for it, so a reader recognises it in a log"},
		{"1970", "the epoch is why there is no time gate for images; without the measurement the absence reads as an oversight"},
		{"--insecure-registry", "docker treats only a LOOPBACK registry as plain HTTP; the page must say why the demo address is localhost, or the reader's first hostname fails"},
	} {
		if !strings.Contains(doc, want.needle) {
			t.Errorf("%s no longer says %q: %s", referenceDocPath, want.needle, want.why)
		}
	}
}

// TestReferenceDeploymentGuardsCanFail is the negative control. Every check above is a
// substring test over a file, the kind that quietly stops matching anything -- a renamed
// path, an empty read -- and then passes forever.
func TestReferenceDeploymentGuardsCanFail(t *testing.T) {
	compose := readTextFile(t, referenceComposePath)
	if len(compose) < 500 {
		t.Fatalf("%s read back as %d bytes; the substring checks above would pass vacuously",
			referenceComposePath, len(compose))
	}
	// A setting that cannot exist must not be found in the config source.
	if configVarsIn(t, configSourcePath)["FW_THIS_SETTING_DOES_NOT_EXIST"] {
		t.Fatal("config.go appears to contain an invented setting, so the membership check proves nothing")
	}
	// The refusal check must be able to notice an absence.
	if strings.Contains("a page that only starts a stack", "403") {
		t.Fatal("the refusal check matched text with no 403 in it")
	}
	// And the ports check must be able to SEE a ports entry -- the whole custreg
	// assertion is worthless if serviceBlock returns nothing.
	fw := serviceBlock(t, compose, "firewall")
	for _, gate := range []string{"firewall-pypi", "firewall-oci"} {
		if !strings.Contains(serviceBlock(t, compose, gate), "ports:") {
			t.Fatalf("serviceBlock could not find %s's ports entry, so the no-ports check on its "+
				"registry stand-in proves nothing", gate)
		}
	}
	if !strings.Contains(fw, "ports:") {
		t.Fatalf("serviceBlock could not find the firewall's ports entry, so its use on custreg "+
			"proves nothing; got %d bytes", len(fw))
	}
	// withoutComments must drop a comment that NAMES a setting and keep a real setting,
	// or the absence check on firewall-oci passes on a block that sets the knob -- or
	// fails on its own explanation, which is how its first version behaved.
	sample := `      # FW_IN_A_COMMENT: 1
      FW_REAL: 2
`
	if got := withoutComments(sample); strings.Contains(got, "FW_IN_A_COMMENT") || !strings.Contains(got, "FW_REAL") {
		t.Fatalf("withoutComments cannot tell a setting from a comment about one: %q", got)
	}
}

// withoutComments drops whole-line YAML comments so a check can ask what a service
// CONFIGURES rather than what its documentation mentions. Deliberately only
// whole-line: a trailing comment after a real setting is part of that setting's line
// and dropping it could hide the setting itself.
func withoutComments(block string) string {
	var out []string
	for _, l := range strings.Split(block, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func readTextFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// serviceBlock returns the lines of one compose service: from "  <name>:" at two-space
// indent up to the next line at that same indent. Deliberately indentation-based rather
// than a YAML parse -- pulling in a YAML dependency to read our own example file would
// add attack surface to the binary for the sake of a test.
func serviceBlock(t *testing.T, compose, name string) string {
	t.Helper()
	lines := strings.Split(compose, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimRight(l, "\r") == "  "+name+":" {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("no service %q in %s -- it was renamed or removed, and every assertion about "+
			"it is now vacuous", name, referenceComposePath)
	}
	var out []string
	for _, l := range lines[start:] {
		trimmed := strings.TrimRight(l, "\r")
		if strings.HasPrefix(trimmed, "  ") && !strings.HasPrefix(trimmed, "   ") &&
			strings.HasSuffix(trimmed, ":") {
			break // the next service at the same indent
		}
		out = append(out, trimmed)
	}
	return strings.Join(out, "\n")
}

// TestTheWalkthroughDocumentsTheModeTheDeploymentRuns exists because the walkthrough
// drifted silently: !329 switched the reference deployment to FW_SCORECARD_MODE=off and
// left docs/REFERENCE_DEPLOYMENT.md showing a `scorecard mode: stub` banner, explaining
// the stub pairing, and stating that `off` did not exist. Every gate stayed green --
// nothing compared the documented banner with the deployment it documents.
//
// The expectation is DERIVED from the compose file rather than written here, so the next
// mode change fails this test until the walkthrough is re-captured, whichever way it goes.
func TestTheWalkthroughDocumentsTheModeTheDeploymentRuns(t *testing.T) {
	compose := readTextFile(t, referenceComposePath)
	m := regexp.MustCompile(`(?m)^\s*FW_SCORECARD_MODE:\s*"?([a-z]+)"?\s*$`).FindAllStringSubmatch(withoutComments(compose), -1)
	if len(m) == 0 {
		t.Fatal("no FW_SCORECARD_MODE found in the reference compose; this check is reading nothing")
	}
	mode := m[0][1]
	for _, mm := range m[1:] {
		if mm[1] != mode {
			t.Fatalf("the reference deployment's services disagree about FW_SCORECARD_MODE (%q vs %q); "+
				"the walkthrough can only document one", mode, mm[1])
		}
	}

	doc := readTextFile(t, "docs/REFERENCE_DEPLOYMENT.md")
	want := "scorecard mode:    " + mode
	if !strings.Contains(doc, want) {
		t.Errorf("docs/REFERENCE_DEPLOYMENT.md does not show %q, but the deployment it walks through runs "+
			"FW_SCORECARD_MODE=%s. The captured banner is stale -- re-capture it.", want, mode)
	}
	if mode == "off" && strings.Contains(doc, "has no `off` yet") {
		t.Error("the walkthrough still says FW_SCORECARD_MODE has no `off`, while running it")
	}
}
