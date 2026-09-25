package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D312, applied: *"if the administrator allows it, it is allowed."*
//
// An allow entry that NAMES A RELEASE outranks a known-malware advisory for that release.
// Three things it must not do — each of them the harm D312 itself names — have a test
// here beside the override, because a precedence rule is only as good as its edges:
//
//	1. a NAME-scoped allow must not override an advisory,
//	2. an override must not apply when the request's version is unknown,
//	3. the operator's own deny list still wins.
//
// The override must also be LOUD (D312's second condition): the decision carries it, the
// log says it, and the audit record exports it. An override nobody can see is
// indistinguishable from a gate that missed something.

func overrideFirewall(t *testing.T, feed, allow, deny string) *Firewall {
	t.Helper()
	cfg := Config{
		Ecosystem:        "oci", // the identity carries the version, so Evaluate decides alone
		UpstreamRegistry: "https://registry.example.invalid",
		ScorecardMode:    scorecardModeOff,
		UnscorablePolicy: "allow",
		MalwareListPath:  feed,
	}
	if allow != "" {
		cfg.AllowListPath = writeList(t, "allow.txt", allow)
	}
	if deny != "" {
		cfg.DenyListPath = writeList(t, "deny.txt", deny)
	}
	f, err := NewFirewall(cfg)
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	return f
}

const (
	ovImage = "library/hijacked"
	ovBad   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	ovOther = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// ovFeed condemns BOTH releases. The discriminator in the first test needs a release
// that the ADVISORY names and the ALLOW does not; with only ovBad pinned, ovOther was
// served on its own merits and the test passed for the wrong reason (measured — it failed
// on the first run, correctly).
func ovFeed(t *testing.T) string {
	t.Helper()
	return writeFeed(t, `{"id":"MAL-2026-OV","ecosystem":"oci","name":"`+ovImage+`","versions":["`+ovBad+`","`+ovOther+`"]}`)
}

func TestAnAllowNamingTheReleaseOutranksTheAdvisory(t *testing.T) {
	buf := captureStdLog(t)
	f := overrideFirewall(t, ovFeed(t), ovImage+"@"+ovBad, "")

	d := f.Evaluate(ovImage + "@" + ovBad)
	if !d.Allowed {
		t.Fatalf("the administrator allowed this exact release and it was refused: %s", d.Reason)
	}
	if d.Override == "" {
		t.Error("the decision carries no Override, so the audit record and the console cannot show that " +
			"this allow was made over a standing advisory — D312's second condition")
	}
	for _, want := range []string{"MAL-2026-OV", "administrator override", ovBad} {
		if !strings.Contains(d.Override+d.Reason, want) {
			t.Errorf("the override text does not mention %q: %q", want, d.Override)
		}
	}
	if got := buf.String(); !strings.Contains(got, "[administrator-override]") {
		t.Errorf("the override was not logged with its own token:\n%s", got)
	}

	// DISCRIMINATOR: the SAME advisory names another release, which the allow list does
	// not, and that one stays refused. Without this the test passes on a gate that
	// stopped enforcing the feed at all.
	if d := f.Evaluate(ovImage + "@" + ovOther); d.Allowed {
		t.Error("a release the advisory names and the allow list does NOT was served; the override is " +
			"not scoped to the release the administrator judged")
	}
}

func TestANameScopedAllowDoesNotOverrideAnAdvisory(t *testing.T) {
	// The harm D312 names: an allow granted before the hijack, covering the release
	// nobody looked at. A reading, not the ruling's words — left open as a question.
	buf := captureStdLog(t)
	f := overrideFirewall(t, ovFeed(t), ovImage, "")

	d := f.Evaluate(ovImage + "@" + ovBad)
	if d.Allowed {
		t.Fatalf("a NAME-scoped allow overrode a version-pinned advisory: %s", d.Reason)
	}
	if d.Deny != denyKnownMalware {
		t.Errorf("Deny = %q, want %q", d.Deny, denyKnownMalware)
	}
	// And the refusal must tell them how to say what they mean, or they will edit the
	// wrong file: the log names the pin as the way to override.
	if got := buf.String(); !strings.Contains(got, "Pin the release") && !strings.Contains(got, "pin the release") {
		t.Errorf("nothing told the operator that pinning the release is how to override:\n%s", got)
	}
}

func TestAnOverrideNeedsAKnownVersion(t *testing.T) {
	// An override is an instruction about ONE artifact. A request we cannot attribute to
	// a release is not that artifact, and failing open here would handpick the advisory's
	// release for whoever can break the join.
	f := overrideFirewall(t, ovFeed(t), ovImage+"@"+ovBad, "")
	if d := f.Evaluate(ovImage); d.Allowed {
		t.Errorf("a request whose version could not be determined was served under a version-scoped "+
			"allow: %s", d.Reason)
	}
}

func TestTheOperatorsOwnDenyStillOutranksTheirAllow(t *testing.T) {
	// Two instructions from the same authority; the refusing one wins. Unchanged from the
	// name-scoped rule, and stated because the override could plausibly have been read as
	// outranking everything.
	f := overrideFirewall(t, ovFeed(t), ovImage+"@"+ovBad, ovImage)
	d := f.Evaluate(ovImage + "@" + ovBad)
	if d.Allowed {
		t.Errorf("a package on the operator's own deny list was served because of their allow entry: %s", d.Reason)
	}
	// The OVERRIDE is what must not have fired; the ATTRIBUTION is the feed's, and that is
	// the pre-existing design rather than an accident of ordering: when a release is on
	// both, the advisory's reason is the more informative one because it carries a MAL-
	// id (Evaluate says so where it refuses a package on both lists). Asserting
	// denyOperator here would pin the wrong thing — it was this test's first expectation,
	// and the code was right.
	if d.Override != "" {
		t.Errorf("the override fired for a release the operator's own deny list refuses: %q", d.Override)
	}
	if d.Deny != denyKnownMalware {
		t.Errorf("Deny = %q, want %q — a release on both is attributed to the advisory, which names an id", d.Deny, denyKnownMalware)
	}

	// And with NO advisory in play, the same pair is refused by the deny list itself.
	f2 := overrideFirewall(t, writeFeed(t, `{"id":"MAL-2026-OTHER","ecosystem":"oci","name":"someone-else"}`),
		ovImage+"@"+ovBad, ovImage)
	d2 := f2.Evaluate(ovImage + "@" + ovBad)
	if d2.Allowed || d2.Deny != denyOperator {
		t.Errorf("deny vs allow with no advisory: allowed=%v deny=%q, want refused by %q", d2.Allowed, d2.Deny, denyOperator)
	}
}

func TestAPackageWideAdvisoryIsNotOverriddenByAVersionScopedAllow(t *testing.T) {
	// The limit of this increment, pinned rather than left to be discovered: an advisory
	// that condemns EVERY version is decided on the package name, before any release is
	// named, so a version-scoped allow has nothing to match against. It is refused — and
	// the log says the entry exists and why it could not apply, because an entry that
	// appears to do nothing is the failure the parser refuses lines over.
	buf := captureStdLog(t)
	feed := writeFeed(t, `{"id":"MAL-2026-ALL","ecosystem":"oci","name":"`+ovImage+`"}`)
	f := overrideFirewall(t, feed, ovImage+"@"+ovBad, "")

	d := f.Evaluate(ovImage + "@" + ovBad)
	if d.Allowed {
		t.Fatalf("a package-wide advisory was overridden by a version-scoped allow. If this is now "+
			"intended, the reason text and docs/CONFIGURATION.md must say so: %s", d.Reason)
	}
	if got := buf.String(); !strings.Contains(got, "VERSION-SCOPED allow entry") {
		t.Errorf("the operator's entry was ignored silently; nothing said why it could not apply:\n%s", got)
	}
}

// ---------------------------------------------------------------- npm, through the proxy

func TestTheAllowedReleaseSurvivesTheNpmPackumentFilter(t *testing.T) {
	// The packument filter is where an npm client learns which releases exist. An
	// override that did not reach it would leave the release refused at resolution while
	// the gate believed it was serving it.
	up := npmDenyUpstream(t)
	feed := writeFeed(t, `{"id":"MAL-2026-NPM","ecosystem":"npm","name":"hijacked","versions":["2.0.0"]}`)
	p := newTestProxy(t, up, func(c *Config) {
		c.Ecosystem = "npm"
		c.MalwareListPath = feed
		c.AllowListPath = writeList(t, "allow.txt", "hijacked@2.0.0")
		c.UnscorablePolicy = "allow"
	})

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/hijacked", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("packument = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"2.0.0"`) {
		t.Errorf("the release the administrator allowed was filtered out of the packument anyway:\n%s", rec.Body.String())
	}

	// CONTROL: without the allow entry the same release is removed. Without this, the
	// assertion above would pass on a filter that stopped enforcing advisories.
	p2 := newTestProxy(t, up, func(c *Config) {
		c.Ecosystem = "npm"
		c.MalwareListPath = feed
		c.UnscorablePolicy = "allow"
	})
	rec = httptest.NewRecorder()
	p2.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/hijacked", nil))
	if strings.Contains(rec.Body.String(), `"2.0.0"`) {
		t.Errorf("control: with no allow entry the advisory's release stayed in the packument:\n%s", rec.Body.String())
	}
}

func TestTheOverrideIsRefusedWhenTheVERSIONISNotKNOWN(t *testing.T) {
	// Sharper than the request-level test above, and it exists because a sabotage of the
	// `!known` guard reddened NOTHING: hasVersion refuses an empty version on its own, so
	// the request-level test could not tell the two guards apart. This asks the rule
	// directly, with a version string that is present but UNATTRIBUTED — the shape a
	// broken filename join produces, where failing open hands over exactly the release
	// the advisory names.
	f := overrideFirewall(t, ovFeed(t), ovImage+"@"+ovBad, "")
	if f.adminAllowsRelease(ovImage, ovBad, false) {
		t.Error("an override was granted for a version the request could not be attributed to")
	}
	if !f.adminAllowsRelease(ovImage, ovBad, true) {
		t.Error("control: the same release with a KNOWN version was not overridden, so the test above " +
			"passes for the wrong reason")
	}
}

func TestTheConsoleAndTheGateAgreeOnALLOWGrammar(t *testing.T) {
	// The shared corpus (testdata/operator_list_lines.tsv) is the DENY boundary: both
	// readers are called with "deny" there. The two kinds now differ — an OCI allow may
	// name a digest — so the allow grammar needs its own paired assertion, or a console
	// that drifted would author a line the gate refuses to start on. A sabotage passing
	// "deny" to the console's validator reddened nothing before this existed.
	//
	// The console half of this pair lives in console/liststore_test.go under the same
	// name; they are deliberately two tests, because the packages cannot import each
	// other, which is the whole reason the corpus exists.
	//
	// ⚠️ This pair pins the GRAMMAR, not the kind-awareness of the console: sabotaging the
	// console to validate allow entries as deny reddens nothing, because both lists now
	// accept the same set and the one kind-dependent case (an OCI digest) is accepted
	// either way — as an exact entry or as a repository-wide one. Only the gate can
	// observe that difference, and TestAnAllowNamingTheReleaseOutranksTheAdvisory is where
	// it is observed. Said here so the next reader does not take this pair for more than
	// it proves.
	for _, c := range []struct {
		eco, entry string
		ok         bool
	}{
		{"oci", "library/nginx@sha256:" + strings.Repeat("a", 64), true},
		{"oci", "library/nginx:1.25", true}, // a tag: still the whole repository, with its warning
		{"npm", "lodash@4.17.20", true},     // version-scoped allow
		{"npm", "lodash@", false},           // a separator with nothing after it
		{"pypi", "requests:2.31.0", false},  // a colon is not PyPI's pin spelling
	} {
		_, err := parseOperatorList("allow", c.eco, strings.NewReader(c.entry+"\n"))
		if c.ok && err != nil {
			t.Errorf("gate REFUSED a well-formed allow entry (%s %q): %v", c.eco, c.entry, err)
		}
		if !c.ok && err == nil {
			t.Errorf("gate ACCEPTED a malformed allow entry (%s %q)", c.eco, c.entry)
		}
	}
}
