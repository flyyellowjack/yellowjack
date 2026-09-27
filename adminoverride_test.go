package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D312, applied: *"if the administrator allows it, it is allowed."* D367 widened "it":
// a BARE NAME on the allow list covers every release (*"the admin is always right, even if
// they're wrong"*), where D328 had read it narrowly.
//
// An allow entry outranks a known-malware advisory for every release it covers. The edges
// that remain each have a test here beside the override, because a precedence rule is only
// as good as its edges:
//
//	1. a PINNED entry does not reach a request whose version is unknown,
//	2. the operator's own deny list still wins, including a version-scoped deny when the
//	   version is unknown (fail closed),
//	3. an allow for a DIFFERENT package overrides nothing.
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

// REVERSED IN PLACE by D367. This test used to assert that a NAME-scoped allow did not
// override (D328's narrow reading, which D367 rejected on purpose): "if the admin
// whitelists all future versions of a package, that's dumb, but they did it, their
// problem, not ours". A bare name now covers every release the advisory names, loudly.
func TestANameScopedAllowOverridesAnAdvisory(t *testing.T) {
	buf := captureStdLog(t)
	f := overrideFirewall(t, ovFeed(t), ovImage, "")

	for _, v := range []string{ovBad, ovOther} {
		d := f.Evaluate(ovImage + "@" + v)
		if !d.Allowed {
			t.Errorf("a bare-name allow did not override the advisory for %s: %s", v, d.Reason)
		}
		if !strings.Contains(d.Override, "MAL-2026-OV") {
			t.Errorf("the override for %s does not name the advisory: %q", v, d.Override)
		}
	}
	if got := buf.String(); !strings.Contains(got, "[administrator-override]") {
		t.Errorf("the override was not logged:\n%s", got)
	}
	// DISCRIMINATOR: an allow for a DIFFERENT image overrides nothing, so the test above
	// cannot pass on a gate that stopped enforcing the feed.
	g := overrideFirewall(t, ovFeed(t), "library/unrelated", "")
	if d := g.Evaluate(ovImage + "@" + ovBad); d.Allowed {
		t.Errorf("an allow entry for another image overrode this advisory: %s", d.Reason)
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

// The edges D367 moved. A bare name covers every release, so it reaches a request whose
// version could not be determined; a pinned line still does not (TestAnOverrideNeedsAKnown
// Version); and the operator's own version-scoped deny fails the unknown case closed,
// because it might name exactly this release.
func TestABareNameCoversAReleaseWhoseVersionIsUnknown(t *testing.T) {
	feed := writeFeed(t, `{"id":"MAL-2026-UNK","ecosystem":"npm","name":"pkg","versions":["2.0.0"]}`)
	build := func(allow, deny string) *Firewall {
		t.Helper()
		cfg := Config{Ecosystem: "npm", UpstreamRegistry: "http://127.0.0.1:1", ScorecardMode: "stub",
			ScoreThreshold: 5.0, MalwareListPath: feed, AllowListPath: writeList(t, "allow.txt", allow)}
		if deny != "" {
			cfg.DenyListPath = writeList(t, "deny.txt", deny)
		}
		f, err := NewFirewall(cfg)
		if err != nil {
			t.Fatalf("NewFirewall: %v", err)
		}
		return f
	}
	d, blocked := build("pkg", "").pinnedMalwareVerdict("pkg", "", false)
	if !blocked || !d.Allowed || d.Override == "" {
		t.Errorf("a bare-name allow did not cover an unknown-version request: blocked=%v %+v", blocked, d)
	}
	if d, _ := build("pkg", "pkg@9.9.9").pinnedMalwareVerdict("pkg", "", false); d.Allowed {
		t.Errorf("an unknown-version request was served although the operator's deny list names a "+
			"release of this package that it could be: %+v", d)
	}
	if d, _ := build("other", "").pinnedMalwareVerdict("pkg", "", false); d.Allowed {
		t.Errorf("control: an allow for another package covered this one: %+v", d)
	}
}

// The metadata filters ask the same question the verdict does: a bare name keeps every
// advisory-named release in the npm packument and unyanked in the PyPI index.
func TestTheMetadataFiltersHonourABareNameAllow(t *testing.T) {
	list, err := loadMalwareList(writeFeed(t,
		`{"id":"MAL-NPM","ecosystem":"npm","name":"pkg","versions":["2.0.0"]}`,
		`{"id":"MAL-PY","ecosystem":"pypi","name":"pkg","versions":["2.0"]}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	bare := func(eco string) *operatorList {
		l, err := parseOperatorList("allow", eco, strings.NewReader("pkg\n"))
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	empty := func(eco string) *operatorList {
		l, _ := parseOperatorList("allow", eco, strings.NewReader(""))
		return l
	}
	if reason, _ := npmPinnedRefuser(list, bare("npm"), "pkg")(npmVersionFacts{Version: "2.0.0"}); reason != "" {
		t.Errorf("the npm packument filter removed a release a bare-name allow covers: %q", reason)
	}
	if reason, _ := npmPinnedRefuser(list, empty("npm"), "pkg")(npmVersionFacts{Version: "2.0.0"}); reason == "" {
		t.Error("control: with no allow entry the npm filter kept the advisory's release")
	}
	pin := malwarePin{list: list, allow: bare("pypi"), ecosystem: "pypi", pkg: "pkg",
		versions: map[string]string{"pkg-2.0.tar.gz": "2.0"}}
	for _, file := range []string{"pkg-2.0.tar.gz", "pkg-unknown.tar.gz"} {
		if r := pin.yankFor(file); r != "" {
			t.Errorf("the PyPI index yanked %s although a bare-name allow covers every release: %q", file, r)
		}
	}
	pin.allow = empty("pypi")
	if pin.yankFor("pkg-2.0.tar.gz") == "" || pin.yankFor("pkg-unknown.tar.gz") == "" {
		t.Error("control: with no allow entry the PyPI index left the advisory's file (or an unknown one) unyanked")
	}
}
