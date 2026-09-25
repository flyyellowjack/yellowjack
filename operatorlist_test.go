package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

// Tests for the OPERATOR's own allow/deny lists (D193, issue #58).
//
// The properties worth pinning are not "does a map lookup work". They are the five
// things that would make these lists look enforced while enforcing nothing, or make
// them enforce something the operator did not ask for:
//
//  1. an unreadable or malformed list must be a STARTUP failure, never a silent empty
//     set — a deny list that quietly loaded zero entries is the false-confidence shape
//  2. a name respelt the way the ecosystem treats as equivalent must still match, or
//     "Requests" in the file silently fails to block "requests"
//  3. both verdicts must be reachable with NO upstream contact, or the lists stop
//     working in exactly the outage where they matter most
//  4. the published-advisory feed must OUTRANK the allow list — "we vouch for this"
//     cannot override "someone published an advisory naming it"
//  5. unconfigured must change nothing at all (the negative control)
//
// Every case asserts the deny KIND or the reason text, not merely that something was
// blocked: an implementation that blocked everything would pass a test that only
// counts blocks.

// writeList writes an operator list to a temp file and returns its absolute path.
func writeList(t *testing.T, name string, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

func TestOperatorDenyListRefusesWithoutContactingUpstream(t *testing.T) {
	up, hits := deadUpstream(t)
	deny := writeList(t, "deny.txt", "# our own call, nothing to do with OSV", "internal-forbidden")

	f, err := NewFirewall(Config{
		Ecosystem:        "npm",
		UpstreamRegistry: up.URL,
		DepsDevBase:      up.URL,
		ScorecardMode:    "stub",
		ScoreThreshold:   5.0,
		DenyListPath:     deny,
	})
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}

	d := f.Evaluate("internal-forbidden")
	if d.Allowed {
		t.Fatalf("a package on the operator deny list was ALLOWED (reason %q)", d.Reason)
	}
	if d.Deny != denyOperator {
		t.Errorf("Deny = %q, want %q — the kind is what makes the byte gate refuse the "+
			"tarball too, so getting it wrong leaves the lockfile install path open (#11)",
			d.Deny, denyOperator)
	}
	// The reason must attribute the decision to the ORGANISATION, not to a published
	// advisory. A developer who reads "malware" for what is actually an internal policy
	// call will abandon a fine dependency or route around the proxy (#50).
	if !strings.Contains(d.Reason, "deny list") {
		t.Errorf("reason = %q, want it to name the deny list as the decider", d.Reason)
	}
	if strings.Contains(strings.ToLower(d.Reason), "advisory") &&
		!strings.Contains(d.Reason, "not a published malware advisory") {
		t.Errorf("reason = %q reads like a published advisory; this is a local policy "+
			"decision and must not be confused with one", d.Reason)
	}
	if n := atomic.LoadInt64(hits); n != 0 {
		t.Errorf("the deny list made %d upstream request(s); a deny that stops denying "+
			"during an outage is not a deny", n)
	}

	// An operator deny must be a HARD deny, or the byte gate serves the tarball anyway
	// to anyone whose lockfile pins its URL — the #11 bypass, and the operator would see
	// their block listed in the console while packages kept flowing.
	if !hardDenyKind(d.Allowed, d.Deny) {
		t.Error("an operator deny is SOFT: the artifact byte route would still serve it, " +
			"so a lockfile install walks straight past the block")
	}
}

func TestOperatorAllowListServesWithoutScoring(t *testing.T) {
	up, hits := deadUpstream(t)
	allow := writeList(t, "allow.txt", "vetted-internal-tool")

	f, err := NewFirewall(Config{
		Ecosystem:        "npm",
		UpstreamRegistry: up.URL,
		DepsDevBase:      up.URL,
		ScorecardMode:    "stub",
		ScoreThreshold:   5.0,
		AllowListPath:    allow,
	})
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}

	d := f.Evaluate("vetted-internal-tool")
	if !d.Allowed {
		t.Fatalf("a package on the operator allow list was BLOCKED (reason %q)", d.Reason)
	}
	if !strings.Contains(d.Reason, "allow list") {
		t.Errorf("reason = %q, want it to say the allow list is why this was served — an "+
			"allowed-by-policy package must not read as allowed-on-merit", d.Reason)
	}
	// The availability half, and the reason the check sits ahead of the network: an
	// operator allow-lists a package precisely so it keeps working. An allow list that
	// stops allowing when deps.dev is unreachable is a suggestion, not a list.
	if n := atomic.LoadInt64(hits); n != 0 {
		t.Errorf("the allow list made %d upstream request(s); it must decide locally", n)
	}
}

// TestKnownMalwareOutranksTheOperatorAllowList.
//
// The one genuinely surprising interaction in this feature, and the reason it is
// asserted rather than commented: an operator who allow-lists a package that is
// publicly reported as malicious must still be refused. Without this test, someone
// "fixing" the ordering so the allow list wins would break the sharpest gate we have
// and every other test would stay green.
func TestKnownMalwareOutranksTheOperatorAllowList(t *testing.T) {
	up, hits := deadUpstream(t)
	feed := writeList(t, "malware.ndjson",
		`{"id":"MAL-2024-0002","ecosystem":"npm","name":"compromised-dep"}`)
	allow := writeList(t, "allow.txt", "compromised-dep")

	f, err := NewFirewall(Config{
		Ecosystem:        "npm",
		UpstreamRegistry: up.URL,
		DepsDevBase:      up.URL,
		ScorecardMode:    "stub",
		ScoreThreshold:   5.0,
		MalwareListPath:  feed,
		AllowListPath:    allow,
	})
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}

	d := f.Evaluate("compromised-dep")
	if d.Allowed {
		t.Fatalf("the operator allow list overrode a PUBLISHED MALWARE ADVISORY — the "+
			"allow list must never be able to do that (reason %q)", d.Reason)
	}
	if d.Deny != denyKnownMalware {
		t.Errorf("Deny = %q, want %q: the advisory is the more informative reason and is "+
			"the one the developer should be shown", d.Deny, denyKnownMalware)
	}
	if !strings.Contains(d.Reason, "MAL-2024-0002") {
		t.Errorf("reason = %q, want it to name the advisory ID so it can be looked up", d.Reason)
	}
	if n := atomic.LoadInt64(hits); n != 0 {
		t.Errorf("made %d upstream request(s) deciding a local conflict", n)
	}
}

// TestUnconfiguredOperatorListsAreInert is the negative control. Without it, an
// implementation that denied (or allowed) unconditionally would pass everything above.
func TestUnconfiguredOperatorListsAreInert(t *testing.T) {
	var nilList *operatorList
	if nilList.has("npm", "anything") {
		t.Error("a nil operator list matched a package; unconfigured must match nothing")
	}
	if n := nilList.count(); n != 0 {
		t.Errorf("nil list count = %d, want 0", n)
	}

	// And through the real constructor, so the wiring is covered too and not just the
	// predicate — the failure this project has hit repeatedly is a correct predicate
	// that nothing calls.
	up, _ := deadUpstream(t)
	f, err := NewFirewall(Config{
		Ecosystem:        "npm",
		UpstreamRegistry: up.URL,
		DepsDevBase:      up.URL,
		ScorecardMode:    "stub",
		ScoreThreshold:   5.0,
	})
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	if f.deny() != nil || f.allow() != nil {
		t.Error("lists were constructed despite no path being configured")
	}
	if f.deny().has("npm", "anything") || f.allow().has("npm", "anything") {
		t.Error("an unconfigured list matched a package")
	}
}

// TestOperatorListNamesNormalizeLikeTheEcosystem.
//
// The silent-miss case, and the reason this file reuses malwareKey rather than
// comparing strings: an operator writes the name the way a human writes it, and the
// gate must match the way the ecosystem resolves it. A denylist that misses is worse
// than no denylist, because the operator believes it is working.
func TestOperatorListNamesNormalizeLikeTheEcosystem(t *testing.T) {
	cases := []struct {
		ecosystem string
		written   string // what the operator typed in the file
		requested string // what the client actually asks for
	}{
		{"npm", "LoDash", "lodash"},
		{"pypi", "Flask_Login", "flask-login"},
		{"pypi", "Zope.Interface", "zope-interface"},
		{"oci", "library/NGINX", "library/nginx:1.25"},
	}
	for _, c := range cases {
		l, err := parseOperatorList("deny", c.ecosystem, strings.NewReader(c.written+"\n"))
		if err != nil {
			t.Fatalf("%s: parse %q: %v", c.ecosystem, c.written, err)
		}
		if !l.has(c.ecosystem, c.requested) {
			t.Errorf("%s: an operator wrote %q and a client asking for %q was NOT matched — "+
				"the block they configured silently does nothing",
				c.ecosystem, c.written, c.requested)
		}
	}

	// Anti-vacuity: the matcher must not match everything. Without this, a `has` that
	// always returned true would pass every line above.
	l, err := parseOperatorList("deny", "npm", strings.NewReader("lodash\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if l.has("npm", "left-pad") {
		t.Error("the list matched a package it does not name")
	}
}

// TestAMalformedOperatorListIsAStartupFailure.
//
// Each of these would otherwise fail SILENTLY and in the direction that does nothing:
// a version-pinned line normalizes to a name nothing requests, so the operator's entry
// sits in the file looking correct and blocking (or allowing) nothing at all.
func TestAMalformedOperatorListIsAStartupFailure(t *testing.T) {
	bad := []struct {
		name      string
		kind      string
		ecosystem string
		body      string
		wantIn    string
	}{
		// A version-scoped entry is valid in BOTH lists now (#155/D312): deny since the
		// first half of that issue, allow since this one. What stays malformed is a line
		// that is not an identity in its ecosystem's own grammar — those would load and
		// then match nothing, which is the silent failure this parser refuses lines over.
		{"a colon is not pypi's pin spelling", "deny", "pypi", "requests:2.31.0\n", "not a PyPI project name"},
		{"a colon is not npm's pin spelling", "deny", "npm", "lodash:latest\n", "not an npm package name"},
		{"a maven coordinate needs its group", "deny", "maven", "commons-lang3\n", "not a Maven coordinate"},
		{"a separator with no version", "deny", "npm", "lodash@\n", "empty version"},
		{"trailing comment field", "deny", "npm", "lodash 4.17.20\n", "whitespace"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseOperatorList(c.kind, c.ecosystem, strings.NewReader(c.body))
			if err == nil {
				t.Fatalf("%q parsed without error; it would have silently done nothing", c.body)
			}
			if !strings.Contains(err.Error(), c.wantIn) {
				t.Errorf("error = %q, want it to mention %q so the operator can fix the line",
					err.Error(), c.wantIn)
			}
		})
	}

	// A relative path must be refused (#38 / CVE-2025-64726). It matters more here than
	// for the feed, because THIS file can allow packages.
	if _, err := loadOperatorList("allow", "npm", "lists/allow.txt"); err == nil {
		t.Error("a relative path was accepted; it resolves against the working directory, " +
			"so whoever launches the process picks which allow list we honour")
	}

	// And the shapes that must KEEP working, or the test above is just banning input.
	good := []struct {
		ecosystem string
		body      string
		want      string
	}{
		{"npm", "@scope/pkg\n", "@scope/pkg"},            // npm scopes start with @
		{"npm", "lodash # our call\n", "lodash"},         // trailing comment
		{"oci", "library/nginx:1.25\n", "library/nginx"}, // OCI references are part of the identity
	}
	for _, c := range good {
		l, err := parseOperatorList("deny", c.ecosystem, strings.NewReader(c.body))
		if err != nil {
			t.Fatalf("%s: %q was rejected but is valid: %v", c.ecosystem, c.body, err)
		}
		if !l.has(c.ecosystem, c.want) {
			t.Errorf("%s: %q did not match %q", c.ecosystem, c.body, c.want)
		}
	}
}

// TestABrokenOperatorListIsAStartupFailure — through NewFirewall, so the wiring is
// what is asserted rather than the parser in isolation. A firewall that booted with an
// unreadable deny list would report healthy and enforce nothing.
func TestABrokenOperatorListIsAStartupFailure(t *testing.T) {
	up, _ := deadUpstream(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist.txt")

	_, err := NewFirewall(Config{
		Ecosystem:        "npm",
		UpstreamRegistry: up.URL,
		DepsDevBase:      up.URL,
		ScorecardMode:    "stub",
		ScoreThreshold:   5.0,
		DenyListPath:     missing,
	})
	if err == nil {
		t.Fatal("NewFirewall succeeded with an unreadable deny list — it would have run " +
			"enforcing nothing while looking healthy")
	}
	if !strings.Contains(err.Error(), "deny-list") {
		t.Errorf("error = %q, want it to name WHICH list failed; an operator with both "+
			"configured cannot otherwise tell which file to fix", err.Error())
	}
}

// TestEveryDeclaredDenyKindHasANextStep is a DRIFT GUARD, not a unit test.
//
// It exists because adding denyOperator revealed the gap it now closes: nextStepFor
// falls through to "" for any kind it does not know, and TestNoNextStepIsInventedForAnUnknownKind
// asserts exactly that — correctly, for an UNKNOWN kind. But a kind that is declared
// in firewall.go and simply forgotten in the switch is not unknown, it is ours, and it
// silently ships a refusal with no guidance attached. Nothing caught that.
//
// So this reads the declarations out of the source and requires each to be handled.
// It deliberately reads ONE named file rather than walking the tree: a test that walks
// from "." also walks .gocache/, which is inside the checkout in CI and would make this
// scan every dependency.
func TestEveryDeclaredDenyKindHasANextStep(t *testing.T) {
	src, err := os.ReadFile("firewall.go")
	if err != nil {
		t.Fatalf("reading firewall.go: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\s*(deny\w+)\s+denyKind\s*=\s*"([^"]*)"`)
	found := re.FindAllStringSubmatch(string(src), -1)

	// Anti-vacuity. A regex that matched nothing would make this test pass while
	// checking nothing at all — the exact failure this project treats as worse than
	// having no check.
	if len(found) < 5 {
		t.Fatalf("found only %d denyKind declarations in firewall.go; the pattern has "+
			"drifted from the source and this test is no longer checking anything", len(found))
	}

	for _, m := range found {
		constName, value := m[1], m[2]
		if value == "" { // denyNone is not a denial
			continue
		}
		if step := nextStepFor(denyKind(value)); step == "" {
			t.Errorf("%s (%q) is a declared denial kind with NO next-step guidance: a "+
				"developer hitting it gets a refusal and no way to act on it. Add a case "+
				"to nextStepFor.", constName, value)
		}
	}
}

// TestOperatorAllowListIsTheColdStartPathForUnverifiedPackages pins the interaction the
// roadmap says does not exist.
//
// D36/D42 made a durably unverified package fail CLOSED, and accepted the consequence in
// In the ruling's own words: a cold deployment queues every package deps.dev does not know, and
// "an operator tests and builds an allowlist first". The build roadmap has carried a
// "bulk-allowlist / cold-start path" item ever since, on the grounds that "approvals are
// one package at a time, and with no FW_APPROVAL_URL there is no queue at all".
//
// FW_ALLOW_LIST (!179) IS that path — a file, one name per line, no approval service, no
// database — and nothing tested the property that makes it one: the allow list is
// consulted BEFORE the repo is looked up (firewall.go), so it reaches a package that
// would otherwise be refused as unverified. Every existing allow-list test runs in
// `stub` scoring mode, where repo verification is skipped entirely (repoVerificationEnabled),
// so none of them exercises this at all.
//
// Written as a DISCRIMINATOR rather than a single assertion: the same package, the same
// fixtures, allowed only by the presence of the list. Without the first half, the second
// would pass just as happily against a firewall that allowed everything.
func TestOperatorAllowListIsTheColdStartPathForUnverifiedPackages(t *testing.T) {
	const pkg = "brand-new-evil"
	// The D36 shape: a package deps.dev has never ingested, declaring a repo that scores
	// 9.0. Under the fail-closed default this is exactly what a cold deployment is full of.
	registry := npmRegistry(t, "git+https://github.com/lodash/lodash.git")
	depsDev := depsDevUnknownPackageWithScore(t, 9.0)

	// 1. WITHOUT the list: refused, because the link cannot be verified.
	if d := evalFirewall(registry, depsDev, true).Evaluate(pkg); d.Allowed {
		t.Fatalf("the discriminator is broken: %q was allowed with NO allow list, so the "+
			"second half below would prove nothing (reason: %s)", pkg, d.Reason)
	}

	// 2. WITH it on the operator allow list: served, without a score.
	l, err := parseOperatorList("allow", "npm", strings.NewReader(pkg+"\n"))
	if err != nil {
		t.Fatalf("parseOperatorList: %v", err)
	}
	f := evalFirewall(registry, depsDev, true)
	f.allowList = staticList(l)

	d := f.Evaluate(pkg)
	if !d.Allowed {
		t.Fatalf("an allow-listed package was still refused under the fail-closed unverified "+
			"default, so FW_ALLOW_LIST is NOT a cold-start path and the roadmap item is real "+
			"after all (reason: %s)", d.Reason)
	}
	if !strings.Contains(d.Reason, "allow list") {
		t.Errorf("reason = %q, want it to name the allow list — an operator who pre-approved a "+
			"package must be able to tell that from a package that passed on its merits", d.Reason)
	}
	// It must NOT arrive carrying the borrowed 9.0. The whole point of D36 is that the
	// claimed repo's score is not this package's; the allow list says "we vouch for it",
	// which is a different statement from "it scored well".
	if d.HasScore {
		t.Errorf("an allow-listed package came back with score=%v; it must be served WITHOUT "+
			"scoring, or the borrowed score D36 exists to refuse is back by another door", d.Score)
	}
}
