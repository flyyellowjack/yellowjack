package main

import (
	"strings"
	"testing"
)

// Tier-1 tests for the CLASSIFICATION gate (issue #58 increment 2, D76).
//
// What is being pinned here is a default inversion. Before this, a request the
// gate could not name a package for was relayed with no decision at all; now it
// must be either an ENUMERATED control-plane endpoint or refused. Two failure
// directions matter and they pull against each other:
//
//	too strict -> a real client breaks (npm can't audit, Maven can't resolve)
//	too loose  -> a silent hole of exactly the #11/#56/#57/#59 kind
//
// So every ecosystem gets both halves: the endpoints that MUST pass, and the
// shapes that MUST NOT — including the near-miss spellings that would sail
// through a sloppier predicate.

// ─────────────────────── the enumeration, per ecosystem ───────────────────────

func TestControlPlaneEnumerationPerEcosystem(t *testing.T) {
	cases := []struct {
		eco   string
		build func() Ecosystem
		// allow: infrastructure a real client genuinely needs.
		allow []string
		// refuse: must NOT be treated as infrastructure. Each entry is either a
		// real attack shape or a near-miss of an allowed one.
		refuse []string
	}{
		{
			eco:   "npm",
			build: func() Ecosystem { return npmEcosystem{} },
			allow: []string{
				"/",
				"/-/ping",
				"/-/whoami",
				"/-/v1/search?text=lodash",
				"/-/npm/v1/security/audits/quick",
				"/-/npm/v1/security/advisories/bulk",
			},
			refuse: []string{
				// The near-miss that matters: "/-/" appears, but NOT at the start.
				// npmArtifactPath claims real tarballs before we get here, so a path
				// that still contains the marker is one it REFUSED to parse — and
				// treating it as infrastructure would hand back exactly the bytes
				// the #11 byte gate exists to stop.
				"/lodash/-/lodash-4.17.21.tgz",
				"/@scope/pkg/-/pkg-1.0.0.tgz",
				"/evil/-/../../-/ping",
				// Not infrastructure, just unrecognised.
				"/some/deep/unknown/path",
				"/-",
				"/x-/ping",
			},
		},
		{
			eco:   "pypi",
			build: func() Ecosystem { return pypiEcosystem{} },
			allow: []string{"/", "/simple", "/simple/"},
			refuse: []string{
				// Case matters, and NOT folding is the correct call: PackageNameFromPath
				// is likewise case-sensitive, so "/Simple/" parses as a package named
				// "Simple" and gets GATED. Folding here would instead hand back the
				// entire project index ungated.
				"/Simple/",
				"/SIMPLE",
				"/simple/requests/", // a project page — gated as a package, not infra
				"/pypi/requests/json",
				"/files/any.whl",
			},
		},
		{
			eco:   "oci",
			build: func() Ecosystem { return ociEcosystem{} },
			allow: []string{
				"/", "/v2", "/v2/",
				"/v2/library/alpine/tags/list",
				"/token", "/v2/token", "/v2/auth",
			},
			refuse: []string{
				// The exact shape !76's tier-3 pass found. ociNameBefore folds case so
				// this PARSES and is gated as a blob; this predicate must NOT fold, or
				// "/V2/" becomes an allowed infrastructure prefix and the fold that
				// closed the hole reopens it here.
				"/V2/",
				"/V2/library/alpine/blobs/sha256:abc",
				// A push. We are a pull-through gate; passage is not owed.
				"/v2/library/alpine/blobs/uploads/",
				// tags/list must be under /v2/, not merely end with it.
				"/tags/list",
				"/v2/library/alpine/manifests/latest", // gated as a package
			},
		},
		{
			eco:   "maven",
			build: func() Ecosystem { return mavenEcosystem{} },
			allow: []string{
				"/",
				// Every Maven resolve fetches this. Note the SHORT group: only three
				// segments, so PackageNameFromPath's `len(segs) < 4` guard returns ""
				// before mavenUngatedFile is ever consulted. If ControlPlanePath did
				// not re-check the filename at any depth, this would be refused and
				// every resolve would break.
				"/junit/junit/maven-metadata.xml",
				"/com/google/guava/guava/maven-metadata.xml",
				"/com/google/guava/guava/33.0.0/guava-33.0.0.jar.sha1",
				"/com/google/guava/guava/33.0.0/guava-33.0.0.pom.md5",
				"/com/google/guava/guava/33.0.0/guava-33.0.0.jar.asc",
				"/junit/junit/maven-metadata.xml.sha1",
			},
			refuse: []string{
				// !80's finding, re-pinned at this layer: an EXACT match on
				// maven-metadata.xml, never a prefix. This is a fully functional
				// artifact URL that a prefix test would exempt.
				"/com/evil/badlib/1.0.0/maven-metadata.xml.evil.jar",
				// Directory listings stay refused, consistent with !80.
				"/com/google",
				"/com/google/guava/guava/33.0.0",
				// A real artifact is a package request, not infrastructure.
				"/com/google/guava/guava/33.0.0/guava-33.0.0.jar",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.eco, func(t *testing.T) {
			eco := tc.build()
			for _, p := range tc.allow {
				if !eco.ControlPlanePath(p) {
					t.Errorf("ControlPlanePath(%q) = false, want true — a real %s client needs this endpoint and would break", p, tc.eco)
				}
			}
			for _, p := range tc.refuse {
				if eco.ControlPlanePath(p) {
					t.Errorf("ControlPlanePath(%q) = true, want false — this would be relayed UNGATED as infrastructure", p)
				}
			}
		})
	}
}

// ─────────────────────── the classification ruleset ───────────────────────

func TestClassificationRulesetDefaultBlocksUnknown(t *testing.T) {
	// D76's inversion, at the ruleset level: with the shipped default, a
	// control-plane path is allowed and an unknown path is REJECTED — and the
	// rejection is attributed to the implicit terminal rule, because on `block`
	// the unknown-path rule deliberately does not match at all.
	rs := defaultClassificationRuleset(Config{}) // zero value -> block (see unknownPathPolicy)

	rule, action := rs.Decide(Facts{Path: "/-/ping", Kind: PathControlPlane})
	if action != ActionAllow {
		t.Errorf("control-plane path: action = %q, want %q (rule %q)", action, ActionAllow, rule.Name)
	}

	rule, action = rs.Decide(Facts{Path: "/mystery", Kind: PathUnknown})
	if action != ActionReject {
		t.Errorf("unknown path under the DEFAULT policy: action = %q, want %q — this is the inversion the epic exists for", action, ActionReject)
	}
	if !strings.Contains(rule.Name, "terminal") {
		t.Errorf("unknown path attributed to rule %q, want the implicit terminal rule — nothing should have *chosen* to allow it", rule.Name)
	}
}

func TestUnknownPathPolicyModes(t *testing.T) {
	cases := []struct {
		policy string
		want   Action
	}{
		{unknownPathBlock, ActionReject},
		{unknownPathAllowButLog, ActionAllowLog},
		{unknownPathAllow, ActionAllow},
		// A typo must fail CLOSED. If this ever returns an allow, a fat-fingered
		// env var silently reopens the hole the increment closed.
		{"allowbutlog", ActionReject},
		{"yes", ActionReject},
		{"", ActionReject},
		{"BLOCK", ActionReject},
	}
	for _, tc := range cases {
		t.Run("policy="+tc.policy, func(t *testing.T) {
			rs := defaultClassificationRuleset(Config{UnknownPathPolicy: tc.policy})
			if _, got := rs.Decide(Facts{Path: "/mystery", Kind: PathUnknown}); got != tc.want {
				t.Errorf("FW_UNKNOWN_PATH_POLICY=%q -> %q, want %q", tc.policy, got, tc.want)
			}
			// Whatever the policy, a control-plane path is always allowed —
			// otherwise turning the knob up would break the client's plumbing.
			if _, got := rs.Decide(Facts{Path: "/-/ping", Kind: PathControlPlane}); got != ActionAllow {
				t.Errorf("FW_UNKNOWN_PATH_POLICY=%q wrongly affected a control-plane path: %q", tc.policy, got)
			}
		})
	}
}

func TestClassificationRulesetIsOrderedControlPlaneFirst(t *testing.T) {
	// Order is the semantics. Under the most permissive policy every rule would
	// return an allow, so the only way to observe ordering is the rule NAME.
	rs := defaultClassificationRuleset(Config{UnknownPathPolicy: unknownPathAllow})
	rule, _ := rs.Decide(Facts{Path: "/-/ping", Kind: PathControlPlane})
	if !strings.Contains(rule.Name, "control-plane") {
		t.Errorf("control-plane path matched rule %q, want the control-plane rule to come FIRST", rule.Name)
	}
}

func TestFirewallClassifyRulesetFallsBackWhenNil(t *testing.T) {
	// Same nil-safety trap as f.ruleset(): a hand-built &Firewall{} has no
	// classifyRules, and a nil Ruleset matches nothing, which the terminal rule
	// turns into "refuse every infrastructure request" — i.e. a firewall that
	// answers nothing. The fallback is what keeps that from happening silently.
	f := &Firewall{cfg: Config{}}
	if _, action := f.classifyRuleset().Decide(Facts{Path: "/-/ping", Kind: PathControlPlane}); action != ActionAllow {
		t.Fatalf("nil classifyRules: control-plane path got %q, want %q", action, ActionAllow)
	}
	if _, action := f.classifyRuleset().Decide(Facts{Path: "/mystery", Kind: PathUnknown}); action != ActionReject {
		t.Errorf("nil classifyRules: unknown path got %q, want %q", action, ActionReject)
	}

	// Negative control: an explicitly installed ruleset must WIN over the
	// fallback, or the field would be decorative.
	f2 := &Firewall{cfg: Config{}, classifyRules: Ruleset{allowAll("permit everything")}}
	if _, action := f2.classifyRuleset().Decide(Facts{Path: "/mystery", Kind: PathUnknown}); action != ActionAllow {
		t.Errorf("installed classifyRules was ignored: got %q, want %q", action, ActionAllow)
	}
}

// TestEveryEcosystemImplementsControlPlanePath makes the interface obligation
// explicit. Go already enforces it at compile time, but naming the ecosystems
// here means ADDING one (Go modules are next per the build plan) fails this test
// until someone has consciously decided what its control plane is — rather than
// inheriting an empty enumeration that refuses all of its infrastructure, or a
// copy-pasted one that allows too much.
func TestEveryEcosystemImplementsControlPlanePath(t *testing.T) {
	for _, name := range []string{"npm", "pypi", "oci", "maven"} {
		eco, err := newEcosystem(name, "https://example.test")
		if err != nil {
			t.Fatalf("newEcosystem(%q): %v", name, err)
		}
		// The root must pass for every ecosystem: clients probe it for reachability.
		if !eco.ControlPlanePath("/") {
			t.Errorf("%s: ControlPlanePath(%q) = false; the registry root must be reachable", name, "/")
		}
		// And a plainly unrecognised path must not.
		if eco.ControlPlanePath("/definitely/not/a/known/endpoint/xyzzy") {
			t.Errorf("%s: an arbitrary path was classified as control-plane", name)
		}
	}
}
