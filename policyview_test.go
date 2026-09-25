package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// shippedConfig is what loadConfig produces for a default install. Written out rather than
// using a zero Config on purpose: a zero Config reads as the PERMISSIVE unscorable posture
// and a zero threshold, so a test built on one would describe a policy nobody ships. That
// exact mistake was caught twice before in the ruleset tests (see BUILD_LOG, issue #58
// increment 3).
func shippedConfig() Config {
	return Config{
		ScoreThreshold:    5.0,
		UnscorablePolicy:  "block",
		UnverifiedPolicy:  "block",
		UnknownPathPolicy: unknownPathBlock,
		ByteGate:          byteGateAllowButLog,
		WritePolicy:       writePolicyBlock,
		MaxReleaseAgeDays: 0,
		VerifyRepo:        true,
	}
}

func describeShipped(t *testing.T) PolicyView {
	t.Helper()
	f := &Firewall{cfg: shippedConfig()}
	return f.describePolicy()
}

func chain(t *testing.T, v PolicyView, name string) ChainView {
	t.Helper()
	for _, c := range v.Chains {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q chain in the view; got %d chains", name, len(v.Chains))
	return ChainView{}
}

// All three chains are reported. A view missing one would silently describe a gate with
// fewer decision points than it has.
func TestDescribePolicyCoversEveryChain(t *testing.T) {
	v := describeShipped(t)
	if len(v.Chains) != 3 {
		t.Fatalf("got %d chains, want 3 (verdict, classification, bytes)", len(v.Chains))
	}
	for _, name := range []string{chainVerdict, chainClassification, chainBytes} {
		c := chain(t, v, name)
		if len(c.Rules) == 0 {
			t.Errorf("chain %q has no rules", name)
		}
	}
}

// The implicit terminal is shown and marked. It is the defining property of the model, and
// an operator comparing this against a config file has to be able to tell which lines they
// own and which the engine supplies.
func TestDescribePolicyShowsTheImplicitTerminal(t *testing.T) {
	v := describeShipped(t)
	for _, c := range v.Chains {
		last := c.Rules[len(c.Rules)-1]
		if !last.Implicit {
			t.Errorf("chain %q does not end with the implicit terminal; last rule is %q", c.Name, last.Name)
		}
		for _, r := range c.Rules[:len(c.Rules)-1] {
			if r.Implicit {
				t.Errorf("chain %q marks an authored rule %q as implicit", c.Name, r.Name)
			}
		}
	}
}

// THE MISLEADING-RENDER TRAP, and the reason DefaultAction is asked of the engine.
//
// Every chain carries an implicit terminal REJECT, so a view that simply displayed it
// would tell an operator that unmatched artifact-byte requests are blocked. They are not:
// the shipped byte chain ends in a match-all allow-but-log (D49's visibility-first
// posture), which makes the terminal unreachable there. An operator who read "block" and
// believed their artifact route was fail-closed would have exactly the wrong picture of
// their own deployment, and would learn otherwise from an incident.
//
// Sabotage check: set DefaultAction to string(terminalRule.Action) instead of asking
// Decide, and the bytes case here fails.
func TestByteChainDefaultActionIsNotTheTerminalReject(t *testing.T) {
	v := describeShipped(t)

	if got := chain(t, v, chainBytes).DefaultAction; got != string(ActionAllowLog) {
		t.Errorf("bytes chain default = %q, want %q — the shipped byte gate is visibility-first (D49); "+
			"reporting a reject here would tell an operator their artifact route is fail-closed when it is not",
			got, ActionAllowLog)
	}
	// The other two really are fail-closed, and must still say so — otherwise this test
	// would pass just as well against a view that always reported allow-but-log.
	if got := chain(t, v, chainVerdict).DefaultAction; got != string(ActionReject) {
		t.Errorf("verdict chain default = %q, want reject", got)
	}
	if got := chain(t, v, chainClassification).DefaultAction; got != string(ActionReject) {
		t.Errorf("classification chain default = %q, want reject (D76/D94 ship default-block)", got)
	}
}

// Enforce mode must be visibly different from the shipped visibility mode, or the view
// cannot tell an operator which posture they are in.
func TestByteChainReflectsEnforceMode(t *testing.T) {
	cfg := shippedConfig()
	cfg.ByteGate = byteGateEnforce
	f := &Firewall{cfg: cfg}
	v := f.describePolicy()

	if got := chain(t, v, chainBytes).DefaultAction; got != string(ActionReject) {
		t.Errorf("bytes chain default under enforce = %q, want reject", got)
	}
	if v.Values["byte_gate"] != byteGateEnforce {
		t.Errorf("values[byte_gate] = %q, want %q", v.Values["byte_gate"], byteGateEnforce)
	}
}

// THE DIGEST BLIND SPOT.
//
// Rule names do not always change when policy does. Raising the threshold from 5.0 to 7.0
// leaves the rule "allow: OSSF score at or above threshold" byte-for-byte identical,
// because the threshold is captured in the closure rather than written into the name. A
// digest over rules alone would report two replicas as running the same policy while one
// blocked packages the other served — exactly the condition the divergence alert exists to
// catch, made invisible.
//
// Sabotage check: drop the Values loop from digest() and this test fails while every other
// test in this file still passes.
func TestDigestChangesWithThreshold(t *testing.T) {
	a := (&Firewall{cfg: shippedConfig()}).describePolicy()

	cfg := shippedConfig()
	cfg.ScoreThreshold = 7.0
	b := (&Firewall{cfg: cfg}).describePolicy()

	// The rule names really are identical — that is the premise, so assert it rather than
	// assuming it. If a future change writes the threshold into the rule name this test
	// would otherwise start passing for a different reason than it was written for.
	an, bn := viewRuleNames(chain(t, a, chainVerdict)), viewRuleNames(chain(t, b, chainVerdict))
	if an != bn {
		t.Fatalf("premise broken: verdict rule names now differ between thresholds\n 5.0: %s\n 7.0: %s", an, bn)
	}
	if a.Digest == b.Digest {
		t.Errorf("digest %q is identical for threshold 5.0 and 7.0 — two replicas enforcing different policies would report as identical", a.Digest)
	}
}

func viewRuleNames(c ChainView) string {
	var b strings.Builder
	for _, r := range c.Rules {
		b.WriteString(r.Name)
		b.WriteString("|")
	}
	return b.String()
}

// The digest must be STABLE for identical policy — including across calls, which Go's
// randomized map iteration would break if Values were hashed unsorted. A digest that
// changed per call would make every replica look divergent from itself.
func TestDigestIsStableAcrossCalls(t *testing.T) {
	f := &Firewall{cfg: shippedConfig()}
	first := f.describePolicy().Digest
	for i := 0; i < 20; i++ {
		if got := f.describePolicy().Digest; got != first {
			t.Fatalf("digest changed between calls: %q then %q (map iteration order leaking into the hash?)", first, got)
		}
	}
	// ...and two independently built firewalls with the same config must agree, which is
	// what makes cross-replica comparison meaningful at all.
	if other := (&Firewall{cfg: shippedConfig()}).describePolicy().Digest; other != first {
		t.Errorf("two firewalls with identical config digest differently: %q vs %q", first, other)
	}
}

// Every policy setting must actually reach the digest. Written as a loop over the value
// map rather than one case per field, so a setting added to policyValues later is covered
// the day it is added rather than the day someone remembers.
//
// The mutators take the whole *Firewall, not just its *Config, because not every reported
// value is config-derived: the known-malware feed is reported from the LOADED LIST, since
// two replicas naming the same path with different bytes behind it must not agree.
func TestDigestCoversEveryReportedValue(t *testing.T) {
	base := (&Firewall{cfg: shippedConfig()}).describePolicy()

	mutate := map[string]func(*Firewall){
		// Report mode conditions every other value here, so the digest MUST move: two
		// replicas identical except that one enforces and one does not are the most
		// important difference this view can surface.
		"mode":                 func(f *Firewall) { f.cfg.Mode = modeReport },
		"score_threshold":      func(f *Firewall) { f.cfg.ScoreThreshold = 9.9 },
		"unscorable_policy":    func(f *Firewall) { f.cfg.UnscorablePolicy = "allow" },
		"unverified_policy":    func(f *Firewall) { f.cfg.UnverifiedPolicy = "allow" },
		"unknown_path_policy":  func(f *Firewall) { f.cfg.UnknownPathPolicy = unknownPathAllow },
		"byte_gate":            func(f *Firewall) { f.cfg.ByteGate = byteGateEnforce },
		"write_policy":         func(f *Firewall) { f.cfg.WritePolicy = writePolicyAllow },
		"max_release_age_days": func(f *Firewall) { f.cfg.MaxReleaseAgeDays = 30 },
		"min_release_age_days": func(f *Firewall) { f.cfg.MinReleaseAgeDays = 7 },
		"verify_repo":          func(f *Firewall) { f.cfg.VerifyRepo = false },
		"scorecard_mode":       func(f *Firewall) { f.cfg.ScorecardMode = scorecardModeOff },
		// Loading a feed must move the digest away from "off".
		"known_malware_feed": func(f *Firewall) {
			l, err := parseMalwareList(strings.NewReader(`{"id":"MAL-1","ecosystem":"npm","name":"bad"}` + "\n"))
			if err != nil {
				t.Fatalf("parseMalwareList: %v", err)
			}
			f.malware = l
		},
		// The operator's own lists (D193). Same reasoning as the feed above: reported
		// from the LOADED list, so loading one must move the digest away from "off".
		"operator_allow_list": func(f *Firewall) {
			f.allowList = staticList(mustParseOperatorList(t, "allow", "npm", "vetted-tool"))
		},
		"operator_deny_list": func(f *Firewall) {
			f.denyList = staticList(mustParseOperatorList(t, "deny", "npm", "internal-forbidden"))
		},
	}
	for key := range base.Values {
		fn, ok := mutate[key]
		if !ok {
			t.Errorf("policyValues reports %q but this test does not vary it — add a case, or the digest may not cover it", key)
			continue
		}
		f := &Firewall{cfg: shippedConfig()}
		fn(f)
		if got := f.describePolicy().Digest; got == base.Digest {
			t.Errorf("changing %q did not change the digest — replicas differing only in that setting would look identical", key)
		}
	}
}

// The blind spot the content digest exists to close: the SAME configured path with
// DIFFERENT bytes behind it. A path-only report would call these two replicas
// identical while one blocked a package the other served — which is precisely the
// condition the divergence digest was built to detect.
func TestPolicyDigestSeesADifferentFeedAtTheSamePath(t *testing.T) {
	load := func(line string) *malwareList {
		l, err := parseMalwareList(strings.NewReader(line + "\n"))
		if err != nil {
			t.Fatalf("parseMalwareList: %v", err)
		}
		return l
	}
	cfg := shippedConfig()
	cfg.MalwareListPath = "/etc/yellowjack/malware.ndjson" // identical on both replicas
	a := &Firewall{cfg: cfg, malware: load(`{"id":"MAL-1","ecosystem":"npm","name":"bad"}`)}
	b := &Firewall{cfg: cfg, malware: load(`{"id":"MAL-2","ecosystem":"npm","name":"worse"}`)}

	if a.describePolicy().Digest == b.describePolicy().Digest {
		t.Error("two replicas loaded different feeds from the same path and digested identically — " +
			"the divergence alert would stay silent while they enforced different policy")
	}
}

// SECRETS AND TOPOLOGY MUST NEVER APPEAR. The view is reported to the control plane and
// rendered in a browser; POLICY_DISTRIBUTION.md §3 draws the line at "policy is what the
// gate decides, not what the gate is". FW_UPSTREAM in particular: a surface that carries
// the upstream is a step toward one that can change it, which !101 exists to prevent.
func TestViewCarriesNoSecretsOrTopology(t *testing.T) {
	cfg := shippedConfig()
	cfg.UpstreamRegistry = "https://registry.npmjs.org"
	cfg.UpstreamAuth = "Bearer super-secret-token"
	cfg.ApprovalURL = "http://approval.internal:8090"

	body, err := json.Marshal((&Firewall{cfg: cfg}).describePolicy())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"super-secret-token", "registry.npmjs.org", "approval.internal"} {
		if strings.Contains(string(body), forbidden) {
			t.Errorf("the reported policy view leaked %q:\n%s", forbidden, body)
		}
	}
}

// A firewall built with an EXPLICIT ruleset must be described by that ruleset, not by what
// its config implies. Rebuilding from cfg would describe a policy this process is not
// running — and every override test constructs a firewall exactly this way.
func TestDescribeReadsTheInstalledRulesetNotTheConfig(t *testing.T) {
	f := &Firewall{
		cfg: shippedConfig(),
		rules: Ruleset{{
			Name:   "allow: a rule no config would produce",
			Match:  func(Facts) bool { return true },
			Action: ActionAllow,
		}},
	}
	v := f.describePolicy()

	c := chain(t, v, chainVerdict)
	if !strings.Contains(c.Rules[0].Name, "no config would produce") {
		t.Errorf("verdict chain was rebuilt from config instead of read from the installed ruleset: %s", viewRuleNames(c))
	}
	// ...and the engine, not an assumption, decides what an unmatched request gets: this
	// ruleset ends in a match-all allow, so the terminal is unreachable.
	if c.DefaultAction != string(ActionAllow) {
		t.Errorf("default action = %q, want allow — this ruleset allows everything", c.DefaultAction)
	}
}

// The heartbeat has a size budget (approval's maxHealthBytes). A view that outgrew it
// would be rejected, and the failure would present as the replica going SILENT — the
// liveness signal lost to a policy-reporting feature. Assert there is real headroom.
func TestViewFitsTheHeartbeatBudget(t *testing.T) {
	body, err := json.Marshal(describeShipped(t))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// NOT the control plane's cap, which is 64 KiB and is derived from its source in
	// heartbeatbudget_test.go. This number was once a hand-copy of that cap and went stale when
	// the cap was raised; it is kept as what it actually is now -- a tripwire on how big the
	// SHIPPED view is allowed to get before someone looks at it.
	const budget = 8 << 10
	if len(body) > budget/2 {
		t.Errorf("policy view is %d bytes, over half the %d-byte heartbeat budget — "+
			"adding it to the beat risks the whole heartbeat being rejected, which reads as a DEAD replica",
			len(body), budget)
	}
	t.Logf("policy view: %d bytes of the %d-byte heartbeat budget", len(body), budget)
}

// mustParseOperatorList builds a list for the digest-coverage cases above.
func mustParseOperatorList(t *testing.T, kind, ecosystem string, lines ...string) *operatorList {
	t.Helper()
	body := strings.Join(lines, "\n") + "\n"
	l, err := parseOperatorList(kind, ecosystem, strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseOperatorList(%s): %v", kind, err)
	}
	return l
}
