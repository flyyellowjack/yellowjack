package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// A serializable description of the policy this replica is ACTUALLY enforcing
// (#32 Phase D / D4). The firewall reports it on the heartbeat; the console renders it.
//
// WHY THIS EXISTS RATHER THAN THE CONSOLE DERIVING IT. The console could, in principle,
// read the same config and work out which rules it produces. It would then be a second
// implementation of defaultRuleset/defaultClassificationRuleset/byteGateRuleset, and the
// day the two disagreed the console would confidently show a policy the gate was not
// running — which is worse than showing nothing, because an operator would act on it.
// Same argument C4c made for calling one evaluateAlerts.
//
// WHY IT IS REPORTED OUTBOUND ON THE HEARTBEAT AND NOT SERVED FROM AN ENDPOINT. The
// firewall's listener is the DEVELOPER-FACING one — /healthz is answered in ServeHTTP
// before the path guards, on the port package managers talk to. A policy endpoint beside
// it would publish the threshold, which categories are only allow-but-log, and whether the
// byte gate is in visibility mode, unauthenticated, to exactly the population with a motive
// to route around the gate. It would also shadow another package name in all four
// ecosystems, the way /healthz already shadows a package called "healthz". Reporting
// outbound over the heartbeat C4a already established costs no new surface. See
// docs/POLICY_DISTRIBUTION.md §6.1.

// RuleView is one rule reduced to what an operator needs to read: what it is called and
// what it does. The condition is deliberately absent — it is a Go closure and cannot be
// serialized, which is the whole crux of Phase D (POLICY_DISTRIBUTION.md §2).
type RuleView struct {
	// ID is the positional identifier a refusal carries on the wire and in the audit
	// record for this rule (D182): "<chain>#<n>", the same numbering as this list.
	ID     string `json:"id"`
	Name   string `json:"name"`
	Action string `json:"action"`
	// Implicit marks the engine's terminal rule, which is not a line anyone wrote and
	// cannot be deleted or reordered. Flagged rather than silently blended in, because an
	// operator comparing this against a config file must be able to tell which lines they
	// own.
	Implicit bool `json:"implicit,omitempty"`
}

// ChainView is one ordered ruleset. Three chains, not one, because the engine has three:
// what is this request, what do we think of this package, may these bytes be served —
// the iptables-per-hook shape (see byteGateRuleset).
type ChainView struct {
	Name  string     `json:"name"`
	Rules []RuleView `json:"rules"`

	// DefaultAction is what this chain does to a request that matches nothing specific,
	// obtained by asking the REAL engine — Decide(Facts{}) — rather than by assuming it is
	// the terminal reject.
	//
	// THIS FIELD EXISTS TO PREVENT A MISLEADING RENDER, and the byte chain is why. Every
	// chain carries an implicit terminal reject, so a view that simply displayed it would
	// tell an operator that unmatched artifact-byte requests are BLOCKED. They are not: in
	// the shipped default the byte chain ends in a match-all allow-but-log (D49's
	// visibility-first posture), so the terminal is unreachable there. An operator who
	// read "block" and believed their artifact route was fail-closed would have exactly
	// the wrong picture of their own deployment — and would find out from an incident.
	// Asking the engine cannot be wrong in that way.
	DefaultAction string `json:"default_action"`
}

// ListView is one of the operator's own allow/deny lists, rendered for the console
// (D193, issue #58 increment 2).
//
// Carried as its own field rather than folded into Values, because Values is a flat
// map of settings and these are CONTENT. An operator reading the enforced-policy page
// needs to see which packages they put on the list, not only that a list exists -- the
// count alone cannot answer "did my edit actually reach the gate?", which is the whole
// question this page is for.
type ListView struct {
	Kind string `json:"kind"` // "allow" | "deny"
	// Path is where this replica read it from. Shown because an operator debugging a
	// list that "isn't working" is usually editing a different file than the one mounted.
	Path string `json:"path"`
	// Names are the NORMALIZED entries -- what the gate matches, which is not always what
	// was typed. The page is titled "enforced policy", so it shows the enforced spelling.
	Names []string `json:"names,omitempty"`
	// Omitted is how many names are not in Names because of the cap. Never silently
	// dropped: a truncated list that did not say so would read as the whole policy.
	Omitted int    `json:"omitted,omitempty"`
	Digest  string `json:"digest"`
}

// maxListNamesReported caps how many entries travel in each heartbeat.
//
// These lists are hand-authored, so the realistic size is dozens; the cap exists for the
// operator who pastes a bulk blocklist and would otherwise turn a health report into a
// transfer. 200 is chosen to be far above any hand-written list and far below a bulk one.
const maxListNamesReported = 200

// PolicyView is the whole reported policy for one replica.
type PolicyView struct {
	Chains []ChainView `json:"chains"`

	// Lists is emitted only when a list is configured -- an unused feature should not put
	// an empty array in every heartbeat or an empty section on the page.
	//
	// ⚠ NOTE what this does NOT buy, so nobody relies on it: the digest still changes on
	// upgrade even for a deployment using neither list, because the two Values entries
	// below are reported unconditionally (as "off"). That is deliberate and matches
	// known_malware_feed: an operator has to be able to tell "the feature is off" from
	// "this build predates the feature", and only an explicit "off" says the first one.
	// The consequence is that a ROLLING upgrade shows old and new replicas as divergent,
	// which is true -- they are running different policy surfaces -- and it clears itself
	// when the rollout completes.
	Lists []ListView `json:"lists,omitempty"`

	// Values are the effective policy settings the rules were compiled from. They are
	// carried SEPARATELY from the rules, and not for display convenience — see digest().
	//
	// Only the settings POLICY_DISTRIBUTION.md §3 lists as policy. Deliberately no
	// upstream URLs (a UI that can retarget the upstream can point the gate at an
	// attacker's registry — see !101) and never FW_UPSTREAM_AUTH, which is a credential.
	Values map[string]string `json:"values"`

	// Digest is a stable fingerprint of everything above, so the control plane can tell
	// two replicas apart without deep-comparing their chains.
	Digest string `json:"digest"`
}

// Chain names. Stable identifiers — the console keys off these, and they appear in the
// digest, so renaming one is a policy-visible change.
const (
	chainVerdict        = "verdict"
	chainClassification = "classification"
	chainBytes          = "bytes"
)

// describeRuleset renders one chain, appending the engine's implicit terminal and asking
// the engine what an unmatched request actually gets.
func describeRuleset(name string, rs Ruleset) ChainView {
	rules := make([]RuleView, 0, len(rs)+1)
	for _, r := range rs {
		rules = append(rules, RuleView{ID: rs.ruleID(name, r), Name: r.Name, Action: string(r.Action)})
	}
	// Always shown, always flagged. It is the defining property of the model — "a Ruleset
	// that matches nothing REJECTS" — and hiding it would make the shipped two-rule policy
	// look like it has no fallback at all. DefaultAction is what says whether it is
	// reachable.
	rules = append(rules, RuleView{
		ID:       rs.ruleID(name, terminalRule),
		Name:     terminalRule.Name,
		Action:   string(terminalRule.Action),
		Implicit: true,
	})

	_, action := rs.Decide(Facts{})
	return ChainView{Name: name, Rules: rules, DefaultAction: string(action)}
}

// describePolicy renders everything this firewall is enforcing.
//
// It reads the rulesets through the same accessors the request path uses (f.ruleset() and
// friends), NOT by rebuilding them from cfg. Rebuilding would describe what the config
// implies rather than what this process installed, and those differ for any firewall
// constructed with an explicit ruleset — which is how every override test builds one.
func (f *Firewall) describePolicy() PolicyView {
	v := PolicyView{
		Chains: []ChainView{
			describeRuleset(chainVerdict, f.ruleset()),
			describeRuleset(chainClassification, f.classifyRuleset()),
			describeRuleset(chainBytes, f.byteRuleset()),
		},
		Values: policyValues(f.cfg),
	}
	// The release-age window, reported as what this gate can ENFORCE rather than as
	// what the operator typed (#150). On an ecosystem with no trustworthy release date
	// the knob is deliberately inert -- whyOCIHasNoReleaseWindow records the measurement,
	// and its own reasoning is that shipping a window there would be worse than none
	// "because the operator would believe the window applied to containers". Listing
	// `min_release_age_days: 7` on that gate's policy page produces exactly that belief,
	// on the one surface D136 says must let an operator prove what the instance will do.
	//
	// A zero stays "0": nothing was asked for, so there is nothing to mislead about.
	//
	// The annotation is applied BEFORE the digest on purpose, and it costs something: an
	// npm gate and an OCI gate sharing a cooldown of 7 used to digest identically and
	// now form two groups, so /policy reports a divergence. That is the truthful reading
	// (one gate holds new releases back, the other does not), and the alternative is
	// worse: the console shows ONE policy per digest group, taken from whichever replica
	// it met first, so with equal digests the note would either vanish or be pinned on
	// the npm gates. The operator clears it the way both shipped deployments already do:
	// leave the knob off the OCI gate.
	if !f.releaseWindowEnforced() {
		for _, key := range []string{"min_release_age_days", "max_release_age_days"} {
			if v.Values[key] != "0" {
				v.Values[key] = fmt.Sprintf("%s (NOT ENFORCED on %s: no trustworthy release date to judge by, #127)",
					v.Values[key], f.cfg.Ecosystem)
			}
		}
	}
	// D172 layer 1, reported from the LOADED FEED rather than from cfg — the same
	// distinction this function's doc comment draws about rulesets. Reporting
	// cfg.MalwareListPath would say which file was named; this says what was actually
	// installed, so two replicas pointing at the same path with different bytes behind
	// it diverge in the digest instead of agreeing falsely.
	v.Values["known_malware_feed"] = f.malwareFeed().describe(f.cfg.Ecosystem)
	// The operator's own lists (D193), reported from the LOADED lists for the same reason
	// as the feed above. This is what makes replica divergence VISIBLE for a list someone
	// edits: the console already groups replicas by this digest and flags disagreement, so
	// a half-rolled-out list edit shows up as two groups rather than as silence.
	// Read through the source, so the reported policy is the list CURRENTLY in force
	// rather than the one loaded at boot (D195). Otherwise the console would show a
	// stale list while the gate enforced a newer one, which is worse than showing
	// nothing: the page would be confidently wrong.
	allow, deny := f.allow(), f.deny()
	v.Values["operator_allow_list"] = allow.describe()
	v.Values["operator_deny_list"] = deny.describe()
	if l := describeList("allow", allow); l != nil {
		v.Lists = append(v.Lists, *l)
	}
	if l := describeList("deny", deny); l != nil {
		v.Lists = append(v.Lists, *l)
	}
	v.Digest = v.digest()
	return v
}

// describeList renders one operator list, or nil when it is not configured.
func describeList(kind string, l *operatorList) *ListView {
	if l == nil {
		return nil
	}
	names, omitted := l.listEntries(maxListNamesReported)
	return &ListView{
		Kind:    kind,
		Path:    l.path,
		Names:   names,
		Omitted: omitted,
		Digest:  l.contentDigest,
	}
}

// releaseWindowEnforced reports whether THIS gate can apply the release-age window
// (#26 cooldown, D22 floor) at all. It is the one statement of that fact, so the policy
// view cannot drift from the enforcement again:
//
//   - npm and PyPI enforce it by filtering the metadata document they already rewrite
//     (proxy.go's two index branches);
//   - an ecosystem with no filterable index enforces it per request IF it implements
//     releaseDated (Maven does -- mavenage.go);
//   - everything else does not. Today that is OCI, deliberately and by measurement.
//
// A new ecosystem lands in the last bucket by default, which is the honest default:
// "not enforced" until somebody builds and proves otherwise. TestEveryEcosystemIs-
// ClassifiedForTheReleaseWindow makes that an explicit decision rather than a silence.
func (f *Firewall) releaseWindowEnforced() bool {
	switch f.cfg.Ecosystem {
	case "npm", "pypi":
		return true
	}
	_, ok := f.eco.(releaseDated)
	return ok
}

// policyValues extracts the effective policy settings — POLICY_DISTRIBUTION.md §3's
// editable surface, which is also exactly what Phase D's D1 will store.
func policyValues(cfg Config) map[string]string {
	return map[string]string{
		// Reported FIRST because it conditions every other value here: in report mode
		// none of them are enforced. A console showing a strict threshold beside a mode
		// it does not mention would tell an operator they are protected when they are
		// not, which is the failure this whole view exists to prevent.
		"mode":                 cfg.Mode,
		"score_threshold":      strconv.FormatFloat(cfg.ScoreThreshold, 'f', -1, 64),
		"unscorable_policy":    cfg.UnscorablePolicy,
		"unverified_policy":    cfg.UnverifiedPolicy,
		"unknown_path_policy":  unknownPathPolicy(cfg.UnknownPathPolicy),
		"byte_gate":            byteGateMode(cfg.ByteGate),
		"write_policy":         writePolicy(cfg.WritePolicy),
		"max_release_age_days": strconv.Itoa(cfg.MaxReleaseAgeDays),
		"min_release_age_days": strconv.Itoa(cfg.MinReleaseAgeDays),
		"verify_repo":          strconv.FormatBool(cfg.VerifyRepo),
		// Reported because two replicas differing ONLY in whether they score at all are
		// the most consequential divergence this page can show after report mode -- one
		// gate compares to a threshold, the other never asks (D273). It is also what lets
		// the console treat "no scanner" as a configuration rather than a gap (#151): the
		// console hides its scoring surfaces only when every reporting replica says off.
		"scorecard_mode": cfg.ScorecardMode,
	}
}

// digest fingerprints the policy so divergence between replicas is one string comparison.
//
// IT COVERS THE VALUES, NOT JUST THE RULES, and that is the trap this function exists to
// avoid. Rule NAMES do not always change when policy does: raising FW_SCORE_THRESHOLD from
// 5.0 to 7.0 leaves the rule called "allow: OSSF score at or above threshold" byte for
// byte identical, because the threshold is captured in the closure, not written into the
// name. A digest over names alone would therefore report two replicas as running the same
// policy while one blocked packages the other served — which is precisely the condition
// the divergence alert exists to catch, made invisible. TestDigestChangesWithThreshold
// pins this.
//
// Not a security boundary: sha256 here is for stable, collision-resistant identity, not
// authentication. Nothing trusts a digest it was handed.
func (v PolicyView) digest() string {
	h := sha256.New()
	for _, c := range v.Chains {
		fmt.Fprintf(h, "chain:%s;default:%s\n", c.Name, c.DefaultAction)
		for _, r := range c.Rules {
			fmt.Fprintf(h, "  rule:%s;action:%s;implicit:%t\n", r.Name, r.Action, r.Implicit)
		}
	}
	// Map iteration order is randomized in Go, so the keys are sorted before hashing —
	// otherwise the same policy would digest differently on each call and every replica
	// would look divergent from itself.
	for _, k := range sortedKeys(v.Values) {
		fmt.Fprintf(h, "value:%s=%s\n", k, v.Values[k])
	}
	// The lists are part of the policy, so they are part of the fingerprint. Hashing the
	// list's own content digest rather than its names keeps this cheap and bounded, and it
	// covers the entries the CAP omitted -- a digest that only saw the first 200 names
	// would call two replicas identical when their lists differed at entry 201.
	for _, l := range v.Lists {
		fmt.Fprintf(h, "list:%s;path:%s;digest:%s;omitted:%d\n", l.Kind, l.Path, l.Digest, l.Omitted)
	}
	return hex.EncodeToString(h.Sum(nil))[:16] // 64 bits: plenty to distinguish a handful of policies
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Insertion sort: the map has eight entries and this avoids pulling in sort for it.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// String renders the policy as text for the startup log, so an operator can see the gate's
// posture in the place they already look when something is wrong.
func (v PolicyView) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "policy %s:", v.Digest)
	for _, c := range v.Chains {
		fmt.Fprintf(&b, " %s(%d rules, default=%s)", c.Name, len(c.Rules), c.DefaultAction)
	}
	return b.String()
}
