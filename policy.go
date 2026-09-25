package main

import (
	"fmt"
	"log"
	"net/http"
)

// The policy ENGINE (D76, issue #58).
//
// Yellow Jack's decision logic is modelled on a network firewall's config: ONE
// ORDERED LIST of rules, evaluated top-down, FIRST MATCH WINS, with an implicit
// terminal "block everything". That shape is not cosmetic. It inverts the
// property that produced four separate critical bypasses (#11, #56, #57, #59):
// today anything the gate does not recognise falls through to ALLOW, so every
// unrecognised path, artifact type and byte route is ungated by default. In an
// ordered ruleset the last line is a block, so "unrecognised" fails closed and a
// new request shape cannot quietly become a hole — someone has to write a rule.
//
// WHAT IS BUILT. Increments 1-4 are merged; #58's issue checklist is the current
// record of what remains, and it is the thing to read — not this comment.
//
//   1. the engine itself, plus the two-rule set a default install ships (!82)
//   2. REQUEST CLASSIFICATION through the same engine, which is where #56
//      (maven's extension allowlist) and #57 (ungated OCI blobs) actually lived
//      — not verdict bugs but "we never even asked" bugs, in proxy.go's old
//      `pkgName == "" -> pass through ungated` branch (!86)
//   3. the unscorable and unverified CATEGORIES moved off direct cfg reads onto
//      rules, each emitted only when it differs from the terminal (!87)
//   4. FW_BYTE_GATE onto rules (!95)
//
// ⚠️ THIS PARAGRAPH IS A DATED CLAIM, NOT A FACT, AND IT HAS ALREADY BEEN WRONG.
// It said "this is increment 1 ... increments 2 and 3 come next" for four
// increments after that stopped being true, and on 2026-09-05 a session read it,
// believed it, and reported the epic's state incorrectly in two places before
// #58's own acceptance checklist corrected it. A comment is prose that happens to
// live in a source file: it rots exactly like a planning doc, because nothing
// breaks when it does. So — trust the tracker's checklist and the tests over this
// block, and if you change what is built, change this too or delete it.
//
// The client-facing reason strings stay hardcoded in decideFinal. That was
// originally "until increment 3", to keep increment 1 provably a no-op for
// existing deployers; it is now simply where they live, and moving them onto
// per-rule reasons is still open work on #58.

// Action is what a rule does when its condition matches. The taxonomy is
// borrowed from network firewalls (D76), with one deliberate omission: there is
// no `drop` (silent block). The project judged it useless for packages — a developer
// whose install hangs with no explanation cannot act on it — and leaving it out
// keeps the engine honest about the fact that every denial owes the user a
// reason. It can be added later if a real need appears.
type Action string

const (
	// ActionAllow serves the package. No record beyond the normal decision log.
	ActionAllow Action = "allow"

	// ActionAllowLog serves the package but records that it got through on a
	// rule rather than on merit. This is the migration ramp: it lets an operator
	// turn a new gate on in visibility mode, read the log, and decide whether
	// enforcing it would break their builds — which is exactly how FW_BYTE_GATE
	// already works for npm tarballs. Increment 2 needs it, because flipping
	// "unrecognised path -> block" straight to enforcement would break every
	// registry control-plane endpoint at once.
	ActionAllowLog Action = "allow-but-log"

	// ActionReject refuses the request WITH feedback the developer can read —
	// today's 403-plus-reason, surfaced wherever the package manager's protocol
	// shows it.
	ActionReject Action = "reject"
)

// Facts is the set of request properties a rule condition may match on. It is
// deliberately the SMALLEST set the current rules need, not a speculative model
// of everything a rule might ever want: an over-wide Facts would have to be
// populated at every call site, and a field that is silently zero at some call
// sites is precisely how a condition starts matching the wrong requests.
//
// Fields arrive as the increments that need them arrive — increment 2 adds the
// request path and its classification, increment 3 the denial kind and the
// ecosystem.
type Facts struct {
	// Package is the resolved package identity ("lodash", "com.evil:badlib",
	// "library/alpine"). Not matched on by any default rule; carried so a rule
	// and its log line can name the subject.
	Package string

	// Score is the OpenSSF Scorecard score, meaningful only when HasScore.
	Score float64

	// HasScore distinguishes "scored 0.0" from "no score at all". A rule that
	// tests Score without first testing HasScore would read an absent score as a
	// genuine zero and block a package it never actually evaluated — the same
	// trap depsDevResponse.OverallScore uses a pointer to avoid.
	HasScore bool

	// Path is the request's EscapedPath, populated on the CLASSIFICATION path
	// only (see defaultClassificationRuleset). Always the escaped form: a rule
	// that matched on the decoded path would be reading a different string than
	// the one we forward upstream, which is the #59 identity-divergence class.
	Path string

	// Kind is what the request path IS, independent of any verdict about a
	// package. Populated on the classification path only; empty on the score
	// path, so a classification rule must test it explicitly rather than assume.
	Kind PathKind

	// Deny names the CATEGORY a package fell into when it could not be decided on
	// its score — denyUnscorable (we could not score it) or denyUnverified (we do
	// not trust the repo a score would come from). Empty on the ordinary score
	// path, so a category rule must test it explicitly.
	//
	// This is what D76 means by a rule "on a category" rather than on a package:
	// "allow-but-log if the package is unscorable" is one line of policy covering
	// every package with thin metadata, not an entry per package.
	Deny denyKind

	// Allowed carries the verdict the METADATA path already reached for this
	// package, and is populated on the BYTE route only (see byteGateRuleset). It
	// is what lets the byte gate's enforce mode say "allow what the metadata
	// verdict allowed" as a rule rather than as an inlined `!decision.Allowed`.
	//
	// False everywhere else — the score and classification rulesets never set it.
	// That zero value is the SAFE direction on purpose: a rule that tested Allowed
	// outside the byte route would read every request as not-allowed and fall
	// toward the terminal block, rather than toward an allow. Getting this field
	// wrong therefore over-blocks, which is visible, instead of over-serving,
	// which is not.
	Allowed bool
}

// PathKind classifies a request the gate did NOT resolve to a package identity.
// It exists because "we couldn't name a package here" was, until now, silently
// synonymous with "relay it ungated" (proxy.go) — the single property behind
// #11, #56, #57 and #59. Naming the two cases apart is what lets a rule treat
// them differently, and lets the terminal rule catch the second.
type PathKind string

const (
	// PathControlPlane is registry infrastructure that carries no package and
	// must pass for the client to work at all: npm's /-/ endpoints, OCI's /v2/
	// handshake and token endpoints, PyPI's index root, Maven's checksums and
	// maven-metadata.xml. Each ecosystem enumerates its own — see
	// Ecosystem.ControlPlanePath — and the enumeration IS the fail-open surface,
	// deliberately short enough to review at a glance.
	PathControlPlane PathKind = "control-plane"

	// PathUnknown is everything else: a path we cannot name a package for AND
	// cannot justify as infrastructure. Today it is relayed ungated. Under the
	// classification ruleset it falls through to the terminal rule, which blocks.
	PathUnknown PathKind = "unknown"
)

// defaultClassificationRuleset is the ordered policy for requests that carry no
// package identity — the second instance of the same engine, and the increment
// that actually inverts the default (D76, issue #58).
//
// Two rules plus the implicit terminal, mirroring the shipped verdict ruleset:
//
//  1. allow the ecosystem's enumerated control-plane endpoints;
//  2. apply FW_UNKNOWN_PATH_POLICY to everything else;
//  3. (implicit) block.
//
// Rule 2 exists because rule 1's enumeration is a claim about four registry
// protocols that we can be wrong about, and being wrong means breaking a real
// client. FW_UNKNOWN_PATH_POLICY is the operator's escape hatch and the
// migration ramp — the same shape FW_BYTE_GATE already uses. It defaults to
// BLOCK per D76 ("everything should default to block"); an operator who hits an
// endpoint we failed to enumerate can set allow-but-log, read exactly which path
// it was from the log line, and report it.
func defaultClassificationRuleset(cfg Config) Ruleset {
	policy := unknownPathPolicy(cfg.UnknownPathPolicy)
	return Ruleset{
		{
			Name:   "allow: registry control-plane endpoint",
			Match:  func(f Facts) bool { return f.Kind == PathControlPlane },
			Action: ActionAllow,
		},
		{
			Name:   "unknown request path (FW_UNKNOWN_PATH_POLICY=" + policy + ")",
			Match:  func(f Facts) bool { return f.Kind == PathUnknown && policy != unknownPathBlock },
			Action: unknownPathAction(policy),
			// NOTE the condition, not just the action: on `block` this rule does
			// not match AT ALL, so the request falls to the implicit terminal
			// rule and is attributed to it in the log. That is deliberate — a
			// blocked unknown path should read as "nothing allowed it", which is
			// the true statement, rather than as a rule that chose to block.
		},
	}
}

// The three FW_UNKNOWN_PATH_POLICY settings. Same vocabulary as FW_BYTE_GATE so
// an operator learns one idiom, not two.
const (
	unknownPathBlock       = "block"         // default (D76)
	unknownPathAllowButLog = "allow-but-log" // the ramp: relay, but say so loudly
	unknownPathAllow       = "allow"         // pre-#58 behaviour, kept as an escape hatch
)

// unknownPathPolicy normalizes the configured value. An unrecognized setting
// reads as the DEFAULT (block) rather than the most permissive option: a typo in
// this knob must not silently reopen the hole the increment exists to close.
func unknownPathPolicy(v string) string {
	switch v {
	case unknownPathBlock, unknownPathAllowButLog, unknownPathAllow:
		return v
	default:
		return unknownPathBlock
	}
}

// The three FW_WRITE_POLICY settings (issue #66). Same vocabulary again, on purpose:
// an operator learns one idiom — block / allow-but-log / allow — and it means the same
// thing everywhere.
const (
	writePolicyBlock       = "block"         // default: we are a read-only gate
	writePolicyAllowButLog = "allow-but-log" // the ramp: relay, but say loudly that we did
	writePolicyAllow       = "allow"         // pre-#66 passthrough
)

// readMethods are the HTTP methods a pull-through gate needs. Everything else is
// treated as a write.
//
// AN ALLOWLIST, NOT A DENYLIST, and that is the entire security content of this fix.
// Enumerating writes (PUT/POST/PATCH/DELETE) would have to stay complete forever: the
// OCI spec alone reaches the upstream through `POST` to start an upload, `PATCH` per
// chunk and `PUT` to finalise, and a registry extension or a future spec revision only
// has to add one verb we did not list to be relayed. Listing what a READ is instead
// makes an unrecognised method fail closed by construction — the same inversion issue
// #58 is about, applied to the method rather than the path.
//
// OPTIONS is deliberately NOT here. It is not a read of a package, and no package
// manager in our e2e matrix sends one; if some client turns out to need it, that is a
// deliberate addition with a test, not a hole we left open in advance.
var readMethods = map[string]bool{
	http.MethodGet:  true,
	http.MethodHead: true,
}

// isWriteRequest reports whether this request would MODIFY the upstream registry.
//
// Method-based rather than path-based on purpose. The path shapes differ per ecosystem
// and per registry implementation, and #66 exists precisely because a path parser
// written for downloads happily accepted an upload URL. The method is the one signal
// that means the same thing in all four ecosystems.
func isWriteRequest(method string) bool {
	return !readMethods[method]
}

// writePolicy normalizes FW_WRITE_POLICY. An unrecognized value reads as the DEFAULT
// (block), never as the most permissive option — same reasoning as unknownPathPolicy,
// and the opposite of unscorableAction: a write is not a noisy-but-legitimate case we
// are being strict about, it is a capability this product does not have.
func writePolicy(v string) string {
	switch v {
	case writePolicyBlock, writePolicyAllowButLog, writePolicyAllow:
		return v
	default:
		return writePolicyBlock
	}
}

// unknownPathAction maps a policy string to the engine action it means.
func unknownPathAction(policy string) Action {
	if policy == unknownPathAllow {
		return ActionAllow
	}
	return ActionAllowLog
}

// Rule is one line of the policy: a condition, and what to do when it matches.
type Rule struct {
	// Name is what the log and (later) the console call this rule. It is the
	// operator's handle on WHY a request was decided the way it was, so it should
	// read like a firewall rule, not like a function name.
	Name string

	// Match is the condition. A nil Match never matches — a malformed rule is
	// skipped rather than treated as match-all, so a rule someone forgot to
	// finish falls through toward the terminal block instead of silently
	// becoming an allow-everything.
	//
	// MATCH MUST BE PURE: no I/O, no recording, no mutation. Two things already
	// depend on that. Decide may evaluate conditions that end up not deciding the
	// outcome, so a side-effecting condition would fire on requests it did not
	// decide; and decideByScore now asks the ruleset BEFORE consulting the
	// approval service, where it previously asked after — a reordering that is
	// only sound because evaluating a rule cannot do anything.
	//
	// This is a live trap for increment 3, whose "allow if the user explicitly
	// allowed this package" rule is the obvious place to reach for the approval
	// service from inside a condition. Resolve that lookup into Facts BEFORE
	// calling Decide instead.
	Match func(Facts) bool

	// Action is what happens on a match.
	Action Action
}

// Ruleset is the ordered policy. The ORDER IS THE SEMANTICS — a Ruleset is not a
// set of independent predicates, it is a sequence, and moving one line changes
// what the firewall does. This is the same contract as an iptables chain or an
// ACL, and it is the reason Decide never sorts, filters or reorders.
type Ruleset []Rule

// terminalRule is the implicit final line of EVERY ruleset — the whole point of
// the model. It is not appended to the slice: it lives here so that it cannot be
// deleted, reordered, or forgotten by whoever writes a config. A Ruleset that
// matches nothing REJECTS, including the empty Ruleset and a Ruleset whose
// author left the block-everything line off.
var terminalRule = Rule{
	Name:   "terminal: block everything (implicit)",
	Match:  func(Facts) bool { return true },
	Action: ActionReject,
}

// Decide walks the rules in order and returns the FIRST whose condition matches,
// together with its action. With no match the implicit terminalRule applies, so
// Decide can never return "no decision" — that absence of a fall-through is the
// property the whole epic exists to establish.
// ruleID is the identifier a refusal carries for the rule that decided it (D182): the
// rule's POSITION in its chain, "<chain>#<n>", 1-based, with the implicit terminal as
// the last position -- exactly the order the policy view lists the chain in, so an
// operator resolves it in one look. Positional rather than the rule's NAME on purpose:
// names carry knob values and policy vocabulary ("block everything (FW_BYTE_GATE=enforce)"),
// and the adversarial suite holds that those describe the gate to whoever is probing it
// and belong in the log only. The log still names the rule; the wire numbers it.
func (rs Ruleset) ruleID(chain string, r Rule) string {
	for i, x := range rs {
		if x.Name == r.Name {
			return fmt.Sprintf("%s#%d", chain, i+1)
		}
	}
	return fmt.Sprintf("%s#%d", chain, len(rs)+1) // the implicit terminal
}

func (rs Ruleset) Decide(f Facts) (Rule, Action) {
	for _, r := range rs {
		if r.Match != nil && r.Match(f) {
			return r, r.Action
		}
	}
	return terminalRule, terminalRule.Action
}

// defaultRuleset is what a default install ships: EXACTLY TWO RULES (D76) — the
// package analogue of a real firewall's "allow admin access to myself on the
// default network; block everything".
//
// The block-everything line is written out explicitly even though terminalRule
// would produce the same outcome. That is deliberate and the redundancy is the
// point: the shipped config should READ like the policy it is, so an operator
// looking at two lines can see the posture without knowing that the engine has
// an implicit terminal. terminalRule remains the safety net for rulesets that
// omit it — and policy_test.go proves both halves independently.
//
// The threshold is captured by value at construction, not read from cfg on every
// evaluation, so a Ruleset is an immutable snapshot of the policy and is safe to
// share across the per-request goroutines without a lock.
func defaultRuleset(cfg Config) Ruleset {
	threshold := cfg.ScoreThreshold
	rs := Ruleset{
		{
			Name:   "allow: OSSF score at or above threshold",
			Match:  func(f Facts) bool { return f.HasScore && f.Score >= threshold },
			Action: ActionAllow,
		},
	}
	// The unscorable CATEGORY rule (D76's example rule 3) is emitted ONLY when
	// it would differ from the terminal block — i.e. when the operator has
	// opted OUT of the fail-closed default. Under the shipped configuration
	// FW_UNSCORABLE_POLICY is "block", which is exactly what "block
	// everything" already does, so adding a rule for it would be a line that
	// changes nothing.
	//
	// That is not tidiness, it is the config-surface budget (#51) and D76's
	// "a default install ships only two rules" taken literally: a policy an
	// operator reads should have no lines in it that do not do anything. The
	// two-rule promise is enforced by TestDefaultRulesetShipsExactlyTwoRules,
	// which is what caught an earlier draft of this increment shipping four.
	//
	// The unverified category needs no rule at all, in any configuration: it
	// always refuses when reached, which is what the terminal already does.
	// FW_UNVERIFIED_POLICY governs whether a package REACHES the category, and
	// that branch lives upstream in verifyRepo — see unverified().
	if action := unscorableAction(cfg.UnscorablePolicy); action != ActionReject {
		rs = append(rs, Rule{
			Name:   "allow-but-log: unscorable (FW_UNSCORABLE_POLICY=" + cfg.UnscorablePolicy + ")",
			Match:  func(f Facts) bool { return f.Deny == denyUnscorable },
			Action: action,
		})
	}
	return append(rs, Rule{
		Name:   "block everything",
		Match:  func(Facts) bool { return true },
		Action: ActionReject,
	})
}

// unscorableAction maps FW_UNSCORABLE_POLICY onto the engine action it means.
//
// "block" is the only value that refuses; anything else allows-but-logs. That
// asymmetry mirrors the original `f.cfg.UnscorablePolicy != "block"` exactly — an
// unset or misspelled value has always meant allow here, and increment 3 is not
// the place to change a shipped default. (Note this runs OPPOSITE to
// FW_UNKNOWN_PATH_POLICY, where a typo fails closed. The difference is deliberate
// and load-bearing: an unscorable package is a legitimate package with thin
// metadata, while an unrecognised request path is the shape four bypasses used.)
func unscorableAction(policy string) Action {
	if policy == "block" {
		return ActionReject
	}
	return ActionAllowLog
}

// byteGateRuleset is the ordered policy for the ARTIFACT BYTE route — the third
// instance of the engine, alongside the score verdict and the classification
// ruleset (D76, issue #58 increment 4).
//
// Three rulesets rather than one is the iptables shape, not a dilution of D76's
// "one ordered list": a packet filter has one ordered chain PER HOOK, each with
// its own default policy, because INPUT and FORWARD are different questions. Ours
// are: "what is this request?", "what do we think of this package?", and "may
// these bytes be served?".
//
// WHAT THIS RULESET OWNS: the allow-vs-refuse axis, and only that. FW_BYTE_GATE
// makes three different decisions and just one of them is a verdict, so the other
// two deliberately stay in proxyArtifactBytes — stated here so a half-migration is
// not mistaken for the whole one:
//
//   - COVERAGE ("off"). Off does not merely allow, it declines to EVALUATE, and
//     also stops rewriting artifact URLs. A rule cannot express that: Match is
//     required to be pure and runs after Evaluate, so modelling off as a rule
//     would force a score lookup on every tarball fetch in the one mode whose
//     purpose is not doing that. Off is which requests the gate covers, which
//     increment 2 already established as a separate question from the verdict.
//     The off case below therefore exists to keep the two representations
//     agreeing, and is pinned by TestByteGateOffRulesetAgreesWithTheShortCircuit.
//   - RETRYABILITY (Pending / Unavailable -> 503). Decision's own doc says these
//     are "NOT a verdict on the package", and D76's taxonomy is three actions with
//     no "come back later" — an omission made on purpose, so extending it is
//     his call, not a technique decision to be smuggled in here. It is not a free
//     extraction either: Pending is MODE-DEPENDENT (503 under enforce, served
//     under allow-but-log), so lifting it out would change behaviour.
//
// The verdicts this produces are identical to the pre-increment ladder, pinned
// against a verbatim copy of it in policy_bytegate_test.go across every mode and
// every decision shape.
func byteGateRuleset(cfg Config) Ruleset {
	switch byteGateMode(cfg.ByteGate) {
	case byteGateOff:
		// Never consulted in practice — proxyArtifactBytes short-circuits before
		// evaluating — but written out so "off" has one meaning rather than two.
		return Ruleset{{
			Name:   "allow: artifact byte gate disabled (FW_BYTE_GATE=off)",
			Match:  func(Facts) bool { return true },
			Action: ActionAllow,
		}}

	case byteGateEnforce:
		return Ruleset{
			{
				Name: "allow: the metadata verdict allowed this package",
				// The SAME verdict the index request would have produced, by
				// construction — one Evaluate, consulted twice — which is what
				// stops the byte route and the metadata route from drifting.
				Match:  func(f Facts) bool { return f.Allowed },
				Action: ActionAllow,
			},
			{
				Name:   "block everything (FW_BYTE_GATE=enforce)",
				Match:  func(Facts) bool { return true },
				Action: ActionReject,
			},
		}

	default: // allow-but-log, the shipped default (D49)
		return Ruleset{
			{
				// D72's carve-out, now legible as policy instead of as a helper
				// plus a paragraph. The enumeration is the point: it lists the two
				// FINDING-based denials, so a denial kind added later falls to the
				// rule below and is served-and-logged rather than silently starting
				// to block artifact fetches.
				//
				// That default runs OPPOSITE to the epic's own fail-closed thesis,
				// and it is a project ruling (D49/D72), not an oversight. Writing it
				// as an ordered pair is what makes the exception visible to an
				// operator reading the policy instead of buried in hardDeny's doc.
				//
				// Calls the same predicate Decision.hardDeny() does, rather than
				// restating it — see hardDenyKind. A second copy here is how the
				// rule and the helper would quietly come to mean different things.
				//
				// "BYTE-GATE mode" is the load-bearing qualifier, not padding. The name
				// read "in every mode" until FW_MODE=report shipped (!191), which DOES
				// suppress this refusal — proxy.go routes it through p.refuseDecision.
				// So the unqualified claim became false, and it was false in the SAME log
				// line that already said report mode suppresses it. A rule name is
				// operator-facing text: it states what fired and why, so it rots exactly
				// like a comment when a new axis is added above it.
				Name:   "reject: denied on a positive finding — blocks bytes in every BYTE-GATE mode (D72)",
				Match:  func(f Facts) bool { return hardDenyKind(f.Allowed, f.Deny) },
				Action: ActionReject,
			},
			{
				// Terminal for this chain is an ALLOW, uniquely among the three
				// rulesets — that IS the visibility-first default, and it is the
				// side door D49 knowingly leaves open until an operator sets
				// enforce. The implicit terminalRule is unreachable here, so this
				// ruleset never inherits the fail-closed default the other two get.
				Name:   "allow-but-log: byte gate is in visibility mode (FW_BYTE_GATE=allow-but-log)",
				Match:  func(Facts) bool { return true },
				Action: ActionAllowLog,
			},
		}
	}
}

// ruleset returns the policy this Firewall decides with, falling back to the
// default two-rule set when none was installed.
//
// The fallback is load-bearing, not defensive clutter. Fourteen test call sites
// (and any future caller) build a &Firewall{} literal directly rather than going
// through NewFirewall, and a nil Ruleset means "matches nothing", which the
// terminal rule turns into "block everything". Without this fallback those
// firewalls would silently start denying every package — the same class of
// zero-value trap NewFirewall already guards for depsDevBase.
func (f *Firewall) ruleset() Ruleset {
	if f.rules != nil {
		return f.rules
	}
	return defaultRuleset(f.cfg)
}

// policyAllows asks the ruleset for a verdict on a scored package and reports
// whether the bytes may be served. It is the ONE place the score verdict is
// decided, so decideFinal and decideByScore cannot drift apart.
//
// allow-but-log is logged here rather than at the call site because the log line
// IS the action — an allow-but-log that produced no record would be an ordinary
// allow. The default ruleset never returns it, so this line cannot appear in a
// default deployment; it exists for the increments that add category rules.
func (f *Firewall) policyAllows(pkgName string, score float64) (Rule, bool) {
	rule, action := f.ruleset().Decide(Facts{
		Package:  pkgName,
		Score:    score,
		HasScore: true,
	})
	if action == ActionAllowLog {
		log.Printf("POLICY (allow-but-log) %q -> served by rule %q (score %.1f) — allowed by policy, not by merit",
			pkgName, rule.Name, score)
	}
	return rule, action != ActionReject
}

// categoryAction asks the ruleset what to do about a package that could not be
// decided on its score and fell into a CATEGORY instead — unscorable, or
// unverified provenance. It is the category counterpart to policyAllows, and
// exists so those two paths consult the same ordered ruleset as the score path
// rather than reading cfg directly.
//
// Called only AFTER applyHumanRuling has declined to decide, so a human ruling
// still outranks the ruleset — the D11 override path is unchanged.
func (f *Firewall) categoryAction(pkgName string, kind denyKind) (Rule, Action) {
	rule, action := f.ruleset().Decide(Facts{Package: pkgName, Deny: kind})
	if action == ActionAllowLog {
		log.Printf("POLICY (allow-but-log) %q -> served by rule %q [%s] — allowed by policy, not by merit",
			pkgName, rule.Name, kind)
	}
	return rule, action
}
