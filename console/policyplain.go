package main

import (
	"fmt"
	"strconv"
	"strings"
)

// The Policy page's plain-language rules (the design canvas's "Checked top to bottom. The
// first rule that matches decides."): the gate's evaluation order, said the way an
// operator reads it, with each row's numbers taken from what the gates REPORT.
//
// ⚠️ THE ORDER IS THE GATE'S, NOT THE CANVAS'S. The canvas put the allow list first,
// "wins over every rule below". The gate's Evaluate (firewall.go) checks, in order:
//
//  1. the known-malware feed -- package-wide advisories, then version-pinned ones, where
//     an allow entry naming THAT release outranks the advisory for it (D312);
//  2. the operator's deny list, which outranks the allow list;
//  3. the operator's allow list, served without scoring;
//  4. with scoring off, everything else is served;
//  5. a package that cannot be scored, then the score against the threshold, each of which
//     a person's ruling in Decisions can override (applyHumanRuling, humanDenyOnRecord).
//
// A row here that disagreed with that order would be the page lying about the one thing
// it exists to show, so policyplain_test.go pins the order against these branches by name.
// The release window is shown BESIDE the list rather than in it: it filters which versions
// a registry response offers, which is not a step in this chain.

// plainRule is one row of the ordered list.
type plainRule struct {
	N      int // position in the chain, from 1
	Title  string
	Detail string
	Action string // what happens, in words
	Class  string // badge class: reject | allow | allow-but-log | pending
	Off    bool   // configured off on this deployment: shown, dimmed, so the order stays legible
}

// plainPolicy is the Policy page's summary of one reported policy.
type plainPolicy struct {
	Rules      []plainRule
	Also       []plainRule // applies alongside the chain (the release window)
	ReportMode bool
	Threshold  string
}

// entriesOf shortens a gate's list/feed description to its count ("12 entries").
func entriesOf(desc string) (string, bool) {
	switch {
	case desc == "" || desc == "off":
		return "", false
	case strings.HasPrefix(desc, "configured, 0 entries"):
		return "configured, but empty", true
	}
	if i := strings.Index(desc, ","); i > 0 {
		return desc[:i], true
	}
	return desc, true
}

func number(rs []plainRule) {
	for i := range rs {
		rs[i].N = i + 1
	}
}

func buildPlainPolicy(p *policyDoc) plainPolicy {
	if p == nil {
		return plainPolicy{}
	}
	v := p.Values
	out := plainPolicy{ReportMode: v["mode"] == "report", Threshold: v["score_threshold"]}

	// 1. The known-malware feed.
	feed := plainRule{Title: "On the known-malware list", Action: "Block", Class: "reject"}
	if m := feedCount.FindStringSubmatch(v["known_malware_feed"]); m != nil {
		n, _ := strconv.Atoi(m[1])
		feed.Detail = humanCount(int64(n)) + " advisories, checked on the gate before the registry is contacted. " +
			"A release pinned on your allow list outranks the advisory for that release only."
	} else if v["known_malware_feed"] == "" || v["known_malware_feed"] == "off" {
		feed.Detail, feed.Off = "No known-malware list is loaded on this deployment.", true
	} else {
		feed.Detail = v["known_malware_feed"]
	}
	out.Rules = append(out.Rules, feed)

	// 2. The operator's deny list.
	deny := plainRule{Title: "On your block list", Action: "Block", Class: "reject"}
	if n, ok := entriesOf(v["operator_deny_list"]); ok {
		deny.Detail = entryCount(n) + ". Outranks your allow list: a package on both is refused."
	} else {
		deny.Detail, deny.Off = "No block list is configured.", true
	}
	out.Rules = append(out.Rules, deny)

	// 3. The operator's allow list.
	allow := plainRule{Title: "On your allow list", Action: "Allow", Class: "allow"}
	if n, ok := entriesOf(v["operator_allow_list"]); ok {
		allow.Detail = entryCount(n) + ". Served without scoring."
	} else {
		allow.Detail, allow.Off = "No allow list is configured.", true
	}
	out.Rules = append(out.Rules, allow)

	// 4. Scoring off ends the chain: everything else is served.
	if v["scorecard_mode"] == "off" {
		out.Rules = append(out.Rules, plainRule{Title: "Everything else", Action: "Allow", Class: "allow",
			Detail: "Scoring is off (FW_SCORECARD_MODE=off), so a package on neither list nor the known-malware list is served."})
		number(out.Rules)
		return out
	}

	// 5. A repository the package names but that cannot be confirmed as its own. Checked
	// while the repository is resolved, so before scoring; only when verification is on.
	if v["verify_repo"] == "true" {
		unv := plainRule{Title: "Source repository can't be confirmed",
			Detail: "The repository it names does not point back at it, so its score is not borrowed. Sent to a person in Decisions."}
		if v["unverified_policy"] == "open-with-visibility" {
			unv.Action, unv.Class = "Allow, logged", "allow-but-log"
			unv.Detail = "The repository it names does not point back at it. Scored anyway and logged (FW_UNVERIFIED_POLICY=open-with-visibility)."
		} else {
			unv.Action, unv.Class = "Block, ask a person", "reject"
		}
		out.Rules = append(out.Rules, unv)
	}

	// 6. A package the gate cannot score.
	unscorable := plainRule{Title: "Can't be scored", Detail: "No source repository the gate can score. Sent to a person in Decisions."}
	if v["unscorable_policy"] == "block" {
		unscorable.Action, unscorable.Class = "Block, ask a person", "reject"
	} else {
		unscorable.Action, unscorable.Class = "Allow, logged, ask a person", "allow-but-log"
		unscorable.Detail = "No source repository the gate can score. Served and logged while a person decides in Decisions."
	}
	out.Rules = append(out.Rules, unscorable)

	// 7. The score against the threshold.
	th := v["score_threshold"]
	if th == "" {
		th = "the threshold"
	}
	out.Rules = append(out.Rules,
		plainRule{Title: "Health score " + th + " or higher", Action: "Allow", Class: "allow",
			Detail: "Unless a person has denied it in Decisions, which outranks a passing score."},
		plainRule{Title: "Health score below " + th, Action: "Block, ask a person", Class: "reject",
			Detail: "Sent to a person in Decisions. An allow there outranks the score."},
	)

	number(out.Rules)

	// The release window filters versions, beside the chain rather than in it.
	if d := v["min_release_age_days"]; d != "" && d != "0" {
		out.Also = append(out.Also, plainRule{Title: fmt.Sprintf("Published in the last %s days", d),
			Action: "Hold", Class: "pending",
			Detail: "Too new to trust yet: those versions are left out of what the registry offers."})
	}
	if d := v["max_release_age_days"]; d != "" && d != "0" {
		out.Also = append(out.Also, plainRule{Title: fmt.Sprintf("Published more than %s days ago", d),
			Action: "Hold", Class: "pending", Detail: "Older than your age limit: those versions are left out."})
	}
	return out
}
