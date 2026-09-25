package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// The page's order is the GATE's order, and this pins it to the gate's source rather than
// to a list written down here. Each plain row names the branch of Evaluate (firewall.go)
// that implements it; the test finds those branches in the source and requires they come
// in the same order as the rows. Reordering Evaluate without reordering the page -- or the
// reverse -- fails here, with the two orders side by side.
//
// Derived from the source, not from memory, because the design this page was drawn from
// had the order wrong (the allow list first), and a hand-kept list is how that error
// would come back.
func TestPlainRuleOrderMatchesTheGatesEvaluate(t *testing.T) {
	src, err := os.ReadFile("../firewall.go")
	if err != nil {
		t.Fatalf("read the gate's source: %v", err)
	}
	// A Windows checkout has CRLF endings; CI's has LF. Read both the same way.
	s := strings.ReplaceAll(string(src), "\r\n", "\n")
	start := strings.Index(s, "func (f *Firewall) Evaluate(pkgName string) Decision {")
	if start < 0 {
		t.Fatal("Evaluate not found in firewall.go; this test must follow it")
	}
	end := strings.Index(s[start:], "\n}\n")
	if end < 0 {
		t.Fatal("the end of Evaluate was not found")
	}
	body := s[start : start+end]

	// Row title -> the branch in Evaluate that implements it.
	branch := map[string]string{
		"On the known-malware list": "f.malwareFeed().lookupAll(",
		"On your block list":        "if f.deny().has(f.cfg.Ecosystem, pkgName) {",
		"On your allow list":        `"package %q is on this organisation's allow list; "`,
		"Everything else":           "f.cfg.ScorecardMode == scorecardModeOff",
		"Can't be scored":           "return f.unscorable(pkgName, fmt.Sprintf(\"package %q does not declare a usable source repository\"",
		"Health score":              "return f.decideByScore(pkgName, sc.Score, \"\")",
	}
	for _, values := range []map[string]string{
		{"known_malware_feed": "10 enforced (10 package-wide, 0 version-pinned), sha256:x", "operator_deny_list": "1 entries, sha256:x",
			"operator_allow_list": "1 entries, sha256:x", "score_threshold": "5", "unscorable_policy": "block"},
		{"known_malware_feed": "10 enforced (10 package-wide, 0 version-pinned), sha256:x", "scorecard_mode": "off"},
	} {
		rules := buildPlainPolicy(&policyDoc{Values: values}).Rules
		last, lastTitle := -1, ""
		for _, r := range rules {
			key := r.Title
			if strings.HasPrefix(key, "Health score") {
				key = "Health score"
			}
			marker, ok := branch[key]
			if !ok {
				continue // rows with no single branch (the unverified check sits inside repo resolution)
			}
			at := strings.Index(body, marker)
			if at < 0 {
				t.Fatalf("row %q: its branch %q is no longer in Evaluate -- find where the gate does this now", r.Title, marker)
			}
			if at < last {
				t.Errorf("row %q is listed after %q, but the gate checks it first", r.Title, lastTitle)
			}
			last, lastTitle = at, r.Title
		}
	}
}

func titles(rs []plainRule) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Title)
	}
	return out
}

func TestPlainPolicyFollowsTheReportedSettings(t *testing.T) {
	base := map[string]string{
		"known_malware_feed": "1482 enforced (1482 package-wide, 0 version-pinned), sha256:x", "operator_deny_list": "4 entries, sha256:x",
		"operator_allow_list": "12 entries, sha256:x", "score_threshold": "5", "unscorable_policy": "block",
		"min_release_age_days": "7", "mode": "enforce",
	}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range base {
			m[a] = b
		}
		m[k] = v
		return m
	}

	p := buildPlainPolicy(&policyDoc{Values: base})
	if got := strings.Join(titles(p.Rules), " | "); got != "On the known-malware list | On your block list | On your allow list | Can't be scored | Health score 5 or higher | Health score below 5" {
		t.Errorf("default rows = %s", got)
	}
	if p.Rules[0].N != 1 || p.Rules[len(p.Rules)-1].N != len(p.Rules) {
		t.Errorf("rows are not numbered 1..n")
	}
	if !strings.Contains(p.Rules[0].Detail, "1,482 advisories") {
		t.Errorf("feed row = %q", p.Rules[0].Detail)
	}
	if len(p.Also) != 1 || p.Also[0].Title != "Published in the last 7 days" {
		t.Errorf("release window = %+v", p.Also)
	}

	// Scoring off ends the chain: nothing below the lists, and no score rows.
	off := buildPlainPolicy(&policyDoc{Values: with("scorecard_mode", "off")})
	if last := off.Rules[len(off.Rules)-1]; last.Title != "Everything else" || last.Class != "allow" {
		t.Errorf("scoring off ends with %+v", last)
	}
	for _, r := range off.Rules {
		if strings.HasPrefix(r.Title, "Health score") {
			t.Errorf("scoring off still lists %q", r.Title)
		}
	}

	// The unscorable row says what the setting does.
	open := buildPlainPolicy(&policyDoc{Values: with("unscorable_policy", "allow")})
	for _, r := range open.Rules {
		if r.Title == "Can't be scored" && r.Class != "allow-but-log" {
			t.Errorf("unscorable_policy=allow renders as %q", r.Action)
		}
	}

	// Verification on adds its row, before scoring.
	v := buildPlainPolicy(&policyDoc{Values: with("verify_repo", "true")})
	if got := titles(v.Rules); got[3] != "Source repository can't be confirmed" || got[4] != "Can't be scored" {
		t.Errorf("verify_repo=true rows = %v", got)
	}

	// A list that is not configured is shown Off, not dropped: the order stays legible.
	nofeed := buildPlainPolicy(&policyDoc{Values: with("known_malware_feed", "off")})
	if !nofeed.Rules[0].Off {
		t.Errorf("an unloaded feed is not shown as off")
	}
	if !buildPlainPolicy(&policyDoc{Values: with("mode", "report")}).ReportMode {
		t.Errorf("report mode not surfaced")
	}
}

// The page: plain rules on top, and the engine's view kept in full below for the rig and
// for anyone who needs it.
func TestPolicyPageLeadsWithThePlainRules(t *testing.T) {
	body := getPage(t, &server{approval: galleryFake(time.Now().UTC())}, "/policy")
	rules := strings.Index(body, `<h2 id="rl">Rules`)
	engine := strings.Index(body, `<details class="engine"`)
	if rules < 0 || engine < 0 || rules > engine {
		t.Fatalf("the plain rules do not lead the page (rules at %d, engine view at %d)", rules, engine)
	}
	for _, want := range []string{"On the known-malware list", "In the order the gate checks them", "OSSF score at or above threshold", "Operator lists"} {
		if !strings.Contains(body, want) {
			t.Errorf("policy page lacks %q", want)
		}
	}
	if strings.Contains(body, "Enterprise") {
		t.Errorf("the policy page carries packaging copy D345 left out")
	}
}
