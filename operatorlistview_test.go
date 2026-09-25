package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Tests for reporting the operator's lists in the policy view (D193, issue #58
// increment 2).
//
// The point of this increment is not "the page shows a list". It is that a list someone
// EDITS becomes observable across replicas: D193 ruled the console will edit the
// whitelist, and the failure that ruling introduces is two replicas enforcing different
// lists while both look healthy. The console already groups replicas by policy digest and
// flags disagreement, so the whole mechanism reduces to one question — does the digest
// move when, and only when, the enforced entries move?
//
// That is what these tests pin, in both directions:
//
//   - a comment or reordering must NOT read as a policy change (or every routine edit
//     lights the divergence banner and the banner stops meaning anything)
//   - a changed ENTRY must, including one past the display cap (or two replicas whose
//     lists differ at entry 201 are reported as identical, which is the silent case)

func mustList(t *testing.T, kind, ecosystem string, lines ...string) *operatorList {
	t.Helper()
	l, err := parseOperatorList(kind, ecosystem, strings.NewReader(strings.Join(lines, "\n")+"\n"))
	if err != nil {
		t.Fatalf("parse %s list: %v", kind, err)
	}
	return l
}

// viewFor builds a PolicyView from a firewall carrying the given lists.
func viewFor(t *testing.T, allow, deny *operatorList) PolicyView {
	t.Helper()
	f := &Firewall{cfg: Config{Ecosystem: "npm", ScoreThreshold: 5.0, UnscorablePolicy: "block"}}
	f.allowList, f.denyList = staticList(allow), staticList(deny)
	return f.describePolicy()
}

func TestTheOperatorListsAppearInTheReportedPolicy(t *testing.T) {
	deny := mustList(t, "deny", "npm", "internal-forbidden", "another-one")
	v := viewFor(t, nil, deny)

	if len(v.Lists) != 1 {
		t.Fatalf("Lists has %d entries, want 1 (only the deny list is configured)", len(v.Lists))
	}
	got := v.Lists[0]
	if got.Kind != "deny" {
		t.Errorf("Kind = %q, want %q", got.Kind, "deny")
	}
	// Sorted, so the page is stable between reloads and two replicas with the same
	// entries in a different file order do not look different.
	want := []string{"another-one", "internal-forbidden"}
	if strings.Join(got.Names, ",") != strings.Join(want, ",") {
		t.Errorf("Names = %v, want %v (sorted)", got.Names, want)
	}
	if got.Digest == "" {
		t.Error("Digest is empty; the console keys divergence off it")
	}

	// The Values entries report unconditionally, including "off". An operator must be
	// able to tell "the feature is off" from "this build predates the feature".
	if v.Values["operator_allow_list"] != "off" {
		t.Errorf("operator_allow_list = %q, want %q for an unconfigured list",
			v.Values["operator_allow_list"], "off")
	}
	if !strings.HasPrefix(v.Values["operator_deny_list"], "2 entries") {
		t.Errorf("operator_deny_list = %q, want it to lead with the count",
			v.Values["operator_deny_list"])
	}
}

// TestAConfiguredButEmptyListIsNotReportedAsOff.
//
// The distinction costs one branch and answers the first question an operator asks when
// their list "isn't working": did the file load at all? "off" and "configured, 0 entries"
// send them to two different places — the env var, or the file's contents.
func TestAConfiguredButEmptyListIsNotReportedAsOff(t *testing.T) {
	empty := mustList(t, "deny", "npm", "# every line is a comment", "")
	if empty.count() != 0 {
		t.Fatalf("fixture is not empty: %d entries", empty.count())
	}
	if d := empty.describe(); d != "configured, 0 entries" {
		t.Errorf("describe() = %q; a configured-but-empty list must not be indistinguishable "+
			"from an unconfigured one", d)
	}
	var unconfigured *operatorList
	if d := unconfigured.describe(); d != "off" {
		t.Errorf("nil describe() = %q, want %q", d, "off")
	}
}

// TestCommentsAndOrderingAreNotAPolicyChange.
//
// The digest is over the normalized ENTRY SET, deliberately unlike the malware feed's
// raw-byte digest, because this file is hand-edited. If a reworded comment moved the
// digest, every routine edit would light the console's divergence banner and an operator
// would learn to ignore it — the same reasoning the divergence window itself uses.
func TestCommentsAndOrderingAreNotAPolicyChange(t *testing.T) {
	a := mustList(t, "deny", "npm", "# our reasons", "alpha", "beta")
	b := mustList(t, "deny", "npm", "beta", "# completely different comment", "alpha  # inline")
	if a.contentDigest != b.contentDigest {
		t.Errorf("two lists with the same entries digest differently (%s vs %s); a comment "+
			"edit would read as a policy change", a.contentDigest[:12], b.contentDigest[:12])
	}

	// Anti-vacuity: a digest that ignored everything would also pass the above.
	c := mustList(t, "deny", "npm", "alpha", "gamma")
	if a.contentDigest == c.contentDigest {
		t.Error("lists with DIFFERENT entries digest identically — the digest is not " +
			"discriminating and divergence would never be reported")
	}
}

// TestTheDigestCoversEntriesBeyondTheDisplayCap.
//
// The silent case, and the reason the policy digest hashes the list's own content digest
// rather than the names it sends. Two replicas whose lists agree for the first 200 entries
// and differ at 201 must NOT be reported as running the same policy.
func TestTheDigestCoversEntriesBeyondTheDisplayCap(t *testing.T) {
	base := make([]string, 0, maxListNamesReported+50)
	for i := 0; i < maxListNamesReported+50; i++ {
		base = append(base, fmt.Sprintf("pkg-%04d", i))
	}
	a := mustList(t, "deny", "npm", base...)

	changed := append([]string(nil), base...)
	changed[len(changed)-1] = "pkg-differs-at-the-tail" // past the cap
	b := mustList(t, "deny", "npm", changed...)

	names, omitted := a.listEntries(maxListNamesReported)
	if len(names) != maxListNamesReported {
		t.Fatalf("listEntries returned %d names, want the cap %d", len(names), maxListNamesReported)
	}
	if omitted != 50 {
		t.Errorf("omitted = %d, want 50 — a truncated list that does not say so reads as "+
			"the whole policy", omitted)
	}

	va, vb := viewFor(t, nil, a), viewFor(t, nil, b)
	if va.Digest == vb.Digest {
		t.Error("two policies whose deny lists differ ONLY past the display cap produced " +
			"the same digest — the console would report the replicas as identical and the " +
			"divergence would be invisible")
	}
}

// TestTheConsoleWireFormatMatchesTheFirewall.
//
// console/client.go declares its own policyList rather than importing ListView, because
// the console is an HTTP client of the control plane. The cost is that the json tags must
// agree, and the failure is SILENT and one-directional: a renamed tag decodes to an empty
// list, which the page renders as "no list configured" rather than as an error. So this
// asserts the tags against a literal, the same way capacity_test.go does for the flow
// payload.
func TestTheConsoleWireFormatMatchesTheFirewall(t *testing.T) {
	// Distinct, non-zero, non-equal values so a SWAPPED pair is caught too — equal
	// placeholders would let kind/path transpose undetected.
	in := ListView{
		Kind:    "deny",
		Path:    "/etc/yellowjack/operator-deny.txt",
		Names:   []string{"alpha", "beta"},
		Omitted: 7,
		Digest:  "abcdef0123456789",
	}
	blob, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// The literal the console must be able to read. Written out rather than round-tripped
	// through ListView, because round-tripping would pass even if BOTH sides renamed a
	// tag together — which is exactly the drift the seam exists to make visible.
	var out struct {
		Kind    string   `json:"kind"`
		Path    string   `json:"path"`
		Names   []string `json:"names,omitempty"`
		Omitted int      `json:"omitted,omitempty"`
		Digest  string   `json:"digest"`
	}
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Kind != in.Kind || out.Path != in.Path || out.Omitted != in.Omitted || out.Digest != in.Digest {
		t.Errorf("wire format drifted: got %+v, want %+v", out, in)
	}
	if strings.Join(out.Names, ",") != strings.Join(in.Names, ",") {
		t.Errorf("Names drifted: got %v want %v", out.Names, in.Names)
	}
	// The failure this whole test exists for: a tag mismatch decodes to zero, not an
	// error. Prove the assertions above would actually notice.
	if len(out.Names) == 0 || out.Omitted == 0 {
		t.Error("decoded to empty/zero — that is what a renamed tag looks like, and it " +
			"renders as 'no list configured' rather than as a failure")
	}
}
