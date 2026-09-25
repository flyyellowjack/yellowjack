package main

import "testing"

// THE REFERRERS ENDPOINT WAS NOT ENUMERATED, AND THAT BROKE REAL PULLS (found with #129).
//
// "/v2/<name>/referrers/<digest>" is OCI 1.1's "which manifests refer to this digest" --
// signatures, SBOMs, attestations. It carries no image content and every manifest it
// names is still gated when the client fetches it, so it belongs beside tags/list.
//
// It was missing, so it fell to the implicit terminal block:
//
//	REFUSED "/v2/library/alpine/referrers/sha256:ea72def7..." : unrecognized request path
//	=> docker pull: ... blocked by firewall: unrecognized request path
//
// WHY IT LOOKED INTERMITTENT, which is the part worth keeping. A Docker daemon that
// already holds the image's content does not fetch the index at all -- it asks referrers
// about a digest it has locally. So the request appears only for a PARTIALLY CACHED
// image and never in a clean-state measurement. The first run of the #129 investigation
// hit exactly this and spent an hour treating referrers as the cause of that defect,
// which it is not: a cold pull never issues one.
func TestReferrersIsAControlPlanePath(t *testing.T) {
	e := ociEcosystem{}

	for _, tc := range []struct {
		path string
		want bool
		why  string
	}{
		{"/v2/library/alpine/referrers/sha256:" + strRepeat("a", 64), true,
			"the listing a Docker daemon asks for when it already holds the content"},
		{"/v2/team/app/referrers/sha256:" + strRepeat("b", 64), true,
			"repository names have slashes in them; this must not be a two-segment rule"},
		{"/v2/x/referrers/whatever", true,
			"this decides that the PATH is a listing endpoint, not that the reference is " +
				"well formed — the relay forwards it verbatim and the registry answers"},

		{"/v2/library/alpine/referrers/", false,
			"names no reference, so it is not the referrers endpoint"},
		{"/v2/library/alpine/referrers", false, "same, without the trailing slash"},
		{"/v2/referrers/sha256:" + strRepeat("c", 64), false,
			"no repository name at all — a bare /referrers/ must not become an open path"},
		{"/v2/library/alpine/manifests/latest", false,
			"CONTROL: a manifest is content and stays gated; if this reads true the " +
				"prefix test is matching far too much"},
		{"/v2/library/alpine/blobs/sha256:" + strRepeat("d", 64), false,
			"CONTROL: blobs are the bytes themselves"},
		{"/V2/library/alpine/referrers/sha256:" + strRepeat("e", 64), false,
			"case folding here would make /V2/ an allowed infrastructure path, which is " +
				"the hole the existing lowercase rule exists to keep shut"},
	} {
		if got := e.ControlPlanePath(tc.path); got != tc.want {
			t.Errorf("ControlPlanePath(%q) = %v, want %v — %s", tc.path, got, tc.want, tc.why)
		}
	}
}

// TestReferrersRuleIsNotVacuous is the negative control: the table above is a list of
// booleans over one function, the kind that keeps passing when the function starts
// answering the same thing to everything.
func TestReferrersRuleIsNotVacuous(t *testing.T) {
	e := ociEcosystem{}
	if !e.ControlPlanePath("/v2/") {
		t.Error("the version handshake is not a control-plane path, so the function is " +
			"answering false to everything and the false rows above prove nothing")
	}
	if e.ControlPlanePath("/v2/library/alpine/manifests/sha256:deadbeef") {
		t.Error("a manifest reads as a control-plane path, so the function is answering " +
			"true to everything and the true rows above prove nothing")
	}
}

func strRepeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
