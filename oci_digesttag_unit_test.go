package main

import (
	"strings"
	"testing"
)

// The spelling rule for #109, pinned at the two seams it touches: the reference
// normaliser and the identity a request path yields. The negatives are the important
// half -- cosign signs an image by pushing TAGS named "sha256-<hex>.sig" beside it,
// and those must stay tags.
func TestOciDigestInTagPositionIsTheDigest(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	cases := []struct {
		ref    string
		digest bool
		why    string
	}{
		{"sha256-" + hex64, true, "the OCI 1.1 referrers-tag spelling of a digest"},
		{"sha256:" + hex64, true, "the canonical digest spelling is unchanged"},
		{"3.19", false, "an ordinary tag"},
		{"sha256-" + hex64 + ".sig", false, "a cosign signature TAG lives beside the image and is not the image"},
		{"sha256-" + hex64 + ".att", false, "a cosign attestation tag, likewise"},
		{"sha256-" + strings.Repeat("ab", 31), false, "63 hex characters is not a sha256"},
		{"sha256-" + strings.ToUpper(hex64), false, "a digest grammar admits lowercase hex only"},
		{"sha256-" + strings.Repeat("zz", 32), false, "not hex at all"},
		{"sha512-" + strings.Repeat("ab", 64), false, "only the algorithm the tag schema actually spells this way"},
	}
	for _, c := range cases {
		got := ociJoinRef("library/img", c.ref)
		if c.digest && !strings.HasPrefix(got, "library/img@sha256:") {
			t.Errorf("ociJoinRef(%q) = %q; want the @sha256: identity -- %s", c.ref, got, c.why)
		}
		if !c.digest && got != "library/img:"+c.ref {
			t.Errorf("ociJoinRef(%q) = %q; want it kept as the tag %q -- %s", c.ref, got, "library/img:"+c.ref, c.why)
		}

		path := "/v2/library/img/manifests/" + c.ref
		id := (ociEcosystem{}).PackageNameFromPath(path)
		if c.digest != strings.Contains(id, "@sha256:") {
			t.Errorf("PackageNameFromPath(%q) = %q; digest identity should be %v -- %s", path, id, c.digest, c.why)
		}
	}

	// The two spellings of one digest must be ONE identity, or the reuse cache keyed on
	// it would split them.
	if a, b := ociJoinRef("library/img", "sha256-"+hex64), ociJoinRef("library/img", "sha256:"+hex64); a != b {
		t.Errorf("the two spellings yield different identities: %q vs %q", a, b)
	}
}
