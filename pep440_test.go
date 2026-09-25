package main

import "testing"

// PEP 440 comparison, the join between a version-pinned advisory and the version a
// client is resolving (issue #103).
//
// Both directions matter and neither table is optional. The MATCH table guards against a
// silent bypass — an advisory and an index that spell the same release differently, where
// a miss serves the file and looks like a clean package. The NO-MATCH table is its
// discriminator: without it, "normalise until it matches" passes, and an implementation
// that considered every version equal would satisfy every case above while blocking the
// world.

func TestPep440SameRelease(t *testing.T) {
	same := []struct{ a, b, why string }{
		{"1.0", "1.0.0", "trailing zeros: PEP 440 zero-pads release segments before comparing"},
		{"1", "1.0.0", "same, two segments apart"},
		{"1.0.0", "v1.0.0", "the optional v prefix is not part of the version"},
		{"1.0.0RC1", "1.0.0-rc1", "case and separator, the two most common advisory spellings"},
		{"1.0.0rc1", "1.0.0.rc1", "dot separator before the pre-release marker"},
		{"1.0a", "1.0a0", "an absent pre-release number means 0"},
		{"1.0alpha1", "1.0a1", "alpha is a spelling of a"},
		{"1.0c1", "1.0rc1", "c is a spelling of rc"},
		{"1.0preview2", "1.0rc2", "preview is a spelling of rc"},
		{"1.0-1", "1.0.post1", "PEP 440's implicit post-release form"},
		{"1.0.post", "1.0.post0", "an absent post number means 0"},
		{"1.0.dev", "1.0.dev0", "an absent dev number means 0"},
		{"0!1.0", "1.0", "epoch 0 is the default and is omitted"},
		{"1.01", "1.1", "leading zeros inside a segment are not significant"},
		{"1.0+ubuntu-1", "1.0+ubuntu.1", "local version separators normalise to dots"},
	}
	for _, c := range same {
		if !pep440Same(c.a, c.b) {
			t.Errorf("%q and %q should be the SAME release (%s) — a miss here is a silent "+
				"bypass: the file is served and looks clean", c.a, c.b, c.why)
		}
	}
}

func TestPep440DifferentRelease(t *testing.T) {
	diff := []struct{ a, b, why string }{
		{"1.0", "1.0.1", "different releases"},
		{"1.0.0", "2.0.0", "different majors"},
		{"1.0rc1", "1.0rc2", "different pre-release numbers"},
		{"1.0", "1.0rc1", "a release and its release candidate are not the same artifact"},
		{"1.0", "1.0.post1", "a post-release is a separate upload"},
		{"1.0", "1.0.dev0", "a dev release is a separate upload"},
		{"1!1.0", "1.0", "a non-zero epoch is significant"},
		{"1.0+a", "1.0+b", "different local versions"},
		{"1.0", "1.0+local", "a local version is not the plain release"},
	}
	for _, c := range diff {
		if pep440Same(c.a, c.b) {
			t.Errorf("%q and %q should be DIFFERENT releases (%s) — over-matching denies a "+
				"clean release of a hijacked package", c.a, c.b, c.why)
		}
	}
}

// TestPep440UnparseableFallsBackToExactMatch. A version we cannot parse must not become
// a silent allow: the exact-spelling case is still caught. Epoch-only garbage, arbitrary
// text and empty strings all reach this path.
func TestPep440UnparseableFallsBackToExactMatch(t *testing.T) {
	if _, ok := pep440Key("not-a-version"); ok {
		t.Fatal("pep440Key claimed to parse garbage; the fallback below would never run")
	}
	if !pep440Same("not-a-version", "NOT-A-VERSION") {
		t.Error("an unparseable version must still match itself case-insensitively, or an " +
			"advisory naming it is discarded entirely")
	}
	if pep440Same("not-a-version", "other-garbage") {
		t.Error("the fallback must be equality, not a blanket match")
	}
}
