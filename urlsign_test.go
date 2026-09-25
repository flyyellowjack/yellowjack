package main

import "testing"

const (
	testKey  = "yellowjack-unit-test-signing-key"
	testKey2 = "yellowjack-unit-test-signing-alt"
)

func mustSigner(t *testing.T, current, previous string) *urlSigner {
	t.Helper()
	s, err := newURLSigner(current, previous)
	if err != nil {
		t.Fatalf("newURLSigner(%q, %q): %v", current, previous, err)
	}
	return s
}

func TestURLSignRoundTrip(t *testing.T) {
	s := mustSigner(t, testKey, "")
	sig := s.Sign("npm", "lodash", "/lodash/-/lodash-4.17.21.tgz")
	if sig == "" {
		t.Fatal("Sign returned empty with a key configured")
	}
	if !s.Verify("npm", "lodash", "/lodash/-/lodash-4.17.21.tgz", sig) {
		t.Error("a signature this signer just minted did not verify")
	}
}

// The #67 attack itself: an allowed package's prefix paired with a blocked package's
// object path. This is the case the whole file exists for, so it is asserted directly
// rather than left implied by the generic tamper tests.
func TestURLSignRefusesSwappedObjectPath(t *testing.T) {
	s := mustSigner(t, testKey, "")
	allowedPath := "/lodash/-/lodash-4.17.21.tgz"
	blockedPath := "/evil-pkg/-/evil-pkg-1.0.0.tgz"

	sig := s.Sign("npm", "lodash", allowedPath)
	if s.Verify("npm", "lodash", blockedPath, sig) {
		t.Error("a signature minted for lodash's tarball verified against a different package's " +
			"object path — this is exactly the confused deputy in #67")
	}
}

func TestURLSignRejectsTampering(t *testing.T) {
	s := mustSigner(t, testKey, "")
	const (
		eco  = "npm"
		pkg  = "lodash"
		path = "/lodash/-/lodash-4.17.21.tgz"
	)
	sig := s.Sign(eco, pkg, path)

	cases := []struct {
		name           string
		eco, pkg, path string
		sig            string
	}{
		{"different package", eco, "express", path, sig},
		{"different object path", eco, pkg, "/lodash/-/lodash-4.17.20.tgz", sig},
		{"different ecosystem", "pypi", pkg, path, sig},
		{"empty signature", eco, pkg, path, ""},
		{"not base64", eco, pkg, path, "!!!!not-base64!!!!"},
		{"right encoding, wrong length", eco, pkg, path, "AAAA"},
		{"flipped character", eco, pkg, path, flip(sig)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if s.Verify(tc.eco, tc.pkg, tc.path, tc.sig) {
				t.Errorf("Verify accepted a signature it must refuse (%s)", tc.name)
			}
		})
	}
}

// flip changes one character of a base64url signature to something else in the alphabet.
func flip(sig string) string {
	b := []byte(sig)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}

// Negative control for the length-prefixed canonical encoding.
//
// If signingInput concatenated its fields instead of length-prefixing them, ("a", "bc")
// and ("ab", "c") would hash the SAME message, and a package whose name ended where
// another's began could present an object path it was never signed with. This test
// fails if anyone "simplifies" signingInput back to concatenation.
func TestURLSignFieldBoundariesAreUnambiguous(t *testing.T) {
	s := mustSigner(t, testKey, "")
	if a, b := s.Sign("npm", "a", "bc"), s.Sign("npm", "ab", "c"); a == b {
		t.Fatal("(\"a\",\"bc\") and (\"ab\",\"c\") produced the same signature: the canonical " +
			"encoding is ambiguous, so a crafted package name can claim an unsigned object path")
	}
	// Same check across the ecosystem/package boundary.
	if a, b := s.Sign("npm", "x", "/p"), s.Sign("np", "mx", "/p"); a == b {
		t.Fatal("the ecosystem and package fields run together in the canonical encoding")
	}
}

// A nil signer means the feature is off. Verify must return FALSE, not true: a call
// site that forgets to check Enabled() has to fail closed and be caught, rather than
// silently verify nothing.
func TestURLSignDisabledFailsClosed(t *testing.T) {
	var s *urlSigner
	if s.Enabled() {
		t.Error("a nil signer reported Enabled")
	}
	if got := s.Sign("npm", "lodash", "/x.tgz"); got != "" {
		t.Errorf("a nil signer minted a signature: %q", got)
	}
	if s.Verify("npm", "lodash", "/x.tgz", "anything") {
		t.Error("a nil signer VERIFIED a signature — signing-off must fail closed, not open")
	}
}

func TestURLSignOffByDefault(t *testing.T) {
	s, err := newURLSigner("", "")
	if err != nil {
		t.Fatalf("no key configured must be a supported default, got error: %v", err)
	}
	if s != nil {
		t.Error("no key configured should produce no signer")
	}
}

// Rotation: a URL minted under the old key must keep verifying while that key is still
// listed as previous — otherwise every in-flight lockfile breaks the moment an operator
// rotates. Once the old key is dropped, the same signature must stop verifying.
func TestURLSignRotationAcceptsPreviousKey(t *testing.T) {
	const (
		eco  = "npm"
		pkg  = "lodash"
		path = "/lodash/-/lodash-4.17.21.tgz"
	)
	old := mustSigner(t, testKey2, "")
	minted := old.Sign(eco, pkg, path)

	rotated := mustSigner(t, testKey, testKey2)
	if !rotated.Verify(eco, pkg, path, minted) {
		t.Error("after rotation, a URL minted under the previous key did not verify — " +
			"every lockfile in flight would break")
	}
	// New URLs are minted under the CURRENT key, not the previous one.
	if rotated.Sign(eco, pkg, path) == minted {
		t.Error("rotated signer is still minting with the old key")
	}

	dropped := mustSigner(t, testKey, "")
	if dropped.Verify(eco, pkg, path, minted) {
		t.Error("the previous key was dropped but its signatures still verify")
	}
}

func TestURLSignRejectsForeignKey(t *testing.T) {
	a := mustSigner(t, testKey, "")
	b := mustSigner(t, testKey2, "")
	sig := a.Sign("npm", "lodash", "/lodash/-/lodash-4.17.21.tgz")
	if b.Verify("npm", "lodash", "/lodash/-/lodash-4.17.21.tgz", sig) {
		t.Error("a signature verified under a key that did not mint it")
	}
}

func TestURLSignRejectsWeakConfig(t *testing.T) {
	cases := []struct {
		name              string
		current, previous string
	}{
		{"short current key", "tooshort", ""},
		{"short previous key", testKey, "tooshort"},
		{"previous without current", "", testKey2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newURLSigner(tc.current, tc.previous); err == nil {
				t.Errorf("newURLSigner(%q, %q) was accepted; it must fail fast at startup",
					tc.current, tc.previous)
			}
		})
	}
}
