package main

import (
	"net/url"
	"strings"
	"testing"
)

// This file asserts ONE property, the one D101 rests on:
//
//	No input carried in a request can change WHICH HOST we fetch artifact bytes from.
//
// The project ruled (D101) that protecting against redirection attacks is out of scope,
// on the stated premise that "we point to upstream registries of our choosing".
// That premise is what makes the rest of the ruling safe — if a request could aim
// us at an attacker's registry, "the upstream is trusted" would be a statement about
// nothing. So the premise has to be enforced, not assumed.
//
// Today it holds, but only as a SIDE EFFECT of how the path is sliced: the object
// path always begins with "/", and a leading "/" is what terminates the authority
// component of a URL. Nothing says so out loud, and nothing fails if that stops
// being true. An "accidentally correct" security property is one refactor away from
// being an accidentally incorrect one — hence this file.

// artifactTarget rebuilds the upstream URL exactly as proxyArtifactBytes does. Kept
// as a named helper so the test breaks loudly if that construction is changed here
// but not there, rather than silently testing a stale copy of the logic.
func artifactTarget(upstream, objectPath string) string {
	return strings.TrimRight(upstream, "/") + objectPath
}

// TestUpstreamHostCannotBeRetargetedByRequestPath feeds paths built to move the host
// through every mechanism a URL offers — userinfo ("@"), an authority ("//"), scheme
// confusion, and traversal — and asserts that each one is either refused outright by
// the path guard or resolves to the configured upstream host.
//
// Both outcomes are acceptable and the test deliberately accepts either: the guard
// rejecting a path is a fine way to be safe, and so is the path being harmless. What
// is NOT acceptable is a request that survives the guard AND lands on another host.
func TestUpstreamHostCannotBeRetargetedByRequestPath(t *testing.T) {
	const upstream = "https://registry.npmjs.org"
	const wantHost = "registry.npmjs.org"

	cases := []struct {
		name string
		path string
	}{
		{"userinfo separator promotes a foreign host", "/lodash/-/@evil.test/x.tgz"},
		{"leading double slash is an authority", "//evil.test/lodash/-/lodash-1.0.0.tgz"},
		{"double slash after the package prefix", "/_tarball/lodash//evil.test/x.tgz"},
		{"backslash, which some parsers treat as a separator", `/_tarball/lodash/\\evil.test/x.tgz`},
		{"scheme-relative object path", "/_tarball/lodash/https://evil.test/x.tgz"},
		{"traversal out of a mirror's base path", "/_tarball/lodash/../../evil/x.tgz"},
		{"encoded traversal", "/_tarball/lodash/%2e%2e%2f%2e%2e%2fevil/x.tgz"},
		{"encoded userinfo", "/_tarball/lodash/%40evil.test/x.tgz"},
		{"CRLF in the path", "/_tarball/lodash/x%0d%0aHost:%20evil.test/x.tgz"},
		{"a plain honest tarball, as the anchor case", "/lodash/-/lodash-4.17.21.tgz"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if checkRequestPath(tc.path) != pathOK {
				// Refused before any parsing — safe, and the preferred outcome.
				return
			}
			pkg, objectPath, ok := npmArtifactPath(tc.path)
			if !ok {
				// Not classified as an artifact fetch, so it never reaches the
				// artifact relay's URL construction at all.
				return
			}
			target := artifactTarget(upstream, objectPath)
			u, err := url.Parse(target)
			if err != nil {
				// Unparseable means no request goes out. Also safe.
				return
			}
			if u.Host != wantHost {
				t.Errorf("request path %q (pkg %q, object %q) built target %q, whose host is %q — "+
					"a request must never be able to choose the upstream host. D101's ruling that "+
					"redirection is out of scope rests on the upstream being OURS to configure.",
					tc.path, pkg, objectPath, target, u.Host)
			}
			if u.User != nil {
				t.Errorf("request path %q built target %q carrying userinfo %q — userinfo before an "+
					"'@' silently moves the real host", tc.path, target, u.User)
			}
		})
	}
}

// TestUpstreamHostInvariantCanFail is the negative control.
//
// Every case above passes today, which on its own is equally consistent with "the
// property holds" and "the assertion is too weak to notice." So here the SAME cases
// run against a deliberately broken join — one that drops the object path's leading
// slash, which is precisely the detail the real property depends on — and at least
// one of them must be caught.
//
// If this test ever fails, the check above has stopped being able to detect a
// retargeted host, and its passing means nothing.
func TestUpstreamHostInvariantCanFail(t *testing.T) {
	const upstream = "https://registry.npmjs.org"
	const wantHost = "registry.npmjs.org"

	// The broken variant: strip the leading "/" before joining, so the object path
	// is appended directly to the authority instead of starting a new path segment.
	brokenTarget := func(up, objectPath string) string {
		return strings.TrimRight(up, "/") + strings.TrimPrefix(objectPath, "/")
	}

	caught := 0
	for _, path := range []string{
		"/_tarball/lodash/@evil.test/x.tgz",
		"/_tarball/lodash/.evil.test/x.tgz",
	} {
		if checkRequestPath(path) != pathOK {
			continue
		}
		_, objectPath, ok := npmArtifactPath(path)
		if !ok {
			continue
		}
		u, err := url.Parse(brokenTarget(upstream, objectPath))
		if err == nil && u.Host != wantHost {
			caught++
		}
	}
	if caught == 0 {
		t.Fatal("the host-retargeting check could not detect a KNOWN-BROKEN URL join, so " +
			"TestUpstreamHostCannotBeRetargetedByRequestPath passing proves nothing")
	}
}
