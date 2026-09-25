package main

import "testing"

// TestCheckRequestPathRefusesEvasions is the regression test for issue #59. Every
// case here was MEASURED against the real registry.npmjs.org / pypi.org before the
// guard existed: each one returned the blocked package's real bytes through a
// firewall configured to refuse it (FW_BYTE_GATE=enforce, FW_UNSCORABLE_POLICY=block).
// They are not hypothetical shapes.
func TestCheckRequestPathRefusesEvasions(t *testing.T) {
	cases := []struct {
		name string
		path string
		want pathRejection
	}{
		// --- measured bypasses, npm ---
		{
			// Returned the real 247KB lodash packument. PackageNameFromPath saw an
			// empty first segment, returned "", and ServeHTTP relayed it ungated.
			name: "empty segment leaks the packument",
			path: "//lodash",
			want: pathEmptySegment,
		},
		{
			// Confused deputy: the gate logged "express allowed" and the CDN served
			// lodash, which was blocked.
			name: "dot segment swaps the package after the gate",
			path: "/express/../lodash",
			want: pathDotSegment,
		},
		{
			// Returned the real 318KB tarball with NO decision line logged at all:
			// the byte gate looks for a literal "/-/" in the escaped path, the
			// metadata gate finds "/-/" in the decoded path and defers to the byte gate.
			name: "encoded artifact marker hides the tarball fetch",
			path: "/lodash/%2d/lodash-4.17.21.tgz",
			want: pathHiddenMarker,
		},
		{
			// Mangled the name to "/express", which is unknown, downgrading a hard
			// score deny into a soft unscorable one that allow-but-log then serves.
			name: "empty segment mangles the name on the byte path",
			path: "//express/-/express-4.18.2.tgz",
			want: pathEmptySegment,
		},
		{
			name: "dot segment mangles the name on the byte path",
			path: "/lodash/../express/-/express-4.18.2.tgz",
			want: pathDotSegment,
		},
		// --- measured bypass, PyPI ---
		{
			// Returned the real index with 244 installable links where the honest
			// path returned 248 yanked ones.
			name: "pypi empty segment leaks the unyanked index",
			path: "/simple//requests/",
			want: pathEmptySegment,
		},
		// --- the same tricks, encoded, so the fix isn't a literal-string denylist ---
		{name: "encoded dot-dot", path: "/express/%2e%2e/lodash", want: pathDotSegment},
		{name: "encoded single dot", path: "/express/%2e/lodash", want: pathDotSegment},
		{name: "uppercase encoded marker", path: "/lodash/%2D/lodash-4.17.21.tgz", want: pathHiddenMarker},
		{
			// The scoped-package exemption must not become a hole: this decodes to
			// "@foo/../bar", which is a dot segment wearing a scope's clothes.
			name: "dot segment smuggled inside a scoped name",
			path: "/@foo%2f..%2fbar",
			want: pathEncodedSlash,
		},
		{
			name: "encoded separator outside a scope",
			path: "/lodash%2f..%2fexpress",
			want: pathEncodedSlash,
		},
		{name: "trailing empty segment", path: "/lodash//", want: pathEmptySegment},
		{name: "undecodable escape", path: "/lod%zzash", want: pathBadEscape},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := checkRequestPath(tc.path)
			if got == pathOK {
				t.Fatalf("checkRequestPath(%q) = OK — this exact path served a BLOCKED package's real bytes before the guard existed (issue #59)", tc.path)
			}
			if got != tc.want {
				t.Errorf("checkRequestPath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestCheckRequestPathAllowsRealClientTraffic is the other half, and the one that
// decides whether this guard can ship: a firewall that refuses ambiguous paths is
// worthless if it also refuses the package managers. Every path here is a shape a
// real npm/pip/docker/maven client (or our own URL rewriter) actually emits — see
// e2e/harness.go and the ecosystem parsers.
//
// Without this test the safe-looking move is to tighten the guard until something
// breaks in production; with it, the compatibility surface is stated and pinned.
func TestCheckRequestPathAllowsRealClientTraffic(t *testing.T) {
	paths := []string{
		"/",                               // registry root / ping
		"/lodash",                         // npm packument
		"/lodash.merge",                   // a dot INSIDE a name is not a dot segment
		"/lodash/-/lodash-4.17.21.tgz",    // npm tarball, registry's own shape
		"/@babel%2fcore",                  // npm scoped, encoded separator (how npm asks)
		"/@babel%2Fcore",                  // ... and uppercase-encoded
		"/@babel/core",                    // ... and with a literal separator
		"/@babel%2fcore/-/core-7.0.0.tgz", // npm scoped tarball
		"/_tarball/lodash/lodash/-/lodash-4.17.21.tgz",      // our rewriter's shape
		"/_tarball/@babel%2Fcore/@babel/core/-/core.tgz",    // ... scoped: the case that
		"/_files/requests/packages/requests-2.31.0-py3.whl", // PyPI byte relay (D22)
		"/-/ping",                               // npm control plane
		"/-/npm/v1/security/audits",             // npm audit endpoint
		"/-/whoami",                             //
		"/simple/requests/",                     // PyPI index, trailing slash is canonical
		"/simple/zope.interface/",               // PEP 503 name containing a dot
		"/v2/",                                  // OCI version handshake
		"/v2/library/nginx/manifests/latest",    // OCI manifest
		"/v2/library/nginx/blobs/sha256:abc123", // OCI blob
		"/com/google/guava/guava/31.0/guava-31.0.jar", // maven artifact
		"/com/google/guava/guava/maven-metadata.xml",  // maven metadata
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			if why := checkRequestPath(p); why != pathOK {
				t.Errorf("checkRequestPath(%q) = %q, want OK — this is real client traffic; refusing it breaks the ecosystem, which is a worse outcome than the bypass it guards against", p, why)
			}
		})
	}
}
