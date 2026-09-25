package main

import (
	"net/url"
	"strings"
)

// Request-path canonicalization — the choke point that keeps the identity we GATE
// and the identity the upstream RESOLVES from drifting apart (issue #59).
//
// THE ATTACK. The firewall decides using the package name it parses out of the
// request path, then forwards that path to the registry. The registry is a CDN, and
// CDNs normalize: they collapse "//", resolve "..", and decode percent-escapes of
// unreserved characters. We did not. So for any path the two sides read differently,
// the gate evaluates one thing and the client receives another. Measured against the
// real registry.npmjs.org, at FW_BYTE_GATE=enforce and FW_UNSCORABLE_POLICY=block —
// the strictest posture we ship — with lodash blocked and express allowed:
//
//	GET /lodash                        -> 403, blocked (the gate works)
//	GET //lodash                       -> 200, the real lodash packument
//	GET /express/../lodash             -> 200, the real lodash packument, gate logged "express allowed"
//	GET /lodash/%2d/lodash-4.17.21.tgz -> 200, the real 318KB tarball, no decision logged at all
//
// Each shape defeats a different part of the machinery, which is why this is a
// property of the ARCHITECTURE and not a bug in one parser:
//
//   - "//lodash" — PackageNameFromPath splits on "/", gets an empty first segment,
//     and returns "" meaning "not a package request", so ServeHTTP relays it ungated
//     as if it were a registry control endpoint.
//   - "/express/../lodash" — we read segment 0 ("express") as the identity; the CDN
//     resolves the "..". Classic confused deputy: we approve the decoy, the client
//     gets the target.
//   - "/lodash/%2d/…" — npmArtifactPath looks for a literal "/-/" in the ESCAPED path
//     and doesn't find it, so the byte gate declines; PackageNameFromPath looks at the
//     DECODED path, finds "/-/", and returns "" because tarballs "are the byte gate's
//     job". Two parsers, two views of one request, each assuming the other has it.
//
// It is not npm-only. On PyPI, "/simple//requests/" returned the real index with 244
// installable links where the honest path returned 248 yanked ones. The surviving
// shape differs per ecosystem, which is precisely why this lives HERE — before
// ecosystem dispatch — instead of being patched into four parsers that would each
// have to get it right forever.
//
// THE FIX, and why it is a whitelist. We do not try to normalize hostile input into
// something safe: to normalize correctly we would have to predict every upstream
// CDN's normalization, which is the assumption that failed in the first place.
// Instead we REQUIRE the path to be unambiguous already, and refuse it otherwise.
// A real npm/pip/docker/maven client emits canonical paths — the shapes below are
// not things a package manager produces — so refusing them costs no compatibility
// and fails closed, which is the correct direction for a firewall.
//
// This is reachable in production, not just by curl: `npm ci` fetches exactly the
// "resolved" URL recorded in package-lock.json, so a poisoned lockfile can carry any
// of these spellings. Same side-door class as issue #11, reopened via encoding.

// pathRejection describes why a request path was refused. Empty means the path is
// canonical and safe to hand on to the ecosystem parsers.
type pathRejection string

const (
	pathOK              pathRejection = ""
	pathEmptySegment    pathRejection = "empty path segment (\"//\") — ambiguous: upstreams collapse it, we do not"
	pathDotSegment      pathRejection = "relative path segment (\".\" or \"..\") — the upstream would resolve it to a different package than the one gated"
	pathBadEscape       pathRejection = "undecodable percent-encoding"
	pathEncodedSlash    pathRejection = "percent-encoded path separator outside a scoped package name"
	pathHiddenMarker    pathRejection = "percent-encoded \"/-/\" artifact marker — hides an artifact fetch from the byte gate"
	pathEncodedNotPlain pathRejection = "percent-encoding that decodes to a path-structural character"
)

// checkRequestPath reports whether escapedPath (always r.URL.EscapedPath()) is
// canonical enough that our parsers and the upstream cannot disagree about which
// package it names. Returns pathOK when the path is safe.
//
// Deliberately operates on the ESCAPED path, because that is what we forward
// upstream. Checking the decoded form would re-introduce the exact split view that
// caused the vulnerability.
func checkRequestPath(escapedPath string) pathRejection {
	// "//" anywhere. Upstreams collapse it; PackageNameFromPath turns it into an
	// empty segment and reports "not a package", which routes to the ungated relay.
	// Checked on the raw string rather than per segment so a trailing "//" is caught
	// too.
	if strings.Contains(escapedPath, "//") {
		return pathEmptySegment
	}

	segments := strings.Split(strings.TrimPrefix(escapedPath, "/"), "/")
	for _, seg := range segments {
		decoded, err := url.PathUnescape(seg)
		if err != nil {
			return pathBadEscape
		}
		// Dot segments, literal or encoded ("%2e%2e"). Compared AFTER decoding so
		// "%2e%2e" is caught by the same rule that catches "..".
		if decoded == "." || decoded == ".." {
			return pathDotSegment
		}
		if strings.Contains(decoded, "/") {
			// npm addresses scoped packages as one segment carrying an encoded
			// separator — "/@scope%2fname" from the client, and "/_tarball/@scope%2fname/…"
			// from our own rewriter — so this is the one legitimate encoded slash in any
			// ecosystem we serve. Recognized by the segment DECODING to a scope rather
			// than by its position, because both of those shapes are real and they put
			// it at different depths.
			//
			// The exemption is then re-validated rather than trusted: "@foo/../bar"
			// also starts with "@" and also decodes to something containing a slash,
			// and would smuggle a dot segment through the very check above. So a scoped
			// name must be exactly two non-empty parts, neither of them a dot segment.
			if strings.HasPrefix(decoded, "@") {
				parts := strings.Split(decoded, "/")
				if len(parts) == 2 && parts[0] != "" && parts[1] != "" &&
					parts[1] != "." && parts[1] != ".." {
					continue
				}
			}
			return pathEncodedSlash
		}
		// A segment that decodes to "-" is how the "/-/" artifact marker gets hidden
		// from npmArtifactPath while the CDN still sees it. Any segment whose encoded
		// and decoded forms differ but which decodes to a purely structural token is
		// refused rather than guessed at.
		if seg != decoded && decoded == "-" {
			return pathHiddenMarker
		}
	}

	// Belt and braces for the marker specifically: after decoding the WHOLE path, the
	// artifact marker must be visible in the escaped form too, or the metadata gate
	// and the byte gate are looking at different requests. This catches any encoding
	// of "/-/" the per-segment rule above might not enumerate.
	if decodedWhole, err := url.PathUnescape(escapedPath); err == nil {
		if strings.Contains(decodedWhole, "/-/") != strings.Contains(escapedPath, "/-/") {
			return pathHiddenMarker
		}
	}

	return pathOK
}
