package main

import (
	"fmt"
	"strings"
)

// Validation of the two attacker-influenced values the OCI path contributes: the
// repository NAME and the REF (issue #17, part 2).
//
// Both are taken from the client's request path, percent-decoded, and interpolated
// straight into upstream URLs. The #59 path guard already refuses the shapes that
// change WHICH package is addressed — "..", "%2e%2e", "//", encoded separators — and
// it still does; this is a narrower, per-ecosystem grammar check underneath it,
// because the guard is deliberately about path AMBIGUITY, not about whether a name is
// a legal OCI name at all.
//
// The concrete defect this closes: `GET /v2/library/ng%00inx/manifests/latest`
// decoded to a name containing a NUL byte, which url.Parse rejects — so
// http.NewRequest returned (nil, err), the error was discarded, and the next line
// dereferenced the nil request. One unauthenticated request panicked the handler.
// The discarded errors are fixed at their three call sites as well; validating here
// means the request never gets that far and the operator sees WHY.

// validOCIName reports whether s is a legal OCI repository name.
//
// Grammar from the distribution spec: one or more path components separated by "/",
// each component being lowercase alphanumerics with optional ".", "_", "__" or "-"
// separators between alphanumeric runs. Written out rather than pulled from a regexp
// so the rules are readable at the point of enforcement, and so a rejection can say
// which rule failed if that is ever wanted.
//
// Deliberately strict: this is the one place a name is checked before it becomes a
// URL, and every legitimate client sends a spec-legal name. Anything else is either
// a broken client or someone probing what we forward.
func validOCIName(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, component := range strings.Split(s, "/") {
		if !validOCINameComponent(component) {
			return false
		}
	}
	return true
}

func validOCINameComponent(c string) bool {
	if c == "" {
		return false
	}
	// Must start and end with an alphanumeric: that alone rejects leading/trailing
	// dots and dashes, which is what a traversal or an option-looking name needs.
	if !isLowerAlnum(c[0]) || !isLowerAlnum(c[len(c)-1]) {
		return false
	}
	for i := 0; i < len(c); i++ {
		ch := c[i]
		if isLowerAlnum(ch) {
			continue
		}
		if ch == '.' || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
}

func isLowerAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// validOCIRef reports whether s is a legal tag or digest reference.
//
// A tag is [a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}. A digest is "<algorithm>:<hex>", which
// contains a colon and so cannot be confused with a tag. Both are accepted here
// because both appear in the same position of the manifest path.
func validOCIRef(s string) bool {
	if s == "" {
		return false
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return validOCIDigest(s, i)
	}
	if len(s) > 128 {
		return false
	}
	if !(isAlnum(s[0]) || s[0] == '_') {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if isAlnum(ch) || ch == '.' || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
}

// validOCIDigest checks "<algorithm>:<hex>" where the separator is at index i.
// The hex part must be at least 32 characters — the spec's floor, and enough that a
// truncated or empty digest is rejected rather than sent upstream.
func validOCIDigest(s string, i int) bool {
	algo, hex := s[:i], s[i+1:]
	if algo == "" || len(hex) < 32 {
		return false
	}
	for j := 0; j < len(algo); j++ {
		ch := algo[j]
		if isAlnum(ch) || ch == '+' || ch == '.' || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	for j := 0; j < len(hex); j++ {
		ch := hex[j]
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
			continue
		}
		return false
	}
	return true
}

func isAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// checkOCITarget validates the pair before either is interpolated into a URL.
// Returns a non-nil error naming which of the two was rejected, and showing the
// offending value quoted so a control character is visible in the log rather than
// silently rendering as nothing.
func checkOCITarget(image, ref string) error {
	if !validOCIName(image) {
		return fmt.Errorf("%w: image name %q is not a legal OCI repository name", errOCIMalformedRef, image)
	}
	if ref != "" && !validOCIRef(ref) {
		return fmt.Errorf("%w: reference %q is not a legal OCI tag or digest", errOCIMalformedRef, ref)
	}
	return nil
}
