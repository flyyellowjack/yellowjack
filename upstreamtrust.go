package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// FW_UPSTREAM_CA_BUNDLE — the roots the firewall verifies its OWN outbound TLS against
// (#137, #39 failure class 7).
//
// WHAT THIS IS FOR. An estate that already terminates TLS in front of everything —
// the estate most likely to buy a package firewall, and #74's posture A — presents its
// own corporate certificate for registry.npmjs.org. Our upstream leg then fails
// `x509: certificate signed by unknown authority` on every probe, so nothing resolves
// and nothing installs. The rig measured this in increment 6: an upstream proxy address
// gets us TO the corporate proxy and no further; a CA bundle is what gets us THROUGH.
//
// APPENDED, NEVER SUBSTITUTED. The bundle is added to the system roots, which stay. A
// firewall that trusted only the corporate root would work through the proxy and fail
// on every host reached directly — and because NO_PROXY, split-horizon DNS and a
// partially-inspecting proxy all leave some hosts direct, that failure would be
// intermittent and host-dependent, which is the worst shape a trust bug can have. If
// the system pool cannot be loaded at all we refuse to start rather than quietly become
// that firewall.
//
// ⚠️ THE HONEST ACCOUNT OF WHAT THIS BUYS, because a stronger claim is available and
// would be wrong. It is NOT "there was no way to add a corporate root". Go also reads
// SSL_CERT_FILE, and MEASURED on our own image (P15-4/P15-5, both pre-registered) it
// leaves the public roots in place and gets through a real corporate proxy: crypto/x509
// reads that file and then still scans certDirectories, where distroless/static:nonroot
// keeps its one bundle at /etc/ssl/certs/ca-certificates.crt. So the capability exists
// today BY ACCIDENT OF THE BASE IMAGE'S LAYOUT. What it does not have is any of: a startup
// refusal when the file is wrong, a line naming what was trusted, or a contract that
// survives a base-image bump — the day /etc/ssl/certs stops holding the public bundle,
// SSL_CERT_FILE silently becomes a REPLACE and the operator learns about it from a
// developer's failed install. That is what this knob is for — and P15-4 is kept as a
// standing measurement, so the day that layout changes it is a red test here rather than
// a customer incident. The same discipline as
// pypiwheelversion.go: state the narrower claim in the source, where it is read.
//
// NOT HERE, deliberately:
//
//   - The proxy ADDRESS. http.DefaultTransport already honours HTTPS_PROXY/NO_PROXY, so
//     the deliverable for that half is a TEST that pins it (transport_test.go), not a
//     knob that re-implements the environment. P15-2 is what proves the environment
//     alone routes us to a corporate proxy: it cannot pass unless it did.
//   - Proxy AUTHENTICATION. Increment 6b measured userinfo in the proxy URL working
//     unaided. A dedicated value is worth having because a secret in a URL reaches logs,
//     `ps` and every error message — but that is its own decision, not a rider on this.
//   - Hot reload. Read once at startup, like FW_INTERCEPT_CA_FILE. Rotating a corporate
//     root is a restart.
//   - What the interception listener PRESENTS (FW_INTERCEPT_CA_FILE) and whether a
//     client trusts it (class 1, a fact about each client's store). This knob governs
//     only the TLS we originate.

// systemCertPool is the seam the tests swap to prove the bundle is APPENDED to the
// system roots rather than replacing them. Production never reassigns it.
//
// A seam rather than a direct call because the property that matters — "a root that was
// already trusted is still trusted afterwards" — cannot be asserted against the real
// system pool without depending on the host's store, and the whole point of the check is
// that it must hold on every host.
var systemCertPool = x509.SystemCertPool

// upstreamRoots builds the root pool for every TLS connection the firewall MAKES, and
// the startup line describing it. An empty path returns a nil pool, which is the stdlib's
// "use the platform's own roots" and byte-for-byte the behaviour before this existed.
//
// Every failure here is a STARTUP refusal (loadConfig folds it into the one-line report
// #19 asks for). A bundle that cannot be read or holds nothing usable means the operator
// intended to trust something and we are not trusting it; starting anyway produces a
// firewall that fails every upstream fetch for a reason nobody can see from the outside.
func upstreamRoots(bundlePath string) (*x509.CertPool, string, error) {
	if bundlePath == "" {
		return nil, "", nil
	}
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, "", fmt.Errorf("%s could not be read: %w -- the path is resolved INSIDE the "+
			"container, so check the mount as much as the path (mount the DIRECTORY, not the file)", bundlePath, err)
	}
	pool, err := systemCertPool()
	if err != nil {
		return nil, "", fmt.Errorf("the system root pool could not be loaded, so %s cannot be APPENDED "+
			"to it: %w -- refusing to start rather than trusting the bundle alone, which would silently "+
			"drop every public root and break any host reached directly", bundlePath, err)
	}
	added, ignored, err := appendCARoots(pool, raw)
	if err != nil {
		return nil, "", fmt.Errorf("%s %w", bundlePath, err)
	}
	return pool, describeUpstreamTrust(bundlePath, added, ignored), nil
}

// appendCARoots adds every CA certificate in a PEM bundle to pool, and reports the ones
// it could not use. A non-certificate block (a private key sitting in the same file, a
// CSR) is skipped rather than refused — real corporate bundles carry them — but a
// CERTIFICATE block that does not parse is an error, because that file is not what the
// operator thinks it is.
func appendCARoots(pool *x509.CertPool, raw []byte) (added, ignored []*x509.Certificate, err error) {
	rest := raw
	certs := 0
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		certs++
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("PEM CERTIFICATE block %d does not parse as a certificate: %w", certs, err)
		}
		if !canAnchorChain(c) {
			ignored = append(ignored, c)
			continue
		}
		pool.AddCert(c)
		added = append(added, c)
	}
	if certs == 0 {
		return nil, nil, fmt.Errorf("contains no PEM CERTIFICATE block (%d bytes read): a DER, a "+
			"PKCS#12 or a private key alone looks exactly like this. Convert it with "+
			"`openssl x509 -inform der -in <file> -out bundle.pem`", len(raw))
	}
	if len(added) == 0 {
		return nil, nil, fmt.Errorf("holds %d certificate(s) and none of them can anchor a chain "+
			"(each carries basicConstraints CA:FALSE): this is usually the proxy's LEAF certificate "+
			"rather than the CA that ISSUED it. Export the issuer, and the whole chain above it", certs)
	}
	return added, ignored, nil
}

// canAnchorChain reports whether Go's own verifier would accept c as a root or
// intermediate. It mirrors crypto/x509's rule exactly, including the old-certificate
// case: a certificate with NO basic-constraints extension is still usable as a CA, so
// testing `!c.IsCA` alone would refuse bundles that work.
func canAnchorChain(c *x509.Certificate) bool { return !c.BasicConstraintsValid || c.IsCA }

// describeUpstreamTrust is the startup line. It names every anchor with the SHA-256
// fingerprint in `openssl x509 -fingerprint -sha256` form — the same form increment 13's
// trust preflight prints — so the operator can compare it against what their estate
// distributed rather than trusting that the right file got mounted.
//
// It also says the system roots were kept. That sentence is the one an operator needs
// when they are deciding whether this knob will break their direct path, and it is
// cheaper to print than to answer later.
func describeUpstreamTrust(path string, added, ignored []*x509.Certificate) string {
	var b strings.Builder
	fmt.Fprintf(&b, "upstream trust: %d certificate(s) from FW_UPSTREAM_CA_BUNDLE=%s appended to the system roots:", len(added), path)
	for i, c := range added {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, " %q (sha256 %s)", c.Subject.CommonName, certFingerprint(c))
	}
	b.WriteString("; the system roots are KEPT, so a host reached directly still verifies against them")
	if len(ignored) > 0 {
		names := make([]string, 0, len(ignored))
		for _, c := range ignored {
			names = append(names, fmt.Sprintf("%q", c.Subject.CommonName))
		}
		fmt.Fprintf(&b, ". %d certificate(s) in the file cannot anchor a chain and were IGNORED (%s): "+
			"if the chain you meant to trust ends there, the bundle is incomplete",
			len(ignored), strings.Join(names, ", "))
	}
	return b.String()
}
