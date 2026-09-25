//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// Increment 6 of the #39 measurement: class 7, an existing corporate CA already in the path.
//
// Our interception proxy's UPSTREAM leg must itself traverse an enterprise TLS-inspecting
// proxy that terminates TLS with its own corporate CA. The rig is chained through itself:
//
//	client --(trusts CA-A)--> rig A (us) --(HTTPS_PROXY)--> rig B (corporate, CA-B) --> registry
//
// Pre-registered in docs/TLS_INTERCEPTION.md before the rig could chain:
//
//   - C7-1: rig A trusting only default roots FAILS at the boundary BETWEEN the proxies.
//     rig A's upstream TLS to rig B's leaf errors x509; the client sees rig A's 502; and
//     rig B's request log is EMPTY -- the handshake dies before a request is parsed. That
//     empty log is the signature separating "class 7" from "the chain routed wrong".
//   - C7-2: rig A handed CA-B as an upstream CA WORKS: both rigs log the request (a real
//     two-hop chain) and the client's digest verifies.
//   - C7-3: integrity survives two faithful interception hops (two re-framings, bytes
//     untouched) -- folded into C7-2's digest assertion.
//
// The consequence being measured: class 7 costs exactly two operator-supplied values, an
// upstream proxy address and an upstream CA bundle. C7-1 shows the bundle is necessary,
// C7-2 that the pair is sufficient. Rig B is a STAND-IN for a corporate proxy: proxy
// authentication, name-constrained/intermediate CAs and header manipulation are untested
// here, and the design note says so.

// mentionsUpstreamTrustFailure recognises rig A refusing rig B's leaf on trust, so C7-1
// measures class 7 and not some unrelated upstream fault.
func mentionsUpstreamTrustFailure(logs string) bool {
	l := strings.ToLower(logs)
	return strings.Contains(l, "x509") ||
		strings.Contains(l, "unknown authority") ||
		strings.Contains(l, "failed to verify certificate")
}

func TestInterceptionChainsThroughCorporateProxy(t *testing.T) {
	caA := newInterceptCA(t) // ours -- the only CA the client trusts
	caB := newInterceptCA(t) // the corporate MITM's

	// Rig B plays the corporate proxy: faithful, its own CA, nothing between it and the
	// registry. Shared by both legs; each leg diffs its request log from a baseline.
	rigB := startMitmProxy(t, caB)

	// -- C7-1 -- rig A chained through rig B, trusting only the default roots.
	t.Run("C7-1_untrusted_corporate_CA_breaks_the_chain_at_the_proxy_boundary", func(t *testing.T) {
		rigA := startMitmProxy(t, caA, mitmOpts{upstreamProxy: rigB.proxyURLForClients()})
		b0 := len(rigB.requests(t))
		code, out := craneThroughMitm(t, rigA.proxyURLForClients(), caA.certPEM, true, ociImageRepo+"@"+ociReal320Amd64)

		if craneOK(out) {
			t.Fatalf("PREDICTION FALSIFIED -- the pull SUCCEEDED with rig A trusting only default roots. "+
				"Either some proxy trust we have not accounted for exists, or rig A went direct and "+
				"never used rig B. Find out which before recording anything.\n%s", tail(out, 25))
		}
		// The client must have reached OUR proxy, or this measures a client fault, not class 7.
		if len(rigA.requests(t)) == 0 {
			t.Fatalf("rig A saw NO request: the client never reached our proxy, so this cell does not "+
				"measure the upstream trust boundary.\n%s", tail(out, 25))
		}
		// THE SIGNATURE: rig B saw nothing -- the handshake died before any request was parsed.
		if n := len(rigB.requests(t)) - b0; n != 0 {
			t.Fatalf("rig B logged %d request(s), so the corporate hop WAS traversed and the failure is "+
				"not the class-7 trust boundary -- a weaker claim than the one being made.\n%s", n, tail(out, 25))
		}
		// Reason-assertion on the headline: rig A's own log must name the trust failure.
		logs := rigA.logs(t)
		if !mentionsUpstreamTrustFailure(logs) {
			t.Fatalf("the chain broke (exit %d) but rig A's log does not name an x509/trust failure, so "+
				"the cause is unproven.\nrig A log tail:\n%s", code, tail(logs, 15))
		}
		t.Logf("C7-1 CONFIRMED -- the chain broke at the boundary BETWEEN the proxies (client exit %d): "+
			"rig A saw %d request(s) and failed upstream on trust, rig B saw 0.\n  reason: %s",
			code, len(rigA.requests(t)), reasonLine(logs, "x509"))
	})

	// -- C7-2 -- the same chain, rig A handed CA-B as an upstream CA bundle.
	t.Run("C7-2_upstream_CA_bundle_makes_the_two_hop_chain_work", func(t *testing.T) {
		rigA := startMitmProxy(t, caA, mitmOpts{
			upstreamProxy: rigB.proxyURLForClients(),
			upstreamCAPEM: caB.certPEM,
		})
		b0 := len(rigB.requests(t))
		_, out := craneThroughMitm(t, rigA.proxyURLForClients(), caA.certPEM, true, ociImageRepo+"@"+ociReal320Amd64)

		if !craneOK(out) {
			t.Fatalf("PREDICTION FALSIFIED -- the pull FAILED despite the upstream CA bundle. That would "+
				"mean a SECOND trust boundary in the chain, and the class-7 cost is higher than two "+
				"values. Find out where.\n%s\nrig A log tail:\n%s", tail(out, 25), tail(rigA.logs(t), 15))
		}
		// Vacuity: it must be a real two-hop chain, not rig A going direct.
		seenB := rigB.requests(t)[b0:]
		nA, nB := len(rigA.requests(t)), len(seenB)
		if nA == 0 || nB == 0 {
			t.Fatalf("VACUOUS PASS: rig A saw %d and rig B saw %d request(s) -- not a two-hop chain.", nA, nB)
		}
		if countOciBlobs(seenB) < 1 {
			t.Fatalf("rig B saw no blob request, so the image bytes did not traverse the corporate hop.\nrig B saw: %v", seenB)
		}
		t.Logf("C7-2 CONFIRMED -- the two-hop chain works with exactly two operator values (proxy address + "+
			"CA bundle): rig A %d request(s), rig B %d request(s) incl. %d blob(s). The client's digest "+
			"verified through TWO faithful interception hops (C7-3).", nA, nB, countOciBlobs(seenB))
	})
}
