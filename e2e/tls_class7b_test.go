//go:build e2e

package e2e

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// Increment 6b of the #39 measurement: the two corporate-proxy realities increment 6 left
// untested, each of which threatens "class 7 costs exactly two operator values".
//
//   - The corporate proxy AUTHENTICATES. Rig B demands Proxy-Authorization on CONNECT and
//     answers 407 before any TLS. Rig A carries credentials the way every Go client does:
//     userinfo in the proxy URL, which http.ProxyFromEnvironment turns into the header.
//   - The corporate CA is a root -> intermediate -> leaf chain, and the intermediate is often
//     NOT served. Rig B signs leaves with an intermediate and can withhold it from the
//     handshake; rig A's bundle holds the root alone or the full chain.
//
// Pre-registered in docs/TLS_INTERCEPTION.md before the rig could do either. Rig B remains a
// stand-in: Basic is what it speaks; NTLM/Kerberos are a different instrument.

// mentionsProxyAuthRequired recognises rig A failing on the corporate proxy's 407, not on
// anything else, so A1 measures authentication and not a routing fault.
func mentionsProxyAuthRequired(logs string) bool {
	l := strings.ToLower(logs)
	return strings.Contains(l, "407") || strings.Contains(l, "proxy authentication required")
}

func TestInterceptionChainThroughAuthenticatingProxy(t *testing.T) {
	caA, caB := newInterceptCA(t), newInterceptCA(t)
	const user, pass = "corp", "s3cret-pr0xy"

	// Rig B plays a corporate proxy that demands Basic credentials on every CONNECT.
	rigB := startMitmProxy(t, caB, mitmOpts{proxyAuth: user + ":" + pass})

	// -- A1 -- rig A chained through rig B with NO credentials in its proxy URL.
	t.Run("A1_no_credentials_fails_at_the_corporate_proxy_before_TLS", func(t *testing.T) {
		rigA := startMitmProxy(t, caA, mitmOpts{upstreamProxy: rigB.proxyURLForClients(), upstreamCAPEM: caB.certPEM})
		b0 := rigB.state(t)
		_, out := craneThroughMitm(t, rigA.proxyURLForClients(), caA.certPEM, true, ociImageRepo+"@"+ociReal320Amd64)

		if craneOK(out) {
			t.Fatalf("PREDICTION FALSIFIED -- the pull SUCCEEDED with no proxy credentials, so either rig B "+
				"never demanded them or rig A sent some it was not given.\n%s", tail(out, 25))
		}
		st := rigB.state(t)
		// Vacuity: the auth demand must actually have fired.
		if st.AuthChallenges-b0.AuthChallenges == 0 {
			t.Fatalf("rig B issued NO 407: the authentication demand never fired, so this leg measures nothing.")
		}
		// The signature: rig B logged no request -- the tunnel was refused before TLS.
		if n := len(st.Seen) - len(b0.Seen); n != 0 {
			t.Fatalf("rig B logged %d request(s): the tunnel opened despite the missing credentials.", n)
		}
		logs := rigA.logs(t)
		if !mentionsProxyAuthRequired(logs) {
			t.Fatalf("rig A's log does not name the 407, so the cause is unproven.\nrig A log tail:\n%s", tail(logs, 15))
		}
		t.Logf("A1 CONFIRMED -- refused at the corporate proxy BEFORE TLS: rig B issued %d challenge(s), logged 0 requests.\n  reason: %s",
			st.AuthChallenges-b0.AuthChallenges, reasonLine(logs, "407"))
	})

	// -- A2 -- the same chain, credentials carried as userinfo in rig A's proxy URL.
	t.Run("A2_credentials_in_the_proxy_URL_make_the_chain_work", func(t *testing.T) {
		rigA := startMitmProxy(t, caA, mitmOpts{upstreamProxy: rigB.proxyURLForClientsWithAuth(user, pass), upstreamCAPEM: caB.certPEM})
		b0 := rigB.state(t)
		_, out := craneThroughMitm(t, rigA.proxyURLForClients(), caA.certPEM, true, ociImageRepo+"@"+ociReal320Amd64)

		if !craneOK(out) {
			t.Fatalf("PREDICTION FALSIFIED -- the pull FAILED with credentials in the proxy URL, so Go's userinfo "+
				"handling did not produce Proxy-Authorization, or rig B rejected valid credentials.\n%s\nrig A log tail:\n%s",
				tail(out, 25), tail(rigA.logs(t), 12))
		}
		st := rigB.state(t)
		if n := len(st.Seen) - len(b0.Seen); n == 0 {
			t.Fatalf("VACUOUS PASS: rig B logged no request, so this was not a two-hop chain.")
		}
		if c := st.AuthChallenges - b0.AuthChallenges; c != 0 {
			t.Fatalf("rig B still issued %d challenge(s) with credentials present -- the credential did not reach it intact.", c)
		}
		t.Logf("A2 CONFIRMED -- credentials as userinfo in the proxy URL authenticate the corporate hop: "+
			"%d request(s) through rig B, 0 challenges, digest verified. The cost stays two knobs ONLY if the "+
			"address may carry a secret; a product will more likely want a third value.",
			len(st.Seen)-len(b0.Seen))
	})
}

func TestInterceptionChainThroughIntermediateCA(t *testing.T) {
	caA, caB := newInterceptCA(t), newInterceptCA(t)

	// Instrument check, once: intermediate mode must really sign with an intermediate, or I2
	// could pass for the wrong reason (a leaf signed by the root would be trusted regardless).
	probe := startMitmProxy(t, caB, mitmOpts{intermediate: true})
	intPEM := probe.intermediatePEM(t)
	blk, _ := pem.Decode(intPEM)
	if blk == nil {
		t.Fatalf("INSTRUMENT INVALID: rig B in intermediate mode served no intermediate PEM")
	}
	ic, err := x509.ParseCertificate(blk.Bytes)
	if err != nil || !ic.IsCA {
		t.Fatalf("INSTRUMENT INVALID: the served intermediate is not a CA certificate: %v", err)
	}
	rootBlk, _ := pem.Decode(caB.certPEM)
	if rootBlk != nil && string(rootBlk.Bytes) == string(ic.Raw) {
		t.Fatalf("INSTRUMENT INVALID: the 'intermediate' IS the root; leaves would be root-signed and I2 could not fail")
	}

	// -- I1 -- intermediate SERVED, rig A trusts the root only.
	t.Run("I1_intermediate_served_root_only_bundle_works", func(t *testing.T) {
		rigB := startMitmProxy(t, caB, mitmOpts{intermediate: true})
		rigA := startMitmProxy(t, caA, mitmOpts{upstreamProxy: rigB.proxyURLForClients(), upstreamCAPEM: caB.certPEM})
		_, out := craneThroughMitm(t, rigA.proxyURLForClients(), caA.certPEM, true, ociImageRepo+"@"+ociReal320Amd64)
		if !craneOK(out) {
			t.Fatalf("PREDICTION FALSIFIED -- a served intermediate with a trusted root did NOT verify; chain "+
				"building is broken somewhere.\n%s\nrig A log tail:\n%s", tail(out, 25), tail(rigA.logs(t), 12))
		}
		if len(rigB.requests(t)) == 0 {
			t.Fatalf("VACUOUS PASS: rig B saw no request.")
		}
		t.Logf("I1 CONFIRMED -- served intermediate + root-only bundle verifies (%d requests through rig B).", len(rigB.requests(t)))
	})

	// -- I2 -- intermediate NOT served, rig A trusts the root only. The operator's ticket.
	t.Run("I2_intermediate_NOT_served_root_only_bundle_FAILS", func(t *testing.T) {
		rigB := startMitmProxy(t, caB, mitmOpts{intermediate: true, omitIntermediate: true})
		rigA := startMitmProxy(t, caA, mitmOpts{upstreamProxy: rigB.proxyURLForClients(), upstreamCAPEM: caB.certPEM})
		_, out := craneThroughMitm(t, rigA.proxyURLForClients(), caA.certPEM, true, ociImageRepo+"@"+ociReal320Amd64)
		if craneOK(out) {
			t.Fatalf("PREDICTION FALSIFIED -- the pull SUCCEEDED with the intermediate withheld and only the root "+
				"trusted. Check the instrument first: was the leaf signed by the root after all?\n%s", tail(out, 25))
		}
		if n := len(rigB.requests(t)); n != 0 {
			t.Fatalf("rig B logged %d request(s): the handshake did NOT fail, so this is not the trust failure claimed.", n)
		}
		logs := rigA.logs(t)
		if !mentionsUpstreamTrustFailure(logs) {
			t.Fatalf("the chain broke but rig A's log does not name an x509/trust failure.\nrig A log tail:\n%s", tail(logs, 15))
		}
		t.Logf("I2 CONFIRMED -- an unserved intermediate with a root-only bundle FAILS on trust (rig B saw 0 requests).\n"+
			"  reason: %s\nThis is the 'I added the root and it still fails' ticket, reproduced.", reasonLine(logs, "x509"))
	})

	// -- I3 -- intermediate NOT served, rig A's bundle holds root + intermediate.
	t.Run("I3_intermediate_NOT_served_full_chain_bundle_works", func(t *testing.T) {
		rigB := startMitmProxy(t, caB, mitmOpts{intermediate: true, omitIntermediate: true})
		bundle := append(append([]byte{}, caB.certPEM...), rigB.intermediatePEM(t)...)
		rigA := startMitmProxy(t, caA, mitmOpts{upstreamProxy: rigB.proxyURLForClients(), upstreamCAPEM: bundle})
		_, out := craneThroughMitm(t, rigA.proxyURLForClients(), caA.certPEM, true, ociImageRepo+"@"+ociReal320Amd64)
		if !craneOK(out) {
			t.Fatalf("PREDICTION FALSIFIED -- bundling root + intermediate did NOT rescue an unserved intermediate; "+
				"a multi-certificate PEM is not being appended whole.\n%s\nrig A log tail:\n%s", tail(out, 25), tail(rigA.logs(t), 12))
		}
		if len(rigB.requests(t)) == 0 {
			t.Fatalf("VACUOUS PASS: rig B saw no request.")
		}
		t.Logf("I3 CONFIRMED -- the full-chain bundle supplies what the proxy withheld (%d requests through rig B). "+
			"'Upstream CA bundle' must mean root + every intermediate.", len(rigB.requests(t)))
	})
}
