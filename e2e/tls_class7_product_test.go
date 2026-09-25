//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// Increment 15 (#137): class 7 against the PRODUCT, not the rig.
//
// Increments 6 and 6b chained two rigs and priced an enterprise TLS-inspecting proxy at
// two operator values. Both were facts about e2e/mitmproxy. This file asks the same
// questions of the shipped firewall container, with a real `npm install` in front of it:
//
//	npm --(http)--> FIREWALL --(HTTPS_PROXY)--> corporate proxy (CA-B) --> registry.npmjs.org
//
// Pre-registered in docs/TLS_INTERCEPTION.md before any of it was built:
//
//   - P15-1 no bundle: the install FAILS, the firewall's own log names the x509 failure,
//     and the corporate proxy logs ZERO requests — the handshake dies before a request is
//     parsed, which is increment 6's signature for "this is the trust boundary, not a
//     routing mistake".
//   - P15-2 with FW_UPSTREAM_CA_BUNDLE: it WORKS, and the corporate proxy logs the
//     registry requests. That second half is also the only proof that HTTPS_PROXY alone
//     routed us there, since we ship no knob for the address.
//   - P15-3 bundle set, no proxy: the direct path to the public registry still works. An
//     implementation that REPLACED the system roots passes P15-2 and fails only here.
//   - P15-4/P15-5 measure the workaround an operator would otherwise reach for
//     (SSL_CERT_FILE), because the claim this feature is described with depends on it.
//
// The client is npm because it is the cheapest real client that makes the firewall do an
// upstream TLS handshake; the trust boundary under test is the firewall's, not the
// client's, so the ecosystem is not the variable here.

const class7Pkg = "ms@2.1.3" // no dependencies: one packument, one tarball, ~7 KB

// corporateProxyFirewallEnv is the firewall's configuration for these legs. Scoring is
// stubbed and repo verification off so that the ONLY thing the container talks to is the
// registry — with deps.dev in the picture a leg could pass or fail on a second
// destination's trust, which is not what any of this measures.
func corporateProxyFirewallEnv(extra map[string]string) map[string]string {
	m := map[string]string{
		"FW_ECOSYSTEM":         "npm",
		"FW_SCORECARD_MODE":    "stub",
		"FW_SCORE_THRESHOLD":   "0",
		"FW_UNSCORABLE_POLICY": "allow",
		"FW_UNVERIFIED_POLICY": "open-with-visibility",
		"FW_VERIFY_REPO":       "false",
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// throughCorporateProxy sets the environment variables Go's HTTP client reads. Both
// spellings, because that is what every other client in this suite does and because
// getting it wrong would look exactly like "the proxy support is missing".
func throughCorporateProxy(url string, extra map[string]string) map[string]string {
	m := map[string]string{"HTTPS_PROXY": url, "https_proxy": url}
	for k, v := range extra {
		m[k] = v
	}
	return corporateProxyFirewallEnv(m)
}

// npmInstalledOK recognises a successful install of class7Pkg. npm reports "added N
// packages"; asserting on that rather than on the exit code alone keeps a leg from
// passing on an install that silently did nothing.
func npmInstalledOK(out string) bool {
	return strings.Contains(out, "added 1 package") || strings.Contains(out, "added 1 packages")
}

func TestTheProductChainsThroughACorporateProxy(t *testing.T) {
	bin := buildFirewall(t)

	// The corporate proxy: faithful, its own CA, nothing between it and the registry.
	// Shared by every leg; each diffs its request log against a baseline.
	caB := newInterceptCA(t)
	rigB := startMitmProxy(t, caB)

	// The corporate ROOT, as an operator would mount it: the certificate only, no key.
	// A named volume rather than a host path because under dind the daemon is a separate
	// container — the same helper the credential-rotation and interception legs use.
	vol := newCredVolume(t, buildCredWriter(t))
	vol.write(t, string(caB.certPEM))
	bundle := credMountDir + "/token"

	// ── P15-1 ── no bundle: the chain breaks at the trust boundary between us and them.
	t.Run("P15-1_without_the_bundle_the_upstream_leg_fails_on_trust", func(t *testing.T) {
		b0 := len(rigB.requests(t))
		fw := startFirewallWithMounts(t, bin, throughCorporateProxy(rigB.proxyURLForClients(), nil), nil)
		code, out := runNpmInstall(t, fw.port, class7Pkg)
		logs := fw.log.String()

		if code == 0 && npmInstalledOK(out) {
			t.Fatalf("PREDICTION FALSIFIED -- the install SUCCEEDED with no corporate root configured. "+
				"Either the firewall ignored HTTPS_PROXY and went direct (check the proxy's request "+
				"count below), or it trusts something we have not accounted for. Find out which before "+
				"recording anything.\n  proxy saw %d new request(s)\n%s",
				len(rigB.requests(t))-b0, tail(out, 20))
		}
		// Reason, not status: an install can fail for a dozen reasons and only one of
		// them is class 7.
		if !mentionsUpstreamTrustFailure(logs) {
			t.Fatalf("the install failed (exit %d) but the FIREWALL's log does not name an x509/trust "+
				"failure, so the cause is unproven -- this leg would then be asserting nothing more "+
				"than 'something broke'.\n--- firewall ---\n%s", code, tail(logs, 25))
		}
		// THE SIGNATURE: the corporate proxy saw the CONNECT and nothing after it. A
		// request logged there would mean the tunnel opened and the failure is somewhere
		// else -- a weaker claim than the one being made.
		if n := len(rigB.requests(t)) - b0; n != 0 {
			t.Fatalf("the corporate proxy logged %d request(s), so the TLS handshake SUCCEEDED and the "+
				"failure is not the trust boundary this leg claims to measure.\n--- firewall ---\n%s",
				n, tail(logs, 25))
		}
		t.Logf("P15-1 CONFIRMED -- npm exit %d; the firewall failed upstream on trust and the corporate "+
			"proxy parsed no request.\n  reason: %s", code, reasonLine(logs, "x509"))
	})

	// ── P15-2 ── the bundle: a real two-hop chain, and the proof HTTPS_PROXY is enough.
	t.Run("P15-2_the_bundle_makes_the_two_hop_chain_work", func(t *testing.T) {
		b0 := len(rigB.requests(t))
		fw := startFirewallWithMounts(t, bin,
			throughCorporateProxy(rigB.proxyURLForClients(), map[string]string{"FW_UPSTREAM_CA_BUNDLE": bundle}),
			[]string{vol.mount()})
		code, out := runNpmInstall(t, fw.port, class7Pkg)
		logs := fw.log.String()

		if code != 0 || !npmInstalledOK(out) {
			t.Fatalf("PREDICTION FALSIFIED -- the install FAILED (exit %d) despite the upstream CA bundle. "+
				"That means a SECOND trust boundary in the chain, and class 7 costs more than one "+
				"value.\n%s\n--- firewall ---\n%s", code, tail(out, 25), tail(logs, 25))
		}
		// Vacuity: it must be a real two-hop chain, not the firewall quietly going direct.
		// This is also what proves the ADDRESS half needs no knob of ours: nothing but
		// HTTPS_PROXY put us on the other side of that proxy.
		if n := len(rigB.requests(t)) - b0; n == 0 {
			t.Fatalf("VACUOUS PASS: the install worked but the corporate proxy saw NO request, so the "+
				"firewall went direct and this leg measured nothing.\n--- firewall ---\n%s", tail(logs, 25))
		}
		// The startup line an operator compares against what their estate distributed.
		if !strings.Contains(logs, "upstream trust:") || !strings.Contains(logs, "sha256 ") {
			t.Errorf("the container never announced what it added to its trust store, so an operator "+
				"cannot tell a mounted bundle from a missing one until something breaks.\n--- firewall ---\n%s",
				tail(logs, 25))
		}
		t.Logf("P15-2 CONFIRMED -- the install succeeded through TWO hops; the corporate proxy logged %d "+
			"request(s) and the firewall announced its anchor.\n  %s",
			len(rigB.requests(t))-b0, reasonLine(logs, "upstream trust:"))
	})

	// ── P15-3 ── the append control. The leg that separates "added" from "replaced".
	t.Run("P15-3_with_the_bundle_set_the_direct_path_still_works", func(t *testing.T) {
		fw := startFirewallWithMounts(t, bin,
			corporateProxyFirewallEnv(map[string]string{"FW_UPSTREAM_CA_BUNDLE": bundle}),
			[]string{vol.mount()})
		code, out := runNpmInstall(t, fw.port, class7Pkg)

		if code != 0 || !npmInstalledOK(out) {
			t.Fatalf("PREDICTION FALSIFIED -- with a corporate bundle configured and NO proxy in the "+
				"path, a public registry stopped verifying (exit %d). The bundle REPLACED the system "+
				"roots instead of being appended to them, which breaks every host reached directly "+
				"(NO_PROXY, split-horizon DNS, a partially-inspecting proxy) -- intermittently and per "+
				"host.\n%s\n--- firewall ---\n%s", code, tail(out, 25), tail(fw.log.String(), 25))
		}
		t.Logf("P15-3 CONFIRMED -- the public registry still verifies with the corporate bundle loaded: " +
			"appended, not substituted.")
	})

	// ── P15-4 / P15-5 ── the workaround, measured, because the feature is DESCRIBED in
	// terms of it. Go also reads SSL_CERT_FILE; on this base image the public roots are
	// expected to survive it, because crypto/x509 reads that file and then still scans
	// certDirectories, where distroless/static keeps its one bundle. If that is true the
	// honest claim for the knob is "unvalidated, undocumented and one base-image bump from
	// silently becoming a replace" -- not "there was no other way".
	//
	// A red here is not a product regression: it means the base image's /etc/ssl/certs
	// layout changed and the workaround now DROPS the public roots. That is precisely the
	// failure this knob exists to prevent, and the claims in upstreamtrust.go and
	// docs/CONFIGURATION.md have to change with it.
	t.Run("P15-4_SSL_CERT_FILE_alone_still_leaves_the_public_roots_in_place", func(t *testing.T) {
		fw := startFirewallWithMounts(t, bin,
			corporateProxyFirewallEnv(map[string]string{"SSL_CERT_FILE": bundle}),
			[]string{vol.mount()})
		code, out := runNpmInstall(t, fw.port, class7Pkg)

		if code != 0 || !npmInstalledOK(out) {
			t.Fatalf("MEASUREMENT CHANGED -- with SSL_CERT_FILE pointing at a corporate root, the public "+
				"registry NO LONGER verifies (exit %d). On this image that env var now REPLACES the "+
				"system roots rather than adding to them. Nothing in the product is wrong; what is wrong "+
				"is every sentence we wrote about the workaround. Update upstreamtrust.go, "+
				"docs/CONFIGURATION.md and docs/TLS_INTERCEPTION.md increment 15 -- and note this is the "+
				"exact failure FW_UPSTREAM_CA_BUNDLE exists to avoid.\n%s", code, tail(out, 25))
		}
		t.Logf("P15-4 CONFIRMED -- SSL_CERT_FILE left the public roots intact on this image (the " +
			"certDirectories scan still finds /etc/ssl/certs/ca-certificates.crt). An accident of the " +
			"base image's layout, not a contract.")
	})

	t.Run("P15-5_SSL_CERT_FILE_also_gets_through_the_corporate_proxy", func(t *testing.T) {
		b0 := len(rigB.requests(t))
		fw := startFirewallWithMounts(t, bin,
			throughCorporateProxy(rigB.proxyURLForClients(), map[string]string{"SSL_CERT_FILE": bundle}),
			[]string{vol.mount()})
		code, out := runNpmInstall(t, fw.port, class7Pkg)

		if code != 0 || !npmInstalledOK(out) {
			t.Logf("P15-5: SSL_CERT_FILE did NOT get the firewall through the corporate proxy (exit %d). "+
				"That makes FW_UPSTREAM_CA_BUNDLE the only route, which is a STRONGER claim than the one "+
				"shipped -- record it before relying on it.\n%s", code, tail(out, 20))
			t.Skip("measurement recorded; the knob is unaffected either way")
		}
		if n := len(rigB.requests(t)) - b0; n == 0 {
			t.Fatalf("the install worked but the corporate proxy saw no request, so this leg did not " +
				"measure the workaround through a proxy at all")
		}
		t.Logf("P15-5 CONFIRMED -- SSL_CERT_FILE also traverses the corporate proxy (%d request(s) "+
			"through it). So the capability exists today; what it lacks is validation, a named anchor "+
			"and a contract.", len(rigB.requests(t))-b0)
	})
}
