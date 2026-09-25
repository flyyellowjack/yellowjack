package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TIER 1 for FW_UPSTREAM_CA_BUNDLE (#137, #39 class 7; pre-registered in
// docs/TLS_INTERCEPTION.md increment 15).
//
// The property that matters is not "the corporate root is trusted" — that one is easy to
// get right and the e2e leg proves it end to end. It is "the corporate root is trusted AND
// everything that was trusted before still is". A firewall that REPLACED its roots works
// perfectly through the corporate proxy and fails on every host reached directly, which,
// with NO_PROXY and split-horizon DNS in the picture, is an intermittent host-dependent
// trust failure — the worst shape this class of bug has. So the marker root below is the
// point of the whole file.

// caPEMFile writes certs as a PEM bundle, the shape an operator exports from their PKI.
func caPEMFile(t *testing.T, name string, certs ...*x509.Certificate) string {
	t.Helper()
	var buf bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return writeTempPEM(t, name, buf.Bytes())
}

func writeTempPEM(t *testing.T, name string, body []byte) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// mintServerLeaf issues a server certificate under parent, so a leg can ask the real
// verifier whether a pool would accept a host signed by a given CA — which is the only
// question an operator actually cares about.
func mintServerLeaf(t *testing.T, host string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{host}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("mint leaf for %s: %v", host, err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// verifiesAgainst asks the real x509 verifier the operator's question: would a TLS
// connection to host, presenting leaf, be accepted with this pool as its roots?
func verifiesAgainst(leaf *x509.Certificate, pool *x509.CertPool, host string) error {
	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName: host, Roots: pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

// withSystemPool swaps the system-roots seam for a pool the test controls, so "appended to
// the system roots" can be asserted on every host. Against the REAL system pool the
// assertion would depend on the developer's own store, which is exactly the dependency a
// trust test must not have.
func withSystemPool(t *testing.T, pool *x509.CertPool) {
	t.Helper()
	prev := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) { return pool, nil }
	t.Cleanup(func() { systemCertPool = prev })
}

func TestTheUpstreamBundleIsAppendedToTheSystemRootsRatherThanReplacingThem(t *testing.T) {
	// A root the platform already trusts (stands in for every public CA), and the
	// corporate root the operator is adding.
	marker, markerKey := mintCA(t, "Already Trusted Root", nil, nil, nil)
	corp, corpKey := mintCA(t, "Corp Root", nil, nil, nil)

	base := x509.NewCertPool()
	base.AddCert(marker)
	withSystemPool(t, base)

	pool, line, err := upstreamRoots(caPEMFile(t, "corp.pem", corp))
	if err != nil {
		t.Fatalf("a well-formed bundle was refused: %v", err)
	}

	// The half everyone tests.
	if err := verifiesAgainst(mintServerLeaf(t, "registry.corp.internal", corp, corpKey), pool, "registry.corp.internal"); err != nil {
		t.Fatalf("the corporate root in the bundle is NOT trusted, so the bundle did nothing: %v", err)
	}
	// The half that catches a REPLACE, and the reason this test exists. A pool built
	// fresh instead of appended passes the leg above and fails here.
	if err := verifiesAgainst(mintServerLeaf(t, "registry.npmjs.org", marker, markerKey), pool, "registry.npmjs.org"); err != nil {
		t.Fatalf("a root that was ALREADY trusted stopped being trusted once the bundle was loaded: %v\n"+
			"That is a REPLACE, not an append: every host reached directly (NO_PROXY, split-horizon DNS, "+
			"a partially-inspecting proxy) would now fail TLS, intermittently and per host.", err)
	}
	if !strings.Contains(line, "system roots are KEPT") {
		t.Errorf("the startup line does not tell the operator the system roots survived, which is the "+
			"one question they have before setting this knob:\n  %s", line)
	}
}

func TestAnUnusableUpstreamCABundleIsRefusedWithItsOwnReason(t *testing.T) {
	withSystemPool(t, x509.NewCertPool())

	ca, caKey := mintCA(t, "Corp Root", nil, nil, nil)
	leafOnly := mintServerLeaf(t, "proxy.corp.internal", ca, caKey)

	keyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	var keyOnly bytes.Buffer
	_ = pem.Encode(&keyOnly, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	var garbledCert bytes.Buffer
	_ = pem.Encode(&garbledCert, &pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})

	cases := []struct {
		name, path, want string
	}{
		{"the file is not there", filepath.Join(t.TempDir(), "absent.pem"), "could not be read"},
		{"a DER export, or anything that is not PEM", writeTempPEM(t, "der.pem", ca.Raw), "no PEM CERTIFICATE block"},
		{"the private key alone", writeTempPEM(t, "key.pem", keyOnly.Bytes()), "no PEM CERTIFICATE block"},
		{"the proxy's leaf instead of its issuer", caPEMFile(t, "leaf.pem", leafOnly), "none of them can anchor a chain"},
		{"a CERTIFICATE block that is not one", writeTempPEM(t, "garbled.pem", garbledCert.Bytes()), "does not parse as a certificate"},
	}
	seen := map[string]string{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := upstreamRoots(tc.path)
			if err == nil {
				t.Fatalf("accepted a bundle that cannot work; the firewall would start and then fail " +
					"every upstream fetch with an x509 error that reads as 'the registry is down'")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not say what is wrong.\n  want mention of: %s\n  got: %v", tc.want, err)
			}
			// Every refusal must name the file, because the operator's next move is to go
			// and look at it — and in a container the path they set is not the path they
			// created.
			if !strings.Contains(err.Error(), tc.path) {
				t.Errorf("the refusal does not name the bundle path %q: %v", tc.path, err)
			}
			if other, dup := seen[tc.want]; dup && other != tc.name {
				t.Logf("shares a reason with %q, which is correct here: both are 'this file holds no certificate'", other)
			}
			seen[tc.want] = tc.name
		})
	}

	// The control. Without it every assertion above is satisfied by a function that
	// refuses everything.
	t.Run("control: a real bundle is accepted", func(t *testing.T) {
		if _, _, err := upstreamRoots(caPEMFile(t, "good.pem", ca)); err != nil {
			t.Fatalf("the refusals above prove nothing if nothing is ever accepted: %v", err)
		}
	})
}

func TestTheUpstreamTrustLineNamesEveryAnchorWithItsFingerprint(t *testing.T) {
	withSystemPool(t, x509.NewCertPool())

	root, rootKey := mintCA(t, "Corp Root", nil, nil, nil)
	issuing, _ := mintCA(t, "Corp Issuing CA", root, rootKey, nil)
	leaf := mintServerLeaf(t, "proxy.corp.internal", root, rootKey)

	_, line, err := upstreamRoots(caPEMFile(t, "chain.pem", root, issuing, leaf))
	if err != nil {
		t.Fatalf("a root + intermediate + stray leaf bundle was refused: %v", err)
	}

	for _, c := range []*x509.Certificate{root, issuing} {
		if !strings.Contains(line, c.Subject.CommonName) {
			t.Errorf("the line does not name the anchor %q:\n  %s", c.Subject.CommonName, line)
		}
		// Computed here from the certificate's own bytes rather than by calling the
		// same helper the product calls, so the two can disagree.
		want := independentFingerprint(c)
		if !strings.Contains(line, want) {
			t.Errorf("the line does not carry %q's SHA-256 fingerprint %s, so the operator cannot "+
				"compare it with what they distributed:\n  %s", c.Subject.CommonName, want, line)
		}
	}
	if !strings.Contains(line, "IGNORED") || !strings.Contains(line, "proxy.corp.internal") {
		t.Errorf("a certificate in the file that cannot anchor a chain was dropped SILENTLY. If the "+
			"chain the operator meant to trust ends there, they need to be told:\n  %s", line)
	}
	if !strings.Contains(line, "2 certificate(s) from FW_UPSTREAM_CA_BUNDLE=") {
		t.Errorf("the line does not say how many anchors were added, or does not name the knob:\n  %s", line)
	}
}

// independentFingerprint recomputes the `openssl x509 -fingerprint -sha256` form without
// going through certFingerprint, so the assertion is not a tautology.
func independentFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	var parts []string
	for _, b := range sum {
		parts = append(parts, fmt.Sprintf("%02X", b))
	}
	return strings.Join(parts, ":")
}

func TestLoadConfigResolvesTheBundleBeforeAnythingBinds(t *testing.T) {
	withSystemPool(t, x509.NewCertPool())
	ca, _ := mintCA(t, "Corp Root", nil, nil, nil)
	good := caPEMFile(t, "corp.pem", ca)

	t.Run("unset leaves the platform's own roots in place", func(t *testing.T) {
		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig: %v", err)
		}
		if cfg.upstreamRoots != nil {
			t.Errorf("an unconfigured firewall built a root pool; the default deployment must be " +
				"byte-for-byte what it was before this knob existed")
		}
		if cfg.upstreamTrustLine != "" {
			t.Errorf("an unconfigured firewall would print a trust line: %q", cfg.upstreamTrustLine)
		}
	})

	t.Run("a configured bundle is parsed once, by loadConfig", func(t *testing.T) {
		t.Setenv("FW_UPSTREAM_CA_BUNDLE", good)
		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig refused a good bundle: %v", err)
		}
		// The wiring assertion, not a restatement of upstreamRoots' own test: #136
		// shipped a feature whose unit tests were green in a configuration production
		// never runs. There is exactly ONE path that produces this pool, and this is it.
		if cfg.upstreamRoots == nil {
			t.Fatal("FW_UPSTREAM_CA_BUNDLE was set and loadConfig produced no pool, so nothing " +
				"downstream can be trusting it")
		}
		if !strings.Contains(cfg.upstreamTrustLine, "Corp Root") {
			t.Errorf("no startup line names the anchor: %q", cfg.upstreamTrustLine)
		}
	})

	t.Run("a relative path is refused", func(t *testing.T) {
		t.Setenv("FW_UPSTREAM_CA_BUNDLE", "corp.pem")
		_, err := loadConfig()
		if err == nil || !strings.Contains(err.Error(), "absolute path") {
			t.Fatalf("a working-directory-relative bundle must be refused — which certificates we "+
				"trust upstream cannot depend on where the process was launched. got: %v", err)
		}
	})

	t.Run("an unusable bundle fails startup, not the first fetch", func(t *testing.T) {
		t.Setenv("FW_UPSTREAM_CA_BUNDLE", writeTempPEM(t, "empty.pem", []byte("nothing here")))
		_, err := loadConfig()
		if err == nil {
			t.Fatal("loadConfig accepted a bundle holding no certificate; the listener would bind and " +
				"every upstream fetch would then fail for a reason no operator can see")
		}
		if !strings.Contains(err.Error(), "FW_UPSTREAM_CA_BUNDLE") {
			t.Errorf("the one-line startup report does not name the knob at fault (#19): %v", err)
		}
	})
}

func TestEveryOutboundTransportIsBuiltWithTheOperatorsRoots(t *testing.T) {
	pool := x509.NewCertPool()
	cfg := Config{
		Ecosystem: "npm", UpstreamRegistry: "https://registry.npmjs.org",
		DepsDevBase: "http://example.invalid", upstreamRoots: pool,
	}

	var got []*x509.CertPool
	prev := newTransport
	newTransport = func(n int, roots *x509.CertPool) *http.Transport {
		got = append(got, roots)
		return prev(n, roots)
	}
	t.Cleanup(func() { newTransport = prev })

	fw, err := NewFirewall(cfg)
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	_ = newProxyServer(cfg, fw)

	// Two transports, because the firewall's probe pool and the proxy's relay pool are
	// deliberately different shapes (transport.go). Both dial upstream, so a bundle that
	// reached only one of them would fix metadata and break artifact bytes.
	if len(got) != 2 {
		t.Fatalf("expected the firewall and the proxy to build one transport each, got %d. If a THIRD "+
			"outbound client appeared, it must go through newTransport too or it escapes both the "+
			"operator's roots and the egress observer (#27).", len(got))
	}
	for i, roots := range got {
		if roots != pool {
			t.Errorf("transport %d was built without the operator's root pool (%v), so its TLS verifies "+
				"against the platform's roots alone and a corporate proxy breaks it", i, roots)
		}
	}
}

func TestTheRootPoolReachesTheTransportsTLSConfig(t *testing.T) {
	pool := x509.NewCertPool()

	tr := pooledTransport(0, pool)
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs != pool {
		t.Fatalf("the pool was accepted and discarded: TLSClientConfig=%v", tr.TLSClientConfig)
	}
	// Setting TLSClientConfig at all is what would normally disable the automatic HTTP/2
	// upgrade; ForceAttemptHTTP2 is what keeps it. Losing h2 against the registries would
	// be a silent halving of our concurrency, not an error anyone would see.
	if !tr.ForceAttemptHTTP2 {
		t.Error("attaching a root pool turned off HTTP/2")
	}

	// The default deployment must be untouched: with no bundle the transport's ROOTS stay
	// nil, which is the stdlib's "use the platform's own store".
	//
	// The assertion is about RootCAs rather than about TLSClientConfig being absent, and
	// that is not pedantry: Clone() returns a non-nil TLSClientConfig (carrying h2's
	// NextProtos) once anything has configured HTTP/2 on http.DefaultTransport, and nil
	// before that. Written the other way this test passes or fails on test ORDER — it
	// failed here first time for exactly that reason.
	plain := pooledTransport(0, nil)
	if plain.TLSClientConfig != nil && plain.TLSClientConfig.RootCAs != nil {
		t.Errorf("a firewall with no bundle configured had its root pool replaced: %+v", plain.TLSClientConfig.RootCAs)
	}
}
