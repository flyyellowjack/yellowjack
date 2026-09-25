package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Test helpers shared by the default build and the interception tests.

func shorten(t *testing.T, v *time.Duration, d time.Duration) {
	t.Helper()
	prev := *v
	*v = d
	t.Cleanup(func() { *v = prev })
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}

// mintCA issues a CA certificate signed by parent (self-signed when parent is nil), with
// mutate applied to the template first -- the knob for name constraints and the like.
func mintCA(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, mutate func(*x509.Certificate)) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	if mutate != nil {
		mutate(tmpl)
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("mint %s: %v", cn, err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// npmUpstream serves a packument whose dist.tarball points at ITSELF, which is the shape
// the cooperative rewrite matches — so the two modes can be told apart by whether that
// URL survives.
func npmUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/lodash" || r.URL.Path == "/lodash/latest":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"name":"lodash","dist-tags":{"latest":"1.0.0"},"repository":{"type":"git","url":"https://github.com/lodash/lodash"},`+
				`"versions":{"1.0.0":{"name":"lodash","version":"1.0.0","repository":{"url":"https://github.com/lodash/lodash"},"dist":{"tarball":"`+srv.URL+`/lodash/-/lodash-1.0.0.tgz"}}}}`)
		case r.URL.Path == "/norepo" || r.URL.Path == "/norepo/latest":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"name":"norepo","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"norepo","version":"1.0.0","dist":{"tarball":"`+srv.URL+`/norepo/-/norepo-1.0.0.tgz"}}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}
