// Command mitmproxy is the TLS-interception rig for the #39 class-5 measurement: a
// forward proxy that TERMINATES the client's TLS on CONNECT rather than tunnelling it,
// re-originates to the real origin, and can alter a response body in flight.
//
// WHY THIS IS A CONTAINER AND NOT A HOST PROCESS. It began as a process in the test
// binary and that is exactly the shape this repo already removed once: under
// docker-in-docker the daemon is a SEPARATE container, so a client container's
// `host.docker.internal` resolves to the dind daemon's gateway and never reaches a
// listener in the job container. `.gitlab-ci.yml` records the same lesson about the
// firewall itself ("used to run as a host PROCESS that dind can't route to"), and
// e2e/harness.go records it about the approval stub. Running as a container with a
// published port is what makes the rig work on a laptop and on shared runners alike.
//
// It is a TEST FIXTURE. Nothing here ships, nothing here is imported by the firewall,
// and the CA private key is handed in per run and dies with the container.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// mutation modes. The rig can only ever relay faithfully or do one specific, named
// thing, so a leg cannot accidentally be measuring a different attack than it claims.
const (
	mutateNone  = "none"  // relay verbatim — the class-5 measurement itself
	mutateSwap  = "swap"  // serve the FIRST artifact's bytes for every later artifact
	mutateForge = "forge" // rewrite the packument's hashes AND serve substituted bytes

	// mutateCorrupt appends one byte to any body whose path ends with a configured
	// suffix.
	//
	// ⚠️ IT IS THE WRONG TAMPER FOR A CONTAINER FORMAT, AND THAT IS WHY IT IS DOCUMENTED
	// RATHER THAN DELETED. Go's module hash is computed over the archive's LOGICAL
	// CONTENTS (file names + file bytes), not over the raw archive bytes, so a byte
	// appended after the zip central directory is ignored by every zip reader and the
	// module hash is unchanged -- measured: h1 identical before and after. A leg using
	// this against Go measures nothing and Go is RIGHT to accept it. Kept for formats
	// whose integrity really is over the raw octets (npm tarballs, PyPI wheels).
	mutateCorrupt = "corrupt"

	// mutateZipInject adds a file INSIDE the archive, which is what actually changes a
	// Go module's hash. The tamper has to alter what the integrity mechanism covers.
	mutateZipInject = "zipinject"

	// mutateCorruptSHA1 is mutateCorrupt plus a forged sidecar: the artifact matching the
	// suffix is tampered, and its `<suffix>.sha1` -- which Maven fetches from the SAME
	// repository over the SAME connection -- is rewritten to the tampered bytes' hash.
	// That is the whole point of the leg: a checksum served over the intercepted
	// connection is forgeable, so strict checking cannot survive a hostile proxy.
	mutateCorruptSHA1 = "corruptsha1"

	// mutateOCISwap returns a SUBSTITUTE manifest (a real, different image's manifest,
	// handed in whole via YJ_MITM_OCI_SUB_MANIFEST_B64) for any /manifests/ request, and
	// forges the Docker-Content-Digest response header to match it. It is the OCI analogue
	// of mutateSwap: a tag pull has no expected digest of its own -- the only one it gets
	// is the forged header, which crosses this connection -- so it accepts the substitute;
	// a digest pull carries an expected value supplied OUTSIDE the connection and rejects
	// it. One mode, opposite verdicts, decided entirely by whether the client pinned a
	// digest. Nothing is fetched here: the substitute is static input, like the forge body.
	mutateOCISwap = "ociswap"
)

type proxy struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	client *http.Client

	mode string

	// forge parameters, read once at startup.
	forgePkg       string
	forgeBody      []byte
	forgeIntegrity string
	forgeShasum    string

	corruptSuffix string
	subManifest   []byte // ociswap: the substitute manifest served for any /manifests/ request

	// Class 7 (increment 6b): the rig as a CORPORATE proxy stand-in. proxyAuth, when set,
	// makes every CONNECT require matching Basic credentials (407 before any TLS otherwise).
	// intCert/intKey, when set, sign leaves instead of the root; serveInt says whether the
	// handshake presents that intermediate -- omitting it is the misconfiguration operators
	// actually ship, and the thing a full-chain bundle exists to survive.
	proxyAuth      string
	intCert        *x509.Certificate
	intKey         *ecdsa.PrivateKey
	serveInt       bool
	authChallenges int // CONNECTs refused with 407, for the vacuity guard

	mu         sync.Mutex
	leaves     map[string]*tls.Certificate
	seen       []string
	held       []byte // the first artifact body, for mutateSwap
	forgedSHA1 string // corruptsha1: hex sha1 of the tampered artifact, once seen
	rewrites   int
	swaps      int
}

var (
	integrityFieldRe = regexp.MustCompile(`"integrity"\s*:\s*"[^"]*"`)
	shasumFieldRe    = regexp.MustCompile(`"shasum"\s*:\s*"[^"]*"`)
)

// upstreamTransport builds the rig's UPSTREAM leg. Two things make class 7 measurable:
//
//   - Proxy: http.ProxyFromEnvironment, so an HTTPS_PROXY in the rig's OWN environment routes
//     its upstream through another proxy (a corporate MITM stand-in). Without it the rig
//     always dialled direct and the class-7 composition was untestable.
//   - YJ_MITM_UPSTREAM_CA (PEM): an extra root APPENDED to the system roots -- the shape a
//     product FW_UPSTREAM_CA_BUNDLE would take. Appended, not replaced, so the rig still
//     reaches a real registry direct when no proxy is in the path.
func upstreamTransport() *http.Transport {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		// DisableCompression: do NOT let Go transparently add Accept-Encoding and gunzip
		// the reply. That would leave Content-Encoding describing a body we had already
		// decoded -- a header/body mismatch invented by the proxy, which is precisely the
		// accidental payload mutation this rig exists to rule out.
		DisableCompression: true,
	}
	if pemCA := os.Getenv("YJ_MITM_UPSTREAM_CA"); pemCA != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(pemCA)) {
			log.Fatal("YJ_MITM_UPSTREAM_CA did not parse as PEM certificate(s)")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	return tr
}

func main() {
	p := &proxy{
		mode:   envOr("YJ_MITM_MUTATE", mutateNone),
		leaves: map[string]*tls.Certificate{},
		client: &http.Client{
			// See upstreamTransport for why compression is disabled and how the upstream
			// leg can be routed through, and taught to trust, a corporate proxy (class 7).
			Transport:     upstreamTransport(),
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Timeout:       60 * time.Second,
		},
	}
	p.loadCA()
	p.loadIntermediate()
	p.proxyAuth = os.Getenv("YJ_MITM_PROXY_AUTH")
	p.loadForge()
	if p.mode == mutateCorrupt || p.mode == mutateZipInject || p.mode == mutateCorruptSHA1 {
		p.corruptSuffix = os.Getenv("YJ_MITM_CORRUPT_SUFFIX")
		if p.corruptSuffix == "" {
			log.Fatal("corrupt/zipinject mode needs YJ_MITM_CORRUPT_SUFFIX")
		}
	}
	if p.mode == mutateOCISwap {
		sub, err := base64.StdEncoding.DecodeString(os.Getenv("YJ_MITM_OCI_SUB_MANIFEST_B64"))
		if err != nil || len(sub) == 0 {
			log.Fatalf("ociswap mode needs YJ_MITM_OCI_SUB_MANIFEST_B64 (base64 of a real manifest): %v", err)
		}
		p.subManifest = sub
	}

	// Control plane on its own port, so the test can read back what crossed the
	// interception point. Separate from the proxy port because a client must never be
	// able to reach it by asking the proxy for it.
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/requests", func(w http.ResponseWriter, r *http.Request) {
			p.mu.Lock()
			defer p.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"seen": append([]string(nil), p.seen...), "rewrites": p.rewrites, "swaps": p.swaps,
				"auth_challenges": p.authChallenges,
			})
		})
		// The intermediate's PEM, so a leg can put it in an upstream bundle (I3) or prove
		// intermediate mode is really engaged (the I2 instrument check).
		mux.HandleFunc("/intermediate", func(w http.ResponseWriter, r *http.Request) {
			if p.intCert == nil {
				http.Error(w, "no intermediate", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/x-pem-file")
			_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: p.intCert.Raw})
		})
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "ok\n")
		})
		log.Fatal(http.ListenAndServe(":8889", mux))
	}()

	ln, err := net.Listen("tcp", ":8888")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("mitmproxy: proxy :8888, control :8889, mode=%s", p.mode)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		go p.handle(c)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// loadCA takes the CA from the environment rather than generating one, so the TEST owns
// the certificate it hands to clients and the container holds no state the test cannot
// see.
func (p *proxy) loadCA() {
	certPEM := os.Getenv("YJ_MITM_CA_CERT")
	keyPEM := os.Getenv("YJ_MITM_CA_KEY")
	if certPEM == "" || keyPEM == "" {
		log.Fatal("YJ_MITM_CA_CERT and YJ_MITM_CA_KEY are required")
	}
	cb, _ := pem.Decode([]byte(certPEM))
	kb, _ := pem.Decode([]byte(keyPEM))
	if cb == nil || kb == nil {
		log.Fatal("CA cert/key are not valid PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		log.Fatalf("parse CA cert: %v", err)
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		log.Fatalf("parse CA key: %v", err)
	}
	p.caCert, p.caKey = cert, key
}

// loadIntermediate, when YJ_MITM_INTERMEDIATE=1, mints an intermediate CA under the loaded
// root and signs every leaf with it instead. YJ_MITM_SERVE_INTERMEDIATE=0 withholds it from
// the handshake, which is the common corporate misconfiguration: the leaf's issuer is then
// neither trusted nor presented, and a root-only bundle fails exactly as an operator's does.
func (p *proxy) loadIntermediate() {
	if os.Getenv("YJ_MITM_INTERMEDIATE") != "1" {
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("intermediate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("intermediate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "YJ MITM Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		log.Fatalf("intermediate cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatalf("parse intermediate: %v", err)
	}
	p.intCert, p.intKey = cert, key
	p.serveInt = os.Getenv("YJ_MITM_SERVE_INTERMEDIATE") != "0"
	log.Printf("intermediate CA active (served in handshake: %v)", p.serveInt)
}

func (p *proxy) loadForge() {
	if p.mode != mutateForge {
		return
	}
	p.forgePkg = os.Getenv("YJ_MITM_FORGE_PKG")
	p.forgeIntegrity = os.Getenv("YJ_MITM_FORGE_INTEGRITY")
	p.forgeShasum = os.Getenv("YJ_MITM_FORGE_SHASUM")
	body, err := base64.StdEncoding.DecodeString(os.Getenv("YJ_MITM_FORGE_BODY_B64"))
	if err != nil || len(body) == 0 {
		log.Fatalf("forge mode needs YJ_MITM_FORGE_BODY_B64: %v", err)
	}
	p.forgeBody = body
	if p.forgePkg == "" || p.forgeIntegrity == "" {
		log.Fatal("forge mode needs YJ_MITM_FORGE_PKG and YJ_MITM_FORGE_INTEGRITY")
	}
}

// leafFor mints (and caches) a server certificate for one hostname.
func (p *proxy) leafFor(host string) (*tls.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.leaves[host]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	// Sign with the intermediate when one is configured (increment 6b), else with the root.
	signer, signerKey := p.caCert, p.caKey
	if p.intCert != nil {
		signer, signerKey = p.intCert, p.intKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		return nil, err
	}
	chain := [][]byte{der}
	switch {
	case p.intCert == nil:
		chain = append(chain, p.caCert.Raw) // as before: leaf + root
	case p.serveInt:
		chain = append(chain, p.intCert.Raw) // correct: leaf + intermediate
	default:
		// leaf ALONE: the intermediate is withheld -- the misconfiguration under test (I2/I3)
	}
	leaf := &tls.Certificate{Certificate: chain, PrivateKey: key}
	p.leaves[host] = leaf
	return leaf, nil
}

func (p *proxy) handle(conn net.Conn) {
	defer conn.Close()
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(conn, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	// A corporate proxy that authenticates (increment 6b): refuse the tunnel BEFORE any TLS
	// unless the CONNECT carries matching Basic credentials. Counted so a leg can prove the
	// demand fired rather than inferring it from a failed pull.
	if p.proxyAuth != "" {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(p.proxyAuth))
		if req.Header.Get("Proxy-Authorization") != want {
			p.mu.Lock()
			p.authChallenges++
			p.mu.Unlock()
			_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\nContent-Length: 0\r\n\r\n")
			return
		}
	}
	host := req.URL.Hostname()
	if host == "" {
		host = strings.Split(req.Host, ":")[0]
	}
	leaf, err := p.leafFor(host)
	if err != nil {
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	tconn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
		// http/1.1 only: this rig parses requests with http.ReadRequest, and offering h2
		// would let the client negotiate a framing it cannot read. Real interception
		// products make the same choice for the same reason.
		NextProtos: []string{"http/1.1"},
	})
	if err := tconn.Handshake(); err != nil {
		return // the untrusted-CA control legs land here, by design
	}
	defer tconn.Close()

	br := bufio.NewReader(tconn)
	for {
		r, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if err := p.relayOne(tconn, r, host); err != nil {
			return
		}
	}
}

var hopByHop = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true,
}

func (p *proxy) relayOne(w io.Writer, req *http.Request, host string) error {
	target := "https://" + host + req.URL.RequestURI()

	p.mu.Lock()
	p.seen = append(p.seen, host+req.URL.Path)
	mutating := p.mode != mutateNone
	p.mu.Unlock()

	out, err := http.NewRequest(req.Method, target, req.Body)
	if err != nil {
		return err
	}
	for k, vv := range req.Header {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vv {
			out.Header.Add(k, v)
		}
	}
	if mutating {
		// A mutating leg must READ the body it rewrites, so stop advertising compression
		// upstream. The faithful leg forwards the client's own Accept-Encoding untouched,
		// which is the case the class-5 measurement is actually about.
		out.Header.Del("Accept-Encoding")
	}

	resp, err := p.client.Do(out)
	if err != nil {
		// Logged so a test can assert WHY the upstream leg failed: class 7 has to
		// distinguish "the corporate proxy's leaf was not trusted" from any other fault.
		log.Printf("upstream %s: %v", target, err)
		_, werr := io.WriteString(w, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return werr
	}
	defer resp.Body.Close()

	// Buffered whole rather than streamed: that is what lets a control leg alter a byte,
	// and it also means this rig RE-FRAMES every response with its own Content-Length.
	// Re-framing is exactly what an interception proxy does and a plausible suspect for
	// breaking a hash, so it belongs inside the measurement rather than engineered away.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// A HEAD response carries NO body, but its Content-Length header describes the entity a
	// GET would return, and clients trust it. The Docker daemon resolves a manifest with a
	// HEAD and reads that size; re-framing Content-Length to the (empty) body length makes it
	// report "content size of zero" and abort the pull. So a HEAD keeps the upstream
	// Content-Length verbatim and is never mutated -- there is no body to tamper with anyway.
	isHead := req.Method == http.MethodHead
	if !isHead {
		body = p.mutate(req.URL.Path, resp.Header, body)
	}

	var head bytes.Buffer
	fmt.Fprintf(&head, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	for k, vv := range resp.Header {
		if hopByHop[http.CanonicalHeaderKey(k)] || http.CanonicalHeaderKey(k) == "Content-Length" {
			continue
		}
		for _, v := range vv {
			fmt.Fprintf(&head, "%s: %s\r\n", k, v)
		}
	}
	if isHead {
		if cl := resp.Header.Get("Content-Length"); cl != "" {
			fmt.Fprintf(&head, "Content-Length: %s\r\n\r\n", cl)
		} else {
			head.WriteString("\r\n")
		}
		_, err := w.Write(head.Bytes())
		return err
	}
	fmt.Fprintf(&head, "Content-Length: %d\r\n\r\n", len(body))
	if _, err := w.Write(head.Bytes()); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func (p *proxy) mutate(path string, hdr http.Header, body []byte) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch p.mode {
	case mutateSwap:
		if !strings.HasSuffix(path, ".tgz") {
			return body
		}
		if p.held == nil {
			p.held = body // the first artifact, relayed untouched
			return body
		}
		p.swaps++
		return p.held // every later artifact gets the FIRST one's bytes
	case mutateCorrupt:
		if !strings.HasSuffix(path, p.corruptSuffix) {
			return body
		}
		p.swaps++
		return append(append([]byte(nil), body...), 0x00)
	case mutateCorruptSHA1:
		switch {
		case strings.HasSuffix(path, p.corruptSuffix):
			tampered := append(append([]byte(nil), body...), 0x00)
			sum := sha1.Sum(tampered)
			p.forgedSHA1 = hex.EncodeToString(sum[:])
			md := md5.Sum(tampered)
			p.swaps++
			// Maven 3.9's resolver takes the expected checksum from the artifact
			// response's OWN headers ("REMOTE_INCLUDED": x-checksum-sha1 / x-checksum-md5)
			// and never fetches the .sha1 sidecar when those are present. Measured: the
			// first version of this mode forged only the sidecar, the sidecar was never
			// requested, and the leg's rewrites==0 guard refused to conclude anything. So
			// the forgery goes where the checksum actually travels -- which is the SAME
			// response as the bytes, an even shorter path than a sidecar. ETag can carry
			// the sha1 too, so it is dropped rather than left contradicting the forgery.
			if hdr.Get("X-Checksum-Sha1") != "" || hdr.Get("X-Checksum-Md5") != "" || hdr.Get("Etag") != "" {
				hdr.Set("X-Checksum-Sha1", p.forgedSHA1)
				hdr.Set("X-Checksum-Md5", hex.EncodeToString(md[:]))
				hdr.Del("Etag")
				p.rewrites++
			}
			return tampered
		case strings.HasSuffix(path, p.corruptSuffix+".sha1"):
			// The sidecar is requested AFTER the artifact (the resolver validates what it
			// just downloaded), so the forged hash is normally in hand. If it is not, the
			// original is relayed and the leg's rewrites==0 guard says so rather than
			// letting a mis-ordered fetch pass as "strict mode survived".
			if p.forgedSHA1 == "" {
				return body
			}
			p.rewrites++
			return []byte(p.forgedSHA1)
		}
		return body
	case mutateZipInject:
		if !strings.HasSuffix(path, p.corruptSuffix) {
			return body
		}
		out, err := injectIntoZip(body)
		if err != nil {
			log.Printf("zipinject: %v (relaying untouched)", err)
			return body
		}
		p.swaps++
		return out
	case mutateForge:
		switch {
		case path == "/"+p.forgePkg:
			b := integrityFieldRe.ReplaceAllLiteral(body, []byte(`"integrity":"`+p.forgeIntegrity+`"`))
			if p.forgeShasum != "" {
				b = shasumFieldRe.ReplaceAllLiteral(b, []byte(`"shasum":"`+p.forgeShasum+`"`))
			}
			p.rewrites++
			return b
		case strings.HasPrefix(path, "/"+p.forgePkg+"/-/"):
			p.swaps++
			return p.forgeBody
		}
	case mutateOCISwap:
		// Only manifests are swapped; blob requests relay faithfully, so the substitute's
		// own layers (which really exist under the same repository) resolve normally. The
		// forged Docker-Content-Digest is the header a tag pull cross-checks the body
		// against; a digest pull ignores it and checks against its OWN pinned digest, so
		// forging it cannot help there -- which is exactly why the two legs diverge.
		if strings.Contains(path, "/manifests/") {
			sum := sha256.Sum256(p.subManifest)
			hdr.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			hdr.Set("Docker-Content-Digest", "sha256:"+hex.EncodeToString(sum[:]))
			hdr.Del("Etag")
			p.rewrites++
			return p.subManifest
		}
	}
	return body
}

// injectIntoZip rewrites a zip archive with one extra file, preserving every original
// entry. This is the tamper a Go module actually notices: its `h1:` hash is a hash of the
// archive's file names and contents, so changing the raw bytes without changing the
// logical contents is invisible (measured), while adding a file is not.
//
// The injected name reuses the first entry's top-level directory, because a Go module zip
// requires every path to sit under `<module>@<version>/` and an archive that breaks that
// rule would be refused for the WRONG reason.
func injectIntoZip(body []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("read zip: %w", err)
	}
	if len(zr.File) == 0 {
		return nil, fmt.Errorf("zip has no entries")
	}
	// The prefix is `<module>@<version>/`, so it runs to the first "/" AFTER the "@".
	// Cutting at the first "/" instead yields "github.com/", and Go then refuses the
	// archive as structurally invalid ("has unexpected file github.com/YJ-FORGED") --
	// a refusal for the WRONG reason, which the leg's reason-assertion caught.
	prefix := zr.File[0].Name
	at := strings.Index(prefix, "@")
	if at < 0 {
		return nil, fmt.Errorf("first entry %q has no @version segment", prefix)
	}
	i := strings.Index(prefix[at:], "/")
	if i < 0 {
		return nil, fmt.Errorf("first entry %q has no path under the module prefix", prefix)
	}
	prefix = prefix[:at+i+1]

	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	for _, f := range zr.File {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: f.Name, Method: f.Method})
		if err != nil {
			return nil, err
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(w, rc); err != nil {
			rc.Close()
			return nil, err
		}
		rc.Close()
	}
	w, err := zw.Create(prefix + "YJ-FORGED")
	if err != nil {
		return nil, err
	}
	if _, err := w.Write([]byte("injected in flight by the interception rig\n")); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
