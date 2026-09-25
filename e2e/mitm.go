//go:build e2e

package e2e

// The test-side half of the TLS-interception rig: it generates the CA, runs
// e2e/mitmproxy as a CONTAINER, and reads back what crossed the interception point.
//
// WHAT THIS IS FOR. D151 phase 1 is TLS-interception mode, and #39 failure class 5 --
// "interception breaks the client's integrity checking" -- is the one class that could
// kill the mode outright: another tool ships `Integrity check failed for tarball: next`
// as a real bug of this architecture. See docs/TLS_INTERCEPTION.md for the
// pre-registered predictions and the results.
//
// WHY THE PROXY IS A CONTAINER, AND NOT A LISTENER IN THIS TEST BINARY. It was first
// written as a listener here, and that is the shape this repo has already removed twice:
// under docker-in-docker the daemon is a SEPARATE container, so a client container's
// `host.docker.internal` resolves to the dind daemon's gateway and never reaches the job
// container. `.gitlab-ci.yml` records it about the firewall ("used to run as a host
// PROCESS that dind can't route to"); harness.go records it about the approval stub.
// The first CI run of this rig failed exactly that way, after 1,036 seconds of npm
// retrying a proxy it could not route to.
//
// WHAT THIS IS NOT. It is not the product. Nothing here is reachable from the firewall
// binary: `//go:build e2e`, package e2e, and the proxy is its own throwaway module.
// D105 says we do not write CA software; a throwaway CA whose key is handed in per run
// and dies with the container is not CA software, and cannot become any.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// interceptCA is a certificate authority generated fresh for one test run. Nothing is
// persisted: it exists only in this process's memory and in the environment of the
// container it is handed to, which is what keeps this a measurement instrument rather
// than a piece of PKI we would then own (D105).
type interceptCA struct {
	certPEM []byte
	keyPEM  []byte
}

// newInterceptCA generates the CA. P-256 rather than RSA is a deliberate choice with a
// measured justification: #39 failure class 3 is another tool's user-visible
// "ca keypair generation took xxx seconds", which is an RSA artifact -- see
// TestInterceptCAGenerationLatency, which puts numbers on both.
func newInterceptCA(t *testing.T) *interceptCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Yellow Jack interception spike CA (throwaway)"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign CA: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	return &interceptCA{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

// mitmOpts selects one of the rig's named, mutually exclusive behaviours. Named and
// exclusive on purpose: the rig can relay faithfully or do one specific stated thing, so
// a leg cannot quietly be measuring a different attack than the one it claims.
type mitmOpts struct {
	mutate string // "" (= none) | "swap" | "forge"

	forgePkg       string
	forgeIntegrity string
	forgeShasum    string
	forgeBodyB64   string

	corruptSuffix string // "corrupt" mode: which artifacts to tamper with

	ociSubManifestB64 string // "ociswap" mode: base64 of the substitute manifest served for any /manifests/ request

	// Class 7 (a corporate CA already in the path): route the rig's OWN upstream leg through
	// another proxy, and optionally hand it that proxy's CA to trust. These are the rig's
	// stand-ins for the two operator values a product would need.
	upstreamProxy string // HTTPS_PROXY for the rig's upstream leg, e.g. another rig's proxyURLForClients()
	upstreamCAPEM []byte // YJ_MITM_UPSTREAM_CA: an extra root appended to the rig's system roots

	// Increment 6b -- the rig as a MORE realistic corporate proxy (rig B's side of the chain).
	proxyAuth        string // YJ_MITM_PROXY_AUTH user:pass -- demand Basic credentials on CONNECT, 407 otherwise
	intermediate     bool   // YJ_MITM_INTERMEDIATE=1 -- sign leaves with an intermediate under the CA
	omitIntermediate bool   // YJ_MITM_SERVE_INTERMEDIATE=0 -- withhold it from the handshake (the misconfiguration)
}

// mitmProxy is one running rig container.
type mitmProxy struct {
	port    int // published :8888 -- what CLIENT CONTAINERS dial
	ctlPort int // published :8889 -- what THIS TEST BINARY dials
	name    string
}

var mitmBuildOnce sync.Once

// buildMitmImage builds the rig image once per test binary. Separate from the firewall
// image build because the rig is deliberately not part of the main module.
func buildMitmImage(t *testing.T) {
	t.Helper()
	mitmBuildOnce.Do(func() {
		cmd := exec.Command("docker", "build", "-q",
			"-f", "e2e/mitmproxy/Dockerfile", "-t", "yellowjack-mitmproxy:e2e", ".")
		cmd.Dir = ".." // repo root; this package lives in ./e2e
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build mitmproxy image: %v\n%s", err, out)
		}
	})
}

// startMitmProxy runs the rig and waits for it to answer. Client containers reach it at
// host.docker.internal:<p.port>; this test binary reads its control plane at
// fwHost():<p.ctlPort>.
func startMitmProxy(t *testing.T, ca *interceptCA, opts ...mitmOpts) *mitmProxy {
	t.Helper()
	buildMitmImage(t)

	var o mitmOpts
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.mutate == "" {
		o.mutate = "none"
	}

	p := &mitmProxy{port: freePort(t), ctlPort: freePort(t)}
	p.name = fmt.Sprintf("yj-mitm-%d", p.port)
	_ = exec.Command("docker", "rm", "-f", p.name).Run()

	args := []string{"run", "-d", "--name", p.name,
		// host-gateway so a rig can reach ANOTHER rig's published port (class 7 chains two
		// of them); harmless for a rig that dials the registry direct.
		"--add-host", "host.docker.internal:host-gateway",
		"-p", fmt.Sprintf("%d:8888", p.port),
		"-p", fmt.Sprintf("%d:8889", p.ctlPort),
		"-e", "YJ_MITM_CA_CERT=" + string(ca.certPEM),
		"-e", "YJ_MITM_CA_KEY=" + string(ca.keyPEM),
		"-e", "YJ_MITM_MUTATE=" + o.mutate,
	}
	if o.upstreamProxy != "" {
		args = append(args, "-e", "HTTPS_PROXY="+o.upstreamProxy, "-e", "https_proxy="+o.upstreamProxy)
	}
	if len(o.upstreamCAPEM) > 0 {
		args = append(args, "-e", "YJ_MITM_UPSTREAM_CA="+string(o.upstreamCAPEM))
	}
	if o.proxyAuth != "" {
		args = append(args, "-e", "YJ_MITM_PROXY_AUTH="+o.proxyAuth)
	}
	if o.intermediate {
		args = append(args, "-e", "YJ_MITM_INTERMEDIATE=1")
		if o.omitIntermediate {
			args = append(args, "-e", "YJ_MITM_SERVE_INTERMEDIATE=0")
		}
	}
	if o.mutate == "corrupt" || o.mutate == "zipinject" || o.mutate == "corruptsha1" {
		args = append(args, "-e", "YJ_MITM_CORRUPT_SUFFIX="+o.corruptSuffix)
	}
	if o.mutate == "forge" {
		args = append(args,
			"-e", "YJ_MITM_FORGE_PKG="+o.forgePkg,
			"-e", "YJ_MITM_FORGE_INTEGRITY="+o.forgeIntegrity,
			"-e", "YJ_MITM_FORGE_SHASUM="+o.forgeShasum,
			"-e", "YJ_MITM_FORGE_BODY_B64="+o.forgeBodyB64,
		)
	}
	if o.mutate == "ociswap" {
		args = append(args, "-e", "YJ_MITM_OCI_SUB_MANIFEST_B64="+o.ociSubManifestB64)
	}
	args = append(args, "yellowjack-mitmproxy:e2e")

	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("start mitmproxy container: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", p.name).Run() })

	// Readiness on the CONTROL port, not the proxy port: a TCP accept on 8888 would say
	// nothing about whether the CA parsed, and a rig that came up misconfigured would
	// then present as a client-side trust failure -- the exact thing several legs assert.
	url := fmt.Sprintf("http://%s:%d/healthz", fwHost(), p.ctlPort)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(url); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return p
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", p.name).CombinedOutput()
	t.Fatalf("mitmproxy never became healthy at %s\n%s", url, logs)
	return nil
}

// mitmState is what the rig observed: every request that crossed the interception point,
// and how often each mutation actually fired.
type mitmState struct {
	Seen           []string `json:"seen"`
	Rewrites       int      `json:"rewrites"`
	Swaps          int      `json:"swaps"`
	AuthChallenges int      `json:"auth_challenges"` // CONNECTs refused with 407 (increment 6b)
}

// state reads the control plane. It is what every vacuity guard here rests on: a green
// leg proves nothing if the client never came through us, and a control leg proves
// nothing if its mutation never fired.
func (p *mitmProxy) state(t *testing.T) mitmState {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("http://%s:%d/requests", fwHost(), p.ctlPort))
	if err != nil {
		t.Fatalf("read mitm control plane: %v", err)
	}
	defer resp.Body.Close()
	var s mitmState
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		t.Fatalf("decode mitm state: %v", err)
	}
	return s
}

// requests is the shorthand for legs that only care about the paths.
func (p *mitmProxy) requests(t *testing.T) []string { return p.state(t).Seen }

// logs returns the rig container's log, so a leg can assert WHY an upstream fetch failed
// rather than only that it did (the class-7 headline is a reason-assertion).
func (p *mitmProxy) logs(t *testing.T) string {
	t.Helper()
	out, _ := exec.Command("docker", "logs", p.name).CombinedOutput()
	return string(out)
}

// proxyURLForClientsWithAuth is proxyURLForClients with credentials as userinfo -- the form
// http.ProxyFromEnvironment turns into a Proxy-Authorization header on CONNECT, i.e. how a
// Go client authenticates to a corporate proxy with no code of its own (increment 6b, A2).
// user and pass must be URL-safe; the legs use plain ASCII on purpose.
func (p *mitmProxy) proxyURLForClientsWithAuth(user, pass string) string {
	return fmt.Sprintf("http://%s:%s@host.docker.internal:%d", user, pass, p.port)
}

// intermediatePEM fetches the rig's intermediate CA certificate (intermediate mode only), so
// a leg can bundle it upstream (I3) or prove the mode is really engaged (the I2 instrument check).
func (p *mitmProxy) intermediatePEM(t *testing.T) []byte {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("http://%s:%d/intermediate", fwHost(), p.ctlPort))
	if err != nil {
		t.Fatalf("read intermediate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read intermediate: HTTP %d (is the rig in intermediate mode?)", resp.StatusCode)
	}
	var b []byte
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b = append(b, buf[:n]...)
		if err != nil {
			break
		}
	}
	return b
}

// proxyURLForClients is the address a CLIENT CONTAINER uses: always
// host.docker.internal (host-gateway), which resolves to the docker host both on a
// laptop and under dind -- the same convention every other client container here uses.
func (p *mitmProxy) proxyURLForClients() string {
	return fmt.Sprintf("http://host.docker.internal:%d", p.port)
}
