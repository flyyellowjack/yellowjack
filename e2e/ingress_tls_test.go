//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #145 box 1, D297: the cooperative listener speaks plain HTTP and has no FW_TLS_* knob, so
// the way a deployment gets HTTPS at the gate's front door is a TLS terminator it already
// runs, in front. The code has always assumed that (proxy.go: "TLS-fronted deployments
// should set FW_PUBLIC_URL explicitly") and no test had ever stood one up. So three claims
// the docs were about to make were unmeasured:
//
//  1. a real client installs THROUGH a terminator and the gate, artifacts included;
//  2. pip's second knob (PIP_TRUSTED_HOST) is a plain-HTTP cost and disappears over HTTPS
//     (e2e/onboarding_test.go measured the plain-HTTP half and only asserted this one);
//  3. FW_PUBLIC_URL is REQUIRED behind a terminator, because the gate mints artifact URLs
//     as "http://"+Host when it is unset -- and behind a terminator that is the wrong
//     scheme for the right host.
//
// The terminator is nginx running e2e/ingress/nginx.conf.tmpl, which is the same text
// docs/SETUP.md prints (ingressdoc_test.go pins the two together), so the documented
// config is the tested config rather than a plausible one.
//
// MAVEN OVER HTTPS -- PRE-REGISTERED 2026-09-21, committed BEFORE the legs exist.
//
// Over plain HTTP the rigs need a settings.xml because Maven 3.8.1+ blocks http:// repositories,
// so a bare -DremoteRepositories never reaches the gate (measured, maven_test.go). Over HTTPS
// that blocker does not apply, and the docs say "not measured -- do not assume a single flag
// suffices". "Suffices" has two meanings and they get one prediction each. The JVM trusts the
// rig CA via keytool -cacerts, the form tls_trust_maven_test.go already measured.
//
//	M1  REACH.  `mvn dependency:get -DremoteRepositories=yj::default::https://front/` with an
//	    EMPTY settings.xml exits 0 AND the gate logs a decision for the artifact.
//	    PREDICTION: PASS. The only thing that stopped the flag over HTTP was the http blocker.
//	M2  ENFORCEMENT.  The same single flag against a gate that BLOCKS the artifact.
//	    PREDICTION: mvn STILL EXITS 0 and the jar lands in the local repository, while the gate
//	    logs the block. The flag ADDS a repository; it does not replace central, so Maven is
//	    refused by us and then fetches the same artifact from central directly. If this holds,
//	    the single flag is an onboarding convenience that enforces NOTHING.
//	M3  THE CONTROL for M2.  Same blocking gate, a settings.xml with <mirrorOf>*</mirrorOf>
//	    pointing at the https front. PREDICTION: mvn FAILS and the gate logs a block. So the
//	    mirror is still required over HTTPS -- for enforcement, not for the protocol.
//
// What would change the docs the other way: M2 failing (mvn exits non-zero) means the flag
// does enforce for the named artifact, and the SETUP.md row becomes "one flag".
// Confidence: M1 high, M3 high, M2 moderate -- it rests on the resolver treating a 403 as
// "try the next repository", which I have not read the source for.

// RESULTS (measured 2026-09-21, Maven 3.9 / Temurin 21, dependency-plugin 3.6.1; legs in
// ingress_maven_test.go). ONE OF THREE PREDICTIONS HELD.
//
//	M1  FALSIFIED. mvn exited 0 and the gate was NEVER CONTACTED: the resolver recorded the
//	    jar and the pom as coming from central. The flag appends a repository; central is
//	    consulted FIRST, central has the artifact, and we are never asked. The leg's contact
//	    guard is what caught it -- on exit code alone M1 "passed".
//	M2  OUTCOME HELD, MECHANISM WRONG. The blocked artifact did arrive (exit 0, jar present),
//	    but not by "refused by us, then fetched from central": the blocking gate logged no
//	    decision at all, so the leg read VOID, correctly. The flag does not merely fail to
//	    enforce; it does not even give visibility.
//	M3  HELD. A mirrorOf=* settings.xml against a blocking gate fails the install, and the
//	    gate logs the block for the artifact itself.
//
// Two legs were added AFTER the first run, and are labelled as such because they were not
// pre-registered: a DIAGNOSTIC (an artifact no repository has does reach the terminator and
// the gate, so the flag was parsed and is consulted second -- without it "never asked" is
// equally explained by a flag Maven ignored), and a POSITIVE CONTROL for M3 (the same mirror
// against a permissive gate installs through us, so M3's failure is the block and not a
// broken mirror).
//
// What I got wrong: I reasoned about what removes the OBSTACLE (the http blocker) and never
// asked what ORDER the repositories are consulted in. Removing an obstacle to a path does
// not put traffic on it.

// ingressName is the name in the leaf certificate, and therefore the name every client in
// this file must dial. host.docker.internal is what the harness gives client containers
// for the docker host (see fwHost), on a laptop and on dind alike.
const ingressName = "host.docker.internal"

// nginxImage is the digest docker-compose.registryfront.yml already pins, so this file
// adds no new image to mirror or audit.
const nginxImage = "nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10"

type tlsFront struct {
	port  int
	name  string
	caPEM []byte
}

func (f *tlsFront) url() string { return fmt.Sprintf("https://%s:%d", ingressName, f.port) }
func (f *tlsFront) logs() string {
	o, _ := exec.Command("docker", "logs", f.name).CombinedOutput()
	return string(o)
}

// mintIngressCert returns a throwaway CA and a leaf for ingressName signed by it. The CA is
// the stand-in for "a CA your machines already trust"; nothing is persisted.
func mintIngressCert(t *testing.T) (caPEM, certPEM, keyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Yellow Jack ingress rig CA (throwaway)"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: ingressName},
		DNSNames:  []string{ingressName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// startTLSFront runs nginx with the documented config in front of the gate on gatePort.
//
// The config, certificate and key travel as ENVIRONMENT, written to disk by the
// container's own shell: under docker:dind the daemon is a different machine from this
// test process, so a bind mount of a file this process wrote resolves to nothing there.
func startTLSFront(t *testing.T, tlsPort, gatePort int) *tlsFront {
	t.Helper()
	tmpl, err := os.ReadFile(filepath.Join("ingress", "nginx.conf.tmpl"))
	if err != nil {
		t.Fatalf("read the documented nginx config: %v", err)
	}
	conf := strings.ReplaceAll(string(tmpl), "${GATE}", fmt.Sprintf("host.docker.internal:%d", gatePort))
	caPEM, certPEM, keyPEM := mintIngressCert(t)
	f := &tlsFront{port: tlsPort, name: fmt.Sprintf("yj-e2e-ingress-%d", tlsPort), caPEM: caPEM}

	_ = exec.Command("docker", "rm", "-f", f.name).Run()
	out, err := exec.Command("docker", "run", "-d", "--name", f.name,
		"-p", fmt.Sprintf("%d:443", f.port),
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "YJ_CONF="+conf, "-e", "YJ_CRT="+string(certPEM), "-e", "YJ_KEY="+string(keyPEM),
		nginxImage, "sh", "-c",
		`mkdir -p /etc/nginx/tls && printf '%s' "$YJ_CRT" > /etc/nginx/tls/tls.crt && `+
			`printf '%s' "$YJ_KEY" > /etc/nginx/tls/tls.key && `+
			`printf '%s' "$YJ_CONF" > /etc/nginx/conf.d/default.conf && exec nginx -g 'daemon off;'`).CombinedOutput()
	if err != nil {
		t.Fatalf("start nginx: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", f.name).Run() })

	// Readiness is a VERIFIED handshake against the rig's CA, under the name the clients
	// will use. Skipping verification here would let a wrong certificate through to be
	// discovered later as a confusing client failure.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: ingressName}}}
	url := fmt.Sprintf("https://%s:%d/healthz", fwHost(), f.port)
	var last error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
		resp, err := hc.Get(url)
		if err != nil {
			last = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return f
		}
		last = fmt.Errorf("healthz through the terminator answered %d", resp.StatusCode)
	}
	t.Fatalf("the TLS front never served the gate's /healthz: %v\n--- nginx ---\n%s", last, tail(f.logs(), 20))
	return nil
}

// gateBehindFront starts a gate and a terminator in front of it. The TLS port is chosen
// FIRST because the gate has to be told its own public address before it starts.
func gateBehindFront(t *testing.T, bin, ecosystem string, setPublicURL bool) (*firewall, *tlsFront) {
	t.Helper()
	tlsPort := freePort(t)
	env := onboardingEnv(ecosystem)
	if setPublicURL {
		env["FW_PUBLIC_URL"] = fmt.Sprintf("https://%s:%d", ingressName, tlsPort)
	}
	fw := startFirewall(t, bin, env)
	return fw, startTLSFront(t, tlsPort, fw.port)
}

// clientWithCA runs a client container with the rig's CA written to /ca.pem first. The CA
// is handed over as environment for the same dind reason as the nginx files.
func clientWithCA(t *testing.T, f *tlsFront, image string, env []string, script string) (int, string) {
	t.Helper()
	args := []string{"docker", "run", "--rm", "-w", "/work",
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "YJ_CA=" + string(f.caPEM)}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	args = append(args, image, "sh", "-c", `printf '%s' "$YJ_CA" > /ca.pem && `+script)
	return runClient(t, args...)
}

func TestGateBehindATLSTerminator(t *testing.T) {
	bin := buildFirewall(t)

	t.Run("npm installs over https through the terminator, artifact included", func(t *testing.T) {
		fw, front := gateBehindFront(t, bin, "npm", true)
		defer fw.stop()
		code, out := clientWithCA(t, front, "node:22-alpine", []string{
			"npm_config_registry=" + front.url() + "/",
			// The ONE trust line, and only because this rig's CA is private. A certificate
			// that chains to something the machine already trusts needs none.
			"npm_config_cafile=/ca.pem",
		}, "npm install --no-save is-number")
		if code != 0 {
			t.Fatalf("npm could not install through the TLS terminator (exit %d).\n%s\n--- nginx ---\n%s",
				code, tail(out, 20), tail(front.logs(), 10))
		}
		mustHaveReachedTheGate(t, fw, "is-number", "npm")
		// The ARTIFACT must have come back through the terminator too. The packument
		// reaching us proves the registry line works; only the tarball proves the URL the
		// gate MINTED was one the client could use.
		if nl := front.logs(); !strings.Contains(nl, ".tgz") {
			t.Errorf("no .tgz request in the terminator's access log: the tarball did not come back "+
				"through the front door, so the minted artifact URL was not the https one.\n--- nginx ---\n%s", tail(nl, 15))
		}
	})

	// THE CONTROL for the docs' "you must set FW_PUBLIC_URL". Same stack, one variable
	// removed. The gate then mints "http://"+Host, and Host behind this terminator is the
	// https front door's host:port -- so the client is sent to speak plain HTTP to a TLS
	// port.
	t.Run("without FW_PUBLIC_URL the minted artifact URL is unusable behind a terminator", func(t *testing.T) {
		fw, front := gateBehindFront(t, bin, "npm", false)
		defer fw.stop()
		code, out := clientWithCA(t, front, "node:22-alpine", []string{
			"npm_config_registry=" + front.url() + "/",
			"npm_config_cafile=/ca.pem",
			// Fail fast: npm retries a failed tarball for minutes by default, and how long
			// it takes to give up is not the quantity here.
			"npm_config_fetch_retries=0",
		}, "npm install --no-save is-number")
		mustHaveReachedTheGate(t, fw, "is-number", "npm") // the packument leg still works
		if code == 0 {
			t.Fatalf("npm installed behind a terminator with FW_PUBLIC_URL UNSET. Then the docs' "+
				"requirement is wrong, or something now derives the scheme (X-Forwarded-Proto?). "+
				"Re-measure and correct docs/SETUP.md rather than this leg.\n%s", tail(out, 15))
		}
		// Assert the REASON. nginx answers a plain-HTTP request on its TLS port with 400
		// and logs it; that line is what distinguishes this failure from a broken rig.
		if nl := front.logs(); !strings.Contains(nl, " 400 ") {
			t.Errorf("npm failed (exit %d) but the terminator logged no 400, so this is not the "+
				"plain-HTTP-to-a-TLS-port failure the leg is about.\n--- npm ---\n%s\n--- nginx ---\n%s",
				code, tail(out, 15), tail(nl, 15))
		}
	})

	t.Run("pip needs no trusted-host over https", func(t *testing.T) {
		fw, front := gateBehindFront(t, bin, "pypi", true)
		defer fw.stop()
		code, out := clientWithCA(t, front, "python:3.12-slim", []string{
			"PIP_INDEX_URL=" + front.url() + "/simple/",
			"PIP_CERT=/ca.pem", // trust in a private CA; NOT PIP_TRUSTED_HOST, which is absent on purpose
		}, "pip install --no-cache-dir --target /tmp/s six")
		if code != 0 {
			t.Fatalf("pip could not install over https without PIP_TRUSTED_HOST (exit %d). The claim "+
				"that the second pip knob is a plain-HTTP cost is then FALSE as stated.\n%s\n--- nginx ---\n%s",
				code, tail(out, 20), tail(front.logs(), 10))
		}
		mustHaveReachedTheGate(t, fw, "six", "pip")
		if nl := front.logs(); !strings.Contains(nl, "/_files/") {
			t.Errorf("no /_files/ request in the terminator's access log: the wheel did not come back "+
				"through the front door.\n--- nginx ---\n%s", tail(nl, 15))
		}
	})
}
