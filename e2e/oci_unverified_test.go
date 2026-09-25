//go:build e2e

package e2e

// Tier 2 for #33 (D48): an OCI image whose config declares a source repository is
// refused under the closed default -- deps.dev has no container index, so the claim can
// never be cross-checked -- and served under the operator's override, through a real
// `crane pull`. A third leg pulls an image that declares NO repo under the same closed
// default and must succeed: the refusal is about an unverifiable CLAIM, not about OCI.
//
// The registry is a stub with real digests (crane verifies every blob it pulls), and
// deps.dev is the fake from coalesce_test.go so `api` mode has something to score the
// override leg's repo against without leaving the machine.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	ociUnverifiedRepo   = "library/labelled" // declares org.opencontainers.image.source
	ociUnverifiedNoRepo = "library/plain"    // declares nothing
	ociUnverifiedSource = "https://github.com/acme/labelled"
)

type ociStubImage struct {
	manifest, config, layer                   []byte
	manifestDigest, configDigest, layerDigest string
}

// buildOCIImage makes the smallest image crane will accept: one gzip layer, a config
// whose diff_ids match it, and an OCI manifest whose digests and sizes match both.
func buildOCIImage(t *testing.T, labels map[string]string) ociStubImage {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	body := []byte("hello\n")
	if err := tw.WriteHeader(&tar.Header{Name: "hello.txt", Mode: 0o644, Size: int64(len(body)), ModTime: time.Unix(0, 0)}); err != nil {
		t.Fatal(err)
	}
	tw.Write(body)
	tw.Close()
	diffID := sha256.Sum256(tarBuf.Bytes())
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(tarBuf.Bytes())
	zw.Close()
	layer := gz.Bytes()
	layerSum := sha256.Sum256(layer)

	cfg := map[string]any{
		"architecture": "amd64", "os": "linux",
		"config": map[string]any{"Labels": labels},
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + hex.EncodeToString(diffID[:])}},
	}
	config, _ := json.Marshal(cfg)
	configSum := sha256.Sum256(config)
	man := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest": "sha256:" + hex.EncodeToString(configSum[:]), "size": len(config)},
		"layers": []map[string]any{{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
			"digest": "sha256:" + hex.EncodeToString(layerSum[:]), "size": len(layer)}},
	}
	manifest, _ := json.Marshal(man)
	manSum := sha256.Sum256(manifest)
	return ociStubImage{
		manifest: manifest, config: config, layer: layer,
		manifestDigest: "sha256:" + hex.EncodeToString(manSum[:]),
		configDigest:   "sha256:" + hex.EncodeToString(configSum[:]),
		layerDigest:    "sha256:" + hex.EncodeToString(layerSum[:]),
	}
}

// startOCIStubRegistry serves two images -- one that declares a source repo, one that
// does not -- and returns the host port. Digests are real, so crane's own checks pass.
func startOCIStubRegistry(t *testing.T) int {
	t.Helper()
	port := freePort(t)
	name := fmt.Sprintf("yj-e2e-ocistub-%d", port)
	labelled := buildOCIImage(t, map[string]string{"org.opencontainers.image.source": ociUnverifiedSource})
	plain := buildOCIImage(t, map[string]string{})

	blobs := map[string]string{}
	manifests := map[string]string{}
	for repo, img := range map[string]ociStubImage{ociUnverifiedRepo: labelled, ociUnverifiedNoRepo: plain} {
		manifests["/v2/"+repo+"/manifests/1.0"] = base64.StdEncoding.EncodeToString(img.manifest)
		manifests["/v2/"+repo+"/manifests/"+img.manifestDigest] = base64.StdEncoding.EncodeToString(img.manifest)
		blobs["/v2/"+repo+"/blobs/"+img.configDigest] = base64.StdEncoding.EncodeToString(img.config)
		blobs["/v2/"+repo+"/blobs/"+img.layerDigest] = base64.StdEncoding.EncodeToString(img.layer)
	}
	manJSON, _ := json.Marshal(manifests)
	blobJSON, _ := json.Marshal(blobs)

	prog := fmt.Sprintf(`import base64, hashlib, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
MANIFESTS = {k: base64.b64decode(v) for k, v in json.loads(base64.b64decode(%q)).items()}
BLOBS = {k: base64.b64decode(v) for k, v in json.loads(base64.b64decode(%q)).items()}
# Threading, because crane and the firewall hold keep-alive connections open: a
# single-threaded HTTP/1.1 server blocks every later connection behind the first,
# and the firewall then reports the registry UNAVAILABLE -- measured, twice.
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def serve(self, head):
        p = self.path.split("?")[0]
        if p == "/v2/" or p == "/v2":
            body, ctype = b"{}", "application/json"
        elif p in MANIFESTS:
            body, ctype = MANIFESTS[p], "application/vnd.oci.image.manifest.v1+json"
        elif p in BLOBS:
            body, ctype = BLOBS[p], "application/octet-stream"
        else:
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Docker-Content-Digest", "sha256:" + hashlib.sha256(body).hexdigest())
        self.end_headers()
        if not head:
            self.wfile.write(body)
    def do_GET(self): self.serve(False)
    def do_HEAD(self): self.serve(True)
    def log_message(self, *a): pass
ThreadingHTTPServer(("", 80), H).serve_forever()`,
		base64.StdEncoding.EncodeToString(manJSON), base64.StdEncoding.EncodeToString(blobJSON))

	if out, err := exec.Command("docker", "run", "-d", "--name", name, "-p", fmt.Sprintf("%d:80", port),
		"python:3.12-slim", "python3", "-c", prog).CombinedOutput(); err != nil {
		t.Fatalf("start OCI stub registry: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	probe := fmt.Sprintf("http://%s:%d/v2/", fwHost(), port)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(probe); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return port
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("OCI stub registry never became ready at %s", probe)
	return 0
}

func ociUnverifiedEnv(registryPort int, depsDevURL, policy string) map[string]string {
	env := map[string]string{
		"FW_ECOSYSTEM":         "oci",
		"FW_UPSTREAM":          fmt.Sprintf("http://host.docker.internal:%d", registryPort),
		"FW_SCORECARD_MODE":    "api", // verification only runs in api/local mode
		"FW_DEPSDEV_BASE":      depsDevURL,
		"FW_VERIFY_REPO":       "true",
		"FW_SCORE_THRESHOLD":   "0",
		"FW_UNSCORABLE_POLICY": "allow",
	}
	if policy != "" {
		env["FW_UNVERIFIED_POLICY"] = policy
	}
	return env
}

func TestOCIDeclaredRepoIsUnverifiableAndFailsClosedByDefault(t *testing.T) {
	bin := buildFirewall(t)
	reg := startOCIStubRegistry(t)
	dd := startDepsDevFake(t, 0)

	t.Run("closed (default): an image that declares a source repo is refused, legibly", func(t *testing.T) {
		fw := startFirewall(t, bin, ociUnverifiedEnv(reg, dd.url, ""))
		defer fw.stop()
		code, out := runCranePull(t, fw.port, ociUnverifiedRepo+":1.0")
		if code == 0 {
			t.Fatalf("crane pulled an image whose source repo can never be cross-checked, under the closed default -- D48 says it fails closed\n%s\n--- firewall ---\n%s",
				tail(out, 20), logAround(fw.log.String(), 25, "unverified", "SECURITY"))
		}
		if !strings.Contains(out, blockedMarker) || !strings.Contains(out, "no oci index") {
			t.Errorf("the refusal did not reach crane with its reason:\n%s", tail(out, 20))
		}
		log := fw.log.String()
		if !strings.Contains(log, "SECURITY evaluate") || !strings.Contains(log, "no oci index") {
			t.Errorf("the firewall log does not say WHY it refused:\n%s", tail(log, 30))
		}
		if !strings.Contains(log, "*** OCI + closed") {
			t.Errorf("the startup banner does not warn that OCI fails closed under this posture:\n%s", tail(log, 40))
		}
		// Which layer refused (E2E_TESTING item 12): the structured verdict names it.
		_, hdr, _ := rawGetHeaders(t, fwHost(), fw.port, "/v2/"+ociUnverifiedRepo+"/manifests/1.0")
		if k := hdr.Get("X-Yellowjack-Kind"); k != "unverified" {
			t.Errorf("X-Yellowjack-Kind = %q, want unverified -- something else refused the pull", k)
		}
		if st := dd.stats(t); st.Total != 0 {
			t.Errorf("deps.dev was called %d time(s) for an ecosystem it does not index -- the refusal must not cost a round-trip", st.Total)
		}
	})

	t.Run("open-with-visibility: the same image is served, logged unverified", func(t *testing.T) {
		fw := startFirewall(t, bin, ociUnverifiedEnv(reg, dd.url, "open-with-visibility"))
		defer fw.stop()
		code, out := runCranePull(t, fw.port, ociUnverifiedRepo+":1.0")
		if code != 0 {
			t.Fatalf("crane pull FAILED under the override (exit %d)\n%s\n--- firewall ---\n%s", code, tail(out, 20), tail(fw.log.String(), 30))
		}
		if !strings.Contains(fw.log.String(), "not indexed by deps.dev (policy=open-with-visibility") {
			t.Errorf("the override served the image without logging the unverified claim:\n%s", tail(fw.log.String(), 30))
		}
	})

	t.Run("control: an image that declares no repo is not refused by the closed default", func(t *testing.T) {
		fw := startFirewall(t, bin, ociUnverifiedEnv(reg, dd.url, ""))
		defer fw.stop()
		code, out := runCranePull(t, fw.port, ociUnverifiedNoRepo+":1.0")
		if code != 0 {
			t.Fatalf("crane pull of an image with NO source claim failed under closed (exit %d) -- the refusal must be about an unverifiable claim, not about OCI\n%s\n--- firewall ---\n%s",
				code, tail(out, 20), tail(fw.log.String(), 30))
		}
	})
}
