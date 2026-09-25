//go:build e2e

package e2e

// Tier 2 for issue #35 (npm version-level soft block) and the npm half of #103: a
// version-pinned known-malware advisory steers a real `npm install` to the next
// compliant release instead of failing the whole package, and the refused release is
// unreachable by every route npm has — the packument, an explicit version, and a
// lockfile-shaped tarball fetch.
//
// The registry is a stub with TWO versions of one package, both real tarballs whose
// package.json agrees with their filename (so #52's check passes and the only thing
// that can refuse anything is the advisory). The feed names 2.0.0. The control leg runs
// without the feed and must resolve 2.0.0, or the "resolved to 1.0.0" leg proves nothing.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	vfPkg      = "yj-versionfilter"
	vfClean    = "1.0.0"
	vfPoisoned = "2.0.0" // upstream's `latest`
	vfAdvisory = "MAL-E2E-VF"
	vfFeedDir  = "/feed"
)

func vfTgz(t *testing.T, version string) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	for _, f := range []struct{ name, body string }{
		{"package/package.json", fmt.Sprintf(`{"name":%q,"version":%q,"main":"index.js"}`, vfPkg, version)},
		{"package/index.js", "module.exports = " + fmt.Sprintf("%q", version) + ";\n"},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), ModTime: time.Unix(0, 0)}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// startTwoVersionRegistry publishes a registry for ONE package with versions 1.0.0 and
// 2.0.0, `latest` = 2.0.0, and returns the host port it listens on. publishedAt, when
// given, becomes the packument's `time` map (the cooldown's date source, #26).
func startTwoVersionRegistry(t *testing.T, publishedAt map[string]time.Time) int {
	t.Helper()
	port := freePort(t)
	name := fmt.Sprintf("yj-e2e-vfreg-%d", port)
	origin := fmt.Sprintf("http://host.docker.internal:%d", port)

	tarballs := map[string]string{}
	versions := map[string]any{}
	for _, v := range []string{vfClean, vfPoisoned} {
		tgz := vfTgz(t, v)
		sum := sha512.Sum512(tgz)
		tarballs[v] = base64.StdEncoding.EncodeToString(tgz)
		versions[v] = map[string]any{
			"name": vfPkg, "version": v, "main": "index.js",
			"repository": map[string]string{"type": "git", "url": "git+https://github.com/yellowjack/" + vfPkg + ".git"},
			"dist": map[string]string{
				"tarball":   fmt.Sprintf("%s/%s/-/%s-%s.tgz", origin, vfPkg, vfPkg, v),
				"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sum[:]),
			},
		}
	}
	doc := map[string]any{
		"name": vfPkg, "dist-tags": map[string]string{"latest": vfPoisoned}, "versions": versions,
	}
	if publishedAt != nil {
		times := map[string]string{}
		for v, at := range publishedAt {
			times[v] = at.UTC().Format(time.RFC3339Nano)
		}
		doc["time"] = times
	}
	packument, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	docs, err := json.Marshal(versions) // version documents, keyed by version
	if err != nil {
		t.Fatal(err)
	}
	tbs, _ := json.Marshal(tarballs)

	prog := fmt.Sprintf(`import base64, json
from http.server import BaseHTTPRequestHandler, HTTPServer
PACKUMENT = base64.b64decode(%q)
DOCS = json.loads(base64.b64decode(%q))
TGZ = json.loads(base64.b64decode(%q))
PKG = %q
LATEST = %q
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/" + PKG:
            body, ctype = PACKUMENT, "application/json"
        elif p.startswith("/" + PKG + "/-/"):
            v = p[len("/" + PKG + "/-/" + PKG + "-"):-len(".tgz")]
            if v not in TGZ:
                self.send_response(404); self.end_headers(); return
            body, ctype = base64.b64decode(TGZ[v]), "application/octet-stream"
        elif p.startswith("/" + PKG + "/"):
            v = p[len("/" + PKG + "/"):]
            v = LATEST if v == "latest" else v
            if v not in DOCS:
                self.send_response(404); self.end_headers(); return
            body, ctype = json.dumps(DOCS[v]).encode(), "application/json"
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
HTTPServer(("", 80), H).serve_forever()`,
		base64.StdEncoding.EncodeToString(packument),
		base64.StdEncoding.EncodeToString(docs),
		base64.StdEncoding.EncodeToString(tbs),
		vfPkg, vfPoisoned)

	if out, err := exec.Command("docker", "run", "-d", "--name", name, "-p", fmt.Sprintf("%d:80", port),
		"python:3.12-slim", "python3", "-c", prog).CombinedOutput(); err != nil {
		t.Fatalf("start two-version registry: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	probe := fmt.Sprintf("http://%s:%d/%s", fwHost(), port, vfPkg)
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
	t.Fatalf("two-version registry never became ready at %s", probe)
	return 0
}

// feedVolume writes a one-line malware feed naming the poisoned version into a docker
// volume the firewall mounts read-only. A volume rather than a file bind mount, for the
// reason upstreamcred_test.go records: Docker Desktop resolves file mounts by path and
// hides what Linux shows.
func feedVolume(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("yj-e2e-vffeed-%d", time.Now().UnixNano())
	if out, err := exec.Command("docker", "volume", "create", name).CombinedOutput(); err != nil {
		t.Fatalf("create feed volume: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "volume", "rm", "-f", name).Run() })
	line := fmt.Sprintf(`{"id":%q,"ecosystem":"npm","name":%q,"versions":[%q]}`, vfAdvisory, vfPkg, vfPoisoned)
	script := "printf '%s\\n' " + shellQuote(line) + " > " + vfFeedDir + "/malware.jsonl"
	if out, err := exec.Command("docker", "run", "--rm", "-v", name+":"+vfFeedDir, "busybox", "sh", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("write feed: %v\n%s", err, out)
	}
	return name
}

func vfEnv(registryPort int, withFeed bool) map[string]string {
	env := permissiveEnv("npm", map[string]string{
		"FW_UPSTREAM": fmt.Sprintf("http://host.docker.internal:%d", registryPort),
	})
	if withFeed {
		env["FW_MALWARE_LIST"] = vfFeedDir + "/malware.jsonl"
	}
	return syntheticRegistryDates(env)
}

// npmInstallResolving installs `spec` through the firewall and prints which version
// landed in node_modules, so the test asserts what the DEVELOPER got, not what we sent.
func npmInstallResolving(t *testing.T, port int, spec string) (int, string) {
	t.Helper()
	reg := fmt.Sprintf("http://host.docker.internal:%d/", port)
	script := "npm install --no-save " + spec + " && echo RESOLVED=$(node -p \"require('" + vfPkg + "/package.json').version\")"
	out, err := exec.Command("docker", "run", "--rm",
		"-w", "/work",
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "npm_config_registry="+reg,
		"-e", "npm_config_cache=/tmp/npmcache",
		"-e", "npm_config_fund=false",
		"-e", "npm_config_audit=false",
		"node:22-alpine", "sh", "-c", script,
	).CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatalf("could not run docker: %v\n%s", err, out)
	}
	return 0, string(out)
}

func TestNpmPinnedAdvisorySteersResolutionToTheCompliantVersion(t *testing.T) {
	bin := buildFirewall(t)
	reg := startTwoVersionRegistry(t, nil)

	t.Run("control: without the feed, npm resolves upstream's latest", func(t *testing.T) {
		fw := startFirewall(t, bin, vfEnv(reg, false))
		defer fw.stop()
		code, out := npmInstallResolving(t, fw.port, vfPkg)
		if code != 0 || !strings.Contains(out, "RESOLVED="+vfPoisoned) {
			t.Fatalf("control: expected npm to resolve %s through a firewall with NO feed (exit %d) — the rig "+
				"is broken, so a different resolution in the next leg would prove nothing\n%s\n--- firewall ---\n%s",
				vfPoisoned, code, tail(out, 25), tail(fw.log.String(), 30))
		}
	})

	vol := feedVolume(t)
	fw := startFirewallWithMounts(t, bin, vfEnv(reg, true), []string{vol + ":" + vfFeedDir + ":ro"})
	defer fw.stop()

	t.Run("npm install resolves to the compliant release, not a failure", func(t *testing.T) {
		code, out := npmInstallResolving(t, fw.port, vfPkg)
		if code != 0 {
			t.Fatalf("npm install FAILED (exit %d) — a version-pinned advisory must steer resolution, not fail the "+
				"package (#35)\n%s\n--- firewall ---\n%s", code, tail(out, 25), logAround(fw.log.String(), 30, "known-malware", "refused"))
		}
		if !strings.Contains(out, "RESOLVED="+vfClean) {
			t.Fatalf("npm installed something other than %s\n%s\n--- firewall ---\n%s", vfClean, tail(out, 25), tail(fw.log.String(), 30))
		}
		for _, want := range []string{
			fmt.Sprintf("version %s removed from the packument (known malware: %s)", vfPoisoned, vfAdvisory),
			fmt.Sprintf(`dist-tag "latest" repointed from refused version %s to %s`, vfPoisoned, vfClean),
		} {
			if !strings.Contains(fw.log.String(), want) {
				t.Errorf("the operator's log lacks %q — the steering happened without a record:\n%s", want, tail(fw.log.String(), 40))
			}
		}
	})

	t.Run("an explicit request for the refused version does not install it", func(t *testing.T) {
		code, out := npmInstallResolving(t, fw.port, vfPkg+"@"+vfPoisoned)
		if code == 0 {
			t.Fatalf("npm INSTALLED %s@%s past a pinned advisory\n%s\n--- firewall ---\n%s",
				vfPkg, vfPoisoned, tail(out, 25), logAround(fw.log.String(), 30, "known-malware"))
		}
		// The soft block's shape, recorded rather than hidden: the version is simply not
		// offered, so npm reports it as nonexistent (ETARGET). The operator's log names
		// the removal; the developer's console does not — the same legibility gap PyPI's
		// yank has with pip (#79), and the price of resolution that never fails on a
		// clean sibling.
		if !strings.Contains(out, "No matching version") && !strings.Contains(out, "ETARGET") {
			t.Errorf("npm failed for an unexpected reason:\n%s", tail(out, 25))
		}
	})

	t.Run("a lockfile-shaped tarball fetch of the refused version is refused with the reason", func(t *testing.T) {
		client := &http.Client{Timeout: 30 * time.Second}
		url := fmt.Sprintf("http://%s:%d/%s/-/%s-%s.tgz", fwHost(), fw.port, vfPkg, vfPkg, vfPoisoned)
		resp, err := client.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s: status %d, want 403 — `npm ci` never reads the filtered packument, so the byte path must refuse on its own", url, resp.StatusCode)
		}
		if reason := resp.Header.Get("X-Yellowjack-Reason"); !strings.Contains(reason, vfAdvisory) {
			t.Errorf("reason %q does not name the advisory", reason)
		}
		if strings.Contains(fw.log.String(), fmt.Sprintf("/-/%s-%s.tgz -> http://", vfPkg, vfPoisoned)) {
			t.Errorf("the refused tarball was RELAYED from upstream before or after the refusal:\n%s",
				logAround(fw.log.String(), 20, vfPoisoned+".tgz"))
		}
		clean := fmt.Sprintf("http://%s:%d/%s/-/%s-%s.tgz", fwHost(), fw.port, vfPkg, vfPkg, vfClean)
		resp, err = client.Get(clean)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200 — the clean sibling was refused with the poisoned one", clean, resp.StatusCode)
		}
	})
}
