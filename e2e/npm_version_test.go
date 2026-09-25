//go:build e2e

package e2e

// Tier 2 for issue #52: the version a tarball is served as must be the version inside
// it, asserted through a real `npm install` against a registry that lies.
//
// The registry is a stub because no real registry serves a mismatching tarball on
// purpose, and the whole point is that a real registry CAN — a stale mirror, a cache that
// paired one version's URL with another's bytes, a vendor that shipped one major version
// under another's tag. It is the smallest registry npm needs: a packument with one
// version, the version document, and the tarball, with a correct dist.integrity so npm's
// own check is satisfied and the only party between the developer and a wrong file is us.
//
// Two legs differ in exactly one string, the version the tarball's package.json declares.
// The control runs FIRST and must see the check run, or the refusal leg proves nothing.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha512"
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
	versionCheckPkg    = "yj-versioncheck"
	versionCheckServed = "1.0.0" // the version the URL and the packument promise
)

// versionCheckTgz is an installable npm tarball — the npm-pack layout, a package.json
// and a main file — declaring `declared` as its version.
func versionCheckTgz(t *testing.T, declared string) []byte {
	t.Helper()
	return versionCheckTgzFiles(t,
		vcFile{"package/package.json", versionCheckManifest(declared)},
		vcFile{"package/index.js", "module.exports = 'yj';\n"})
}

// vcFile is one tar entry: a name exactly as it goes on the wire, and a body.
type vcFile struct{ name, body string }

// vcSymlinkPrefix marks a vcFile as a SYMLINK entry: {"symlink:package/package.json",
// "index.js"} writes a symlink named package/package.json pointing at index.js. A name
// prefix rather than a new field, because every fixture builds vcFile positionally.
const vcSymlinkPrefix = "symlink:"

// versionCheckManifest is the package.json body declaring `declared`.
func versionCheckManifest(declared string) string {
	return fmt.Sprintf(`{"name":%q,"version":%q,"main":"index.js"}`, versionCheckPkg, declared)
}

// versionCheckTgzFiles builds a tarball from entries the caller spells out, in order, so
// a test can serve a layout `npm pack` would never produce -- a duplicate manifest, or
// one at the archive root (#122). The order is load-bearing: an extractor writes entries
// as it meets them, so the LAST manifest is the one that survives in node_modules.
func versionCheckTgzFiles(t *testing.T, files ...vcFile) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	for _, f := range files {
		if link, ok := strings.CutPrefix(f.name, vcSymlinkPrefix); ok {
			// A symlink entry named `link`, pointing at f.body, with no content (#47).
			if err := tw.WriteHeader(&tar.Header{Name: link, Mode: 0o777, Typeflag: tar.TypeSymlink,
				Linkname: f.body, ModTime: time.Unix(0, 0)}); err != nil {
				t.Fatal(err)
			}
			continue
		}
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

// startVersionCheckRegistry publishes a registry for ONE package whose 1.0.0 tarball
// declares `declared`, and returns the host port it listens on. The firewall reaches it
// as host.docker.internal:<port>, which is also the origin of the packument's tarball
// URL — the firewall rewrites dist.tarball only when it points at the configured
// upstream, so the two must agree for the tarball to come back through the gate.
func startVersionCheckRegistry(t *testing.T, declared string) int {
	t.Helper()
	return startVersionCheckRegistryTgz(t, versionCheckTgz(t, declared))
}

// startVersionCheckRegistryTgz is startVersionCheckRegistry for a tarball the caller
// built, with dist.integrity computed over whatever bytes it was given -- so npm's own
// check is satisfied and the firewall is again the only party in a position to notice
// that the tarball is not what its URL says.
func startVersionCheckRegistryTgz(t *testing.T, tgz []byte) int {
	t.Helper()
	port := freePort(t)
	name := fmt.Sprintf("yj-e2e-vcheck-%d", port)

	sum512 := sha512.Sum512(tgz)
	sum1 := sha1.Sum(tgz)
	origin := fmt.Sprintf("http://host.docker.internal:%d", port)
	tarballPath := fmt.Sprintf("/%s/-/%s-%s.tgz", versionCheckPkg, versionCheckPkg, versionCheckServed)
	version := map[string]any{
		"name":    versionCheckPkg,
		"version": versionCheckServed,
		"main":    "index.js",
		"repository": map[string]string{
			"type": "git", "url": "git+https://github.com/yellowjack/" + versionCheckPkg + ".git",
		},
		"dist": map[string]string{
			"tarball":   origin + tarballPath,
			"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sum512[:]),
			"shasum":    hex.EncodeToString(sum1[:]),
		},
	}
	packument := map[string]any{
		"name":      versionCheckPkg,
		"dist-tags": map[string]string{"latest": versionCheckServed},
		"versions":  map[string]any{versionCheckServed: version},
	}
	packumentJSON, err := json.Marshal(packument)
	if err != nil {
		t.Fatal(err)
	}
	versionJSON, err := json.Marshal(version)
	if err != nil {
		t.Fatal(err)
	}

	prog := fmt.Sprintf(`import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
PACKUMENT = base64.b64decode(%q)
VERSION = base64.b64decode(%q)
TGZ = base64.b64decode(%q)
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/%s":
            body, ctype = PACKUMENT, "application/json"
        elif p in ("/%s/latest", "/%s/%s"):
            body, ctype = VERSION, "application/json"
        elif p == "%s":
            body, ctype = TGZ, "application/octet-stream"
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
		base64.StdEncoding.EncodeToString(packumentJSON),
		base64.StdEncoding.EncodeToString(versionJSON),
		base64.StdEncoding.EncodeToString(tgz),
		versionCheckPkg, versionCheckPkg, versionCheckPkg, versionCheckServed, tarballPath)

	args := []string{"run", "-d", "--name", name, "-p", fmt.Sprintf("%d:80", port),
		"python:3.12-slim", "python3", "-c", prog}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("start version-check registry: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	probe := fmt.Sprintf("http://%s:%d/%s", fwHost(), port, versionCheckPkg)
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
	t.Fatalf("version-check registry never became ready at %s", probe)
	return 0
}

func versionCheckEnv(registryPort int) map[string]string {
	// The shipped defaults for everything the check does not depend on: byte gate at
	// allow-but-log, so the refusal is shown to bite in the posture an operator who
	// changes nothing is running, and a permissive policy so nothing ELSE can refuse
	// the package and be mistaken for the check.
	return syntheticRegistryDates(permissiveEnv("npm", map[string]string{
		"FW_UPSTREAM": fmt.Sprintf("http://host.docker.internal:%d", registryPort),
	}))
}

func TestNpmServedVersionMustMatchTheTarball(t *testing.T) {
	bin := buildFirewall(t)

	t.Run("control: a truthful tarball installs, and the check is seen to run", func(t *testing.T) {
		reg := startVersionCheckRegistry(t, versionCheckServed)
		fw := startFirewall(t, bin, versionCheckEnv(reg))
		defer fw.stop()
		code, out := runNpmInstall(t, fw.port, versionCheckPkg)
		if code != 0 {
			t.Fatalf("control: npm could not install a TRUTHFUL fixture through the firewall (exit %d) — "+
				"the rig is broken, so a refusal in the other leg would prove nothing\n%s\n--- firewall ---\n%s",
				code, tail(out, 25), tail(fw.log.String(), 40))
		}
		// The install succeeding is necessary, not sufficient: if the tarball had reached
		// npm without passing through the gate (a dist.tarball the firewall did not
		// rewrite), this leg would be green and the next leg would be red for the wrong
		// reason. The verified line proves the bytes came through, and were read.
		if !strings.Contains(fw.log.String(), "version verified: "+versionCheckServed) {
			t.Fatalf("npm installed %s but the firewall never verified a tarball version — the bytes "+
				"did not come through the gate, or the check did not run\n--- firewall ---\n%s",
				versionCheckPkg, tail(fw.log.String(), 40))
		}
	})

	t.Run("a tarball declaring another version is refused, and the developer is told why", func(t *testing.T) {
		const declared = "9.9.9"
		reg := startVersionCheckRegistry(t, declared)
		fw := startFirewall(t, bin, versionCheckEnv(reg))
		defer fw.stop()
		code, out := runNpmInstall(t, fw.port, versionCheckPkg)
		if code == 0 {
			t.Fatalf("npm INSTALLED a tarball declaring %s under a %s URL — the misrepresentation reached "+
				"the developer's node_modules\n%s\n--- firewall ---\n%s",
				declared, versionCheckServed, tail(out, 25), logAround(fw.log.String(), 30, "artifact", "refused"))
		}
		for _, want := range []string{blockedMarker, "declares version " + declared, "served as version " + versionCheckServed} {
			if !strings.Contains(out, want) {
				t.Errorf("BLOCK IS ILLEGIBLE: npm failed (exit %d) but its output never says %q — the developer "+
					"cannot tell a misrepresenting tarball from a broken registry (#20)\n--- what the developer saw ---\n%s",
					code, want, tail(out, 30))
			}
		}
		if strings.Contains(strings.ToLower(out), "unscorable") {
			t.Errorf("the developer was told the package is UNSCORABLE; #52 requires the reason to be "+
				"distinct from that, because a misrepresenting package is not an unknown one\n%s", tail(out, 30))
		}
		for _, bad := range []string{"500 Internal Server Error", "502 Bad Gateway", "timed out"} {
			if strings.Contains(strings.ToLower(out), strings.ToLower(bad)) {
				t.Errorf("the refusal reads as an OUTAGE (%q) rather than a decision — that teaches "+
					"developers to retry through the gate\n%s", bad, tail(out, 30))
			}
		}
		if !strings.Contains(fw.log.String(), "refused: tarball declares version "+declared) {
			t.Errorf("the operator's log does not name the refusal:\n%s", tail(fw.log.String(), 40))
		}
	})
}

// npmInstalledVersionNoFirewall installs from `port` with NO firewall in the path and
// reports npm's exit code, its output, and the version that actually landed in
// node_modules — which is the number that matters, and not the one the lockfile records.
func npmInstalledVersionNoFirewall(t *testing.T, port int) (int, string, string) {
	t.Helper()
	reg := fmt.Sprintf("http://host.docker.internal:%d/", port)
	// No command substitution anywhere: busybox sh choked on a $(node -p "...") whose
	// expression contained parentheses, and the failure surfaced as a broken CONTROL
	// rather than as a syntax error anyone would read.
	script := `set -e
echo '{"name":"h","version":"1.0.0"}' > package.json
npm install --no-audit --no-fund PKG > /tmp/o 2>&1 || echo "NPM_FAILED"
cat /tmp/o
printf 'INSTALLED='
node -p "try{require('/work/node_modules/PKG/package.json').version}catch(e){'NONE'}"
printf 'LOCKFILE='
node -p "try{Object.values(require('/work/package-lock.json').packages||{}).map(function(v){return v.version}).filter(Boolean).join(',')}catch(e){'-'}"
`
	script = strings.ReplaceAll(script, "PKG", versionCheckPkg)

	cmd := exec.Command("docker", "run", "--rm", "-w", "/work",
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "npm_config_registry="+reg,
		"-e", "npm_config_cache=/tmp/npmcache",
		"node:22-alpine", "sh", "-c", script)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("could not run docker: %v\n%s", err, out)
	}
	body := string(out)
	if strings.Contains(body, "NPM_FAILED") {
		code = 1
	}
	installed := "NONE"
	for _, line := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "INSTALLED="); ok {
			installed = v
		}
	}
	return code, body, installed
}

// TestNpmItselfDoesNotCompareTheVersions pins the PREMISE npmversion.go rests on, rather
// than the behaviour of our own check.
//
// npmversion.go says the comparison is "impossible anywhere else" and that a mismatched
// tarball is "invisible to the client". Every other leg in this file exercises the GATE;
// none of them establish that npm would miss it, so the premise was asserted rather than
// measured. It is measured here, with no firewall in the path at all.
//
// This is not a theoretical tidy-up. The same claim was made for PyPI in `#136`'s first
// version and was WRONG: pip resolving from an index compares the filename version against
// the PEP 658 metadata itself and discards the file. So "the client does not check" is a
// per-ecosystem fact, and assuming it transfers is how that error happened.
//
// Measured 2026-09-17, npm 10 on node 22: npm installs the tarball, node_modules gets
// 9.9.9 from the bytes, and the LOCKFILE records 1.0.0 from the URL — the two disagree
// inside one install, which is the concrete form of "invisible to the client".
//
// If this ever fails because npm started checking, that is GOOD NEWS and not a
// regression — but npmversion.go's justification would need rewriting, so it must be loud.
func TestNpmItselfDoesNotCompareTheVersions(t *testing.T) {
	// Control first: an honest tarball must install this way, or the leg below proves
	// nothing about version checking.
	t.Run("control: an honest tarball installs with no firewall", func(t *testing.T) {
		reg := startVersionCheckRegistry(t, versionCheckServed)
		code, out, installed := npmInstalledVersionNoFirewall(t, reg)
		if code != 0 || installed != versionCheckServed {
			t.Fatalf("CONTROL FAILED: an honest tarball did not install directly from the fixture registry (exit %d, node_modules=%q) — the rig is broken\n%s",
				code, installed, tail(out, 25))
		}
	})

	t.Run("npm installs a tarball declaring another version, and says nothing", func(t *testing.T) {
		const declared = "9.9.9"
		reg := startVersionCheckRegistry(t, declared)
		code, out, installed := npmInstalledVersionNoFirewall(t, reg)

		if code != 0 {
			t.Fatalf("PREMISE CHANGED, and this is good news rather than a regression: npm now REFUSES a tarball whose package.json disagrees with its URL (exit %d).\n"+
				"npmversion.go says the comparison is \"impossible anywhere else\" and that the mismatch is \"invisible to the client\" — both need rewriting, and the gate's value becomes central VISIBILITY rather than the only line, exactly as it did for pip in #136.\n%s",
				code, tail(out, 30))
		}
		if installed != declared {
			t.Fatalf("npm installed something other than the tarball's own version (node_modules=%q, tarball declared %q) — the premise this file rests on is not what was measured\n%s",
				installed, declared, tail(out, 30))
		}
		t.Logf("premise HOLDS: npm installed %s from a %s URL without complaint — the gate is the only party that can notice",
			installed, versionCheckServed)
	})
}
