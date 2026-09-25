//go:build e2e

package e2e

// Tier 2 for issue #136: a REAL pip, against an upstream that serves a wheel under a
// version its own PEP 658 metadata contradicts.
//
// Real PyPI never does this — it validates the pairing on upload — so the leg needs a
// crafted upstream, the same shape as the borrow-a-score rig: craft the side an attacker
// (or a broken mirror) controls, leave the client real. The wheels are built by the stub
// with Python's own zipfile, so what pip receives is a genuine installable wheel.
//
// ⚠️ THIS LEG CORRECTED THE FEATURE IT WAS WRITTEN TO CONFIRM. It first asserted that the
// gate refuses the wheel bytes. Run against a real pip, it showed that pip 26.2.1 compares
// the filename version against the PEP 658 metadata ITSELF and discards the file without
// ever requesting the wheel — so the byte-path refusal cannot fire for pip at all, and the
// first version of pypiwheelversion.go, which said "pip does NOT compare them", was wrong
// for the ordinary install path. What the gate is worth here is what #52 argued for: pip's
// refusal reaches one developer's terminal, the gate's reaches the operator. Leg B asserts
// that.
//
// The truthful leg runs FIRST and is not decoration. Its first run failed too — the stub
// advertised a placeholder core-metadata hash, pip verified it, and the install died
// before the product was exercised at all.

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// startWheelVersionUpstream serves a PyPI-shaped registry for one package: a /simple/
// index advertising PEP 658 core-metadata, the wheel, and its .metadata sibling.
//
// declared is the version the METADATA announces; the wheel is always SERVED as 1.0.0,
// so declared == "1.0.0" is the honest control and anything else is the lie.
//
// ThreadingHTTPServer, not HTTPServer: pip keeps the connection alive between the index,
// the metadata and the wheel, and a single-threaded stub deadlocks behind that — a
// failure this suite has already paid for once.
func startWheelVersionUpstream(t *testing.T, declared string) (base string, port int) {
	t.Helper()
	port = freePort(t)
	name := fmt.Sprintf("yj-e2e-wheelver-%d", port)
	prog := fmt.Sprintf(`import base64, csv, hashlib, io, zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = "yjprobe"
SERVED = "1.0.0"
DECLARED = %q
OBJ = "/packages/ab/cd/" + NAME + "-" + SERVED + "-py3-none-any.whl"

def metadata():
    return ("Metadata-Version: 2.1\nName: " + NAME + "\nVersion: " + DECLARED +
            "\nSummary: version-disagreement probe\n\n").encode()

def wheel():
    di = NAME + "-" + DECLARED + ".dist-info"
    files = {
        NAME + "/__init__.py": ('__version__ = "' + DECLARED + '"\n').encode(),
        di + "/METADATA": metadata(),
        di + "/WHEEL": b"Wheel-Version: 1.0\nGenerator: yjprobe\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    rows = []
    for p, b in files.items():
        h = base64.urlsafe_b64encode(hashlib.sha256(b).digest()).decode().rstrip("=")
        rows.append((p, "sha256=" + h, str(len(b))))
    rows.append((di + "/RECORD", "", ""))
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerows(rows)
    files[di + "/RECORD"] = buf.getvalue().encode()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p, b in files.items():
            z.writestr(p, b)
    return out.getvalue()

WHEEL = wheel()
META = metadata()
# pip VERIFIES this hash against the metadata it fetches, so a placeholder aborts the
# install before the wheel is ever requested -- measured, and it broke the control leg.
META_SHA = hashlib.sha256(META).hexdigest()

class H(BaseHTTPRequestHandler):
    def send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ("/simple/" + NAME + "/", "/simple/" + NAME):
            href = "http://HOSTPORT" + OBJ
            body = ('<!DOCTYPE html><html><body><a href="' + href +
                    '" data-core-metadata="sha256=' + META_SHA + '">' + NAME + "-" + SERVED +
                    '-py3-none-any.whl</a></body></html>').encode()
            self.send(200, body, "text/html")
        elif p == OBJ + ".metadata":
            self.send(200, META, "text/plain")
        elif p == OBJ:
            self.send(200, WHEEL, "application/octet-stream")
        else:
            self.send(404, b"no", "text/plain")
    def log_message(self, *a):
        pass

ThreadingHTTPServer(("", 80), H).serve_forever()`, declared)

	// The index must advertise the artifact at an address the FIREWALL can reach, which
	// is the stub's published port on the docker host — the same host:port pip's own
	// requests traverse.
	prog = strings.ReplaceAll(prog, "HOSTPORT", fmt.Sprintf("host.docker.internal:%d", port))

	args := []string{"run", "-d", "--name", name,
		"--add-host", "host.docker.internal:host-gateway",
		"-p", fmt.Sprintf("%d:80", port),
		"python:3.12-slim", "python3", "-c", prog}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("start wheel-version upstream: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	probe := fmt.Sprintf("http://%s:%d/simple/yjprobe/", fwHost(), port)
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(probe); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return fmt.Sprintf("http://host.docker.internal:%d", port), port
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("wheel-version upstream never became ready at %s", probe)
	return "", 0
}

// TestPypiWheelServedUnderAnotherVersionIsRefusedForRealPip is the leg #136's acceptance
// asks for: a real pip, a real wheel, and the gate's half measured rather than assumed.
func TestPypiWheelServedUnderAnotherVersionIsRefusedForRealPip(t *testing.T) {
	bin := buildFirewall(t)

	env := func(upstream string) map[string]string {
		return syntheticRegistryDates(map[string]string{
			"FW_ECOSYSTEM":         "pypi",
			"FW_UPSTREAM":          upstream,
			"FW_FILES_UPSTREAM":    upstream,
			"FW_SCORECARD_MODE":    "stub",
			"FW_SCORE_THRESHOLD":   "0", // allow everything on score: this leg tests integrity, not policy
			"FW_UNSCORABLE_POLICY": "allow",
			"FW_UNVERIFIED_POLICY": "open-with-visibility",
		})
	}

	// ── Control, and it runs first. An honest wheel must install through the gate, or
	// the refusal below is just a broken rig — which is exactly what its first run was.
	t.Run("A_honest_wheel_installs", func(t *testing.T) {
		upstream, _ := startWheelVersionUpstream(t, "1.0.0")
		fw := startFirewall(t, bin, env(upstream))
		defer fw.stop()

		code, out := runPipInstall(t, fw.port, "yjprobe")
		if code != 0 {
			t.Fatalf("CONTROL FAILED: an honest wheel did not install through the gate (exit %d).\n%s\n--- firewall ---\n%s",
				code, tail(out, 25), tail(fw.log.String(), 30))
		}
		if strings.Contains(fw.log.String(), "INDEX DISAGREES") {
			t.Errorf("the version check fired on a wheel whose metadata agrees:\n%s", tail(fw.log.String(), 20))
		}
		t.Logf("control: pip installed the honest wheel through the gate")
	})

	// ── The finding, and it is not the one this leg was written to assert.
	//
	// pip compares the two versions itself and discards the file WITHOUT requesting the
	// wheel, so the gate's byte-path refusal cannot fire for pip. What the gate adds is
	// that the operator hears about it at all.
	t.Run("B_the_mismatch_is_caught_and_the_operator_can_see_it", func(t *testing.T) {
		upstream, _ := startWheelVersionUpstream(t, "9.9.9")
		fw := startFirewall(t, bin, env(upstream))
		defer fw.stop()

		code, out := runPipInstall(t, fw.port, "yjprobe")
		logs := fw.log.String()

		if code == 0 {
			t.Fatalf("pip INSTALLED a wheel served as 1.0.0 whose metadata declares 9.9.9.\n%s\n--- firewall ---\n%s",
				tail(out, 25), tail(logs, 30))
		}
		// pip's own reason, recorded so that a future pip which STOPS checking shows up
		// here as a change rather than as a silent loss of the client-side half.
		if !strings.Contains(out, "inconsistent version") {
			t.Logf("NOTE: pip did not report an inconsistent version; it failed for another reason. If pip has stopped checking, the gate is the only line left and this leg should be rewritten to say so.\n  pip: %s",
				reasonLine(out, "yjprobe"))
		}
		// The gate's half: the operator learns about it centrally. Asserted on the REASON,
		// never the status — a 403 here is indistinguishable from the could-not-verify 403.
		if !strings.Contains(logs, "INDEX DISAGREES") {
			t.Fatalf("the gate relayed the metadata and said NOTHING about the disagreement, so the operator learns nothing and the only refusal happened on a developer's laptop:\n--- firewall ---\n%s",
				tail(logs, 40))
		}
		t.Logf("pip discarded the file on its own AND the gate recorded the disagreement centrally")
	})
}
