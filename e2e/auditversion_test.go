//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// D363 at tier 2: the release a verdict concerned reaches the control plane from a REAL
// client's traffic. The unit tests drive ServeHTTP with paths we wrote; this drives mvn
// and npm, whose paths we did not write, into a gate that posts its audit events to a
// recording stand-in for the approval service.

// startEventRecorder runs a stand-in approval service that answers "no ruling" to every
// decision lookup and keeps every audit event posted to it, served back at /recorded.
// Returns the URL the firewall container uses and the URL the test host reads.
func startEventRecorder(t *testing.T) (forGate, forTest string) {
	t.Helper()
	port := freePort(t)
	name := fmt.Sprintf("yj-e2e-events-%d", port)
	prog := `import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
events, lock = [], threading.Lock()
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path == "/v1/events":
            with lock:
                events.append(json.loads(body))
            self.send_response(201)
        else:
            self.send_response(404)
        self.end_headers()
    def do_GET(self):
        if self.path == "/recorded":
            with lock:
                out = json.dumps(events).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(out)
            return
        self.send_response(404)
        self.end_headers()
    def log_message(self, *a):
        pass
ThreadingHTTPServer(("", 80), H).serve_forever()`
	if out, err := exec.Command("docker", "run", "-d", "--name", name, "-p", fmt.Sprintf("%d:80", port),
		"python:3.12-slim", "python3", "-c", prog).CombinedOutput(); err != nil {
		t.Fatalf("start event recorder: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	forTest = fmt.Sprintf("http://%s:%d", fwHost(), port)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(forTest + "/recorded"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return fmt.Sprintf("http://host.docker.internal:%d", port), forTest
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("event recorder never became ready at %s", forTest)
	return "", ""
}

// recordedEvents reads back what the gate posted, as raw maps so an ABSENT key is
// distinguishable from an empty one. It waits for at least one event matching pkg,
// because the gate emits after the relay and off the request goroutine.
func recordedEvents(t *testing.T, base, pkg string) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var all []map[string]any
		resp, err := http.Get(base + "/recorded")
		if err == nil {
			_ = json.NewDecoder(resp.Body).Decode(&all)
			resp.Body.Close()
		}
		var mine []map[string]any
		for _, e := range all {
			if e["package"] == pkg {
				mine = append(mine, e)
			}
		}
		if len(mine) > 0 || time.Now().After(deadline) {
			return mine
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func TestTheAuditRecordNamesTheReleaseARealClientFetched(t *testing.T) {
	bin := buildFirewall(t)
	permissive := func(eco, approval string) map[string]string {
		return map[string]string{
			"FW_ECOSYSTEM":         eco,
			"FW_SCORECARD_MODE":    "stub",
			"FW_SCORE_THRESHOLD":   "0",
			"FW_UNSCORABLE_POLICY": "allow",
			"FW_UNVERIFIED_POLICY": "open-with-visibility",
			"FW_APPROVAL_URL":      approval,
		}
	}

	t.Run("maven_the_jar_mvn_fetched_is_named", func(t *testing.T) {
		gateURL, readURL := startEventRecorder(t)
		fw := startFirewall(t, bin, permissive("maven", gateURL))
		const coord, pkg, version = "junit:junit:4.13.2", "junit:junit", "4.13.2"
		if code, out := runMvnGet(t, fw.port, coord); code != 0 {
			t.Fatalf("PREMISE: permissive `mvn get %s` failed (exit %d)\n%s\n--- firewall ---\n%s",
				coord, code, tail(out, 20), logAround(fw.log.String(), 30, "junit"))
		}
		evs := recordedEvents(t, readURL, pkg)
		if len(evs) == 0 {
			t.Fatalf("CONTACT: the gate recorded no event for %s, so this leg proves nothing about the field\n"+
				"--- firewall ---\n%s", pkg, logAround(fw.log.String(), 30, "junit"))
		}
		for _, e := range evs {
			if e["version"] != version {
				t.Errorf("a record for %s names version %v, want %q: %v", pkg, e["version"], version, e)
			}
		}
	})

	t.Run("npm_a_packument_record_names_no_release", func(t *testing.T) {
		gateURL, readURL := startEventRecorder(t)
		fw := startFirewall(t, bin, permissive("npm", gateURL))
		const pkg = "is-number"
		if code, out := runNpmInstall(t, fw.port, pkg); code != 0 {
			t.Fatalf("PREMISE: permissive `npm install %s` failed (exit %d)\n%s", pkg, code, tail(out, 20))
		}
		evs := recordedEvents(t, readURL, pkg)
		if len(evs) == 0 {
			t.Fatalf("CONTACT: the gate recorded no event for %s\n--- firewall ---\n%s", pkg, logAround(fw.log.String(), 30, pkg))
		}
		for _, e := range evs {
			if v, has := e["version"]; has {
				t.Errorf("the packument record carries version %v; npm asked for the whole package, and "+
					"which release it then installs is decided afterwards, from the document: %v", v, e)
			}
		}
		if s := fmt.Sprint(evs); !strings.Contains(s, "allow") {
			t.Errorf("the recorded events are not the allow the install produced: %s", s)
		}
	})
}
