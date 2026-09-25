//go:build e2e

package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// Issue #11 / D70 deferred an OCI byte gate on an argument, never a test:
//
//	"no ordinary OCI client fetches a blob without first fetching the manifest,
//	 which IS gated."
//
// This file tests it with a real, first-party OCI client against a real registry.
// The unit-level twin (oci_bytegate_test.go) establishes that the blob PATH is
// ungated; this establishes that an ordinary client actually walks it.
//
// The client is `crane blob` — "Read a blob from the registry", a subcommand of
// go-containerregistry, the same toolkit that backs ko, kaniko and much of the
// registry ecosystem. It is not an exotic tool and it is not an attack script: it
// is the documented way to read a blob, and it sends NO manifest request at all.
//
// The two legs must both run, in this order, because the second is only meaningful
// if the first proves the gate is live:
//
//	CONTROL: `crane pull` of the image is BLOCKED at the manifest.
//	TEST:    `crane blob` of that same blocked image's layer returns its bytes.

// alpineLayer is a layer digest of library/alpine:3.20 (linux/amd64), and
// alpineConfigDigest its config blob. Pinned by digest deliberately: a tag would
// drift and the test would silently start fetching a different blob, or none.
// Re-derive with:
//
//	crane manifest library/alpine:3.20                       # -> pick the amd64 child
//	crane manifest library/alpine@<amd64 digest>             # -> config + layers
const (
	alpineAmd64Manifest = "sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e"
	alpineLayer         = "sha256:25f1d6b1951ac8eb3740558fe94cb83d377bdadf95fd9f98b50d2e1b96130471"
)

// runCraneBlob fetches a blob by digest through the firewall and returns the number
// of bytes crane wrote to stdout, plus crane's exit code and stderr.
//
// Byte COUNT is the assertion, not the exit code: a bypass means real layer bytes
// reached the client, and only counting them proves that. crane writes the blob to
// stdout, so we read it directly and take len() — a few MB buffered is fine.
//
// TRAP, learned the hard way (it produced a false GREEN on the first run of this
// test): the crane image is DISTROLESS — it contains no shell. An invocation like
//
//	docker run --entrypoint sh crane:latest -c "crane blob ... | wc -c"
//
// dies with "exec: sh: executable file not found", docker exits non-zero, stdout is
// empty, and the byte count is 0 — which this test reads as "no bypass, all good".
// The harness would have reported success while never running the client at all.
// Hence assertClientRan below: a zero byte count is only meaningful if we can prove
// the client actually executed and was refused, rather than never having started.
func runCraneBlob(t *testing.T, port int, ref string) (n int, code int, stderr string) {
	t.Helper()
	target := fmt.Sprintf("host.docker.internal:%d/%s", port, ref)
	// No --entrypoint override: the image's entrypoint IS crane (see trap above).
	// --insecure: the firewall speaks plain HTTP in the e2e rig.
	cmd := exec.Command("docker", "run", "--rm",
		"--add-host", "host.docker.internal:host-gateway",
		"gcr.io/go-containerregistry/crane:latest",
		"blob", "--insecure", target,
	)
	out, err := cmd.Output()
	if e, ok := err.(*exec.ExitError); ok {
		code = e.ExitCode()
		stderr = string(e.Stderr)
	} else if err != nil {
		t.Fatalf("could not run docker (is it installed/running?): %v", err)
	}
	assertClientRan(t, stderr)
	return len(out), code, stderr
}

// assertClientRan turns "the client never started" into a LOUD failure instead of a
// silent zero-byte pass. These stderr signatures mean docker/the image failed before
// the client ever spoke to the firewall, so any conclusion about the gate would be
// unfounded — the preflight names the real problem rather than letting the suite
// report a green it did not earn.
func assertClientRan(t *testing.T, stderr string) {
	t.Helper()
	for _, sig := range []string{
		"executable file not found",
		"Error response from daemon",
		"failed to create task",
		"Unable to find image",
	} {
		if strings.Contains(stderr, sig) {
			t.Fatalf("HARNESS BROKEN, not a security result: the client container never ran (%q).\n"+
				"A zero byte count here would look like 'no bypass' but proves nothing.\nstderr: %s",
				sig, tail(stderr, 10))
		}
	}
}

// TestOciBlobFetchIsGated is the empirical settlement of the D70 deferral, and now
// the regression guard for the fix.
//
// It was written as a CHARACTERIZATION test asserting the BYPASS — `crane blob`
// pulled 3,630,321 bytes of a blocked image's layer — and is kept in place inverted
// (issue #57). The real client is the point: the unit twins in ../oci_bytegate_test.go
// prove the blob PATH is gated, but only a real client proves an ordinary tool
// actually walks that path and is actually stopped.
//
// The firewall is configured so that EVERYTHING is denied: stub mode scores every
// resolvable repo 7.5, the threshold is 9.9, and unscorable images are blocked. So
// there is no configuration under which alpine's bytes should reach the client.
func TestOciBlobFetchIsGated(t *testing.T) {
	bin := buildFirewall(t)
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":         "oci",
		"FW_SCORECARD_MODE":    "stub",
		"FW_SCORE_THRESHOLD":   "9.9", // stub scores 7.5 -> everything is below threshold
		"FW_UNSCORABLE_POLICY": "block",
		// Explicit, not defaulted: the gate must hold in the DEFAULT visibility-first
		// mode too, because a below-threshold score is a hard deny and D72 refuses those
		// bytes in every mode. Pinning it here means a change to the default cannot
		// quietly turn this test into a weaker one.
		"FW_BYTE_GATE": "allow-but-log",
	})

	// ---- CONTROL: the gate is live and blocks this image at the manifest. ----
	// Without this leg the test below could "pass" against a firewall that was
	// misconfigured, crashed, or allowing everything — the false-green case.
	code, out := runCranePull(t, fw.port, "library/alpine:3.20")
	if code == 0 {
		t.Fatalf("CONTROL FAILED: `crane pull` of a below-threshold image SUCCEEDED; "+
			"the gate is not live, so the blob leg below would prove nothing.\n%s", tail(out, 10))
	}
	if fw.blockedCount() == 0 {
		t.Fatalf("CONTROL FAILED: no block decision in the firewall log\n%s", fw.log.String())
	}
	t.Logf("control: `crane pull` correctly blocked at the manifest")

	// ---- TEST: the same image's layer, fetched by digest, with no manifest. ----
	n, exit, stderr := runCraneBlob(t, fw.port, "library/alpine@"+alpineLayer)

	// The primary assertion: no layer bytes. runCraneBlob has already called
	// assertClientRan, so a zero here means "the client ran and was refused" rather
	// than "the container never started" — the distroless trap that produced a false
	// GREEN the first time this test was written.
	if n != 0 {
		t.Errorf("issue #57 REGRESSED: `crane blob` pulled %d bytes of a BLOCKED image's "+
			"layer.\n"+
			"  image: library/alpine:3.20 (blocked at the manifest — see the control above)\n"+
			"  layer: %s\n"+
			"  The client sends NO manifest request, so only the blob gate can stop this.",
			n, alpineLayer)
	}
	// Refused, not merely empty. A zero byte count with a SUCCESSFUL exit would mean
	// crane was handed an empty 200 — the gate failing open on an empty body rather
	// than refusing — which looks identical on the byte count alone.
	if exit == 0 {
		t.Errorf("`crane blob` exited 0 for a blocked image: the client believes it "+
			"succeeded. A gate must refuse, not return an empty success.\nstderr: %s",
			tail(stderr, 5))
	}

	// The decisive log evidence, and the inverse of what this test recorded before the
	// fix: the blob request must now carry a DECISION line, not a bare relay line. The
	// firewall logs "byte gate ... -> allowed=..." for anything it evaluates and a bare
	// "GET /path -> <upstream>" for anything it merely relays.
	logs := fw.log.String()
	evaluated := false
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "byte gate") && strings.Contains(line, "library/alpine") {
			evaluated = true
			t.Logf("the blob request was evaluated: %s", line)
		}
	}
	if !evaluated {
		t.Errorf("no byte-gate decision line for the blob request — the firewall relayed "+
			"it without evaluating. Even if crane happened to get no bytes this run, the "+
			"gate is not the reason, so this is a bypass waiting to surface.\n%s",
			tail(logs, 30))
	}
}
