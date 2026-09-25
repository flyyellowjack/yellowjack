//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The credential-rotation leg (issue #53, D177, !148).
//
// WHAT WAS MISSING. !148 turned the upstream credential into a SOURCE consulted per
// request, so an upstream that mints short-lived tokens (AWS CodeArtifact, the first
// D177 integration target) keeps working as its token rotates. That is unit-tested
// thoroughly — fileCredentialEvery has tests for rotation, for the trailing-newline
// trim, and for the last-good retention. What no test touched was whether any of it
// survives being put in a CONTAINER: `grep FW_UPSTREAM_AUTH_FILE e2e/` returned nothing
// before this file existed.
//
// WHY THAT GAP IS NOT ACADEMIC. On 2026-09-07 the operator-list write path shipped an
// atomic write (temp file + rename) and the gate stopped seeing edits entirely, because
// the compose file bind-mounted the list FILE and a file bind mount pins that file's
// INODE. A rename installs a NEW inode, so the container re-read its own path forever
// and got the old one. Everything visible said it worked.
//
// FW_UPSTREAM_AUTH_FILE has the identical shape and a worse consequence. Every
// mechanism the !148 comment names as its interop point — Kubernetes projected tokens,
// Vault agent, a cron running the AWS CLI — writes by temp-file-and-rename, because
// that is how you avoid a reader seeing a half-written secret. So THE SAFER THE
// REFRESHER, THE MORE CERTAINLY IT BREAKS. And the failure is silent in the direction
// that matters: the credential does not vanish, it goes STALE, so the gate keeps
// presenting an expired token and the upstream starts refusing it — an outage
// attributed to the registry rather than to us.
//
// It is also platform-masked. Docker Desktop resolves file bind mounts by path, so a
// developer's laptop shows rotation working; Linux pins the inode, and Linux is what
// deployments run. A test that mounted the file would therefore pass locally and fail
// in CI, or worse, pass in both while proving nothing.
//
// WHAT THIS LEG ASSERTS, end to end, against the real container:
//
//  1. the credential in the file reaches upstream at all (anti-vacuity — without this
//     step 2 could pass on a fixture that only ever saw one value);
//  2. a credential rotated BY RENAME reaches upstream, with no restart (the claim);
//  3. a blanked file does NOT degrade the gate to anonymous — the last good credential
//     is still presented (!148's security property, previously unit-only).
//
// The mount is a DIRECTORY, which is the deployment requirement docs/CONFIGURATION.md
// records. That is not incidental to the rig: mounting the file instead is precisely
// the bug this leg exists to keep out, and TestReReadConfigFilesAreNotFileMounts in the
// root package is the structural half that stops a compose file reintroducing it.

const credMountDir = "/etc/yellowjack/upstream-auth"

// buildCredUpstream builds the recording registry fixture.
func buildCredUpstream(t *testing.T) string {
	t.Helper()
	const tag = "yellowjack-credupstream:e2e"
	cmd := exec.Command("docker", "build", "-f", "e2e/credupstream/Dockerfile", "-t", tag, ".")
	cmd.Dir = ".."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build credupstream fixture: %v\n%s", err, out)
	}
	return tag
}

// buildCredWriter builds the shell-bearing image used to rewrite the credential file.
//
// Built from a NAMED TARGET of the same Dockerfile rather than written as a string in
// this file, because scripts/pinned-images.sh walks Dockerfile FROM lines and compose
// "image:" lines and nothing else: an image reference living in a .go file is outside
// every pin check the repo has, and would be pinned only for as long as someone
// remembered to. Declaring it in the Dockerfile puts it back under the #22 gate.
func buildCredWriter(t *testing.T) string {
	t.Helper()
	const tag = "yellowjack-credwriter:e2e"
	cmd := exec.Command("docker", "build", "-f", "e2e/credupstream/Dockerfile",
		"--target", "credwriter", "-t", tag, ".")
	cmd.Dir = ".."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build credwriter: %v\n%s", err, out)
	}
	return tag
}

// credUpstream is the running fixture: the URL the FIREWALL uses, and the one the TEST
// uses. They differ, and conflating them is the classic dind mistake — the firewall
// reaches sibling containers through host.docker.internal, while the test reaches them
// through E2E_FW_HOST.
type credUpstream struct {
	forFirewall string
	forTest     string
	name        string
}

func startCredUpstream(t *testing.T, image string) *credUpstream {
	t.Helper()
	port := freePort(t)
	name := fmt.Sprintf("yj-e2e-credupstream-%d", port)
	_ = exec.Command("docker", "rm", "-f", name).Run()

	args := []string{"run", "-d", "--name", name, "-p", fmt.Sprintf("%d:8080", port), image}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("start credupstream: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	u := &credUpstream{
		forFirewall: fmt.Sprintf("http://host.docker.internal:%d", port),
		forTest:     fmt.Sprintf("http://%s:%d", fwHost(), port),
		name:        name,
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(u.forTest + "/_seen"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return u
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("credupstream never became ready at %s/_seen", u.forTest)
	return nil
}

type credObservation struct {
	Path string `json:"path"`
	Auth string `json:"auth"`
}

// seen returns every metadata probe the fixture has recorded, oldest first.
func (u *credUpstream) seen(t *testing.T) []credObservation {
	t.Helper()
	resp, err := http.Get(u.forTest + "/_seen")
	if err != nil {
		t.Fatalf("read credupstream observations: %v", err)
	}
	defer resp.Body.Close()
	var payload struct {
		Seen []credObservation `json:"seen"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode credupstream observations: %v", err)
	}
	return payload.Seen
}

// authFor returns the Authorization the fixture saw on pkg's metadata probe.
//
// found=false means the probe never arrived, which is a DIFFERENT failure from an
// anonymous probe (found=true, auth==""), and the two must not be conflated: the first
// says the firewall never asked upstream, the second says it asked without a
// credential. Only the second is the degrade-to-anonymous case.
func (u *credUpstream) authFor(t *testing.T, pkg string) (auth string, found bool) {
	t.Helper()
	want := "/" + pkg + "/latest"
	for _, o := range u.seen(t) {
		if o.Path == want {
			return o.Auth, true
		}
	}
	return "", false
}

// credVolume is a named docker volume holding the credential file.
//
// A named volume rather than a host path because of dind: see startFirewallWithMounts.
type credVolume struct{ name, writer string }

func newCredVolume(t *testing.T, writer string) *credVolume {
	t.Helper()
	name := fmt.Sprintf("yj-e2e-cred-%d", time.Now().UnixNano())
	if out, err := exec.Command("docker", "volume", "create", name).CombinedOutput(); err != nil {
		t.Fatalf("create credential volume: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "volume", "rm", "-f", name).Run() })
	return &credVolume{name: name, writer: writer}
}

func (v *credVolume) mount() string { return v.name + ":" + credMountDir }

// write installs contents at <volume>/token via TEMP FILE AND RENAME.
//
// The rename is the point of the whole leg, not an implementation detail: it is what
// every real refresher does (a reader must never see a half-written secret), and it is
// what produces a new inode and therefore what a FILE bind mount would hide. Writing in
// place with `>` would make this rig pass against a mount shape that breaks in
// production — a test reproducing the bug instead of catching it.
//
// The writer is a shell-bearing container because the firewall image is distroless and
// cannot write its own credential file; see buildCredWriter for why that image is
// declared in the Dockerfile rather than here.
func (v *credVolume) write(t *testing.T, contents string) {
	t.Helper()
	script := fmt.Sprintf("printf '%%s' %s > /vol/.token.tmp && mv /vol/.token.tmp /vol/token", shellQuote(contents))
	out, err := exec.Command("docker", "run", "--rm",
		"-v", v.name+":/vol", v.writer, "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("write credential file: %v\n%s", err, out)
	}
}

// shellQuote single-quotes s for `sh -c`. The credentials here are test fixtures with
// no quotes in them, but a helper that silently breaks on one would be a trap for
// whoever adds a realistic token later.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// pull asks the firewall for a package, which forces a metadata probe upstream.
//
// A DISTINCT package per phase, deliberately: the firewall caches repo lookups, so
// re-pulling the same name would be served from cache and never reach upstream — the
// leg would then assert on a probe that never happened and pass while measuring
// nothing.
func pullThroughFirewall(t *testing.T, fw *firewall, pkg string) {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("http://%s:%d/%s", fwHost(), fw.port, pkg))
	if err != nil {
		t.Fatalf("pull %s through the firewall: %v", pkg, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
}

func TestUpstreamCredentialRotation(t *testing.T) {
	fwImage := buildFirewall(t)
	upImage := buildCredUpstream(t)

	up := startCredUpstream(t, upImage)
	vol := newCredVolume(t, buildCredWriter(t))

	const (
		tokenA = "Bearer rotation-fixture-token-A"
		tokenB = "Bearer rotation-fixture-token-B"
	)
	vol.write(t, tokenA)

	fw := startFirewallWithMounts(t, fwImage, map[string]string{
		"FW_ECOSYSTEM": "npm",
		"FW_UPSTREAM":  up.forFirewall,
		// The credential under test. The value is a PATH INSIDE THE MOUNTED DIRECTORY,
		// never the mount target itself — mounting the file is the failure this leg
		// exists to keep out.
		"FW_UPSTREAM_AUTH_FILE": credMountDir + "/token",
		// Everything else is set to keep the ONLY upstream contact this fixture:
		// stub scoring makes no deps.dev call, and the repo cross-check would.
		"FW_SCORECARD_MODE":    "stub",
		"FW_SCORE_THRESHOLD":   "0",
		"FW_VERIFY_REPO":       "false",
		"FW_UNSCORABLE_POLICY": "allow",
	}, []string{vol.mount()})

	// --- 1. the credential reaches upstream at all -------------------------------
	//
	// The anti-vacuity step. Without it, step 2 would pass against a fixture that had
	// only ever observed one value, or a firewall that happened to send tokenB from
	// the start — neither of which is rotation.
	pullThroughFirewall(t, fw, "pkg-before-rotation")

	got, found := up.authFor(t, "pkg-before-rotation")
	if !found {
		t.Fatalf("upstream never received a metadata probe for pkg-before-rotation — the firewall did not "+
			"contact this fixture at all, so nothing below measures a credential.\nobservations: %+v\n--- firewall ---\n%s",
			up.seen(t), logAround(fw.log.String(), 25))
	}
	if got != tokenA {
		t.Fatalf("before rotation the upstream saw Authorization %q, want %q\n--- firewall ---\n%s",
			got, tokenA, logAround(fw.log.String(), 25))
	}

	// --- 2. a rotated credential reaches upstream, with no restart ----------------
	vol.write(t, tokenB) // temp file + rename: NEW INODE

	// credFileTTL is 1s (upstreamcred.go). Sleep past it rather than racing the timer;
	// a poll loop would need a fresh package name per attempt, and a name the firewall
	// has already resolved is served from cache.
	time.Sleep(2 * time.Second)

	pullThroughFirewall(t, fw, "pkg-after-rotation")

	got, found = up.authFor(t, "pkg-after-rotation")
	if !found {
		t.Fatalf("upstream never received a probe for pkg-after-rotation\nobservations: %+v\n--- firewall ---\n%s",
			up.seen(t), logAround(fw.log.String(), 25))
	}
	if got != tokenB {
		t.Fatalf("ROTATION DID NOT REACH UPSTREAM: after rewriting the credential file by rename, the "+
			"upstream still saw %q, want %q.\n\nThis is the shape that would break every short-lived-token "+
			"deployment (CodeArtifact, Vault, Kubernetes projected tokens): the gate keeps presenting an "+
			"EXPIRED credential and the resulting refusals look like the registry's fault. If the mount is a "+
			"FILE rather than the directory %s, that is the cause — a file bind mount pins the inode and a "+
			"rename installs a new one.\n--- firewall ---\n%s",
			got, tokenB, credMountDir, logAround(fw.log.String(), 25))
	}

	// --- 3. a blanked file must NOT degrade the gate to anonymous -----------------
	//
	// !148's security property, asserted end to end for the first time. A refresher
	// caught mid-write, a deleted file or a full disk all present as an empty read, and
	// returning "" there would drop the Authorization header entirely: the gate would
	// keep working at the anonymous rate limit and say nothing. That is the
	// "passes for the wrong reason" failure, so the last good value is retained.
	vol.write(t, "")
	time.Sleep(2 * time.Second)

	pullThroughFirewall(t, fw, "pkg-after-blanking")

	got, found = up.authFor(t, "pkg-after-blanking")
	if !found {
		t.Fatalf("upstream never received a probe for pkg-after-blanking\nobservations: %+v\n--- firewall ---\n%s",
			up.seen(t), logAround(fw.log.String(), 25))
	}
	if got == "" {
		t.Fatalf("SILENT DEGRADE TO ANONYMOUS: after the credential file was blanked the firewall sent NO "+
			"Authorization header at all. !148 retains the last good credential precisely so a refresher "+
			"caught mid-write cannot drop the gate to the anonymous rate limit without saying so.\n"+
			"--- firewall ---\n%s", logAround(fw.log.String(), 25))
	}
	if got != tokenB {
		t.Errorf("after blanking, upstream saw %q; want the last good credential %q", got, tokenB)
	}

	// The operator has to be able to SEE the degraded state: a retained credential that
	// is never mentioned is indistinguishable from a healthy one right up until the token
	// expires, which is the same "works, silently, for the wrong reason" shape the
	// retention itself exists to avoid, moved one step later.
	//
	// Asserted on the SPECIFIC transition line rather than on any upstream-auth output:
	// main.go logs an upstream-auth line at STARTUP, so the loose version would pass
	// without the blanking ever having been noticed.
	if !strings.Contains(fw.log.String(), "is empty") {
		t.Errorf("the firewall never logged that the credential file went empty, so an operator has no "+
			"signal that the gate is running on a retained credential\n--- firewall ---\n%s",
			logAround(fw.log.String(), 25, "upstream-auth"))
	}
}
