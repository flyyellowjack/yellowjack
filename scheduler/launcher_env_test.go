package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// docs/SETUP.md's #80 option 1 — "point the launcher at a remote daemon, mount no
// socket" — is the only hardened deployment we can offer today, and it rests on exactly
// two facts about this package:
//
//  1. dockerRunLauncher does NOT override the child's environment, so the docker CLI it
//     shells out to honours DOCKER_HOST / DOCKER_TLS_VERIFY / DOCKER_CERT_PATH.
//  2. newAPILauncher dials ("unix", socket) UNCONDITIONALLY, so the same trick does not
//     work there and a tcp:// value is read as a filename.
//
// Both were verified by hand when that doc was written, and neither was pinned. Fact 1
// is one `cmd.Env = ...` line away from silently breaking a deployment whose entire
// point is that no socket is mounted; fact 2 is what stops an operator reaching for the
// wrong launcher, and !241 had to DELETE a comment from e2e/hardening.sh that offered
// the api launcher as a remote mitigation it cannot perform.
//
// e2e/remote_daemon_drill.sh runs the real thing against a real second daemon. It needs
// a privileged container, so it is not a CI job; these two tests are the part that runs
// on every pipeline.

// envProbe is a variable this package never reads in production. The child reports it
// back so the test can tell "we are reading the CHILD's environment" from "we are
// reading our own" — see the anti-vacuity assertion below.
const envProbe = "YJ_LAUNCHER_ENV_PROBE"

// TestMain doubles as the stand-in `docker` binary. dockerRunLauncher always passes
// "run" as the first argument, so an invocation of this test binary carrying that is one
// of ours: report the environment we were handed and exit non-zero, which makes the
// launcher fold our output into its error where the test can read it.
//
// The detection is ARGUMENT-based, never environment-based, on purpose. If inheritance
// were broken — the very regression this guards — an env-gated child would not recognise
// itself, would run the whole suite, and would spawn another child; this one terminates
// immediately either way.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "run" {
		fmt.Printf("stand-in docker: DOCKER_HOST=%q DOCKER_TLS_VERIFY=%q DOCKER_CERT_PATH=%q %s=%q",
			os.Getenv("DOCKER_HOST"), os.Getenv("DOCKER_TLS_VERIFY"),
			os.Getenv("DOCKER_CERT_PATH"), envProbe, os.Getenv(envProbe))
		os.Exit(7)
	}
	os.Exit(m.Run())
}

// TestDockerRunLauncherHandsItsEnvironmentToTheDockerCLI pins fact 1 by MEASURING it:
// the launcher is pointed at this test binary as its "docker", and what that child
// reports back is what the real CLI would have seen.
func TestDockerRunLauncherHandsItsEnvironmentToTheDockerCLI(t *testing.T) {
	const (
		host    = "tcp://scanner-host.invalid:2376"
		verify  = "1"
		certDir = "/certs/client"
	)
	t.Setenv("DOCKER_HOST", host)
	t.Setenv("DOCKER_TLS_VERIFY", verify)
	t.Setenv("DOCKER_CERT_PATH", certDir)

	d := &dockerRunLauncher{docker: os.Args[0], image: "yellowjack-scanner:dev"}
	err := d.Launch(context.Background(), "github.com/lodash/lodash", "http://sink.invalid/results/1/tok")
	if err == nil {
		t.Fatal("the stand-in docker exits 7, so Launch must report an error carrying its output")
	}
	got := err.Error()

	for _, want := range []struct{ value, why string }{
		{host, "DOCKER_HOST is what sends the launch to another daemon; without it option 1 in docs/SETUP.md silently becomes a local launch"},
		{verify, "DOCKER_TLS_VERIFY is half of the mutual-TLS pair the doc prints"},
		{certDir, "DOCKER_CERT_PATH is the other half; a client cert the CLI never sees is not authentication"},
	} {
		if !strings.Contains(got, want.value) {
			t.Errorf("the docker CLI was NOT given %q: %s\n"+
				"dockerRunLauncher must leave cmd.Env nil so the child inherits the process environment. "+
				"If this was deliberate, docs/SETUP.md's remote-daemon option and e2e/remote_daemon_drill.sh "+
				"both describe a deployment that no longer works.\ngot: %s", want.value, want.why, got)
		}
	}

	// ANTI-VACUITY. Every assertion above would also pass if the error text happened to
	// echo the PARENT's environment rather than the child's. This probe is set here and
	// can only appear in the message by travelling out to the child and back.
	t.Setenv(envProbe, "probe-value-4f1c")
	err = d.Launch(context.Background(), "github.com/lodash/lodash", "http://sink.invalid/results/1/tok")
	if err == nil || !strings.Contains(err.Error(), "probe-value-4f1c") {
		t.Fatalf("the instrument is not reading the CHILD's environment, so the checks above prove nothing: %v", err)
	}
	// And a variable nobody set must come back EMPTY rather than absent-looking, which is
	// what tells the two apart.
	if !strings.Contains(err.Error(), `DOCKER_HOST="`+host+`"`) {
		t.Errorf("the child's report is not in the expected shape; the assertions above may be matching something else: %v", err)
	}
}

// TestAPILauncherCannotReachARemoteDaemon pins fact 2. The transport dials a UNIX socket
// at whatever path SCHEDULER_DOCKER_SOCKET names, so a tcp:// address is a filename that
// does not exist. This test is written to FAIL LOUDLY if that ever changes, because the
// doc, the drill's control B and e2e/hardening.sh's corrected comment all depend on it.
func TestAPILauncherCannotReachARemoteDaemon(t *testing.T) {
	a := newAPILauncher("tcp://scanner-host.invalid:2376", "yellowjack-scanner:dev", "", "", "")
	err := a.Launch(context.Background(), "github.com/lodash/lodash", "http://sink.invalid/results/1/tok")
	if err == nil {
		t.Fatal("the docker-api launcher accepted a tcp:// address. If it gained remote support, that is a " +
			"real improvement — but docs/SETUP.md option 2, e2e/hardening.sh's comment and " +
			"e2e/remote_daemon_drill.sh control B all state the opposite and must be rewritten together.")
	}
	// It must fail as a DIAL, not as some later validation, or the reason the doc gives
	// ("it reads the value as a filename") would be wrong even though the outcome matches.
	if !strings.Contains(err.Error(), "tcp://scanner-host.invalid:2376") {
		t.Errorf("the failure does not name the socket path, so it may not be the dial failing: %v", err)
	}

	// Control: the same launcher against a unix path that also does not exist fails the
	// same way — which is what shows the tcp:// failure is "no such file", the doc's
	// stated mechanism, rather than a scheme check the launcher does not actually have.
	u := newAPILauncher("/var/run/yj-no-such-socket.sock", "yellowjack-scanner:dev", "", "", "")
	uerr := u.Launch(context.Background(), "github.com/lodash/lodash", "http://sink.invalid/results/1/tok")
	if uerr == nil {
		t.Fatal("a nonexistent unix socket must fail too; otherwise the comparison below is meaningless")
	}
	if !strings.Contains(uerr.Error(), "yj-no-such-socket.sock") {
		t.Errorf("the unix-path failure does not name its path either: %v", uerr)
	}
}
