//go:build e2e

package e2e

// #147, the real-client half for Maven: do an artifact and the checksums beside it survive
// the gate, AS JUDGED BY mvn ITSELF?
//
// The unit tier (integritypreserved_test.go) compares bytes. This leg asks the only party
// whose opinion a customer experiences. It needs its own rig rather than a flag on
// TestMavenEndToEnd, for two measured reasons:
//
//   - mvn 3.9's default checksum policy is WARN. A resolve that "succeeds" through the
//     gate says nothing about checksums, so TestMavenEndToEnd is not a verifier and never
//     was. This leg passes -C (--strict-checksums). That flag is justified against the
//     QUANTITY: the checksum check is the thing being measured, not a convenience.
//   - the negative control needs an upstream whose checksum does NOT match its artifact,
//     and real Maven Central cannot be asked to serve one. e2e/mavenrepo can.
//
// THREE LEGS, because a green leg A alone cannot distinguish "mvn verified the checksum
// and was satisfied" from "mvn never verified anything":
//
//	A  honest repository           -> `mvn -C` must SUCCEED through the gate
//	B  .jar.sha1 describes other bytes -> `mvn -C` must FAIL, and fail ON THE CHECKSUM
//	C  one byte of the .jar flipped    -> `mvn -C` must FAIL, and fail ON THE CHECKSUM
//
// In B and C the gate relays faithfully -- the tamper is upstream of it -- so they are
// controls on the INSTRUMENT (mvn -C can fail, and says why), which is what gives A its
// meaning: if our relay altered the artifact or its sidecar, A is the leg that would look
// like B or C.
//
// Every leg proves CONTACT before concluding anything: the repository must have served the
// artifact (so mvn came through the gate to it), and the gate's own log must carry a
// verdict for it (so it came THROUGH US rather than around us).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	fixtureGAV     = "org.example.yjfixture:goodlib:2.1.0"
	fixtureJarPath = "/org/example/yjfixture/goodlib/2.1.0/goodlib-2.1.0.jar"
)

func buildMavenRepoTarget(t *testing.T, target, tag string) string {
	t.Helper()
	args := []string{"build", "-f", "e2e/mavenrepo/Dockerfile", "-t", tag}
	if target != "" {
		args = append(args, "--target", target)
	}
	cmd := exec.Command("docker", append(args, ".")...)
	cmd.Dir = ".."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", tag, err, out)
	}
	return tag
}

// mavenRepo is the running fixture. Two URLs for the classic dind reason: the FIREWALL
// reaches sibling containers through host.docker.internal, the TEST through E2E_FW_HOST.
type mavenRepo struct{ forFirewall, forTest string }

func startMavenRepo(t *testing.T, image, tamper string) *mavenRepo {
	t.Helper()
	port := freePort(t)
	name := fmt.Sprintf("yj-e2e-mavenrepo-%d", port)
	_ = exec.Command("docker", "rm", "-f", name).Run()
	args := []string{"run", "-d", "--name", name, "-p", fmt.Sprintf("%d:8080", port),
		"-e", "MAVENREPO_TAMPER=" + tamper, image}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("start mavenrepo: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	r := &mavenRepo{
		forFirewall: fmt.Sprintf("http://host.docker.internal:%d", port),
		forTest:     fmt.Sprintf("http://%s:%d", fwHost(), port),
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(r.forTest + "/_seen"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return r
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("mavenrepo never became ready at %s/_seen", r.forTest)
	return nil
}

// served reports the tamper mode the fixture is ACTUALLY running in and the paths it has
// served. The mode is read back rather than trusted, because a control whose tamper
// silently did not take is a control that passes for the wrong reason.
func (r *mavenRepo) served(t *testing.T) (tamper string, paths []string) {
	t.Helper()
	resp, err := http.Get(r.forTest + "/_seen")
	if err != nil {
		t.Fatalf("read mavenrepo observations: %v", err)
	}
	defer resp.Body.Close()
	var p struct {
		Tamper string   `json:"tamper"`
		Seen   []string `json:"seen"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		t.Fatalf("decode mavenrepo observations: %v", err)
	}
	return p.Tamper, p.Seen
}

func servedPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

// runMvnStrict resolves the fixture artifact through the gate with strict checksums.
//
// The settings file is EMPTY on purpose. Passing it with -gs replaces Maven's global
// settings, which is what removes the default http-blocker mirror so a plain-HTTP gate is
// reachable (see mavenMirrorSettings). Unlike that file it declares NO mirror: only the
// fixture artifact is pointed at the gate (-DremoteRepositories), and mvn's own plugin
// tree comes from Central directly. The fixture repository holds one artifact, so a
// mirrorOf=* here would starve mvn of its plugins and fail every leg for a reason that has
// nothing to do with checksums.
//
// The local repository is the image's PRE-WARMED one (see the mvnclient target), not a
// throwaway: it holds mvn's plugin tree and can never hold the fixture artifact, which
// exists in no public repository. `docker run --rm` still gives every leg a fresh copy.
func runMvnStrict(t *testing.T, clientImage string, gatePort int) (int, string) {
	t.Helper()
	script := `printf '<settings/>' > /tmp/settings.xml && ` +
		`mvn -B -C -gs /tmp/settings.xml ` +
		`org.apache.maven.plugins:maven-dependency-plugin:3.6.1:get ` +
		`-Dartifact=` + fixtureGAV + ` -Dtransitive=false ` +
		fmt.Sprintf(`-DremoteRepositories=yjfixture::default::http://host.docker.internal:%d/`, gatePort)
	cmd := exec.Command("docker", "run", "--rm",
		"--add-host", "host.docker.internal:host-gateway",
		clientImage, "sh", "-c", script)
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatalf("could not run docker: %v\n%s", err, out)
	}
	return 0, string(out)
}

// mentionsChecksumFailure is the operator-visible reason. Exit code alone is shared with a
// dozen other failures (no route, plugin resolution, a 403), and a control that fires for
// the wrong reason is not a control.
func mentionsChecksumFailure(out string) bool {
	l := strings.ToLower(out)
	return strings.Contains(l, "checksum validation failed") || strings.Contains(l, "checksum") && strings.Contains(l, "expected")
}

func TestMavenStrictChecksumsSurviveTheGate(t *testing.T) {
	gateImage := buildFirewall(t)
	repoImage := buildMavenRepoTarget(t, "", "yellowjack-mavenrepo:e2e")
	clientImage := buildMavenRepoTarget(t, "mvnclient", "yellowjack-mvnclient:e2e")

	// run stands up repository(tamper) <- gate <- mvn -C and returns everything a leg needs
	// to establish WHY it ended the way it did.
	type result struct {
		code                  int
		out                   string
		servedJar, servedSha1 bool
		gateJudgedTheArtifact bool
		tamperActuallyRunning string
		gateLog               string
	}
	run := func(t *testing.T, tamper string) result {
		repo := startMavenRepo(t, repoImage, tamper)
		fw := startFirewall(t, gateImage, syntheticRegistryDates(map[string]string{
			"FW_ECOSYSTEM":      "maven",
			"FW_UPSTREAM":       repo.forFirewall,
			"FW_SCORECARD_MODE": "off",
		}))
		code, out := runMvnStrict(t, clientImage, fw.port)
		mode, paths := repo.served(t)
		log := fw.log.String()
		return result{
			code: code, out: out,
			servedJar:             servedPath(paths, fixtureJarPath),
			servedSha1:            servedPath(paths, fixtureJarPath+".sha1"),
			gateJudgedTheArtifact: strings.Contains(log, "goodlib") && strings.Contains(log, "allowed=true"),
			tamperActuallyRunning: mode,
			gateLog:               log,
		}
	}
	// contact is shared by all three legs: nothing may be concluded from an exit code
	// until mvn is shown to have come through the gate to the repository.
	contact := func(t *testing.T, r result) {
		t.Helper()
		if !r.servedJar {
			t.Fatalf("RIG UNREACHABLE, NOT A FINDING: the repository never served the artifact, so mvn did "+
				"not come through the gate to it (exit %d). This says nothing about checksums.\n%s\n--- gate log ---\n%s",
				r.code, tail(r.out, 30), tail(r.gateLog, 15))
		}
		if !r.gateJudgedTheArtifact {
			t.Fatalf("NO PROOF OF CONTACT WITH THE GATE: the repository served the artifact but the gate's log "+
				"carries no allowed verdict for it, so this leg cannot show the bytes came THROUGH US.\n--- gate log ---\n%s",
				tail(r.gateLog, 25))
		}
	}

	t.Run("A_honest_repository_strict_checksums_pass_through_the_gate", func(t *testing.T) {
		r := run(t, "")
		contact(t, r)
		if !r.servedSha1 {
			t.Fatalf("VACUOUS PASS RISK: mvn never fetched the .sha1 sidecar, so whatever it did, it did not "+
				"verify a checksum that crossed the gate.\n%s", tail(r.out, 30))
		}
		if r.code != 0 {
			if mentionsChecksumFailure(r.out) {
				t.Fatalf("INTEGRITY NOT PRESERVED: `mvn -C` FAILED ON A CHECKSUM against an HONEST repository. "+
					"The repository's artifact and sidecar agree, so the relay changed one of them.\n%s", tail(r.out, 40))
			}
			t.Fatalf("`mvn -C` failed (exit %d) for a reason that is not a checksum; fix the rig before "+
				"reading anything into this.\n%s", r.code, tail(r.out, 40))
		}
		t.Logf("integrity preserved: `mvn -C` accepted the artifact and its .sha1 after both crossed the gate")
	})

	for _, c := range []struct{ leg, tamper, what string }{
		{"B_control_sidecar_describes_other_bytes_must_fail_on_checksum", "sidecar", "a .jar.sha1 that does not match the artifact"},
		{"C_control_artifact_byte_flipped_must_fail_on_checksum", "artifact", "an artifact with one flipped byte"},
	} {
		t.Run(c.leg, func(t *testing.T) {
			r := run(t, c.tamper)
			if r.tamperActuallyRunning != c.tamper {
				t.Fatalf("CONTROL DID NOT ARM: the repository reports tamper=%q, wanted %q", r.tamperActuallyRunning, c.tamper)
			}
			contact(t, r)
			if r.code == 0 {
				t.Fatalf("CONTROL FAILED TO FAIL: `mvn -C` SUCCEEDED against %s. mvn did not verify the checksum, "+
					"so leg A's pass is vacuous and this rig cannot answer the question at all.\n%s", c.what, tail(r.out, 40))
			}
			if !mentionsChecksumFailure(r.out) {
				t.Fatalf("CONTROL FIRED FOR THE WRONG REASON: `mvn -C` failed (exit %d) but never named a checksum.\n%s",
					r.code, tail(r.out, 40))
			}
			t.Logf("control held: mvn refused %s -- %s", c.what, strings.TrimSpace(lastLine(r.out, "hecksum")))
		})
	}
}
