//go:build e2e

package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// Maven over HTTPS, through the documented terminator. The predictions (M1 reach, M2
// enforcement, M3 control) are pre-registered in the header of ingress_tls_test.go and were
// committed before this file existed. THE FIRST RUN FALSIFIED M1 and showed M2's premise
// was wrong; the results block under the predictions records that, and the legs below pin
// what was MEASURED rather than what was predicted.

// INCREMENT 2 -- PRE-REGISTERED 2026-09-21, committed BEFORE the legs exist. The two cells
// increment 1 listed as not covered: a repository DECLARED IN A POM, and Gradle. Both are the
// ordinary way a developer would add us, as opposed to the flag nobody commits. Every leg runs
// against a BLOCKING gate behind the https terminator, because the question is enforcement.
// This time the ORDER is stated before the prediction, which is what increment 1 skipped.
//
//	P1  POM <repositories> naming us, central left implicit. ORDER: POM-declared repositories
//	    precede the super-POM's central. PREDICTION: the gate IS asked and logs a block for the
//	    artifact; Maven treats the 403 as "not here", falls through to central, exits 0 and the
//	    jar is recorded from central. Visibility yes, enforcement no. (This is the mechanism
//	    increment 1's M2 predicted and did not find, because there the order was reversed.)
//	G1  Gradle, our repository declared FIRST, mavenCentral() second. ORDER: declaration order.
//	    PREDICTION: the gate is asked, blocks, and THE BUILD FAILS -- Gradle treats a non-404
//	    answer as a repository error and does not continue to the next repository. If this
//	    holds, Gradle is the one JVM client where adding us first is enough to enforce.
//	G2  Gradle, mavenCentral() first, ours second. PREDICTION: exit 0 and the gate is NEVER
//	    asked for the artifact -- the control that shows G1's result is order, not Gradle.
//
// What would change the docs the other way: P1 failing the build (then a POM repository does
// enforce); G1 exiting 0 (then Gradle falls through a 403 as Maven does, and only an init
// script that clears the repositories enforces).
// Confidence: G2 high. G1 moderate -- I have maven_test.go's measurement that Gradle aborts on
// the first 403 when we are the ONLY repository, which is not the same as aborting with a
// second repository available. P1 moderate, same unread-resolver caveat as before.

// INCREMENT 2 RESULTS (measured 2026-09-21; Maven 3.9 / Temurin 21, Gradle 8.14.5; legs in
// ingress_declared_repo_test.go). TWO OF THREE HELD.
//
//	P1  HELD. A POM-declared repository IS consulted before central: the gate logged two blocks
//	    for the artifact (pom, then jar), Maven treated each 403 as "not here", fetched both
//	    from central, exited 0. Visibility, no enforcement.
//	G1  FALSIFIED. Gradle asked us first, was answered 403 on the .pom (read off the terminator's
//	    access log, not inferred), and resolved the artifact from mavenCentral() anyway, exit 0.
//	    Gradle does NOT stop on a 403 when another repository is declared. maven_test.go's
//	    "Gradle aborts on the first 403" is true only because we were the ONLY repository there.
//	G2  HELD. With central declared first the gate is never asked.
//
// Added after the run, not pre-registered: G3, Gradle with ours as the ONLY repository against
// the same blocking gate fails the build -- the enforcing form, so the docs can name one.
//
// What I got wrong in G1: I carried a measurement ("aborts on the first 403") across a changed
// condition (one repository -> two) and flagged the gap in the confidence note without
// resolving it. The pattern across both increments is now plain: for every JVM client measured,
// a repository ADDED beside central never enforces, whatever the order; only a form that
// leaves NO other repository does (mirrorOf=*, or a sole repository).
// NOT MEASURED: whether a status other than 403 would make either client stop.

// mavenHTTPSArtifact is small and is the artifact tls_trust_maven_test.go already resolves,
// so this file adds no new upstream dependency.
const mavenHTTPSArtifact = "org.apache.commons:commons-lang3:3.14.0"
const mavenHTTPSName = "commons-lang3"

// mavenAbsentArtifact exists on no repository. It is the diagnostic for "was the flag even
// parsed": Maven only falls through to a second repository when the first cannot answer.
const mavenAbsentArtifact = "com.yellowjack.rig:not-on-central:1.0.0"
const mavenAbsentName = "not-on-central"

// mavenBlockingEnv blocks every scored artifact deterministically and offline: the stub
// scorer asserts a flat 7.5 and the threshold is above it.
func mavenBlockingEnv() map[string]string {
	e := onboardingEnv("maven")
	e["FW_SCORE_THRESHOLD"] = "9.9"
	return e
}

// mvnOverHTTPS runs `mvn dependency:get` with the rig CA imported into the JVM's own
// truststore (keytool -cacerts), the trust form tls_trust_maven_test.go measured. settings
// is the WHOLE global settings.xml; mvnArgs is appended to the command line. The script
// reports whether commons-lang3's jar landed in the throwaway local repository and which
// repository the resolver recorded it came from, because an exit code cannot tell
// "fetched through us" from "fetched from central".
//
// m2vol is a named docker volume holding the local repository, shared by every leg. Without
// it each leg re-downloads Maven's whole plugin tree (2-4 minutes, four times over), which
// is CI time spent measuring nothing. Sharing it is only sound because of two things the
// script does: it DELETES the artifact under test first, so no leg can be satisfied from
// the cache; and the mirror is given the id "central", because the resolver records which
// repository id each cached file came from and refuses to reuse a file for a different id
// -- under any other mirror id the whole tree would be fetched again through the gate.
// Every leg still asserts contact (or its measured absence) for the artifact itself.
func mvnOverHTTPS(t *testing.T, f *tlsFront, m2vol, settings, artifact, mvnArgs string) (int, string) {
	t.Helper()
	script := `printf '%s' "$YJ_CA" > /ca.pem; rm -rf /tmp/m2/org/apache/commons/commons-lang3 /tmp/m2/com/yellowjack; ` +
		`keytool -importcert -noprompt -cacerts -storepass changeit -alias yjrig -file /ca.pem >/dev/null 2>&1 || echo KEYTOOL_FAILED; ` +
		`printf '%s' "$YJ_SETTINGS" > /tmp/settings.xml; ` +
		`mvn -B -gs /tmp/settings.xml -Dmaven.repo.local=/tmp/m2 ` +
		`org.apache.maven.plugins:maven-dependency-plugin:3.6.1:get ` +
		`-Dartifact=` + artifact + ` -Dtransitive=false ` + mvnArgs + `; rc=$?; ` +
		`if ls /tmp/m2/org/apache/commons/commons-lang3/3.14.0/*.jar >/dev/null 2>&1; then echo JAR_PRESENT; else echo JAR_ABSENT; fi; ` +
		`echo "--- where the jar came from ---"; cat /tmp/m2/org/apache/commons/commons-lang3/3.14.0/_remote.repositories 2>/dev/null; ` +
		`exit $rc`
	code, out := runClient(t, "docker", "run", "--rm", "-w", "/work",
		"--add-host", "host.docker.internal:host-gateway",
		"-v", m2vol+":/tmp/m2",
		"-e", "YJ_CA="+string(f.caPEM), "-e", "YJ_SETTINGS="+settings,
		mavenImage, "sh", "-c", script)
	if strings.Contains(out, "KEYTOOL_FAILED") {
		t.Fatalf("keytool could not import the rig CA, so nothing below measures Maven.\n%s", tail(out, 15))
	}
	return code, out
}

// gateJudged returns the gate's decisions that name pkg.
func gateJudged(fw *firewall, pkg string) (allowed, blocked int) {
	for _, d := range fw.decisions() {
		if !strings.Contains(d.pkg, pkg) {
			continue
		}
		if d.allowed {
			allowed++
		} else {
			blocked++
		}
	}
	return
}

func blockingGateBehindFront(t *testing.T, bin string) (*firewall, *tlsFront) {
	t.Helper()
	tlsPort := freePort(t)
	env := mavenBlockingEnv()
	env["FW_PUBLIC_URL"] = fmt.Sprintf("https://%s:%d", ingressName, tlsPort)
	fw := startFirewall(t, bin, env)
	return fw, startTLSFront(t, tlsPort, fw.port)
}

// newM2Volume names a throwaway docker volume for the shared local repository and removes
// it when the test ends. See mvnOverHTTPS for why sharing it is sound.
func newM2Volume(t *testing.T) string {
	t.Helper()
	vol := fmt.Sprintf("yj-ingress-m2-%d", freePort(t)) // a free port is a cheap unique suffix
	_ = exec.Command("docker", "volume", "rm", "-f", vol).Run()
	t.Cleanup(func() { _ = exec.Command("docker", "volume", "rm", "-f", vol).Run() })
	return vol
}

func TestMavenBehindATLSTerminator(t *testing.T) {
	bin := buildFirewall(t)
	m2vol := newM2Volume(t)
	flag := func(f *tlsFront) string {
		return "-DremoteRepositories=yj::default::" + f.url() + "/"
	}
	mirror := func(f *tlsFront) string {
		return fmt.Sprintf(`<settings><mirrors><mirror><id>central</id><url>%s/</url><mirrorOf>*</mirrorOf></mirror></mirrors></settings>`, f.url())
	}

	// MEASURED (M1 falsified, M2 re-read): one https repository flag does not route the
	// artifact through the gate AT ALL. Maven consults central first, central has it, and
	// we are never asked -- so a BLOCKING gate is the honest stack to show it on: the
	// install succeeds and the gate has no decision to show for it. Not "refused, then
	// fetched elsewhere" (what M2 predicted); never consulted.
	//
	// If a later Maven or plugin consults the added repository first, this reddens. Then
	// re-measure docs/SETUP.md; do not loosen the leg.
	t.Run("one repository flag: a blocking gate is never even asked, and the artifact arrives from central", func(t *testing.T) {
		fw, front := blockingGateBehindFront(t, bin)
		defer fw.stop()
		code, out := mvnOverHTTPS(t, front, m2vol, "<settings/>", mavenHTTPSArtifact, flag(front))
		allowed, blocked := gateJudged(fw, mavenHTTPSName)
		t.Logf("measured: mvn exit=%d, gate decisions for %s: allowed=%d blocked=%d, jar recorded from central=%v",
			code, mavenHTTPSName, allowed, blocked, strings.Contains(out, ".jar>central="))
		if code != 0 || !strings.Contains(out, "JAR_PRESENT") {
			t.Fatalf("mvn did NOT obtain %s with one repository flag against a blocking gate (exit %d). "+
				"Then the flag DOES put us in the path; re-measure and correct docs/SETUP.md.\n%s\n--- gate ---\n%s",
				mavenHTTPSName, code, tail(out, 25), tail(fw.log.String(), 15))
		}
		if allowed+blocked != 0 {
			t.Fatalf("the gate WAS consulted for %s (allowed=%d blocked=%d) and mvn still got the jar. "+
				"That is the refused-then-fetched-elsewhere shape, not the never-asked one the docs state.\n%s",
				mavenHTTPSName, allowed, blocked, tail(fw.log.String(), 15))
		}
		if !strings.Contains(out, ".jar>central=") {
			t.Errorf("the resolver did not record central as the jar's source, so WHERE it came from is unproven.\n%s", tail(out, 12))
		}
	})

	// THE DIAGNOSTIC that makes the leg above a finding rather than a typo: an artifact no
	// repository has. Central cannot answer, so Maven falls through to the added repository
	// -- and the request must then arrive at the terminator AND the gate. Without this, "the
	// gate was never asked" is equally well explained by a flag Maven silently ignored.
	t.Run("the flag IS live: an artifact central lacks does reach the gate", func(t *testing.T) {
		fw, front := gateBehindFront(t, bin, "maven", true)
		defer fw.stop()
		code, out := mvnOverHTTPS(t, front, m2vol, "<settings/>", mavenAbsentArtifact, flag(front))
		if code == 0 {
			t.Fatalf("mvn resolved an artifact that exists nowhere (exit 0); the rig is broken.\n%s", tail(out, 15))
		}
		if nl := front.logs(); !strings.Contains(nl, mavenAbsentName) {
			t.Fatalf("no request for %s reached the terminator. Then the flag was NOT in effect, and the "+
				"leg above proves nothing about ordering.\n--- mvn ---\n%s\n--- nginx ---\n%s",
				mavenAbsentName, tail(out, 25), tail(nl, 12))
		}
		if !strings.Contains(fw.log.String(), mavenAbsentName) {
			t.Errorf("the terminator saw %s but the gate's log does not name it.\n%s", mavenAbsentName, tail(fw.log.String(), 15))
		}
	})

	// The mirror, positive control first: it must WORK before its failure can mean anything.
	t.Run("a mirrorOf=* settings.xml over https installs through the gate", func(t *testing.T) {
		fw, front := gateBehindFront(t, bin, "maven", true)
		defer fw.stop()
		code, out := mvnOverHTTPS(t, front, m2vol, mirror(front), mavenHTTPSArtifact, "")
		if code != 0 || !strings.Contains(out, "JAR_PRESENT") {
			t.Fatalf("mvn could not install through an https mirror (exit %d).\n%s\n--- nginx ---\n%s\n--- gate ---\n%s",
				code, tail(out, 25), tail(front.logs(), 10), logAround(fw.log.String(), 20, mvnFailedArtifacts(out)...))
		}
		if a, _ := gateJudged(fw, mavenHTTPSName); a == 0 {
			t.Fatalf("mvn exited 0 but the gate never allowed %s: the mirror did not route it through us.\n%s",
				mavenHTTPSName, tail(fw.log.String(), 20))
		}
		if nl := front.logs(); !strings.Contains(nl, mavenHTTPSName+"-3.14.0.jar") {
			t.Errorf("no jar request in the terminator's access log.\n%s", tail(nl, 12))
		}
	})

	// M3 (held): identical mirror, a gate that blocks.
	t.Run("M3 the same mirror against a blocking gate fails the install", func(t *testing.T) {
		fw, front := blockingGateBehindFront(t, bin)
		defer fw.stop()
		code, out := mvnOverHTTPS(t, front, m2vol, mirror(front), mavenHTTPSArtifact, "")
		if _, b := gateJudged(fw, mavenHTTPSName); b == 0 {
			t.Fatalf("M3 is VOID: the gate logged no block for the artifact, so mvn's exit %d is not our doing.\n%s\n--- nginx ---\n%s",
				code, tail(out, 15), tail(front.logs(), 10))
		}
		if code == 0 || strings.Contains(out, "JAR_PRESENT") {
			t.Fatalf("M3: mvn obtained the artifact through a mirrorOf=* to a BLOCKING gate (exit %d). "+
				"Then the mirror does not enforce either.\n%s", code, tail(out, 25))
		}
	})
}
