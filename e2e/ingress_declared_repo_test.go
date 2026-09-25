//go:build e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
)

// Increment 2 of Maven-over-HTTPS: a repository DECLARED by the project (a POM's
// <repositories>, a Gradle repositories block) rather than passed as a flag. Predictions P1,
// G1 and G2 are pre-registered in the header of ingress_maven_test.go and were committed
// before this file existed. Every leg runs against a BLOCKING gate behind the terminator.

// declaredPOM is the smallest project that names us as a repository and depends on the
// artifact under test. Central is NOT mentioned: it arrives from Maven's super-POM, which is
// the situation every real project is in.
const declaredPOM = `<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>` +
	`<groupId>rig</groupId><artifactId>probe</artifactId><version>1</version>` +
	`<repositories><repository><id>yj</id><url>%s/</url></repository></repositories>` +
	`<dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.14.0</version></dependency></dependencies>` +
	`</project>`

// mvnResolveDeclared resolves declaredPOM's dependency with an EMPTY settings.xml, so the
// only thing pointing Maven at us is the project itself. Same trust form, same shared
// local-repository volume and same delete-the-artifact-first rule as mvnOverHTTPS.
func mvnResolveDeclared(t *testing.T, f *tlsFront, m2vol string) (int, string) {
	t.Helper()
	script := `printf '%s' "$YJ_CA" > /ca.pem; rm -rf /tmp/m2/org/apache/commons/commons-lang3; ` +
		`keytool -importcert -noprompt -cacerts -storepass changeit -alias yjrig -file /ca.pem >/dev/null 2>&1 || echo KEYTOOL_FAILED; ` +
		`printf '<settings/>' > /tmp/settings.xml; printf '%s' "$YJ_POM" > /work/pom.xml; ` +
		`mvn -B -gs /tmp/settings.xml -Dmaven.repo.local=/tmp/m2 ` +
		`org.apache.maven.plugins:maven-dependency-plugin:3.6.1:resolve; rc=$?; ` +
		`if ls /tmp/m2/org/apache/commons/commons-lang3/3.14.0/*.jar >/dev/null 2>&1; then echo JAR_PRESENT; else echo JAR_ABSENT; fi; ` +
		`echo "--- where the jar came from ---"; cat /tmp/m2/org/apache/commons/commons-lang3/3.14.0/_remote.repositories 2>/dev/null; ` +
		`exit $rc`
	code, out := runClient(t, "docker", "run", "--rm", "-w", "/work",
		"--add-host", "host.docker.internal:host-gateway",
		"-v", m2vol+":/tmp/m2",
		"-e", "YJ_CA="+string(f.caPEM), "-e", "YJ_POM="+fmt.Sprintf(declaredPOM, f.url()),
		mavenImage, "sh", "-c", script)
	if strings.Contains(out, "KEYTOOL_FAILED") {
		t.Fatalf("keytool could not import the rig CA, so nothing below measures Maven.\n%s", tail(out, 15))
	}
	return code, out
}

// gradleImage is the image maven_test.go's Gradle leg already uses.
const gradleImage = "gradle:8-jdk21"

// gradleFetch resolves the artifact with a real Gradle whose build file declares the given
// repositories block. The `fetch` task resolves FILES, because Gradle's `dependencies` report
// prints FAILED and still exits 0 -- an exit code that cannot fail is not an instrument.
func gradleFetch(t *testing.T, f *tlsFront, repositories string) (int, string) {
	t.Helper()
	build := `plugins { id("java") }
repositories { ` + repositories + ` }
dependencies { implementation("` + mavenHTTPSArtifact + `") }
tasks.register("fetch") { doLast { configurations.compileClasspath.files.each { println("GOT " + it.name) } } }
`
	script := `printf '%s' "$YJ_CA" > /ca.pem; ` +
		`keytool -importcert -noprompt -cacerts -storepass changeit -alias yjrig -file /ca.pem >/dev/null 2>&1 || echo KEYTOOL_FAILED; ` +
		`mkdir -p /w && cd /w && printf '%s' "$YJ_BUILD" > build.gradle && ` +
		`printf 'rootProject.name = "probe"\n' > settings.gradle && ` +
		`gradle --no-daemon -q fetch`
	code, out := runClient(t, "docker", "run", "--rm",
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "YJ_CA="+string(f.caPEM), "-e", "YJ_BUILD="+build,
		"-e", "GRADLE_USER_HOME=/w/.gradle", // throwaway cache: never serve from a warm one
		gradleImage, "sh", "-c", script)
	if strings.Contains(out, "KEYTOOL_FAILED") {
		t.Fatalf("keytool could not import the rig CA, so nothing below measures Gradle.\n%s", tail(out, 15))
	}
	return code, out
}

func TestDeclaredRepositoryBehindATLSTerminator(t *testing.T) {
	bin := buildFirewall(t)
	m2vol := newM2Volume(t)
	gotJar := func(out string) bool { return strings.Contains(out, "GOT "+mavenHTTPSName) }
	ours := func(f *tlsFront) string { return fmt.Sprintf(`maven { url = uri("%s/") }`, f.url()) }

	t.Run("P1 a POM-declared repository against a blocking gate", func(t *testing.T) {
		fw, front := blockingGateBehindFront(t, bin)
		defer fw.stop()
		code, out := mvnResolveDeclared(t, front, m2vol)
		allowed, blocked := gateJudged(fw, mavenHTTPSName)
		t.Logf("P1 measured: mvn exit=%d, gate decisions for %s: allowed=%d blocked=%d, jar present=%v, recorded from central=%v",
			code, mavenHTTPSName, allowed, blocked, strings.Contains(out, "JAR_PRESENT"), strings.Contains(out, ".jar>central="))
		if blocked == 0 {
			t.Fatalf("P1: the gate logged no block for %s, so a POM-declared repository was NOT consulted "+
				"(exit %d). That is increment 1's never-asked shape, not the one predicted.\n%s\n--- gate ---\n%s",
				mavenHTTPSName, code, tail(out, 20), tail(fw.log.String(), 15))
		}
		if code != 0 || !strings.Contains(out, "JAR_PRESENT") {
			t.Fatalf("P1 PREDICTION FALSIFIED: the gate blocked %s and mvn did NOT get it elsewhere (exit %d). "+
				"Then a POM-declared repository DOES enforce; correct docs/SETUP.md.\n%s", mavenHTTPSName, code, tail(out, 25))
		}
	})

	// G1 WAS FALSIFIED. The prediction was that Gradle stops on our 403; measured, it treats the
	// refusal as "not in this repository" and resolves from the next one. The leg pins the
	// measured fact, and asserts the STATUS the client was given, so "Gradle fell through a
	// 403" is read off the terminator's log rather than assumed from the gate's decision.
	t.Run("G1 Gradle with our repository declared first: refused by us with a 403, resolved from central anyway", func(t *testing.T) {
		fw, front := blockingGateBehindFront(t, bin)
		defer fw.stop()
		code, out := gradleFetch(t, front, ours(front)+"; mavenCentral()")
		allowed, blocked := gateJudged(fw, mavenHTTPSName)
		var answered []string
		for _, l := range strings.Split(front.logs(), "\n") {
			if strings.Contains(l, mavenHTTPSName) {
				answered = append(answered, l)
			}
		}
		told := strings.Join(answered, "\n")
		t.Logf("G1 measured: gradle exit=%d, gate decisions for %s: allowed=%d blocked=%d, jar resolved=%v\n--- what the terminator answered ---\n%s",
			code, mavenHTTPSName, allowed, blocked, gotJar(out), told)
		if blocked == 0 {
			t.Fatalf("G1 is VOID: the gate logged no block for %s, so gradle's exit %d says nothing about "+
				"enforcement.\n%s\n--- nginx ---\n%s", mavenHTTPSName, code, tail(out, 20), tail(front.logs(), 10))
		}
		if !strings.Contains(told, " 403 ") {
			t.Fatalf("G1: the gate logged a block but the terminator shows no 403 for %s, so what Gradle was "+
				"actually TOLD is unproven.\n%s", mavenHTTPSName, told)
		}
		if code != 0 || !gotJar(out) {
			t.Fatalf("Gradle did NOT resolve %s past our 403 (exit %d). Then declaring us first DOES enforce; "+
				"re-measure and correct docs/SETUP.md rather than this leg.\n%s", mavenHTTPSName, code, tail(out, 25))
		}
	})

	// POST-HOC, not pre-registered: the form that does enforce, so the docs can name one. With
	// us as the ONLY repository there is nowhere to fall through to. maven_test.go measured this
	// over plain HTTP with an init script; this is the same fact over https, in a build file.
	t.Run("G3 Gradle with ours as the ONLY repository: the block fails the build", func(t *testing.T) {
		fw, front := blockingGateBehindFront(t, bin)
		defer fw.stop()
		code, out := gradleFetch(t, front, ours(front))
		if _, blocked := gateJudged(fw, mavenHTTPSName); blocked == 0 {
			t.Fatalf("G3 is VOID: the gate logged no block for %s (exit %d).\n%s\n--- nginx ---\n%s",
				mavenHTTPSName, code, tail(out, 20), tail(front.logs(), 10))
		}
		if code == 0 || gotJar(out) {
			t.Fatalf("G3: Gradle resolved %s with a blocking gate as its only repository (exit %d).\n%s",
				mavenHTTPSName, code, tail(out, 25))
		}
	})

	t.Run("G2 Gradle with mavenCentral first: the blocking gate is never asked", func(t *testing.T) {
		fw, front := blockingGateBehindFront(t, bin)
		defer fw.stop()
		code, out := gradleFetch(t, front, "mavenCentral(); "+ours(front))
		allowed, blocked := gateJudged(fw, mavenHTTPSName)
		t.Logf("G2 measured: gradle exit=%d, gate decisions for %s: allowed=%d blocked=%d, jar resolved=%v",
			code, mavenHTTPSName, allowed, blocked, gotJar(out))
		if code != 0 || !gotJar(out) {
			t.Fatalf("G2: Gradle did not resolve %s with central declared first (exit %d).\n%s", mavenHTTPSName, code, tail(out, 25))
		}
		if allowed+blocked != 0 {
			t.Fatalf("G2 PREDICTION FALSIFIED: the gate WAS consulted (allowed=%d blocked=%d) with central "+
				"declared first.\n%s", allowed, blocked, tail(fw.log.String(), 15))
		}
	})
}
