//go:build e2e

package e2e

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// mavenMirrorSettings is a global settings.xml whose sole job is to force EVERY
// maven resolve through our firewall. Two traps are baked in here:
//
//   - Maven 3.8.1+ ships a default "maven-default-http-blocker" mirror that
//     refuses any external:http:* URL. Passing this file with -gs REPLACES the
//     global settings (blocker included), so a plain-HTTP proxy becomes reachable.
//     A plain -DremoteRepositories=http://… does NOT work — it silently hits the
//     blocker and never reaches the firewall (empty decision log).
//   - <mirrorOf>*</mirrorOf> captures central AND every parent-POM lookup, so the
//     firewall sees the whole resolution, including the parent chain we rely on to
//     recover SCM for artifacts (like Guava) that inherit it.
const mavenMirrorSettings = `<settings>
  <mirrors>
    <mirror>
      <id>yellowjack</id>
      <name>yellowjack-firewall</name>
      <url>http://host.docker.internal:%d/</url>
      <mirrorOf>*</mirrorOf>
    </mirror>
  </mirrors>
</settings>`

// runMvnGet resolves a single artifact (and its POM/parent chain) through the
// firewall using `mvn dependency:get`. The settings.xml is written inside the
// container from an env var (no host-path mount, so it works the same on Windows
// and Linux CI) and passed via -gs. Returns mvn's exit code and combined output.
func runMvnGet(t *testing.T, port int, artifact string) (int, string) {
	t.Helper()
	settings := fmt.Sprintf(mavenMirrorSettings, port)
	// Write settings from $YJ_SETTINGS, then resolve. -Dmaven.repo.local keeps a
	// throwaway local repo so nothing is served from a warm cache.
	script := `printf '%s' "$YJ_SETTINGS" > /tmp/settings.xml && ` +
		`mvn -q -gs /tmp/settings.xml -Dmaven.repo.local=/tmp/m2 ` +
		`org.apache.maven.plugins:maven-dependency-plugin:3.6.1:get ` +
		`-Dartifact=` + artifact
	cmd := exec.Command("docker", "run", "--rm",
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "YJ_SETTINGS="+settings,
		"maven:3.9-eclipse-temurin-21",
		"sh", "-c", script,
	)
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatalf("could not run docker (is it installed/running?): %v\n%s", err, out)
	}
	return 0, string(out)
}

// TestMavenEndToEnd resolves Guava through the firewall. Guava is the deliberate
// choice: its own POM carries no <scm>, so a correct firewall must walk the
// <parent> chain to recover github.com/google/guava — the exact case the maven
// parent-POM feature exists for. Two policies isolate behavior:
//   - permissive (threshold 0, allow): the resolve SUCCEEDS through the gate.
//   - fail-closed (threshold 9.9, block): with an unreachable threshold the
//     scored repo is BLOCKED, so mvn fails — proving the score was obtained,
//     which in turn proves the parent chain resolved a repo to score.
//
// NOTE: this only runs green on an INTEGRATED tree that includes the maven
// ecosystem (the parent-POM MR); on a plain e2e-suite checkout the firewall has
// no "maven" ecosystem and startup fails fast — which is the documented
// "per-branch e2e is a category error" case.
func TestMavenEndToEnd(t *testing.T) {
	bin := buildFirewall(t)
	const guava = "com.google.guava:guava:33.0.0-jre"

	t.Run("permissive_allows_resolve", func(t *testing.T) {
		fw := startFirewall(t, bin, map[string]string{
			"FW_ECOSYSTEM":       "maven",
			"FW_SCORECARD_MODE":  "api",
			"FW_SCORE_THRESHOLD": "0",
			// BOTH fail-open knobs, because as of D36 there are two independent
			// fail-closed postures and "permissive" has to relax both.
			"FW_UNSCORABLE_POLICY": "allow",
			// Maven needs this far more than npm does, and the reason is worth
			// recording: deps.dev's package->SOURCE_REPO coverage for Maven is patchy
			// in a way it is not for npm. Probed live 2026-07-26 — guava,
			// jackson-databind and junit are mapped, but `commons-lang3` and
			// `org.apache.maven.plugins:maven-dependency-plugin` return 200 with NO
			// SOURCE_REPO relation at all. Since this leg uses <mirrorOf>*</mirrorOf>,
			// maven's own plugin tree crosses the gate, so under the fail-closed
			// default mvn cannot even bootstrap: dependency-plugin is durably
			// unverified and blocked. That is D36 behaving as ruled, not a defect —
			// but it makes the day-one block rate for Maven much higher than for npm,
			// which is flagged as a project decision in D42 / issue #18's MR.
			"FW_UNVERIFIED_POLICY": "open-with-visibility",
		})
		code, out := runMvnGet(t, fw.port, guava)
		if code != 0 {
			// Anchor the dump on the artifacts MAVEN said it could not read, rather than
			// on the tail of the run. In #68 this leg failed on commons-lang and
			// velocity-tools and neither appeared in the 25 lines printed, which left
			// "the proxy blocked them" and "the proxy never saw them" indistinguishable
			// from the evidence (#75).
			anchors := append(mvnFailedArtifacts(out), "guava")
			t.Fatalf("permissive `mvn get guava` failed (exit %d)\n%s\n--- firewall ---\n%s",
				code, tail(out, 20), logAround(fw.log.String(), 40, anchors...))
		}
		if fw.allowedCount() == 0 {
			t.Errorf("expected allow decisions through the gate, saw none\n%s", fw.log.String())
		}
	})

	t.Run("failclosed_blocks_scored_artifact", func(t *testing.T) {
		fw := startFirewall(t, bin, map[string]string{
			"FW_ECOSYSTEM":         "maven",
			"FW_SCORECARD_MODE":    "api",
			"FW_SCORE_THRESHOLD":   "9.9",
			"FW_UNSCORABLE_POLICY": "block",
		})
		code, _ := runMvnGet(t, fw.port, guava)
		if code == 0 {
			t.Fatalf("fail-closed `mvn get guava` unexpectedly succeeded\n--- firewall ---\n%s",
				logAround(fw.log.String(), 30))
		}
		if fw.blockedCount() == 0 {
			t.Errorf("expected at least one block decision, saw none\n%s", fw.log.String())
		}
	})
}

// ───────────────────────── Gradle Module Metadata (issue #56) ─────────────────────────

// gradleInitScript forces every Gradle repository through the firewall — the Gradle
// equivalent of the mirror settings.xml above. `allowInsecureProtocol` is required
// because the e2e firewall speaks plain HTTP; without it Gradle refuses the repository
// outright and the resolve never reaches us, which would look like a clean pass.
const gradleInitScript = `
allprojects {
  repositories {
    clear()
    maven { url = uri("http://host.docker.internal:%d/"); allowInsecureProtocol = true }
  }
}
`

// runGradleResolve resolves one dependency through the firewall with a real Gradle.
//
// Gradle is the client that matters for issue #56: from Gradle 6 onward it requests
// GRADLE MODULE METADATA — "<artifact>-<version>.module" — for dependencies it
// resolves. That extension sat outside Maven's old four-extension allowlist, so it was
// relayed ungated. Everything is written inside the container (no host mount) so this
// behaves the same on the Windows dev host and on Linux CI — the same reason runMvnGet
// does it that way.
func runGradleResolve(t *testing.T, port int, dep string) (int, string) {
	t.Helper()
	init := fmt.Sprintf(gradleInitScript, port)
	script := `mkdir -p /w && cd /w && ` +
		`printf '%s' "$YJ_INIT" > init.gradle && ` +
		`printf 'plugins { id("java") }\ndependencies { implementation("` + dep + `") }\n' > build.gradle && ` +
		`printf 'rootProject.name = "probe"\n' > settings.gradle && ` +
		`gradle --no-daemon --init-script init.gradle -q dependencies --configuration compileClasspath`
	cmd := exec.Command("docker", "run", "--rm",
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "YJ_INIT="+init,
		"-e", "GRADLE_USER_HOME=/w/.gradle", // throwaway cache: never serve from a warm one
		"gradle:8-jdk21",
		"sh", "-c", script,
	)
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatalf("could not run docker (is it installed/running?): %v\n%s", err, out)
	}
	return 0, string(out)
}

// moduleRelayed reports whether the firewall FORWARDED a .module request upstream.
// relay() logs "GET /path -> <upstream>" for everything it forwards, so this is the
// signal that artifact bytes left the repository.
func moduleRelayed(logs string) (string, bool) {
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, ".module") && strings.Contains(line, " -> http") {
			return line, true
		}
	}
	return "", false
}

// TestMavenGradleFetchesModuleMetadata is the real-client leg for issue #56. It proves
// two things a unit test cannot, and — importantly — it does NOT claim to prove a third.
//
// WHAT IT PROVES
//  1. The premise of issue #56 is real: a genuine Gradle resolve requests Gradle Module
//     Metadata ("<artifact>-<version>.module"), an extension that sat outside Maven's
//     old four-extension allowlist and was therefore relayed ungated. Verified
//     first-hand here rather than cited.
//  2. Gating .module gates it without BREAKING it — an allowed dependency still
//     resolves through a firewall with the byte gate enforcing. Inverting a gate's
//     default is easy to overdo, and this is the leg that catches it.
//
// WHAT IT DOES NOT PROVE, AND WHY THE OBVIOUS VERSIONS OF THAT DON'T WORK
// It does not detect the bypass itself. Two attempts were made and both produced tests
// that could not fail; they are recorded so the third person does not try them again:
//
//   - "a .module relay line means it was ungated" — FALSE. The firewall logs
//     "GET /path -> <upstream>" for everything it forwards, including requests it
//     evaluated and ALLOWED. This version reported "issue #56 REGRESSED" against a
//     working fix.
//   - "require a decision line for the package the .module belongs to" — VACUOUS.
//     Gradle also fetches that package's .pom, which was gated even under the old
//     allowlist, so the decision line exists either way. Reverting the parser and
//     re-running gave a clean PASS; the POM's decision masked the ungated .module.
//   - "run it blocking, and assert no .module is ever forwarded" — ALSO VACUOUS, and
//     measured: with every package denied, Gradle aborts on the first 403 (the metadata
//     or POM) and never requests a .module at all. Zero .module lines appear in the log
//     whatever the parser does, so the assertion passes for free.
//     [SCOPE, added 2026-09-21: true here because we are the ONLY repository. With a second
//     repository declared, Gradle falls through our 403 -- ingress_declared_repo_test.go G1.]
//
// The bypass detection therefore lives in the unit twin, ../maven_bytegate_test.go,
// where a fake upstream RECORDS which paths it was asked for — that rig can tell
// "refused" from "never requested", which no log-only e2e assertion here can. Its
// negative control is proven: reverting the parser fails 20 subtests there.
//
// VERIFIED FAILURE MODES of this test, so its worth is known rather than assumed:
// it goes red when the resolve genuinely fails (checked by pointing it at a blocking
// threshold — both assertions fire) and when Gradle stops requesting .module. It does
// NOT go red on the parser regression itself. Note that over-gating alone does not
// trip it either: under a permissive config an over-gated file is simply ALLOWED, so
// the resolve still succeeds. That is a real limit of a permissive compatibility leg,
// not an oversight.
func TestMavenGradleFetchesModuleMetadata(t *testing.T) {
	bin := buildFirewall(t)
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":         "maven",
		"FW_UPSTREAM":          "https://repo.maven.apache.org/maven2",
		"FW_SCORECARD_MODE":    "stub",
		"FW_SCORE_THRESHOLD":   "0", // allow everything: this leg tests the path, not the verdict
		"FW_UNSCORABLE_POLICY": "allow",
		"FW_UNVERIFIED_POLICY": "open-with-visibility",
		"FW_BYTE_GATE":         "enforce", // gate ON, verdict ALLOW — real traffic must flow
	})

	code, out := runGradleResolve(t, fw.port, "com.google.guava:guava:33.0.0-jre")
	logs := fw.log.String()

	// Anti-vacuity: Gradle must actually have resolved through the firewall.
	if !strings.Contains(logs, "guava") {
		t.Fatalf("HARNESS: the firewall never saw a guava request, so Gradle did not resolve through it (exit %d)\n%s\n--- firewall ---\n%s",
			code, tail(out, 25), tail(logs, 25))
	}

	if _, saw := moduleRelayed(logs); !saw {
		t.Errorf("this Gradle requested no .module at all — issue #56's premise (Gradle 6+ fetches Module Metadata for its dependencies) no longer holds for this client, so the unit coverage of that extension is now testing a path nothing walks\n--- firewall ---\n%s",
			tail(logs, 25))
	}

	// COMPATIBILITY: the whole point of gating .module is to gate it, not break it.
	if code != 0 {
		t.Errorf("the Gradle resolve FAILED against a permissive firewall (exit %d) — gating Module Metadata must not break a resolve that should succeed\n%s",
			code, tail(out, 30))
	}
}

// mvnFailedArtifacts pulls the artifacts Maven reported it could not resolve out of its
// own output, so a failure dump can be anchored on them (#75). Maven names them as
// "Failed to read artifact descriptor for group:artifact:jar:version"; the artifactId is
// returned because that is what appears in the proxy's request paths.
func mvnFailedArtifacts(out string) []string {
	var found []string
	seen := map[string]bool{}
	for _, m := range mvnFailedRe.FindAllStringSubmatch(out, -1) {
		if artifactID := m[2]; !seen[artifactID] {
			seen[artifactID] = true
			found = append(found, artifactID)
		}
	}
	return found
}

var mvnFailedRe = regexp.MustCompile(`(?:Failed to read artifact descriptor for|Could not (?:find|resolve) artifact) ([^\s:]+):([^\s:]+)`)
