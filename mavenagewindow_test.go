package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The release window (#26 cooldown, D22 age floor) applied to MAVEN.
//
// Measured 2026-09-12 on origin/main: `maven.go` and `oci.go` referenced the window
// zero times. It was consulted only from the metadata-REWRITE path, which exists for
// npm and PyPI, so the knob was an npm/PyPI control while the config documented it as
// a firewall-wide one. E25's pattern in a second control -- "four ecosystems" true of
// the CODE and false of the EFFECT.
//
// Every test here uses a threshold the stub score CLEARS, so the package would be
// ALLOWED on every other ground. A refusal can therefore only be the release window,
// and an allow is proof the window did not fire. Without that isolation these tests
// would pass just as happily against a gate that blocks everything.

const (
	ageGroupPath = "com/example/widget"
	ageArtifact  = "widget"
	ageVersion   = "2.1.0"
	ageBytes     = "MAVEN-ARTIFACT-BYTES"
)

// mavenAgeUpstream is a fake Maven repository that dates artifacts with a
// Last-Modified header and COUNTS the HEAD probes the window makes. The count is what
// makes the cost claim ("a deployment that has not turned the window on pays nothing")
// an assertion instead of a sentence in a comment.
type mavenAgeUpstream struct {
	*httptest.Server
	mu sync.Mutex
	// lastModified is the header value served for artifact paths. Empty means the
	// repository names no time -- the fail-closed case.
	lastModified string
	// artifactStatus, when non-zero, is returned for artifact HEADs instead of 200.
	artifactStatus int
	heads          int
	gets           int
}

func newMavenAgeUpstream(published time.Time) *mavenAgeUpstream {
	u := &mavenAgeUpstream{}
	if !published.IsZero() {
		u.lastModified = published.UTC().Format(http.TimeFormat)
	}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isMeta := strings.HasSuffix(r.URL.Path, "/maven-metadata.xml")
		isPOM := strings.HasSuffix(r.URL.Path, ".pom")

		u.mu.Lock()
		if r.Method == http.MethodHead {
			u.heads++
		} else {
			u.gets++
		}
		status := u.artifactStatus
		lm := u.lastModified
		u.mu.Unlock()

		// The probe only ever HEADs a gated artifact path. Faults are injected there
		// and nowhere else, so a broken probe cannot be mistaken for broken scoring.
		if r.Method == http.MethodHead && !isMeta && !isPOM && status != 0 {
			w.WriteHeader(status)
			return
		}
		if lm != "" && !isMeta {
			w.Header().Set("Last-Modified", lm)
		}
		switch {
		case isMeta:
			fmt.Fprintf(w, `<metadata><versioning><release>%s</release></versioning></metadata>`, ageVersion)
		case isPOM:
			fmt.Fprint(w, `<project><scm><url>https://github.com/example/widget</url></scm></project>`)
		default:
			fmt.Fprint(w, ageBytes)
		}
	}))
	return u
}

func (u *mavenAgeUpstream) counts() (heads, gets int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.heads, u.gets
}

func (u *mavenAgeUpstream) setArtifactStatus(s int) {
	u.mu.Lock()
	u.artifactStatus = s
	u.mu.Unlock()
}

// newAgeWindowProxy builds a maven proxy whose score threshold the stub score (7.5)
// CLEARS, so the release window is the only thing that can refuse.
func newAgeWindowProxy(t *testing.T, up *httptest.Server, minDays, maxDays int) *proxyServer {
	t.Helper()
	return newTestProxy(t, up, func(c *Config) {
		c.Ecosystem = "maven"
		c.ScoreThreshold = 1.0 // stub scores 7.5 -> comfortably allowed
		c.MinReleaseAgeDays = minDays
		c.MaxReleaseAgeDays = maxDays
	})
}

func ageArtifactPath() string {
	return fmt.Sprintf("/%s/%s/%s-%s.jar", ageGroupPath, ageVersion, ageArtifact, ageVersion)
}

// ── 1. THE ISSUE ITSELF: a brand-new Maven release is held back ──────────────

func TestMavenCooldownRefusesAFreshRelease(t *testing.T) {
	up := newMavenAgeUpstream(time.Now().Add(-2 * 24 * time.Hour)) // published 2 days ago
	defer up.Close()
	p := newAgeWindowProxy(t, up.Server, 7, 0) // 7-day cooldown

	code, body := get(t, p, ageArtifactPath())

	if code == http.StatusOK {
		t.Fatalf("a release 2 days old was served under a 7-day cooldown (status %d)", code)
	}
	if strings.Contains(body, ageBytes) {
		t.Fatal("the artifact BYTES were delivered despite the cooldown refusing it")
	}
	if !strings.Contains(body, "cooldown") {
		t.Errorf("the refusal does not say it was the cooldown, so a developer cannot tell it "+
			"will clear by itself; body = %q", body)
	}
}

// ── 2. THE ALLOW SIDE. Without this the test above passes against a gate that ──
//      refuses everything, which is the failure mode this file exists to avoid.

func TestMavenCooldownAllowsAnAgedRelease(t *testing.T) {
	up := newMavenAgeUpstream(time.Now().Add(-90 * 24 * time.Hour)) // published 90 days ago
	defer up.Close()
	p := newAgeWindowProxy(t, up.Server, 7, 0)

	code, body := get(t, p, ageArtifactPath())

	if code != http.StatusOK {
		t.Fatalf("a 90-day-old release was refused under a 7-day cooldown: status %d, body %q", code, body)
	}
	if !strings.Contains(body, ageBytes) {
		t.Fatalf("allowed, but the artifact bytes did not arrive; body = %q", body)
	}
}

// ── 3. The age floor is the same window's other edge (D22) ───────────────────

func TestMavenAgeFloorRefusesAnAncientRelease(t *testing.T) {
	up := newMavenAgeUpstream(time.Now().Add(-800 * 24 * time.Hour))
	defer up.Close()
	p := newAgeWindowProxy(t, up.Server, 0, 365) // nothing older than a year

	code, body := get(t, p, ageArtifactPath())

	if code == http.StatusOK {
		t.Fatalf("an 800-day-old release was served under a 365-day age floor (status %d)", code)
	}
	if !strings.Contains(body, "age floor") {
		t.Errorf("the refusal does not name the age floor, so it reads like the cooldown "+
			"(which would clear on its own, and this one never will); body = %q", body)
	}
}

// ── 4. FAIL CLOSED on an undateable release, per D100 ────────────────────────

func TestMavenUndateableReleaseFailsClosedWhileABoundIsActive(t *testing.T) {
	up := newMavenAgeUpstream(time.Time{}) // repository serves no Last-Modified
	defer up.Close()
	p := newAgeWindowProxy(t, up.Server, 7, 0)

	code, body := get(t, p, ageArtifactPath())

	if code == http.StatusOK {
		t.Fatalf("a release we could not date was SERVED while a cooldown was active "+
			"(status %d) -- an artifact an attacker arranged for us not to be able to "+
			"date is exactly the one that must not pass", code)
	}
	if strings.Contains(body, ageBytes) {
		t.Fatal("the artifact bytes were delivered for an undateable release")
	}
	if !strings.Contains(body, "could not be verified") {
		t.Errorf("the refusal conflates 'we could not date this' with 'this is too new'; body = %q", body)
	}
}

// ── 5/6. THE DEFAULT COSTS NOTHING — asserted, not claimed ───────────────────
//
// Both bounds default to 0. With no bound configured the window must not fire AND
// must not probe: the probe is a network round trip per artifact, so a silent
// always-on probe would be a real regression that no verdict-based test would catch.

func TestReleaseWindowOffMeansNoRefusalAndNoProbe(t *testing.T) {
	up := newMavenAgeUpstream(time.Time{}) // undateable, which case 4 shows is refused WITH a bound
	defer up.Close()
	p := newAgeWindowProxy(t, up.Server, 0, 0) // the shipped default

	code, body := get(t, p, ageArtifactPath())

	if code != http.StatusOK {
		t.Fatalf("an undateable release was refused with NO bound configured: status %d, body %q", code, body)
	}
	if !strings.Contains(body, ageBytes) {
		t.Fatalf("allowed, but the bytes did not arrive; body = %q", body)
	}
	if heads, _ := up.counts(); heads != 0 {
		t.Errorf("the release-age probe ran %d time(s) with no bound configured -- the "+
			"default must cost no extra upstream requests", heads)
	}
}

// The companion: with a bound ON, the probe MUST run. Without this, case 5 is also
// satisfied by a probe that never runs at all, and every refusal above would be
// coming from somewhere else.
func TestReleaseWindowOnDoesProbe(t *testing.T) {
	up := newMavenAgeUpstream(time.Now().Add(-90 * 24 * time.Hour))
	defer up.Close()
	p := newAgeWindowProxy(t, up.Server, 7, 0)

	if code, body := get(t, p, ageArtifactPath()); code != http.StatusOK {
		t.Fatalf("setup: expected an allow, got %d %q", code, body)
	}
	if heads, _ := up.counts(); heads == 0 {
		t.Error("no HEAD probe was made with a cooldown configured, so the allow above " +
			"was not the window deciding -- it was the window never running")
	}
}

// ── 7. An outage is not a verdict ────────────────────────────────────────────

func TestMavenAgeProbeOutageIsNotAPolicyRefusal(t *testing.T) {
	up := newMavenAgeUpstream(time.Now().Add(-90 * 24 * time.Hour))
	defer up.Close()
	up.setArtifactStatus(http.StatusServiceUnavailable) // the probe cannot get an answer
	p := newAgeWindowProxy(t, up.Server, 7, 0)

	code, body := get(t, p, ageArtifactPath())

	if code == http.StatusOK || strings.Contains(body, ageBytes) {
		t.Fatalf("bytes were served while the age probe was failing (status %d)", code)
	}
	// The distinction that matters: a developer must not read an outage as "too new"
	// and sit out a cooldown that was never the reason.
	if strings.Contains(body, "cooldown") {
		t.Errorf("an upstream outage was reported to the developer as a cooldown; body = %q", body)
	}
	if !strings.Contains(body, "could not determine") {
		t.Errorf("the refusal does not say the window could not be applied; body = %q", body)
	}
}

// ── 8. The window judges ARTIFACTS, not the repository's own index files ─────

func TestReleaseWindowLeavesMavenMetadataAlone(t *testing.T) {
	up := newMavenAgeUpstream(time.Now().Add(-1 * time.Hour)) // everything is brand new
	defer up.Close()
	p := newAgeWindowProxy(t, up.Server, 7, 0)

	// maven-metadata.xml is how a resolver discovers versions at all. Refusing it
	// would break resolution outright rather than holding back a fresh release.
	code, _ := get(t, p, "/"+ageGroupPath+"/maven-metadata.xml")
	if code != http.StatusOK {
		t.Fatalf("maven-metadata.xml was refused by the release window (status %d)", code)
	}
}

// ── 9. THE SHARED-OWNER GUARD ────────────────────────────────────────────────
//
// The window's decision lives in ONE place (ageWindow.reasonFor) so Maven's 403 and
// PyPI's index yank cannot drift on what the knobs mean. This pins the three answers
// directly, including the one a second copy would get wrong first: unknown age is
// refused while a bound is active and ignored when none is.
func TestAgeWindowReasonForIsTheSingleOwner(t *testing.T) {
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	// No request is driven here -- this pins the decision function directly -- but
	// newTestProxy still needs an upstream to point at.
	idle := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer idle.Close()
	p := newTestProxy(t, idle, func(c *Config) {
		c.Ecosystem = "maven"
		c.MinReleaseAgeDays = 7
		c.MaxReleaseAgeDays = 365
	})
	w := p.releaseWindow(now)

	cases := []struct {
		name  string
		t     time.Time
		known bool
		want  string // substring, "" means allow
	}{
		{"inside the window", now.AddDate(0, 0, -30), true, ""},
		{"too new", now.AddDate(0, 0, -1), true, "cooldown"},
		{"too old", now.AddDate(0, 0, -400), true, "age floor"},
		{"unknown age with a bound active", time.Time{}, false, "could not be verified"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := w.reasonFor(c.t, c.known)
			if c.want == "" {
				if got != "" {
					t.Errorf("expected allow, got refusal %q", got)
				}
				return
			}
			if !strings.Contains(got, c.want) {
				t.Errorf("reason %q does not contain %q", got, c.want)
			}
		})
	}

	// The other half of the unknown-age rule: with NO bound, an undateable release is
	// not the window's business. Asserted separately because it is the branch that
	// makes the shipped default free.
	off := newTestProxy(t, idle, func(c *Config) { c.Ecosystem = "maven" }).releaseWindow(now)
	if got := off.reasonFor(time.Time{}, false); got != "" {
		t.Errorf("an undateable release was refused with no bound configured: %q", got)
	}
}

// ── 10. THE E25 GUARD ────────────────────────────────────────────────────────
//
// This is the assertion that would have FAILED on origin/main before this change, and
// the one that stops the window quietly becoming npm/PyPI-only again. It does not
// test a verdict; it tests that the Maven ecosystem is wired to the window at all.
func TestMavenIsWiredToTheReleaseWindow(t *testing.T) {
	eco, err := newEcosystem("maven", "https://repo.maven.apache.org/maven2")
	if err != nil {
		t.Fatalf("building the maven ecosystem: %v", err)
	}
	if _, ok := eco.(releaseDated); !ok {
		t.Fatal("the maven ecosystem does not implement releaseDated, so FW_MIN_RELEASE_AGE_DAYS " +
			"and FW_MAX_RELEASE_AGE_DAYS are documented as firewall-wide while silently " +
			"applying to npm and PyPI only (#26, the E25 pattern)")
	}

	// And the measured counterpart: OCI deliberately does NOT implement it, because
	// its only date is publisher-controlled. If someone wires OCI up, this fails and
	// they must read whyOCIHasNoReleaseWindow first.
	ocieco, err := newEcosystem("oci", "https://registry-1.docker.io")
	if err != nil {
		t.Fatalf("building the oci ecosystem: %v", err)
	}
	if _, ok := ocieco.(releaseDated); ok {
		t.Fatal("OCI now implements releaseDated. The only date in the OCI pull path is " +
			"`created` inside the publisher-uploaded config blob -- measured forgeable by " +
			"back-dating it and recomputing the digest -- and the registry supplies no " +
			"push time at all. A cooldown keyed on it is set by the party it restrains.\n" +
			"And it does not even need an attacker, in two ways. Reproducible builds zero " +
			"the field: 4 of 7 images sampled 2026-09-12 report `created: 1970-01-01`, every " +
			"gcr.io/distroless/* one, and we ship one of those in four Dockerfiles -- a " +
			"cooldown would read our own base image as 56 years old. And where a real date " +
			"exists it runs early: across 18 Docker official images on 2026-09-16, `created` " +
			"was EARLIER than the real push in 18 of 18, median 3.5 h, max 1,041 days, with " +
			"FOUR (22%) off by more than seven days -- nginx:1.27 by 55.5 d, registry:2 by " +
			"501 d, traefik:v3.1 by 14.6 d. Those clear a 7-day cooldown the instant they " +
			"land, with every publisher behaving honestly. Vacuous, not just bypassable.\n" +
			"If you have a NEW source of truth, say which one in the commit message. Docker " +
			"Hub's non-spec API is not it: one registry's private endpoint, on a different " +
			"host from the registry itself. See whyOCIHasNoReleaseWindow.")
	}
}
