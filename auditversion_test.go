package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// D363: every decision is about a specific release. The audit record carried the version
// only inside Reason's prose, so "which releases of X did we refuse" was a text search,
// and the record of an allowed Maven jar did not say which jar. These pin the structured
// field at each control point where a request names a release, and its ABSENCE where the
// request names none (a packument), which is the half that keeps it from being a guess.

func oneEvent(t *testing.T, a *auditEmitter) auditEvent {
	t.Helper()
	evs := drainAudit(a)
	if len(evs) != 1 {
		t.Fatalf("audit events = %d, want exactly 1: %+v", len(evs), evs)
	}
	return evs[0]
}

func TestNpmTarballVerdictsRecordTheRelease(t *testing.T) {
	t.Run("pinned advisory refusal", func(t *testing.T) {
		up, _ := npmVersionedUpstream(t, "pkg", "1.0.0", "2.0.0")
		defer up.Close()
		p := pinnedProxy(t, up, pinTwo)
		a := captureAudit(p)
		if rec := getFrom(t, p, "/pkg/-/pkg-2.0.0.tgz"); rec.Code != http.StatusForbidden {
			t.Fatalf("the pinned release was not refused: %d", rec.Code)
		}
		if e := oneEvent(t, a); e.Version != "2.0.0" {
			t.Errorf("version = %q, want 2.0.0: the record of a refused release must say which release", e.Version)
		}
	})
	t.Run("operator version deny", func(t *testing.T) {
		up, _ := npmVersionedUpstream(t, "pkg", "1.0.0", "2.0.0")
		defer up.Close()
		p := newTestProxy(t, up, func(c *Config) {
			c.UnscorablePolicy = "allow"
			c.DenyListPath = writeList(t, "deny.txt", "pkg@2.0.0")
		})
		a := captureAudit(p)
		if rec := getFrom(t, p, "/pkg/-/pkg-2.0.0.tgz"); rec.Code != http.StatusForbidden {
			t.Fatalf("the operator's version deny did not refuse: %d", rec.Code)
		}
		if e := oneEvent(t, a); e.Version != "2.0.0" {
			t.Errorf("version = %q, want 2.0.0", e.Version)
		}
	})
	t.Run("administrator override", func(t *testing.T) {
		up, _ := npmVersionedUpstream(t, "pkg", "1.0.0", "2.0.0")
		defer up.Close()
		p := newTestProxy(t, up, func(c *Config) {
			c.MalwareListPath = writeFeed(t, pinTwo)
			c.UnscorablePolicy = "allow"
			c.AllowListPath = writeList(t, "allow.txt", "pkg@2.0.0")
		})
		a := captureAudit(p)
		if rec := getFrom(t, p, "/pkg/-/pkg-2.0.0.tgz"); rec.Code != http.StatusOK {
			t.Fatalf("the overridden release was not served: %d", rec.Code)
		}
		if e := oneEvent(t, a); e.Version != "2.0.0" || e.Override == "" {
			t.Errorf("the override record = version %q, override %q; want 2.0.0 and a note", e.Version, e.Override)
		}
	})
}

// The packument names no release, so its record carries none, and the JSON has no
// "version" key at all: absent means "package-level", which "" on the wire would blur
// with "a version nobody could parse".
func TestAPackageLevelVerdictRecordsNoVersion(t *testing.T) {
	up, _ := npmVersionedUpstream(t, "pkg", "1.0.0", "2.0.0")
	defer up.Close()
	p := pinnedProxy(t, up, pinTwo)
	a := captureAudit(p)
	if rec := getFrom(t, p, "/pkg"); rec.Code != http.StatusOK {
		t.Fatalf("packument: %d", rec.Code)
	}
	e := oneEvent(t, a)
	if e.Version != "" {
		t.Errorf("a packument verdict recorded version %q; it names no single release", e.Version)
	}
	body, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), `"version"`) {
		t.Errorf("the wire record carries a version key for a package-level verdict: %s", body)
	}
}

func mavenVersionProxy(t *testing.T) *proxyServer {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "maven-metadata.xml"):
			fmt.Fprint(w, `<metadata><versioning><release>2.0</release></versioning></metadata>`)
		case strings.HasSuffix(r.URL.Path, ".pom"):
			fmt.Fprint(w, `<project><scm><url>https://github.com/acme/widget</url></scm></project>`)
		default:
			fmt.Fprint(w, "JAR")
		}
	}))
	t.Cleanup(up.Close)
	return newTestProxy(t, up, func(c *Config) {
		c.Ecosystem = "maven"
		c.DenyListPath = writeList(t, "deny.txt", "org.example:widget:2.0")
		c.UnscorablePolicy = "allow"
	})
}

// Maven's identity is group:artifact, so Evaluate's own verdict names no version. The
// path does, and the record must take it from there -- for the allow as much as for the
// refusal, since "which jar did we let in" is the incident question.
func TestMavenVerdictsRecordTheReleaseFromThePath(t *testing.T) {
	p := mavenVersionProxy(t)
	a := captureAudit(p)

	if rec := getFrom(t, p, "/org/example/widget/2.0/widget-2.0.jar"); rec.Code == http.StatusOK {
		t.Fatalf("the denied release was served")
	}
	if e := oneEvent(t, a); e.Version != "2.0" || e.Action != auditActionBlock {
		t.Errorf("the refusal's record = %+v; want a block of version 2.0", e)
	}

	rec := getFrom(t, p, "/org/example/widget/1.0/widget-1.0.jar")
	if rec.Code != http.StatusOK {
		t.Fatalf("the sibling release was not served: %d %s", rec.Code, rec.Body.String())
	}
	if e := oneEvent(t, a); e.Version != "1.0" || e.Action != auditActionAllow {
		t.Errorf("the allow's record = %+v; want an allow of version 1.0", e)
	}
}

func TestPypiFileVerdictRecordsTheRelease(t *testing.T) {
	u := newPypiPinUpstream(t, "hijacked")
	p := pypiPinProxy(t, u, writeFeed(t, `{"id":"MAL-2025-PIN","ecosystem":"pypi","name":"hijacked","versions":["2.0"]}`))
	bad := indexFileURL(t, p, "hijacked", "hijacked-2.0.tar.gz")
	a := captureAudit(p)
	if code, _ := getPath(t, p, bad); code != http.StatusForbidden {
		t.Fatalf("the pinned file was not refused: %d", code)
	}
	if e := oneEvent(t, a); e.Version != "2.0" {
		t.Errorf("version = %q, want 2.0", e.Version)
	}
}

func TestRequestedVersionReadsOnlyWhatTheRequestNames(t *testing.T) {
	cases := []struct {
		eco, pkg, path, want, why string
	}{
		{"maven", "org.example:widget", "/org/example/widget/1.2.3/widget-1.2.3.jar", "1.2.3", "the path's version segment"},
		{"maven", "org.example:widget", "/org/example/widget/maven-metadata.xml", "", "metadata names no release"},
		{"oci", "library/nginx:1.27", "/v2/library/nginx/manifests/1.27", "1.27", "the tag"},
		{"oci", "library/nginx@sha256:" + strings.Repeat("a", 64), "", "sha256:" + strings.Repeat("a", 64), "the digest"},
		{"npm", "pkg", "/pkg", "", "a packument names no release"},
		{"pypi", "pkg", "/simple/pkg/", "", "an index names no release"},
	}
	for _, c := range cases {
		f, err := NewFirewall(Config{Ecosystem: c.eco, UpstreamRegistry: "http://127.0.0.1:1", ScorecardMode: "stub"})
		if err != nil {
			t.Fatalf("%s: NewFirewall: %v", c.eco, err)
		}
		if got := f.requestedVersion(c.pkg, c.path); got != c.want {
			t.Errorf("%s %s %s: got %q, want %q (%s)", c.eco, c.pkg, c.path, got, c.want, c.why)
		}
	}
}

// A verdict that overrules the held allow (D346, the npm filter) concerns the same
// request, so it keeps the version the held one carried unless it names its own.
func TestAnOverrulingVerdictKeepsTheRelease(t *testing.T) {
	r, hold := withVerdictHold(httptest.NewRequest(http.MethodGet, "/x", nil))
	hold.armed, hold.d = true, Decision{Allowed: true, Version: "1.2.3"}
	if !overruleVerdict(r, Decision{Allowed: false, Reason: "filtered"}) {
		t.Fatal("an armed hold was not overruled")
	}
	if hold.d.Version != "1.2.3" || hold.d.Allowed {
		t.Errorf("after overruling: %+v; want a refusal that still names 1.2.3", hold.d)
	}
	hold.d = Decision{Allowed: true, Version: "1.2.3"}
	overruleVerdict(r, Decision{Allowed: false, Version: "9.9.9"})
	if hold.d.Version != "9.9.9" {
		t.Errorf("an overruling verdict's own version was replaced: %q", hold.d.Version)
	}
}

// The release window's Maven verdict is built from the probe, which names no version of
// its own; versionVerdict takes it from the path.
func TestMavenReleaseWindowRefusalRecordsTheRelease(t *testing.T) {
	up := newMavenAgeUpstream(time.Now().Add(-2 * 24 * time.Hour))
	defer up.Close()
	p := newAgeWindowProxy(t, up.Server, 7, 0)
	a := captureAudit(p)
	if code, _ := get(t, p, ageArtifactPath()); code == http.StatusOK {
		t.Fatalf("a 2-day-old release was served under a 7-day cooldown")
	}
	if e := oneEvent(t, a); e.Version != ageVersion || e.Rule != "release-window" {
		t.Errorf("the cooldown's record = rule %q, version %q; want release-window and %q", e.Rule, e.Version, ageVersion)
	}
}
