package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMavenPackageNameFromPath(t *testing.T) {
	e := mavenEcosystem{}
	cases := []struct{ path, want string }{
		{"/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar", "com.google.guava:guava"},
		{"/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.pom", "com.google.guava:guava"},
		{"/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar", "org.apache.commons:commons-lang3"},
		// not gated: metadata, checksums, signatures, directory listings, root
		{"/com/google/guava/guava/maven-metadata.xml", ""},
		{"/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.jar.sha1", ""},
		{"/com/google/guava/guava/31.0.1-jre/guava-31.0.1-jre.pom.asc", ""},
		{"/", ""},
		{"/com/google/guava/", ""},
	}
	for _, c := range cases {
		if got := e.PackageNameFromPath(c.path); got != c.want {
			t.Errorf("PackageNameFromPath(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestMavenRepo(t *testing.T) {
	mk := func(scmURL, scmConn, projURL string) mavenPOM {
		var p mavenPOM
		p.URL = projURL
		p.SCM.URL = scmURL
		p.SCM.Connection = scmConn
		return p
	}
	cases := []struct {
		name string
		pom  mavenPOM
		want string
	}{
		{"scm url", mk("https://github.com/google/guava", "", ""), "github.com/google/guava"},
		{"scm connection scm:git:", mk("", "scm:git:https://github.com/owner/repo.git", ""), "github.com/owner/repo"},
		{"project url fallback", mk("", "", "https://github.com/owner/repo"), "github.com/owner/repo"},
		{"prefer scm url over connection", mk("https://github.com/a/b", "scm:git:https://github.com/c/d.git", ""), "github.com/a/b"},
		{"non-github", mk("https://gitlab.com/x/y", "", "https://example.com"), ""},
		{"empty", mavenPOM{}, ""},
	}
	for _, c := range cases {
		if got := mavenRepo(c.pom); got != c.want {
			t.Errorf("%s: mavenRepo = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestMavenRepoFromParents verifies we recover a repo from an inherited <scm>:
// the child declares none, its parent declares none but points at a grandparent,
// and the grandparent carries the SCM. This is the real-world case that made
// Maven's own core plugins unscorable (their parent POM held the SCM).
func TestMavenRepoFromParents(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/org/example/parent/1.0/parent-1.0.pom":
			// Parent: no <scm> of its own, but points at a grandparent.
			w.Write([]byte(`<project><parent><groupId>org.example</groupId><artifactId>grandparent</artifactId><version>2.0</version></parent></project>`))
		case "/org/example/grandparent/2.0/grandparent-2.0.pom":
			// Grandparent carries the SCM.
			w.Write([]byte(`<project><scm><url>https://github.com/example/project</url></scm></project>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	e := mavenEcosystem{base: ts.URL}

	// Child POM: declares no SCM, references the parent above.
	var child mavenPOM
	child.Parent.GroupID = "org.example"
	child.Parent.ArtifactID = "parent"
	child.Parent.Version = "1.0"
	if got := e.repoFromParents(http.DefaultClient, child); got != "github.com/example/project" {
		t.Errorf("repoFromParents (2-level climb) = %q, want github.com/example/project", got)
	}

	// A POM with no parent reference ends the chain immediately.
	if got := e.repoFromParents(http.DefaultClient, mavenPOM{}); got != "" {
		t.Errorf("repoFromParents (no parent) = %q, want empty", got)
	}
}

// TestMavenTransientErrorsAreUnavailable verifies the D17 failure taxonomy applies
// to maven like npm/pypi: a rate-limited (429) or erroring (5xx) Maven Central is
// TRANSIENT — it must surface as errUpstreamUnavailable (-> client 503, mvn
// retries), never be misfiled as "unscorable" (-> quarantine under fail-closed),
// which would spuriously block builds on a registry hiccup. Central rate-limits
// readily in practice (see docs/E2E_TESTING.md). A 404 means the artifact doesn't
// exist upstream -> errPkgNotFound (pass through, let the registry's 404 answer).
func TestMavenTransientErrorsAreUnavailable(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusTooManyRequests, errUpstreamUnavailable},
		{http.StatusBadGateway, errUpstreamUnavailable},
		{http.StatusNotFound, errPkgNotFound},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
		}))
		e := mavenEcosystem{base: srv.URL}
		_, err := e.LookupRepo(srv.Client(), "com.example:artifact")
		srv.Close()
		if !errors.Is(err, c.want) {
			t.Errorf("metadata status %d: err = %v, want %v", c.status, err, c.want)
		}
	}
}
