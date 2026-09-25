package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// VERSION-SCOPED operator deny entries (#155, D312's prerequisite).
//
// The hijack case in the operator's own hands: one release of a package they otherwise
// depend on is refused, and its siblings stay installable. A name entry is unchanged and
// still means every version, which is the property most of these tests exist to protect —
// widening a narrow entry, or narrowing a broad one, are both silent failures.
//
// Every leg drives the PROXY rather than the list, because #103's lesson is that a filter
// which is correct and never invoked is indistinguishable at runtime from one that is
// absent. The parser has its own tests in operatorlist_test.go and the shared corpus.

// ---------------------------------------------------------------- npm

func npmDenyUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	var up *httptest.Server
	up = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/hijacked":
			fmt.Fprintf(w, `{"versions":{"1.0.0":{"dist":{"tarball":"%s/hijacked/-/hijacked-1.0.0.tgz"}},`+
				`"2.0.0":{"dist":{"tarball":"%s/hijacked/-/hijacked-2.0.0.tgz"}}},"dist-tags":{"latest":"2.0.0"},`+
				`"repository":{"url":"git+https://github.com/acme/hijacked.git"}}`, up.URL, up.URL)
		case r.URL.Path == "/hijacked/latest":
			fmt.Fprint(w, `{"repository":{"url":"git+https://github.com/acme/hijacked.git"}}`)
		case strings.HasPrefix(r.URL.Path, "/hijacked/-/"):
			fmt.Fprint(w, "TARBALL")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(up.Close)
	return up
}

func npmDenyProxy(t *testing.T, up *httptest.Server, denyBody string) *proxyServer {
	t.Helper()
	return newTestProxy(t, up, func(c *Config) {
		c.Ecosystem = "npm"
		c.DenyListPath = writeList(t, "deny.txt", denyBody)
		c.UnscorablePolicy = "allow"
	})
}

func TestAVersionScopedDenyRemovesOneReleaseFromTheNpmPackument(t *testing.T) {
	up := npmDenyUpstream(t)
	p := npmDenyProxy(t, up, "hijacked@2.0.0\n")

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/hijacked", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("packument = %d, want 200: a version-scoped deny must not refuse the package\n%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, `"2.0.0"`) {
		t.Errorf("the denied release is still in the packument:\n%s", body)
	}
	if !strings.Contains(body, `"1.0.0"`) {
		t.Errorf("the CLEAN sibling was removed too — that denies a package the operator still depends on:\n%s", body)
	}
	// The dist-tag must be repointed, or npm resolves "latest" to a version we removed and
	// the developer gets an error instead of the compliant release.
	var doc struct {
		DistTags map[string]string `json:"dist-tags"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("packument is not JSON: %v", err)
	}
	if doc.DistTags["latest"] != "1.0.0" {
		t.Errorf(`dist-tag "latest" = %q, want 1.0.0 (repointed off the denied release)`, doc.DistTags["latest"])
	}
}

func TestAVersionScopedDenyRefusesTheNpmTarballToo(t *testing.T) {
	// `npm ci` from a lockfile never reads the packument the filter edits. An entry that
	// lived only in the filter would be advisory, not enforcement — the hole #159
	// measured on PyPI with an exact pin.
	up := npmDenyUpstream(t)
	p := npmDenyProxy(t, up, "hijacked@2.0.0\n")

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/hijacked/-/hijacked-2.0.0.tgz", nil))
	if rec.Code == http.StatusOK {
		t.Fatalf("the denied release's TARBALL was served (%d): a lockfile install walks straight past the packument filter", rec.Code)
	}
	if b := rec.Body.String(); !strings.Contains(b, "deny list") {
		t.Errorf("the refusal does not name the deny list, so the developer cannot tell who to ask: %s", b)
	}

	// DISCRIMINATOR: the sibling's tarball is still served.
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/hijacked/-/hijacked-1.0.0.tgz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("the CLEAN sibling's tarball was refused (%d): %s", rec.Code, rec.Body.String())
	}
}

func TestANameScopedDenyStillMeansEveryVersion(t *testing.T) {
	// The property a version-scoped entry must not weaken. If this ever fails, every deny
	// list already written has quietly narrowed.
	up := npmDenyUpstream(t)
	p := npmDenyProxy(t, up, "hijacked\n")

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/hijacked", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("packument = %d, want 403: a bare name denies the package outright", rec.Code)
	}
	for _, v := range []string{"1.0.0", "2.0.0"} {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/hijacked/-/hijacked-"+v+".tgz", nil))
		if rec.Code == http.StatusOK {
			t.Errorf("tarball %s was served under a NAME-scoped deny", v)
		}
	}
}

func TestAnUnrelatedPackageIsUntouchedByAVersionScopedDeny(t *testing.T) {
	// The anti-vacuity discriminator: without it, every test above passes on a gate that
	// refuses everything.
	up := npmDenyUpstream(t)
	p := npmDenyProxy(t, up, "somethingelse@9.9.9\n")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/hijacked", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("an unrelated package = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"2.0.0"`) {
		t.Errorf("a version was removed from a package no entry names:\n%s", rec.Body.String())
	}
}

// ---------------------------------------------------------------- PyPI

func TestAVersionScopedDenyYanksOnePypiReleaseAndRefusesItsFile(t *testing.T) {
	u := newPypiPinUpstream(t, "hijacked")
	p := newTestProxy(t, u.Server, func(c *Config) {
		c.Ecosystem = "pypi"
		c.DenyListPath = writeList(t, "deny.txt", "hijacked==2.0")
		c.UnscorablePolicy = "allow"
		c.FilesUpstream = u.files.URL
	})

	body := serveSimpleIndex(t, p, "hijacked")
	if !strings.Contains(body, "deny list") {
		t.Errorf("the index does not mark the denied release with the operator's reason:\n%s", body)
	}
	// And the FILE, because an exact pin selects a yanked file (PEP 592) — #159.
	bad := indexFileURL(t, p, "hijacked", "hijacked-2.0.tar.gz")
	if code, b := getPath(t, p, bad); code != http.StatusForbidden {
		t.Errorf("the denied release's file = %d, want 403: %s", code, b)
	}
	good := indexFileURL(t, p, "hijacked", "hijacked-1.0.tar.gz")
	if code, b := getPath(t, p, good); code != http.StatusOK {
		t.Errorf("the CLEAN sibling's file = %d, want 200: %s", code, b)
	}
}

// ---------------------------------------------------------------- Maven

func TestAVersionScopedDenyRefusesOneMavenReleaseOnThePath(t *testing.T) {
	// Maven's identity is version-agnostic on purpose, so the version comes off the
	// request path — the control point a pinned advisory already uses.
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
	defer up.Close()
	p := newTestProxy(t, up, func(c *Config) {
		c.Ecosystem = "maven"
		c.DenyListPath = writeList(t, "deny.txt", "org.example:widget:2.0")
		c.UnscorablePolicy = "allow"
	})

	denied := "/org/example/widget/2.0/widget-2.0.jar"
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, denied, nil))
	if rec.Code == http.StatusOK {
		t.Errorf("the denied Maven release was served (%d)", rec.Code)
	} else if !strings.Contains(rec.Body.String(), "deny list") {
		t.Errorf("the refusal does not name the deny list: %s", rec.Body.String())
	}

	sibling := "/org/example/widget/1.0/widget-1.0.jar"
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, sibling, nil))
	if rec.Code != http.StatusOK {
		t.Errorf("the CLEAN Maven sibling was refused (%d): %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------- the list itself

func TestTheDenyListReportsVersionScopedEntriesToTheOperator(t *testing.T) {
	// The count and the digest are what an operator checks against the file they edited,
	// and the digest is what tells two replicas apart. A version-scoped entry missing from
	// either would make a file of ten entries report "0" and two divergent replicas agree.
	l, err := parseOperatorList("deny", "npm", strings.NewReader("lodash\nhijacked@2.0.0\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if l.count() != 2 {
		t.Errorf("count = %d, want 2 (one name, one version-scoped entry)", l.count())
	}
	entries, _ := l.listEntries(10)
	joined := strings.Join(entries, " ")
	if !strings.Contains(joined, "hijacked@2.0.0") {
		t.Errorf("the reported entries do not include the version-scoped one: %v", entries)
	}
	other, err := parseOperatorList("deny", "npm", strings.NewReader("lodash\nhijacked@3.0.0\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if l.contentDigest == other.contentDigest {
		t.Error("two lists denying DIFFERENT releases share a digest: two replicas enforcing different " +
			"policy would report an identical one, which is the blind spot the digest exists to close")
	}
}

// ---------------------------------------------------------------- fail closed

func TestAnUndeterminableVersionIsRefusedOnlyForAPackageWithVersionScopedEntries(t *testing.T) {
	// The posture pinnedMalwareVerdict owns, applied to the operator's own entries: an
	// entry that stops applying because a join broke is a deny that silently stops
	// denying. A sabotage of this branch reddened NOTHING until this test existed.
	up := npmDenyUpstream(t)
	p := npmDenyProxy(t, up, "hijacked@2.0.0")

	// A tarball path whose version cannot be read: the filename does not carry the
	// package's own name-version shape, so npmTarballVersionFromPath declines.
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/hijacked/-/not-a-versioned-name.tgz", nil))
	if rec.Code == http.StatusOK {
		t.Errorf("a tarball whose version could not be determined was SERVED for a package carrying "+
			"version-scoped deny entries: that is the join an attacker breaks to get the denied release (%d)", rec.Code)
	}

	// And the other half: for a package NO version-scoped entry names, the same
	// unreadable filename is served, because there is nothing it could hide.
	p2 := npmDenyProxy(t, up, "somethingelse@9.9.9")
	rec = httptest.NewRecorder()
	p2.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/hijacked/-/not-a-versioned-name.tgz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("a tarball of a package no entry names was refused (%d) because its version could not be "+
			"read; that denies clean packages for no reason: %s", rec.Code, rec.Body.String())
	}
}
