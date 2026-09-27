package main

import (
	"strings"
	"testing"
	"time"
)

// D363: the audit row names the release a verdict concerned, beside the package. An OCI
// identity already ends in its tag or digest, so it is not repeated there.
func TestTheAuditRowNamesTheRelease(t *testing.T) {
	f := &fakeApproval{events: []event{
		{ID: 1, Package: "org.example:widget", Ecosystem: "maven", Action: "block", Version: "2.0", At: time.Now()},
		{ID: 2, Package: "left-pad", Ecosystem: "npm", Action: "allow", At: time.Now()},
		{ID: 3, Package: "library/nginx:1.27", Ecosystem: "oci", Action: "allow", Version: "1.27", At: time.Now()},
	}}
	body := auditPageAs(t, newTestServer(f), "", "")
	const mark = `title="the release this verdict concerned"`
	if n := strings.Count(body, mark); n != 1 {
		t.Fatalf("%d row(s) show a release, want exactly 1 (the Maven one)", n)
	}
	for _, row := range strings.Split(body, "<tr>") {
		switch {
		case strings.Contains(row, "org.example:widget"):
			if !strings.Contains(row, mark+">2.0<") {
				t.Error("the Maven row does not name release 2.0")
			}
		case strings.Contains(row, "library/nginx:1.27"):
			if strings.Contains(row, mark) {
				t.Error("the OCI row repeats the tag its identity already ends in")
			}
		}
	}
}

func TestVersionBesidePackage(t *testing.T) {
	for _, c := range []struct{ pkg, version, want string }{
		{"org.example:widget", "2.0", "2.0"},
		{"left-pad", "", ""},
		{"library/nginx:1.27", "1.27", ""},
		{"library/nginx@sha256:ab", "sha256:ab", ""},
		{"library/nginx:1.27", "1.2", "1.2"}, // a suffix match on the TAG, not on a prefix of it
	} {
		if got := versionBesidePackage(c.pkg, c.version); got != c.want {
			t.Errorf("versionBesidePackage(%q, %q) = %q, want %q", c.pkg, c.version, got, c.want)
		}
	}
}

// The version comes from a request PATH, which the requester chooses: a Maven path
// segment or a tarball filename can carry markup. It must reach the page as text.
func TestAHostileVersionRendersAsText(t *testing.T) {
	const hostile = `1.0"><script>alert(1)</script>`
	f := &fakeApproval{events: []event{
		{ID: 1, Package: "org.example:widget", Ecosystem: "maven", Action: "block", Version: hostile, At: time.Now()},
	}}
	body := auditPageAs(t, newTestServer(f), "", "")
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("a version taken from a request path was rendered as markup")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("the hostile version is not on the page at all, escaped or otherwise; the check above is vacuous")
	}
}
