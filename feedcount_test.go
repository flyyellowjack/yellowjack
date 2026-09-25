package main

import (
	"strings"
	"testing"
)

// The feed's policy-view string leads with the number of advisories THIS gate's ecosystem
// enforces, and says how many are package-wide and how many name a release. It used to
// print the package-wide count across every ecosystem followed by "incl. version-pinned",
// so a demo feed of 2 package-wide + 2 pinned npm advisories read as "2".
func TestFeedDescribeCountsThisEcosystem(t *testing.T) {
	l, err := parseMalwareList(strings.NewReader(strings.Join([]string{
		`{"id":"D1","ecosystem":"npm","name":"crossenv"}`,
		`{"id":"D2","ecosystem":"npm","name":"electorn"}`,
		`{"id":"D3","ecosystem":"npm","name":"ua-parser-js","versions":["0.7.29"]}`,
		`{"id":"D4","ecosystem":"npm","name":"coa","versions":["2.0.3"]}`,
		// Another ecosystem's advisory: the control, which must not count for npm.
		`{"id":"D5","ecosystem":"pypi","name":"reqeusts"}`,
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got := l.describe("npm"); !strings.HasPrefix(got, "4 enforced (2 package-wide, 2 version-pinned), sha256:") {
		t.Errorf("npm: %q", got)
	}
	if got := l.describe("pypi"); !strings.HasPrefix(got, "1 enforced (1 package-wide, 0 version-pinned), sha256:") {
		t.Errorf("pypi: %q", got)
	}
}
