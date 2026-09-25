package main

import (
	"strings"
	"testing"
)

// TestPublicURLWarning pins WHEN the operator is told that lockfiles will not be
// portable (issue #19).
//
// The interesting cases are the two that must stay SILENT. Warning on OCI or Maven
// would describe a consequence that cannot happen there — those bodies are never
// rewritten — and a warning an operator cannot act on is how a startup log becomes
// noise nobody reads, which is the failure mode this issue is really about.
func TestPublicURLWarning(t *testing.T) {
	cases := []struct {
		name      string
		ecosystem string
		publicURL string
		warn      bool
	}{
		{"npm without a public URL", "npm", "", true},
		{"pypi without a public URL", "pypi", "", true},
		{"npm with one configured", "npm", "https://npm.fw.internal", false},
		{"pypi with one configured", "pypi", "https://pypi.fw.internal", false},

		// No body rewriting on these two, so no drift to warn about.
		{"oci without a public URL", "oci", "", false},
		{"maven without a public URL", "maven", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := publicURLWarning(Config{Ecosystem: tc.ecosystem, PublicURL: tc.publicURL})
			if tc.warn && got == "" {
				t.Fatalf("%s with FW_PUBLIC_URL=%q should warn: lockfiles silently become non-portable",
					tc.ecosystem, tc.publicURL)
			}
			if !tc.warn && got != "" {
				t.Fatalf("%s with FW_PUBLIC_URL=%q must NOT warn, got: %s", tc.ecosystem, tc.publicURL, got)
			}
			// A warning has to name the knob and say what to do about it — "check your
			// config" is the unactionable kind this issue exists to stamp out.
			if tc.warn {
				if !strings.Contains(got, "FW_PUBLIC_URL") {
					t.Errorf("warning must name the knob; got: %s", got)
				}
				if !strings.Contains(got, "lockfile") && !strings.Contains(got, "portable") {
					t.Errorf("warning must state the consequence, not just the fact; got: %s", got)
				}
			}
		})
	}
}
