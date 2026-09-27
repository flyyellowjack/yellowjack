package fipsmode

import (
	"strings"
	"testing"
)

// The three states an operator can meet, and the one wording each must carry. The line is
// read by people, so the test pins the part a person acts on: ON or off, and which module.
func TestFormat(t *testing.T) {
	cases := []struct {
		name    string
		enabled bool
		module  string
		want    []string
		notWant []string
	}{
		{"certified build", true, "v1.0.0-c2097c7c", []string{"ON", "v1.0.0-c2097c7c"}, []string{"off", "in-tree"}},
		{"runtime switch only", true, "", []string{"ON", "in-tree", "not a certified one"}, []string{"off"}},
		{"built with GOFIPS140=off", false, "off", []string{"off"}, []string{"ON"}},
		{"plain build", false, "", []string{"off", "without GOFIPS140"}, []string{"ON"}},
	}
	for _, c := range cases {
		got := format(c.enabled, c.module)
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q does not say %q", c.name, got, w)
			}
		}
		for _, w := range c.notWant {
			if strings.Contains(got, w) {
				t.Errorf("%s: %q says %q, which is the opposite state", c.name, got, w)
			}
		}
	}
}

// A healthy boot must stay quiet (#19): the line is informational in every state, so it
// must never carry a severity token the boot check reads as a complaint.
func TestNoSeverityToken(t *testing.T) {
	for _, en := range []bool{true, false} {
		for _, m := range []string{"", "off", "v1.0.0-c2097c7c"} {
			got := format(en, m)
			for _, tok := range []string{"WARNING", "ERROR", "FATAL", "panic"} {
				if strings.Contains(got, tok) {
					t.Errorf("format(%v,%q) = %q carries %q", en, m, got, tok)
				}
			}
		}
	}
}
