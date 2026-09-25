package main

import (
	"strings"
	"testing"
)

// "1 entries" is the gate's spelling; the page says "1 entry".
func TestPlainRulesSayOneEntry(t *testing.T) {
	p := buildPlainPolicy(&policyDoc{Values: map[string]string{
		"operator_allow_list": "1 entries, sha256:y", "operator_deny_list": "2 entries, sha256:z"}})
	if !strings.HasPrefix(p.Rules[2].Detail, "1 entry.") || !strings.HasPrefix(p.Rules[1].Detail, "2 entries.") {
		t.Errorf("list rows: %q / %q", p.Rules[1].Detail, p.Rules[2].Detail)
	}
}
