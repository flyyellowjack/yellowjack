package main

import (
	"os"
	"strings"
	"testing"
)

// The nginx config docs/SETUP.md prints for "Serving the gate over HTTPS" must be the one
// e2e/ingress_tls_test.go actually runs (#145, D297).
//
// A config in a setup guide is an instruction someone will paste into production. Without
// this, the page and the rig drift the first time either is edited, and the page goes on
// claiming a test stands behind text no test has seen. Same family as the walkthrough
// banner check in referencedeploy_test.go: derive the expectation from the real artefact.
func TestSetupDocPrintsTheTestedIngressConfig(t *testing.T) {
	norm := func(b []byte) string { return strings.ReplaceAll(string(b), "\r\n", "\n") }
	tmpl, err := os.ReadFile("e2e/ingress/nginx.conf.tmpl")
	if err != nil {
		t.Fatalf("read the tested config: %v", err)
	}
	doc, err := os.ReadFile("docs/SETUP.md")
	if err != nil {
		t.Fatalf("read docs/SETUP.md: %v", err)
	}
	if !strings.Contains(norm(tmpl), "${GATE}") {
		t.Fatal("e2e/ingress/nginx.conf.tmpl no longer has a ${GATE} placeholder, so this test " +
			"cannot render it the way the doc and the rig do; it would pass on anything")
	}
	want := "```nginx\n" + strings.ReplaceAll(norm(tmpl), "${GATE}", "yellowjack:8080") + "```"
	if !strings.Contains(norm(doc), want) {
		t.Errorf("docs/SETUP.md does not print e2e/ingress/nginx.conf.tmpl verbatim (with ${GATE} " +
			"rendered as yellowjack:8080) inside an ```nginx fence. One of them was edited alone: " +
			"update the other, and re-run e2e/ingress_tls_test.go if it was the config that changed.")
	}
}
