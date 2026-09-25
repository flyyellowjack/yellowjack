//go:build e2e && !intercept

package e2e

// firewallBuildTags is passed to the firewall image build (the Dockerfile's GO_TAGS). A
// suite built without the intercept tag tests the default gate.
const firewallBuildTags = ""
