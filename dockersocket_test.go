package main

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// THE DOCKER SOCKET IS CONFINED TO ONE SERVICE, AND THIS PINS WHICH (#80, D133).
//
// The scheduler mounts /var/run/docker.sock to launch each run-once scanner container.
// A container holding that socket is root-equivalent ON THE HOST whatever user it runs
// as: it can start a privileged container, bind-mount the host filesystem, and reach
// every sibling container including the firewall. e2e/hardening.sh records the same fact
// as ROOT_BY_DESIGN, and docs/SETUP.md states the blast radius for an operator.
//
// D133 ruled this a DOCUMENTATION duty rather than a defect to engineer away — deployment
// security is the customer's, ours is the Dockerfile, the HA behaviour and the Helm chart.
// So this file does not try to remove the socket, and it is not a claim that the design is
// safe. It does the one cheap thing a document cannot: it makes the blast radius stop
// GROWING silently.
//
// The failure mode being guarded is ordinary and undramatic. Someone needs container
// introspection in a service — a health check, a debug endpoint, a metric — and mounts the
// socket into it in one line of compose. Nothing breaks, no review catches it, and a
// service that terminates traffic from developer machines is now root on the host. The
// firewall is the service where that would matter most, which is why it is named below
// rather than left to the general rule.
//
// If a service legitimately needs the socket, add it to socketAllowed and say why. The
// test failing is the prompt to make that decision consciously, which is the whole point.
var socketAllowed = map[string]string{
	"scheduler": "launches the run-once scanner containers (docker-run / docker-api launchers)",
}

// clientFacing are the services that terminate traffic from developer machines. They are
// asserted by NAME as well as by the general rule above, so that a future edit widening
// socketAllowed cannot quietly take one of them with it.
var clientFacing = []string{"firewall", "firewall-oci", "cache"}

const dockerSocketPath = "/var/run/docker.sock"

// composeVolumeMounts maps each compose service to its volume entries. It is a small
// indentation reader rather than a YAML dependency, in keeping with the repo's few-deps
// rule; the shapes it must handle are the ones docker-compose.yml actually uses, and
// TestComposeVolumeReaderSeesTheRealFile proves it reads the real file correctly.
func composeVolumeMounts(yaml string) map[string][]string {
	out := map[string][]string{}
	inServices, inVolumes := false, false
	service := ""
	for _, raw := range strings.Split(yaml, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))

		switch {
		case indent == 0:
			// A new top-level key ends the services block — including the top-level
			// `volumes:` that declares named volumes, which is not a mount list.
			inServices = trimmed == "services:"
			service, inVolumes = "", false
		case inServices && indent == 2 && strings.HasSuffix(trimmed, ":"):
			service = strings.TrimSuffix(trimmed, ":")
			inVolumes = false
		case inServices && service != "" && indent == 4 && strings.HasSuffix(trimmed, ":"):
			inVolumes = trimmed == "volumes:"
		case inVolumes && indent >= 6 && strings.HasPrefix(trimmed, "- "):
			out[service] = append(out[service], strings.TrimSpace(trimmed[2:]))
		}
	}
	return out
}

func mountsDockerSocket(entries []string) bool {
	for _, e := range entries {
		// A mount is "<source>:<target>[:opts]"; the socket may appear on either side.
		if strings.Contains(e, dockerSocketPath) {
			return true
		}
	}
	return false
}

func readCompose(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatalf("read docker-compose.yml: %v", err)
	}
	return string(b)
}

// TestComposeVolumeReaderSeesTheRealFile is the instrument check. Every assertion below is
// about what the reader FOUND, so a reader that silently found nothing would make them all
// pass. This fails if the parse stops working, before any conclusion is drawn from it.
func TestComposeVolumeReaderSeesTheRealFile(t *testing.T) {
	mounts := composeVolumeMounts(readCompose(t))
	if len(mounts) == 0 {
		t.Fatal("no service in docker-compose.yml has any volume entry — the reader is broken, " +
			"and every socket assertion in this file would pass vacuously")
	}
	found := 0
	for _, entries := range mounts {
		found += len(entries)
	}
	t.Logf("read %d volume entr(ies) across %d service(s)", found, len(mounts))

	// The one mount this file exists for must actually be visible, or "only the scheduler
	// has it" would be true of a file the reader cannot see.
	if !mountsDockerSocket(mounts["scheduler"]) {
		t.Fatalf("the scheduler's docker socket mount was not found; either compose changed or "+
			"the reader missed it. scheduler volumes seen: %v", mounts["scheduler"])
	}
}

// TestOnlyAllowedServicesMountTheDockerSocket is the guard.
func TestOnlyAllowedServicesMountTheDockerSocket(t *testing.T) {
	mounts := composeVolumeMounts(readCompose(t))

	var got []string
	for service, entries := range mounts {
		if mountsDockerSocket(entries) {
			got = append(got, service)
		}
	}
	sort.Strings(got)

	var want []string
	for service := range socketAllowed {
		want = append(want, service)
	}
	sort.Strings(want)

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("services mounting %s = %v, want %v.\n"+
			"A container with this socket is root-equivalent on the host whatever user it runs "+
			"as. If the new service genuinely needs it, add it to socketAllowed with the reason "+
			"and state the widened blast radius in docs/SETUP.md (#80, D133).",
			dockerSocketPath, got, want)
	}
}

// TestNoClientFacingServiceMountsTheDockerSocket names the cases that matter most, so they
// survive a future widening of socketAllowed.
func TestNoClientFacingServiceMountsTheDockerSocket(t *testing.T) {
	mounts := composeVolumeMounts(readCompose(t))
	for _, service := range clientFacing {
		if _, ok := mounts[service]; !ok {
			// Not every client-facing service declares volumes; absent is fine, present
			// with the socket is not. Guard against a rename making this vacuous.
			if !composeDeclaresService(readCompose(t), service) {
				t.Errorf("compose has no service %q — this test is asserting nothing about it; "+
					"update clientFacing if it was renamed", service)
			}
			continue
		}
		if mountsDockerSocket(mounts[service]) {
			t.Errorf("%q terminates traffic from developer machines and mounts %s, which makes "+
				"it root-equivalent on the operator's host (#80)", service, dockerSocketPath)
		}
	}
}

func composeDeclaresService(yaml, service string) bool {
	inServices := false
	for _, raw := range strings.Split(yaml, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			inServices = trimmed == "services:"
		} else if inServices && indent == 2 && trimmed == service+":" {
			return true
		}
	}
	return false
}

// TestTheSocketGuardFiresOnAWideningEdit is the negative control, and it runs every time
// rather than waiting for someone to sabotage the file by hand. It feeds the reader a
// compose file with the socket added to the firewall — the one-line edit described at the
// top of this file — and requires the guard to notice.
func TestTheSocketGuardFiresOnAWideningEdit(t *testing.T) {
	real := readCompose(t)

	widened := addSocketToService(t, real, "firewall")
	mounts := composeVolumeMounts(widened)

	if !mountsDockerSocket(mounts["firewall"]) {
		t.Fatal("the widened fixture does not read back as mounting the socket, so the controls " +
			"below prove nothing about the guard")
	}
	var offenders []string
	for service, entries := range mounts {
		if mountsDockerSocket(entries) {
			if _, ok := socketAllowed[service]; !ok {
				offenders = append(offenders, service)
			}
		}
	}
	if len(offenders) == 0 {
		t.Fatal("the socket was added to the firewall and the allowlist check found no offender — " +
			"TestOnlyAllowedServicesMountTheDockerSocket would pass a one-line edit that makes the " +
			"client-facing service root on the host")
	}
	t.Logf("control: widening the mount to the firewall is caught, offenders=%v", offenders)

	// And the same edit must trip the named client-facing check, not only the general one.
	if !mountsDockerSocket(composeVolumeMounts(widened)["firewall"]) {
		t.Error("the named client-facing assertion would not fire on the widened fixture")
	}
}

// addSocketToService returns the compose file with a docker-socket volume added to one
// service. It appends to an existing `volumes:` block so the fixture stays a shape the
// reader must genuinely parse, and fails loudly rather than returning the file unchanged —
// an unchanged fixture is how a negative control quietly stops controlling anything.
func addSocketToService(t *testing.T, yaml, service string) string {
	t.Helper()
	lines := strings.Split(yaml, "\n")
	inServices, cur := false, ""
	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			inServices = trimmed == "services:"
			cur = ""
			continue
		}
		if inServices && indent == 2 && strings.HasSuffix(trimmed, ":") {
			cur = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if cur == service && indent == 4 && trimmed == "volumes:" {
			out := append([]string{}, lines[:i+1]...)
			out = append(out, "      - "+dockerSocketPath+":"+dockerSocketPath)
			out = append(out, lines[i+1:]...)
			return strings.Join(out, "\n")
		}
	}
	// No volumes block on that service: give it one, immediately after its declaration.
	for i, raw := range lines {
		if strings.TrimSpace(strings.TrimRight(raw, "\r")) == service+":" {
			out := append([]string{}, lines[:i+1]...)
			out = append(out, "    volumes:", "      - "+dockerSocketPath+":"+dockerSocketPath)
			out = append(out, lines[i+1:]...)
			return strings.Join(out, "\n")
		}
	}
	t.Fatalf("could not build the widened fixture: service %q not found in docker-compose.yml", service)
	return ""
}
