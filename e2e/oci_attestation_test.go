//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TIER 2 FOR #129: THE CLIENT THE WORLD ACTUALLY RUNS.
//
// Every OCI leg in this suite drives `crane`. crane resolves one platform and stops.
// The Docker DAEMON also fetches the buildx ATTESTATION manifests the index lists --
// children with the placeholder platform unknown/unknown -- and those declare no
// org.opencontainers.image.source, being in-toto documents ABOUT the image rather than
// an image. Before the fix the gate judged each one alone, found no repo, called it
// unscorable and refused it under the default block policy, killing the pull of an
// allowed image AFTER all its layers had been served.
//
// Nothing here was exotic: 16 of 16 sampled Docker Hub official images carry
// attestations, this repository's own registry:2 and verdaccio among them.
//
// So this file exists as much for the CLASS as for the defect. A leg that names an
// ecosystem is testing whichever client it invoked, and "OCI" had meant "crane" for
// the whole life of the suite.

// attestedImage must (a) carry attestation manifests and (b) declare a source repo, or
// it would be refused on its own merits and the attestation legs would never be reached.
// alpine:3.20 is 8 attestations of 16 children and declares
// github.com/alpinelinux/docker-alpine; it is also what the other OCI legs pull, so a
// failure here is about attestations rather than about a new image.
const attestedImage = "library/alpine:3.20"

// ociIndexChild is the slice of an index entry these legs need.
type ociIndexChild struct {
	Digest   string `json:"digest"`
	Platform struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform"`
}

const ociAccept = "application/vnd.oci.image.index.v1+json," +
	"application/vnd.docker.distribution.manifest.list.v2+json," +
	"application/vnd.oci.image.manifest.v1+json," +
	"application/vnd.docker.distribution.manifest.v2+json"

// bearerFor performs the registry token dance the gate relays from Docker Hub.
//
// The gate passes the upstream's 401 and its WWW-Authenticate challenge straight
// through, which is correct -- it is a proxy, not an identity provider -- so a client
// that does not answer the challenge sees 401 on every manifest. crane and the Docker
// daemon do this for you; a bare http.Client does not, and the first version of this
// file failed on exactly that and looked like a refusal.
func bearerFor(t *testing.T, challenge string) string {
	t.Helper()
	fields := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(strings.TrimSpace(challenge), "Bearer "), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			fields[k] = strings.Trim(v, `"`)
		}
	}
	realm := fields["realm"]
	if realm == "" {
		t.Fatalf("no realm in the registry challenge %q, so the token dance cannot start", challenge)
	}
	u := realm + "?service=" + url.QueryEscape(fields["service"]) + "&scope=" + url.QueryEscape(fields["scope"])
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Get(u)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if tok.Token == "" {
		return tok.AccessToken
	}
	return tok.Token
}

// fetchThroughGate issues one manifest request at the firewall and returns status+body,
// answering the relayed auth challenge once if the registry asks for one.
//
// Deliberately a plain HTTP client rather than a container: this leg is about what the
// GATE answers for a given path, and a client in the loop only adds ways to be wrong.
func fetchThroughGate(t *testing.T, port int, path string) (int, string) {
	t.Helper()
	do := func(bearer string) (*http.Response, string) {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s:%d%s", fwHost(), port, path), nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Accept", ociAccept)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	resp, body := do("")
	if resp.StatusCode == http.StatusUnauthorized {
		if ch := resp.Header.Get("Www-Authenticate"); strings.HasPrefix(ch, "Bearer ") {
			resp, body = do(bearerFor(t, ch))
		}
	}
	return resp.StatusCode, body
}

// attestationDigests pulls the index through the gate and returns the digests of its
// attestation children, plus the count of platform children for the anti-vacuity check.
func attestationDigests(t *testing.T, port int, image string) (att []string, platforms int) {
	t.Helper()
	repo, ref, ok := strings.Cut(image, ":")
	if !ok {
		t.Fatalf("image %q has no tag", image)
	}
	code, body := fetchThroughGate(t, port, "/v2/"+repo+"/manifests/"+ref)
	if code != http.StatusOK {
		t.Fatalf("the index of %s came back %d, so the image itself is refused and nothing "+
			"below is about attestations\nbody: %s", image, code, tail(body, 5))
	}
	var idx struct {
		Manifests []ociIndexChild `json:"manifests"`
	}
	if err := json.Unmarshal([]byte(body), &idx); err != nil {
		t.Fatalf("parse index of %s: %v", image, err)
	}
	for _, c := range idx.Manifests {
		if strings.EqualFold(c.Platform.Architecture, "unknown") && strings.EqualFold(c.Platform.OS, "unknown") {
			att = append(att, c.Digest)
			continue
		}
		platforms++
	}
	return att, platforms
}

// repoOf drops the tag, giving the identity spelling a verdict line uses.
func repoOf(image string) string {
	repo, _, _ := strings.Cut(image, ":")
	return repo
}

// TestAttestationManifestIsServedForAnAllowedImage is #129 against a real registry, and
// it is deliberately independent of any client's cache.
//
// The daemon leg below can be short-circuited by content the daemon already holds --
// that is what made the first investigation of this chase the wrong endpoint. This leg
// asks the gate directly for the exact digests the index declares, so it exercises the
// path every time, on any machine.
func TestAttestationManifestIsServedForAnAllowedImage(t *testing.T) {
	bin := buildFirewall(t)
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":       "oci",
		"FW_SCORECARD_MODE":  "stub", // fixed 7.5; the decision must not hinge on a live score
		"FW_SCORE_THRESHOLD": "0",
		// The DEFAULT, stated rather than inherited: it is the whole defect. Under
		// FW_UNSCORABLE_POLICY=allow this leg passes with the fix reverted.
		"FW_UNSCORABLE_POLICY": "block",
	})

	att, platforms := attestationDigests(t, fw.port, attestedImage)
	if len(att) == 0 {
		t.Fatalf("%s declares no attestation children any more (%d platform children). "+
			"This leg cannot fail as written — pick an image that still ships them, or "+
			"the regression it guards is unguarded.", attestedImage, platforms)
	}
	if platforms == 0 {
		t.Fatalf("%s declares only attestation children, which is not a real index shape; "+
			"the parse is wrong", attestedImage)
	}
	t.Logf("%s: %d platform children, %d attestation children", attestedImage, platforms, len(att))

	repo, _, _ := strings.Cut(attestedImage, ":")
	for i, dig := range att {
		code, body := fetchThroughGate(t, fw.port, "/v2/"+repo+"/manifests/"+dig)
		if code != http.StatusOK {
			t.Fatalf("attestation manifest %d/%d (%s) = %d, want 200.\n"+
				"  This is a request a real `docker pull` makes, and refusing it fails the\n"+
				"  pull of an image the gate ALLOWED one request earlier. An attestation\n"+
				"  declares no source repo because it is not an image; it must inherit the\n"+
				"  verdict of the index that listed it (#129).\n  body: %s\n--- firewall ---\n%s",
				i+1, len(att), dig, code, tail(body, 6), logAround(fw.log.String(), 25))
		}
	}

	// The image itself must have been ALLOWED on its merits, or every 200 above could be
	// a gate that is not deciding anything.
	if fw.allowedCount() == 0 {
		t.Errorf("no allow decision was logged at all, so the 200s above do not show a "+
			"verdict being inherited\n%s", fw.log.String())
	}
}

// runDockerPull drives the REAL Docker daemon, which is the point of this file.
//
// 127.0.0.1 rather than host.docker.internal, and that is load-bearing: the daemon
// treats a loopback registry as insecure automatically, so this needs no
// --insecure-registry anywhere. The firewall container publishes its port on whichever
// daemon is in play, so loopback is correct both on a laptop and against dind.
func runDockerPull(t *testing.T, port int, image string) (int, string) {
	t.Helper()
	ref := fmt.Sprintf("127.0.0.1:%d/%s", port, image)
	// Drops the tag so the pull is a real resolve. It does NOT drop the content, which
	// is exactly the trap this file documents -- hence the assertion below that an
	// attestation actually reached the gate, rather than trusting a clean daemon.
	_ = exec.Command("docker", "rmi", "-f", ref).Run()

	cmd := exec.Command("docker", "pull", ref)
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatalf("could not run docker (is it installed/running?): %v\n%s", err, out)
	}
	return 0, string(out)
}

// TestRealDockerPullOfAnAllowedImageSucceeds is the leg whose absence let #129 ship.
//
// It asserts the thing a customer does, with the client a customer uses, at the gate's
// default settings -- and it checks that the daemon really did ask us about an
// attestation, because a daemon holding the content skips the index and would make this
// pass for free.
func TestRealDockerPullOfAnAllowedImageSucceeds(t *testing.T) {
	bin := buildFirewall(t)
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":         "oci",
		"FW_SCORECARD_MODE":    "stub",
		"FW_SCORE_THRESHOLD":   "0",
		"FW_UNSCORABLE_POLICY": "block",
	})

	att, _ := attestationDigests(t, fw.port, attestedImage)
	if len(att) == 0 {
		t.Skipf("%s ships no attestation manifests any more; the daemon leg would pass "+
			"without exercising anything", attestedImage)
	}

	code, out := runDockerPull(t, fw.port, attestedImage)
	if code != 0 {
		t.Fatalf("`docker pull %s` FAILED (exit %d).\n"+
			"  Every OCI leg using crane can be green while this is red: crane resolves one\n"+
			"  platform, the daemon also fetches the index's attestation manifests (#129).\n"+
			"--- docker ---\n%s\n--- firewall ---\n%s",
			attestedImage, code, tail(out, 12), logAround(fw.log.String(), 30))
	}

	// ANTI-VACUITY, and the reason this is not just "exit 0": a daemon that already holds
	// the content never fetches the index and never asks about an attestation, so the
	// pull would succeed without touching the path under test.
	//
	// It looks for the attestation as a VERDICT IDENTITY ("<repo>@<digest>"), not for the
	// digest anywhere in the log, and the difference is not pedantry. A cached daemon
	// asks "/v2/<repo>/referrers/<digest>" about content it already holds, which puts
	// that same digest in the log as a relayed path while no manifest was ever judged.
	// Written as a substring match this check passed with the fix REVERTED -- measured,
	// in the sabotage run, not reasoned about.
	log := fw.log.String()
	reached := ""
	for _, dig := range att {
		if strings.Contains(log, repoOf(attestedImage)+"@"+dig) {
			reached = dig
			break
		}
	}
	if reached == "" {
		// SKIPPED, NOT PASSED, and not failed either. The pull above really did succeed,
		// but this daemon answered it from content it already held -- it never fetched
		// the index, so it never asked about an attestation and the subject of this leg
		// was not exercised. Calling that a pass is the vacuity this whole file is about.
		//
		// It is a property of the MACHINE, not of the gate: CI runs against a fresh dind
		// with an empty content store and never takes this branch, so a skip here in a
		// pipeline means the daemon stopped fetching attestations and the leg needs
		// rethinking. On a laptop it is routine after the first run.
		//
		// The hard guard is TestAttestationManifestIsServedForAnAllowedImage, which asks
		// the gate for the same digests over HTTP and cannot be short-circuited by any
		// client's cache. It is measured red with the fix reverted.
		t.Skipf("`docker pull` succeeded, but this daemon served it from content it already "+
			"held and never asked the gate about any of the %d attestation manifests, so this "+
			"leg exercised nothing.\n"+
			"  `docker rmi` drops the TAG, not the content. To force a cold pull locally:\n"+
			"      docker image rm -f alpine:3.20\n"+
			"  The cache-proof assertion lives in TestAttestationManifestIsServedForAnAllowedImage.",
			len(att))
	}
	t.Logf("the daemon asked the gate about attestation %s, and the pull completed", reached)
}
