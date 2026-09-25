//go:build e2e

package e2e

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Adversarial e2e: the firewall under attack, not under use (issue #59).
//
// Every other leg in this suite drives the firewall the way a CUSTOMER does — a real
// npm/pip/docker client, doing an honest install. That is the right default, and it is
// also why a whole class of defect stayed invisible: an honest client never sends a
// hostile URL, so no honest-client test can tell you what happens when someone does.
// This file drives it the way an ATTACKER does.
//
// What it found the first time it ran: with lodash blocked and FW_BYTE_GATE=enforce,
// FW_UNSCORABLE_POLICY=block — the strictest posture we ship — the real 247KB lodash
// packument and the real 318KB tarball both came back through a firewall that returned
// 403 for the honest path. Full account in issue #59 and pathguard.go.
//
// The requests are written onto the socket BY HAND rather than through http.Client,
// which is not fussiness: a Go client is entitled to normalize what it sends, and a
// normalizing client would quietly repair the attack before it left the test and
// report a pass. The bytes on the wire are the thing under test.

// rawGet sends a single GET with the path written verbatim — no cleaning, no
// re-encoding — and returns the status code and body. This is what an attacker's
// curl, or a poisoned package-lock.json "resolved" URL, actually puts on the wire.
func rawGet(t *testing.T, host string, port int, rawPath string) (int, []byte) {
	t.Helper()
	code, _, body := rawGetHeaders(t, host, port, rawPath)
	return code, body
}

// rawGetHeaders is rawGet plus the response headers. Needed to tell WHO refused a
// request: the firewall's own refusals (403 writeBlock, 400 pathguard) always carry
// X-Yellowjack-Reason, and an upstream's 401/404 relayed back through us does not.
// Without that distinction an adversarial test scores an upstream's auth challenge as
// its own success — the request was never gated, it just failed for its own reasons.
// rawRequestHeaders is rawGetHeaders for an arbitrary METHOD, with an empty body.
// Needed by the #66 legs: a push is a POST/PATCH/PUT/DELETE, and the whole question is
// what the firewall does with a verb it does not serve. Written on the wire verbatim for
// the same reason rawGet is — an http.Client would be entitled to normalize the request
// before it left the test.
func rawRequestHeaders(t *testing.T, host string, port int, method, rawPath string) (int, http.Header, []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
	if err != nil {
		t.Fatalf("dial firewall: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	// Content-Length: 0 so the server does not wait for a body we are not sending.
	const crlf = "\r\n"
	req := method + " " + rawPath + " HTTP/1.1" + crlf +
		"Host: " + host + crlf +
		"Connection: close" + crlf +
		"Content-Length: 0" + crlf +
		"Accept: */*" + crlf + crlf
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write %s %q: %v", method, rawPath, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response for %s %q: %v", method, rawPath, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body for %s %q: %v", method, rawPath, err)
	}
	return resp.StatusCode, resp.Header, body
}

func rawGetHeaders(t *testing.T, host string, port int, rawPath string) (int, http.Header, []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
	if err != nil {
		t.Fatalf("dial firewall: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	req := "GET " + rawPath + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nAccept: */*\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write request %q: %v", rawPath, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response for %q: %v", rawPath, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body for %q: %v", rawPath, err)
	}
	return resp.StatusCode, resp.Header, body
}

// leaked reports whether a response body contains real package content — a packument
// or a gzip tarball. Checked by CONTENT, not by status code: the failure this guards
// against delivered a 200 that looked perfectly ordinary, so trusting the status is
// exactly the mistake that let it through.
func leaked(body []byte) string {
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		return "gzip tarball"
	}
	if strings.Contains(string(body), `"dist-tags"`) {
		return "npm packument"
	}
	if strings.Contains(string(body), `"versions"`) && len(body) > 10_000 {
		return "npm packument (versions map)"
	}
	return ""
}

// evasions are the request-path spellings that a package manager never emits and an
// attacker does. Each was MEASURED serving a blocked package's real bytes before
// pathguard.go existed; they are recorded here as the paths themselves, so this stays
// a test of behavior rather than a note about history.
var evasions = []struct {
	name string
	path string
}{
	{"empty segment", "//lodash"},
	{"trailing empty segment", "/lodash//"},
	{"dot segment (confused deputy)", "/express/../lodash"},
	{"encoded dot segment", "/express/%2e%2e/lodash"},
	{"encoded artifact marker", "/lodash/%2d/lodash-4.17.21.tgz"},
	{"uppercase encoded marker", "/lodash/%2D/lodash-4.17.21.tgz"},
	{"empty segment on the byte path", "//lodash/-/lodash-4.17.21.tgz"},
	{"dot segment on the byte path", "/express/../lodash/-/lodash-4.17.21.tgz"},
	{"encoded separator", "/lodash%2f..%2fexpress"},
	{"dot segment inside a scope", "/@foo%2f..%2flodash"},
}

// TestAdversarialPathsCannotBypassTheGate is the leak assertion: with every package
// blocked, no spelling of a request may return package content.
//
// Blocking EVERYTHING (stub mode scores a flat 7.5; the threshold sits above it) is
// what makes this drift-proof. An earlier draft used real deps.dev scores to make one
// package allowed and another blocked, which would have re-created issue #44's defect
// in a new place: real scores move, and a test whose meaning depends on express still
// out-scoring lodash is a future flake. Here the verdict is a property of the config.
func TestAdversarialPathsCannotBypassTheGate(t *testing.T) {
	bin := buildFirewall(t)
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":      "npm",
		"FW_SCORECARD_MODE": "stub", // flat 7.5 for every package — no score drift
		// Above the stub score, so EVERY package is blocked by policy, deterministically.
		"FW_SCORE_THRESHOLD":   "8.0",
		"FW_UNSCORABLE_POLICY": "block",
		"FW_UNVERIFIED_POLICY": "closed",
		"FW_BYTE_GATE":         "enforce", // the strictest posture we ship
	})

	// Anti-vacuity 1: the gate must actually be live and refusing. Without this, a
	// firewall that failed to start — or one that 500s every request — would satisfy
	// every "no leak" assertion below perfectly.
	if code, body := rawGet(t, fwHost(), fw.port, "/lodash"); code != http.StatusForbidden {
		t.Fatalf("control: honest GET /lodash returned %d, want 403 — the gate is not blocking, so the assertions below prove nothing\nbody: %s\n--- firewall ---\n%s",
			code, tail(string(body), 5), logAround(fw.log.String(), 20))
	}

	// Anti-vacuity 2: the firewall must still be able to RELAY. If it could not reach
	// or serve upstream content at all, "no package content came back" would be true
	// for reasons having nothing to do with the guard. npm's control plane is relayed
	// ungated by design, so it is the honest way to prove the pipe works.
	if code, _ := rawGet(t, fwHost(), fw.port, "/-/ping"); code != http.StatusOK {
		t.Fatalf("control: GET /-/ping returned %d, want 200 — the firewall cannot relay upstream at all, so a quiet response below would not mean the guard worked",
			code)
	}

	for _, ev := range evasions {
		t.Run(ev.name, func(t *testing.T) {
			code, body := rawGet(t, fwHost(), fw.port, ev.path)
			if what := leaked(body); what != "" {
				t.Errorf("GATE BYPASS: %s (%q) returned %d with %d bytes of %s for a package the firewall blocks (issue #59)",
					ev.name, ev.path, code, len(body), what)
				return
			}
			// A 2xx with no recognizable content is not a pass — it means the request
			// reached upstream and we simply did not recognize what came back. Say so
			// rather than scoring it green.
			if code >= 200 && code < 300 {
				t.Errorf("%s (%q) returned %d and was RELAYED (%d bytes); it must be refused before reaching upstream, not forwarded and hoped about\nbody: %s",
					ev.name, ev.path, code, len(body), tail(string(body), 3))
			}
		})
	}
}

// TestAdversarialPathsRefusedEvenWhenNothingIsBlocked is the discriminator, and the
// reason the test above can be believed.
//
// Every assertion in the leak test is satisfied by a firewall that refuses the whole
// world — "no package content came back" is also what a broken firewall produces. So
// this leg runs the SAME evasions against a firewall configured to allow EVERYTHING
// (threshold 0), where the honest path demonstrably serves real bytes. A refusal here
// cannot be a block verdict, because there are none: it can only be the path guard.
//
// Together the two legs pin the property from both sides — the evasions are refused,
// and they are refused for the right reason.
func TestAdversarialPathsRefusedEvenWhenNothingIsBlocked(t *testing.T) {
	bin := buildFirewall(t)
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":         "npm",
		"FW_SCORECARD_MODE":    "stub",
		"FW_SCORE_THRESHOLD":   "0", // allow everything
		"FW_UNSCORABLE_POLICY": "allow",
		"FW_UNVERIFIED_POLICY": "open-with-visibility",
		"FW_BYTE_GATE":         "off",
	})

	// The premise: with nothing blocked, the honest path really does hand over the
	// package. This is what makes a refusal below meaningful — and it is also the
	// proof that these evasion paths WOULD have leaked something worth having.
	code, body := rawGet(t, fwHost(), fw.port, "/lodash")
	if code != http.StatusOK || leaked(body) == "" {
		t.Fatalf("premise: honest GET /lodash returned %d with %d bytes and no recognizable packument; this leg needs a firewall that serves real content, or a refusal below proves nothing\n--- firewall ---\n%s",
			code, len(body), logAround(fw.log.String(), 20))
	}

	for _, ev := range evasions {
		t.Run(ev.name, func(t *testing.T) {
			code, body := rawGet(t, fwHost(), fw.port, ev.path)
			if code != http.StatusBadRequest {
				t.Errorf("%s (%q) returned %d, want 400: with NOTHING blocked, the only thing that may refuse this is the canonical-path guard — any other outcome means the guard is not what stopped it (issue #59)\nbody: %s",
					ev.name, ev.path, code, tail(string(body), 3))
			}
			if what := leaked(body); what != "" {
				t.Errorf("GATE BYPASS: %s (%q) returned %d bytes of %s", ev.name, ev.path, len(body), what)
			}
		})
	}
}

// TestHonestClientTrafficStillFlows is the compatibility half. A guard that refuses
// ambiguous paths is only shippable if it refuses nothing a real client sends, and
// the cheapest way to get a green adversarial suite is to break the product — so the
// canonical shapes are asserted here, through the running container, not just in the
// unit table.
func TestHonestClientTrafficStillFlows(t *testing.T) {
	bin := buildFirewall(t)
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":         "npm",
		"FW_SCORECARD_MODE":    "stub",
		"FW_SCORE_THRESHOLD":   "0",
		"FW_UNSCORABLE_POLICY": "allow",
		"FW_UNVERIFIED_POLICY": "open-with-visibility",
	})

	honest := []struct {
		name string
		path string
	}{
		{"plain packument", "/lodash"},
		{"name containing a dot", "/lodash.merge"},
		{"tarball, registry shape", "/lodash/-/lodash-4.17.21.tgz"},
		{"scoped, encoded separator", "/@babel%2fcore"},
		{"scoped, uppercase encoding", "/@babel%2Fcore"},
		{"control plane", "/-/ping"},
	}
	for _, h := range honest {
		t.Run(h.name, func(t *testing.T) {
			code, body := rawGet(t, fwHost(), fw.port, h.path)
			if code == http.StatusBadRequest {
				t.Errorf("REGRESSION: honest client path %s (%q) was refused by the canonical-path guard (400). Real clients send this — see pathguard.go's compatibility table\nbody: %s",
					h.name, h.path, tail(string(body), 3))
			}
		})
	}
}

// ───────────────────────── OCI blob path (issue #57) ─────────────────────────

// ociBlobEvasionPaths are blob-fetch spellings aimed at the bytes of a BLOCKED image
// by a route the gate might not recognise as a blob fetch. Anything unrecognised is
// relayed as registry infrastructure, which is a 200 with the layer and no decision
// line — the exact shape issue #57 was about, reachable again through spelling.
//
// The uppercase ones are here because they WORKED. When the OCI byte gate was first
// written, both parsers required a literal lowercase "v2/", so "/V2/…/blobs/…" fell
// through to the infrastructure relay and served a blocked image's layer in full.
// registry-1.docker.io happens to 404 that spelling, so this leg cannot demonstrate
// the leak against Docker Hub — the unit twin in ../oci_bytegate_test.go does that
// with an upstream that answers. What this leg proves is the half a unit test cannot:
// that the REAL firewall, over a real socket, with no client library tidying the path
// on the way out, refuses them before they reach the upstream at all.
var ociBlobEvasionPaths = []struct{ name, path string }{
	{"uppercase API prefix", "/V2/library/alpine/blobs/" + alpineLayer},
	{"uppercase separator", "/v2/library/alpine/Blobs/" + alpineLayer},
	{"mixed-case separator", "/v2/library/alpine/bLoBs/" + alpineLayer},
	{"empty segment", "//v2/library/alpine/blobs/" + alpineLayer},
	{"dot segment (confused deputy)", "/v2/library/nginx/../alpine/blobs/" + alpineLayer},
	{"encoded separator in the name", "/v2/library%2falpine/blobs/" + alpineLayer},
	{"trailing slash", "/v2/library/alpine/blobs/" + alpineLayer + "/"},
	{"name containing \"blobs\"", "/v2/library/alpine/blobs/x/blobs/" + alpineLayer},
}

// TestAdversarialOciBlobPathsCannotBypassTheGate is the tier-3 leg for issue #57.
//
// Assertion is on CONTENT — a layer is a gzip'd tar, so leaked() recognises it — and
// on the firewall having REFUSED rather than relayed. A 2xx that we simply cannot
// identify is scored as a failure, not a pass: it means the request reached the
// upstream, which is the thing being prevented.
func TestAdversarialOciBlobPathsCannotBypassTheGate(t *testing.T) {
	bin := buildFirewall(t)
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":      "oci",
		"FW_SCORECARD_MODE": "stub", // flat 7.5 — no score drift
		// Above the stub score, so every image is blocked deterministically by policy.
		"FW_SCORE_THRESHOLD":   "9.9",
		"FW_UNSCORABLE_POLICY": "block",
		"FW_UNVERIFIED_POLICY": "closed",
		"FW_BYTE_GATE":         "enforce", // strictest posture we ship
	})

	// Anti-vacuity: the gate must actually be refusing the honest path, or "no layer
	// came back" below is satisfied by a firewall that refuses everything for any
	// reason at all.
	if code, body := rawGet(t, fwHost(), fw.port, "/v2/library/alpine/manifests/3.20"); code != http.StatusForbidden {
		t.Fatalf("control: honest manifest GET returned %d, want 403 — the gate is not blocking, so nothing below proves anything\nbody: %s\n--- firewall ---\n%s",
			code, tail(string(body), 5), logAround(fw.log.String(), 20))
	}

	for _, ev := range ociBlobEvasionPaths {
		t.Run(ev.name, func(t *testing.T) {
			code, hdr, body := rawGetHeaders(t, fwHost(), fw.port, ev.path)
			if what := leaked(body); what != "" {
				t.Errorf("GATE BYPASS: %s (%q) returned %d with %d bytes of %s for an image the firewall blocks (issue #57)",
					ev.name, ev.path, code, len(body), what)
				return
			}
			if code >= 200 && code < 300 {
				t.Errorf("%s (%q) returned %d and was RELAYED (%d bytes) — a blob request for a blocked image must be refused before reaching the upstream, not forwarded and hoped about\nbody: %s",
					ev.name, ev.path, code, len(body), tail(string(body), 3))
			}
			// WHO refused matters as much as THAT it was refused, and this is the
			// assertion that makes this leg mean anything. Docker Hub answers an
			// unauthenticated blob GET with 401 and an unknown path with 404, so a
			// relayed-and-rejected request looks superficially identical to a gated
			// one — non-2xx, no payload. Only the firewall sets X-Yellowjack-Reason,
			// so requiring it is what distinguishes "we blocked this" from "we passed
			// it upstream and the registry happened to say no".
			if hdr.Get("X-Yellowjack-Reason") == "" {
				t.Errorf("%s (%q) returned %d, but with NO X-Yellowjack-Reason header: the "+
					"firewall did not refuse this — it forwarded it and the upstream did. "+
					"The request was never gated, so this cell is a bypass that only looks "+
					"clean because Docker Hub rejected it for its own reasons.\nbody: %s",
					ev.name, ev.path, code, tail(string(body), 3))
			}
		})
	}
}

// TestAdversarialOciHonestBlobStillFlows is the compatibility half, and the
// discriminator for the leg above.
//
// The cheapest way to make an adversarial suite green is to break the product, and a
// byte gate that refuses every blob would satisfy every assertion above perfectly. So
// this allows everything and proves the honest blob path still delivers a real layer —
// which simultaneously establishes that those evasion paths were aimed at something
// worth having.
//
// It uses `crane`, NOT rawGet, and that is load-bearing rather than a style choice.
// registry-1.docker.io requires a bearer token for a blob, obtained by following the
// 401 challenge to auth.docker.io; crane does that dance, a hand-written socket write
// does not. A rawGet here returns 401 from the UPSTREAM and would read as "the gate
// broke the honest path" when the gate never saw a problem — a false failure that
// invites someone to "fix" a firewall that was working. Hand-written requests are the
// right tool for the attack legs, where the point is to defeat client normalization;
// they are the wrong tool for the compatibility leg, where the point is to behave like
// a real client.
func TestAdversarialOciHonestBlobStillFlows(t *testing.T) {
	bin := buildFirewall(t)
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":         "oci",
		"FW_SCORECARD_MODE":    "stub",
		"FW_SCORE_THRESHOLD":   "0", // allow everything
		"FW_UNSCORABLE_POLICY": "allow",
		"FW_UNVERIFIED_POLICY": "open-with-visibility",
		"FW_BYTE_GATE":         "enforce", // gate ON, verdict ALLOW: the gate must pass real traffic
	})

	n, exit, stderr := runCraneBlob(t, fw.port, "library/alpine@"+alpineLayer)
	if n == 0 || exit != 0 {
		t.Fatalf("REGRESSION: the honest blob path delivered %d bytes (crane exit %d) with the "+
			"gate enforcing and NOTHING blocked.\n"+
			"The byte gate must GATE blob fetches, not break them — an allowed image's layer has to flow.\n"+
			"crane stderr: %s\n--- firewall ---\n%s",
			n, exit, tail(stderr, 5), logAround(fw.log.String(), 20))
	}
	t.Logf("honest blob path delivered %d bytes of a real layer with FW_BYTE_GATE=enforce", n)
}

// ─────────────────── the classification gate (issue #58 increment 2) ───────────────────

// unclassifiedPaths resolve to NO package identity AND are not in the OCI
// control-plane enumeration. Before increment 2 every one of them was relayed to
// the upstream registry with no decision evaluated and no decision logged — the
// implicit default-ALLOW that #11, #56, #57 and #59 each rode in on.
//
// They are chosen to be things an attacker or a curious client would actually try,
// not synthetic garbage: a registry-wide catalog listing, the case-variant spelling
// that defeated the manifest gate before !76, and a push endpoint on a pull-through
// gate.
//
// THE REFERRERS API USED TO BE IN THIS LIST AND HAS MOVED, not been deleted. It is now
// enumerated control-plane infrastructure and is asserted in the opposite direction by
// TestAdversarialReferrersIsRelayedAsInfrastructure below. The argument for the move is
// there; the reason it is called out here is that shrinking an adversarial list is
// exactly how coverage disappears, so a reader who wonders where it went should be able
// to find the answer without a git blame.
var unclassifiedPaths = []struct {
	name string
	path string
}{
	{"registry catalog listing", "/v2/_catalog"},
	{"case-variant of the version handshake", "/V2/"},
	{"case-variant of a tag listing", "/V2/library/alpine/tags/list"},
	{"unrelated registry endpoint", "/v2/library/alpine/some-future-api"},
}

// TestAdversarialUnknownPathsAreRefused pins the default inversion: a request the
// gate cannot name a package for, and cannot justify as infrastructure, is REFUSED
// rather than forwarded.
//
// Asserted on the firewall's own refusal marker (X-Yellowjack-Reason), not merely on
// a non-2xx. A registry answering 401/404 for its own reasons would otherwise score
// as a pass while the request had in fact been relayed straight through us — the
// request was never gated, it just failed once it got there.
func TestAdversarialUnknownPathsAreRefused(t *testing.T) {
	bin := buildFirewall(t)
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":      "oci",
		"FW_SCORECARD_MODE": "stub",
		// Permissive on purpose. The classification gate must hold on its own, NOT
		// because everything happens to be blocked by score — with the threshold at 0
		// a refusal below cannot be a verdict about a package.
		"FW_SCORE_THRESHOLD":   "0",
		"FW_UNSCORABLE_POLICY": "allow",
	})

	// Anti-vacuity: the enumerated control plane must still work. If the firewall
	// refused everything, every assertion below would pass for the wrong reason —
	// and this is also the exact regression that would break `docker pull`.
	if code, _ := rawGet(t, fwHost(), fw.port, "/v2/"); code != http.StatusOK && code != http.StatusUnauthorized {
		t.Fatalf("control: GET /v2/ returned %d, want 200 or 401 (relayed to the registry) — the control-plane enumeration is broken, so the refusals below prove nothing\n--- firewall ---\n%s",
			code, logAround(fw.log.String(), 20))
	}

	for _, tc := range unclassifiedPaths {
		t.Run(tc.name, func(t *testing.T) {
			code, hdr, body := rawGetHeaders(t, fwHost(), fw.port, tc.path)
			if hdr.Get("X-Yellowjack-Reason") == "" {
				t.Errorf("UNGATED RELAY: %s (%q) returned %d with no X-Yellowjack-Reason — the firewall did not decide this request, it forwarded it (issue #58)\nbody: %s",
					tc.name, tc.path, code, tail(string(body), 3))
			}
			if code != http.StatusForbidden {
				t.Errorf("%s (%q) returned %d, want 403", tc.name, tc.path, code)
			}
		})
	}
}

// TestAdversarialReferrersIsRelayedAsInfrastructure asserts the OPPOSITE of what this
// file asserted for the referrers API until #129, and the inversion is deliberate.
//
// WHY IT MOVED. #58's rule is that a request carrying no package identity is refused
// UNLESS it is enumerated infrastructure. The question is therefore not "is referrers
// unclassified" — it was, and that was the defect — but "does it belong in the
// enumeration". It does, for the same reasons tags/list does:
//
//   - it is a LISTING. The response is a JSON index of manifest DESCRIPTORS, never
//     image bytes;
//   - every manifest it names is still gated when the client goes on to fetch it, so
//     it opens no route to content;
//   - it discloses nothing of ours. The body is the registry's own data, and no policy
//     name, rule or FW_* setting appears in it (the D182 disclosure rule).
//
// WHAT IT COST TO LEAVE OUT. A Docker daemon that already holds an image's content does
// not fetch the index — it asks referrers about a digest it holds — so the refusal
// killed `docker pull` for any partially cached image, with "unrecognized request path".
//
// The assertion is on the ABSENCE of our refusal marker rather than on a status code,
// because the upstream registry answers this path however it likes (200 with an empty
// list, 401, 404); what must be true is that WE did not decide it.
func TestAdversarialReferrersIsRelayedAsInfrastructure(t *testing.T) {
	bin := buildFirewall(t)
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":      "oci",
		"FW_SCORECARD_MODE": "stub",
		// Same permissive settings as the refusal test above, so a relay here cannot be
		// explained by policy being loose in some other way.
		"FW_SCORE_THRESHOLD":   "0",
		"FW_UNSCORABLE_POLICY": "allow",
	})

	// Anti-vacuity FIRST, and it is the whole reason this leg is trustworthy: a gate
	// that refused nothing would relay referrers too. So a path that MUST still be
	// refused is checked in the same process, with the same settings.
	const stillRefused = "/v2/_catalog"
	if _, hdr, _ := rawGetHeaders(t, fwHost(), fw.port, stillRefused); hdr.Get("X-Yellowjack-Reason") == "" {
		t.Fatalf("control: %s was NOT refused, so this firewall is not classifying anything "+
			"and a relayed referrers proves nothing\n--- firewall ---\n%s",
			stillRefused, logAround(fw.log.String(), 20))
	}

	const referrers = "/v2/library/alpine/referrers/sha256:" +
		"0000000000000000000000000000000000000000000000000000000000000000"
	code, hdr, body := rawGetHeaders(t, fwHost(), fw.port, referrers)
	if r := hdr.Get("X-Yellowjack-Reason"); r != "" {
		t.Errorf("the referrers API was REFUSED by us (%d): %q\n"+
			"  It is enumerated infrastructure: a listing of manifest descriptors, with every\n"+
			"  manifest it names still gated on fetch. Refusing it breaks `docker pull` for any\n"+
			"  image whose content the daemon already holds (#129).\nbody: %s",
			code, r, tail(string(body), 3))
	}
}

// TestAdversarialUnknownPathsRelayWhenPolicyAllows is the discriminator, and the
// reason the test above can be believed.
//
// "Nothing came back" is also what a firewall that refuses the whole world produces.
// So this leg runs the SAME paths with FW_UNKNOWN_PATH_POLICY=allow — the pre-#58
// behaviour, kept as an escape hatch — where they must once again reach the upstream
// registry. If they are refused HERE too, then the refusals above were not the
// classification gate and the first test is measuring something else.
func TestAdversarialUnknownPathsRelayWhenPolicyAllows(t *testing.T) {
	bin := buildFirewall(t)
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":           "oci",
		"FW_SCORECARD_MODE":      "stub",
		"FW_SCORE_THRESHOLD":     "0",
		"FW_UNSCORABLE_POLICY":   "allow",
		"FW_UNKNOWN_PATH_POLICY": "allow", // explicitly back to the old behaviour
	})

	for _, tc := range unclassifiedPaths {
		t.Run(tc.name, func(t *testing.T) {
			_, hdr, _ := rawGetHeaders(t, fwHost(), fw.port, tc.path)
			// The firewall stamps X-Yellowjack-Reason on its OWN refusals only. Its
			// absence is the signal the request was relayed — whatever the registry
			// then chose to answer, which is not ours to predict.
			if reason := hdr.Get("X-Yellowjack-Reason"); reason != "" {
				t.Errorf("%s (%q) was still refused under FW_UNKNOWN_PATH_POLICY=allow (reason %q) — so the refusal in the sibling test was NOT the classification gate, and that test proves nothing",
					tc.name, tc.path, reason)
			}
		})
	}
}

// TestOciBlobUploadPathsRouteToTheByteGate records a tier-3 finding about issue #58
// increment 2, and exists so the behaviour cannot change silently.
//
// "/v2/<name>/blobs/uploads/..." LOOKS like it should be an unclassified path, and
// an earlier draft of the classification work asserted exactly that. It is not.
// ociBlobPath splits on the LAST "/blobs/", so an upload path yields the image name
// and is claimed by the BYTE GATE — Yellow Jack evaluates a push as though it were a
// download of that image's bytes.
//
// The consequence that matters is the one asserted here: a push to a BLOCKED image
// is refused by the firewall, with its own reason header. What this test deliberately
// does NOT claim is that relaying push traffic at all is the right posture for a
// pull-through gate — that question is filed, not settled.
func TestOciBlobUploadPathsRouteToTheByteGate(t *testing.T) {
	const uploadPath = "/v2/library/alpine/blobs/uploads/"

	bin := buildFirewall(t)
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":      "oci",
		"FW_SCORECARD_MODE": "stub", // flat 7.5
		// Above the stub score: every image is blocked, so a refusal below is a
		// verdict about the image and not an accident of the registry's auth.
		"FW_SCORE_THRESHOLD":   "9.9",
		"FW_UNSCORABLE_POLICY": "block",
		"FW_BYTE_GATE":         "allow-but-log", // the DEFAULT; a hard deny still blocks bytes (D72)
	})

	code, hdr, body := rawGetHeaders(t, fwHost(), fw.port, uploadPath)
	if hdr.Get("X-Yellowjack-Reason") == "" {
		t.Errorf("upload path %q returned %d with no X-Yellowjack-Reason — the firewall relayed a push for a BLOCKED image instead of deciding it\nbody: %s",
			uploadPath, code, tail(string(body), 3))
	}
	if code != http.StatusForbidden {
		t.Errorf("upload path %q returned %d, want 403 for a blocked image", uploadPath, code)
	}
}

// TestAdversarialDefaultByteGateRefusesAHardDenyWithoutLeakingPolicy is the tier-3 leg
// for issue #58 increment 4, which moved FW_BYTE_GATE's allow-vs-refuse decision onto an
// ordered ruleset.
//
// It targets the DEFAULT posture on purpose. Every other byte-gate test above runs at
// FW_BYTE_GATE=enforce — the strictest setting we ship — but almost nobody deploys that,
// because the shipped default is allow-but-log. The one thing that default still refuses
// is D72's carve-out: a package denied on a POSITIVE FINDING has its bytes blocked even
// in visibility mode. That carve-out is now a line of policy rather than an inlined
// predicate, so it is worth proving from outside the process that moving it did not
// quietly turn the default deployment into a pass-through.
//
// FW_BYTE_GATE is left UNSET rather than spelled out, so this tests what an operator who
// configures nothing actually gets.
//
// Second thing it checks: the increment put the RULE NAME into the byte gate's log lines.
// Rule names carry policy internals ("FW_BYTE_GATE=allow-but-log", "block everything"),
// and a refusal is exactly where an attacker probes for a description of the gate they
// are up against. So the name must reach the log and NOT the client — asserted in both
// directions, because only checking one of them would pass for the wrong reason.
func TestAdversarialDefaultByteGateRefusesAHardDenyWithoutLeakingPolicy(t *testing.T) {
	const tarball = "/lodash/-/lodash-4.17.21.tgz"

	bin := buildFirewall(t)
	shipped := map[string]string{
		"FW_ECOSYSTEM":      "npm",
		"FW_SCORECARD_MODE": "stub", // flat 7.5 for every package — no score drift
		// Above the stub score, so lodash is denied on a SCORE — denyScore, a hard deny.
		// This is the kind the visibility default still refuses; an unscorable package
		// would be served here, and picking that one would test the opposite property.
		"FW_SCORE_THRESHOLD":   "8.0",
		"FW_UNSCORABLE_POLICY": "block",
		"FW_UNVERIFIED_POLICY": "closed",
		// FW_BYTE_GATE deliberately absent — the default is the subject of this test.
	}
	fw := startFirewall(t, bin, shipped)

	// Anti-vacuity: the gate is live, and the firewall can still reach upstream. Without
	// both, "no tarball came back" is satisfied by a firewall that is simply broken.
	if code, body := rawGet(t, fwHost(), fw.port, "/lodash"); code != http.StatusForbidden {
		t.Fatalf("control: honest GET /lodash returned %d, want 403 — the metadata gate is not blocking, so nothing below proves anything\nbody: %s\n--- firewall ---\n%s",
			code, tail(string(body), 5), logAround(fw.log.String(), 20))
	}
	if code, _ := rawGet(t, fwHost(), fw.port, "/-/ping"); code != http.StatusOK {
		t.Fatalf("control: GET /-/ping returned %d, want 200 — the firewall cannot relay at all", code)
	}

	code, body := rawGet(t, fwHost(), fw.port, tarball)
	if what := leaked(body); what != "" {
		t.Errorf("BYTE GATE BYPASS: %s returned %d with %d bytes of %s at the SHIPPED DEFAULT — "+
			"a hard deny must block bytes in every mode (D72)\n--- firewall ---\n%s",
			tarball, code, len(body), what, logAround(fw.log.String(), 25))
	}

	// The rule name belongs in the log...
	if log := fw.log.String(); !strings.Contains(log, "BLOCKED by rule") {
		t.Errorf("the byte gate refused without naming the rule that did it — the operator's "+
			"only handle on WHY is missing, and it is also how we know the ruleset decided "+
			"this rather than a leftover inline predicate\n--- firewall ---\n%s", tail(log, 25))
	}
	// ...and nowhere near the client.
	for _, internal := range []string{"FW_BYTE_GATE", "block everything", "allow-but-log:", "terminal:", "reject:"} {
		if strings.Contains(string(body), internal) {
			t.Errorf("POLICY DISCLOSURE: the client-facing block body contains %q — rule names and "+
				"knob names describe the gate to whoever is probing it, and belong in the log only\nbody: %s",
				internal, tail(string(body), 5))
		}
	}

	// The discriminator. Same binary, same verdict, ONE knob different: FW_BYTE_GATE=off.
	// If that leg does not deliver real tarball bytes, then the refusal above was not the
	// byte gate doing its job — it was the harness unable to fetch a tarball at all, and
	// every assertion in this test would pass for a reason that has nothing to do with
	// policy. Keeping the threshold at 8.0 is the point: the package is still BLOCKED at
	// metadata in this leg, so the only thing that changed is which byte-gate ruleset ran.
	permissive := map[string]string{}
	for k, v := range shipped {
		permissive[k] = v
	}
	permissive["FW_BYTE_GATE"] = "off"
	off := startFirewall(t, bin, permissive)

	offCode, offBody := rawGet(t, fwHost(), off.port, tarball)
	if what := leaked(offBody); what == "" {
		t.Fatalf("DISCRIMINATOR FAILED: with FW_BYTE_GATE=off, %s returned %d and %d bytes that are "+
			"not a tarball. The escape hatch must serve the bytes, so this test cannot tell a working "+
			"gate from a broken fetch — treat the assertions above as unproven\nbody: %s\n--- firewall ---\n%s",
			tarball, offCode, len(offBody), tail(string(offBody), 5), tail(off.log.String(), 25))
	} else {
		t.Logf("discriminator: FW_BYTE_GATE=off delivered %d bytes of %s for the same blocked package, "+
			"so the default-mode refusal above is the gate's doing", len(offBody), what)
	}
}

// TestAdversarialOciPushIsRefused is the tier-3 leg for issue #66.
//
// Found by the tier-3 pass on #58: `ociBlobPath` splits on the LAST "/blobs/", so an
// UPLOAD path parses as a perfectly good blob path and was handed to the byte gate to be
// judged on the image's PULL score. When that score passed, the push was relayed to the
// real registry. A pull-through firewall was acting as a push-through proxy.
//
// Asserted on CONTENT and on the response's ORIGIN, not on the status code alone: the
// upstream registry answers 401 to an unauthenticated push on its own account, so "not a
// 200" is satisfied by the very bug this test exists to catch. The X-Yellowjack-Reason
// header is what distinguishes "we refused it" from "we forwarded it and the registry
// refused it" — and those are opposite outcomes wearing similar clothes.
func TestAdversarialOciPushIsRefused(t *testing.T) {
	pushes := []struct{ name, method, path string }{
		{"start blob upload", http.MethodPost, "/v2/library/alpine/blobs/uploads/"},
		{"chunked blob upload", http.MethodPatch, "/v2/library/alpine/blobs/uploads/abc-123"},
		{"finalise blob upload", http.MethodPut, "/v2/library/alpine/blobs/uploads/abc-123"},
		{"push manifest", http.MethodPut, "/v2/library/alpine/manifests/latest"},
		{"delete manifest", http.MethodDelete, "/v2/library/alpine/manifests/latest"},
	}

	bin := buildFirewall(t)
	// THRESHOLD 0 — every image is ALLOWED. That is the configuration in which the bug
	// actually delivered: a blocked image's push was refused as a side effect of the
	// score, which looks correct for the wrong reason. Only with nothing blocked does
	// this test measure the write policy rather than the verdict.
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":       "oci",
		"FW_UPSTREAM":        "https://registry-1.docker.io",
		"FW_SCORECARD_MODE":  "stub",
		"FW_SCORE_THRESHOLD": "0",
		// FW_WRITE_POLICY deliberately unset: this is the shipped default.
	})

	for _, p := range pushes {
		t.Run(p.name, func(t *testing.T) {
			code, hdr, body := rawRequestHeaders(t, fwHost(), fw.port, p.method, p.path)
			if hdr.Get("X-Yellowjack-Reason") == "" {
				t.Errorf("PUSH RELAYED: %s %s returned %d with no X-Yellowjack-Reason, so the "+
					"refusal came from the upstream registry, not from us — the firewall forwarded "+
					"a write (#66)\nbody: %s", p.method, p.path, code, tail(string(body), 3))
				return
			}
			if code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s = %d, want 405 (body: %s)", p.method, p.path, code, tail(string(body), 3))
			}
			if got := hdr.Get("Allow"); got != "GET, HEAD" {
				t.Errorf("%s %s: Allow = %q, want %q", p.method, p.path, got, "GET, HEAD")
			}
		})
	}

	// Anti-vacuity: the same firewall must still serve READS. Without this, a firewall
	// that refuses everything — or one that failed to start — satisfies every assertion
	// above perfectly.
	if code, _ := rawGet(t, fwHost(), fw.port, "/v2/"); code != http.StatusOK && code != http.StatusUnauthorized {
		t.Fatalf("control: GET /v2/ returned %d, want 200 or 401 — the firewall is not relaying reads, "+
			"so the refusals above prove nothing", code)
	}
}

// TestAdversarialOciPushRelaysWhenPolicyAllows is the discriminator for the test above.
//
// Same binary, same everything, one knob different. The escape hatch must genuinely reach
// the upstream registry — which then answers on its own account, with no
// X-Yellowjack-Reason, because the client has no push credentials. If this leg does not
// reach upstream, the refusals above cannot be attributed to the write policy.
func TestAdversarialOciPushRelaysWhenPolicyAllows(t *testing.T) {
	bin := buildFirewall(t)
	fw := startFirewall(t, bin, map[string]string{
		"FW_ECOSYSTEM":       "oci",
		"FW_UPSTREAM":        "https://registry-1.docker.io",
		"FW_SCORECARD_MODE":  "stub",
		"FW_SCORE_THRESHOLD": "0",
		"FW_WRITE_POLICY":    "allow", // the pre-#66 passthrough
	})

	code, hdr, body := rawRequestHeaders(t, fwHost(), fw.port, http.MethodPost, "/v2/library/alpine/blobs/uploads/")
	if hdr.Get("X-Yellowjack-Reason") != "" || code == http.StatusMethodNotAllowed {
		t.Fatalf("DISCRIMINATOR FAILED: FW_WRITE_POLICY=allow still refused the push (%d, reason=%q). "+
			"The escape hatch does not work, and the refusal test cannot be attributed to the policy\nbody: %s",
			code, hdr.Get("X-Yellowjack-Reason"), tail(string(body), 3))
	}
	t.Logf("discriminator: FW_WRITE_POLICY=allow relayed the push; upstream answered %d on its own account", code)
}
