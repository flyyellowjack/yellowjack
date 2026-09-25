package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Maven's gate USED TO BE an extension allowlist: mavenEcosystem.PackageNameFromPath
// returned a package identity only for files ending .jar/.pom/.aar/.war, and "" for
// everything else — which proxy.go treats as "not an identifiable package request" and
// passes through UNGATED.
//
// Nobody had tested what fell outside that allowlist. These tests did, and answered it
// the only way that counts: with a fake upstream that RECORDS which paths it was asked
// for. Checking the status the client saw is not enough — a 403 with the bytes already
// fetched upstream is still a bypass, and an ungated pass-through is a 200 with the
// bytes delivered. All ten extensions tested walked straight through.
//
// Issue #56 inverted the default: the gate now keys on the GAV PATH SHAPE with a short
// exclusion list (see mavenUngatedFile), so an unknown packaging is gated rather than
// relayed. These tests are the regression guard for that, and the tier-3 table below
// (mavenGateEvasions) is the record of three separate attempts at the fix that were
// each defeated by a chosen filename.
//
// The package under test is scored BELOW the threshold, i.e. a POSITIVE FINDING
// (denyBelowThreshold), not merely unscorable. That distinction matters: D72 made
// npm's byte enforcement follow the denial KIND precisely so a positive finding
// holds on every path that can deliver bytes. If a positive finding does not hold
// on Maven's byte paths, that is the Maven twin of issue #11.

// mavenSpyUpstream is a fake Maven Central that serves a single artifact in many
// packagings and records every path it is asked for. The recorder is the bypass
// detector: contact for an artifact path while the package is blocked means the
// bytes left the upstream regardless of what the client was ultimately told.
type mavenSpyUpstream struct {
	*httptest.Server
	mu  sync.Mutex
	hit []string
}

// gav of the artifact under test. "com.evil:badlib" scores below the test threshold.
const (
	spyGroupPath = "com/evil/badlib"
	spyArtifact  = "badlib"
	spyVersion   = "1.0.0"
)

// artifactBytes is the payload every non-metadata path serves. Tests assert on this
// exact string, so a body carrying it is proof the artifact's BYTES were delivered —
// not merely that some status code came back.
const artifactBytes = "PAYLOAD-DELIVERED"

func newMavenSpyUpstream() *mavenSpyUpstream {
	u := &mavenSpyUpstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hit = append(u.hit, r.URL.Path)
		u.mu.Unlock()

		switch {
		case strings.HasSuffix(r.URL.Path, "/maven-metadata.xml"):
			fmt.Fprintf(w, `<metadata><versioning><release>%s</release></versioning></metadata>`, spyVersion)
		case strings.HasSuffix(r.URL.Path, ".pom"):
			// A real, resolvable SCM so the package is SCORED (7.5 in stub mode) —
			// this is a positive finding below threshold, never "unscorable".
			fmt.Fprint(w, `<project><scm><url>https://github.com/evil/badlib</url></scm></project>`)
		default:
			fmt.Fprint(w, artifactBytes)
		}
	}))
	return u
}

// contacted reports whether the upstream was asked for any path containing sub.
func (u *mavenSpyUpstream) contacted(sub string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, p := range u.hit {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

// newMavenTestProxy builds a proxy gating the "maven" ecosystem against upstream,
// with a threshold the stub score (7.5) cannot meet — so every artifact of the
// package is a positive-finding denial.
func newMavenTestProxy(t *testing.T, upstream *httptest.Server) *proxyServer {
	t.Helper()
	return newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "maven"
		c.ScoreThreshold = 9.9 // stub scores 7.5 -> below threshold -> hard deny
		c.ByteGate = byteGateEnforce
	})
}

// get drives one request through the proxy and returns status and body.
func get(t *testing.T, p *proxyServer, path string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://firewall.local:8080"+path, nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// TestMavenGatedExtensionIsBlocked is the negative control AND, since issue #56 was
// fixed, the regression guard for every packaging that used to walk past the gate.
//
// It began as a control for one extension (.jar) proving the rig could detect a
// working gate. The ten extensions below were then in a separate CHARACTERIZATION
// test asserting they bypassed; as the fix gated each one, each moved into this
// table — which is what the issue's definition of done asked for, and what makes the
// old bypass a permanent assertion instead of a closed ticket.
func TestMavenGatedExtensionIsBlocked(t *testing.T) {
	// The original allowlist, plus every extension that used to bypass it. There is
	// nothing special about these ten now — the gate keys on the PATH SHAPE, so this
	// list is a sample of packagings, not an enumeration the code depends on. That is
	// the point of the fix: an extension nobody has thought of is gated too, which
	// TestMavenUnknownPackagingIsGatedByDefault asserts directly.
	gated := []string{
		".jar", ".pom", ".aar", ".war", // the old allowlist
		".module", ".zip", ".tar.gz", ".ear", ".nar", ".jmod", // issue #56
		".exe", ".dll", ".so", ".dylib",
	}

	for _, ext := range gated {
		t.Run(strings.TrimPrefix(ext, "."), func(t *testing.T) {
			up := newMavenSpyUpstream()
			defer up.Close()
			p := newMavenTestProxy(t, up.Server)

			path := fmt.Sprintf("/%s/%s/%s-%s%s", spyGroupPath, spyVersion, spyArtifact, spyVersion, ext)
			code, body := get(t, p, path)

			if code == http.StatusOK {
				t.Fatalf("%s of a below-threshold package returned 200 — issue #56 has "+
					"REGRESSED; body=%q", ext, body)
			}
			if strings.Contains(body, artifactBytes) {
				t.Errorf("%s body carried the artifact payload despite status %d", ext, code)
			}
			// The upstream must not have been asked for the artifact either: a denial
			// with the bytes already fetched is still a bypass, just a quieter one.
			//
			// .pom is deliberately exempt from THIS half, and the reason is worth
			// knowing before "fixing" it: the firewall fetches the POM itself, during
			// LookupRepo, to read the <scm> URL it scores. So the upstream legitimately
			// sees a .pom request — ours, not the client's. The client's copy is still
			// refused, which the two assertions above cover.
			if ext != ".pom" && up.contacted(ext) {
				t.Errorf("BYPASS: upstream was contacted for the %s of a blocked package "+
					"(bytes fetched even though the client saw a denial)", ext)
			}
		})
	}
}

// TestMavenUnknownPackagingIsGatedByDefault is the assertion that the fix actually
// changed the SHAPE of the gate rather than just lengthening a list.
//
// An extension allowlist would pass every one of these, because nobody has ever heard
// of them — which is precisely how .module and .dll walked through for so long. Under
// a path-shape gate they are gated for the same reason a .jar is: they sit at
// group/artifact/version/artifact-version.*, so they are artifacts.
//
// If someone ever reintroduces an allowlist, this test fails without needing to have
// predicted which extension they forgot.
func TestMavenUnknownPackagingIsGatedByDefault(t *testing.T) {
	invented := []string{
		".rar",         // a real Java EE resource adapter archive, simply never listed
		".apk", ".aab", // Android outputs published to Maven repos
		".whatever", // no such packaging — the point is that it does not matter
		".bin", ".tar.bz2",
	}

	for _, ext := range invented {
		t.Run(strings.TrimPrefix(ext, "."), func(t *testing.T) {
			up := newMavenSpyUpstream()
			defer up.Close()
			p := newMavenTestProxy(t, up.Server)

			path := fmt.Sprintf("/%s/%s/%s-%s%s", spyGroupPath, spyVersion, spyArtifact, spyVersion, ext)
			code, body := get(t, p, path)

			if strings.Contains(body, artifactBytes) || up.contacted(ext) {
				t.Errorf("a blocked package's bytes were reachable via the unlisted packaging %s "+
					"(status=%d) — the gate is keying on an extension list again, so every "+
					"packaging nobody enumerated is fail-OPEN (issue #56)", ext, code)
			}
		})
	}
}

// TestMavenNonArtifactFilesStillPass is the COMPATIBILITY half, and it is what stops
// the fix above from being "gate everything and call it secure".
//
// Inverting a gate's default is easy to overdo: gate maven-metadata.xml and a resolve
// cannot even discover versions, so nothing resolves at all and the firewall looks
// broken rather than strict. These are the files that must keep flowing, and each is
// safe to pass for a stated reason, not by habit.
//
// DIRECTORY LISTINGS ARE DELIBERATELY ABSENT from this list, though an earlier draft
// had them here. Exempting a listing requires telling one from a file, and every rule
// for that was defeated by a chosen filename (see mavenGateEvasions). So a listing is
// now gated under a positionally-shifted identity and refused. No resolver requests
// one, so nothing in a build breaks; a human browsing a repository through the
// firewall gets a 403. That is a real, accepted cost, not an oversight.
func TestMavenNonArtifactFilesStillPass(t *testing.T) {
	base := "/" + spyGroupPath

	cases := []struct{ path, why string }{
		{base + "/maven-metadata.xml",
			"the version index — a resolve reads it BEFORE any artifact, and it carries no bytes"},
		{base + "/" + spyVersion + "/maven-metadata.xml",
			"SNAPSHOT builds publish a per-version index too"},
		{base + "/maven-metadata.xml.sha1",
			"the index's own checksum"},
		{fmt.Sprintf("%s/%s/%s-%s.jar.sha1", base, spyVersion, spyArtifact, spyVersion),
			"40 bytes of hex — no payload can ride in it"},
		{fmt.Sprintf("%s/%s/%s-%s.jar.md5", base, spyVersion, spyArtifact, spyVersion),
			"same, older algorithm"},
		{fmt.Sprintf("%s/%s/%s-%s.jar.sha256", base, spyVersion, spyArtifact, spyVersion),
			"same, newer algorithm"},
		{fmt.Sprintf("%s/%s/%s-%s.jar.asc", base, spyVersion, spyArtifact, spyVersion),
			"a detached PGP signature"},
	}

	for _, c := range cases {
		t.Run(strings.TrimPrefix(c.path, "/"), func(t *testing.T) {
			up := newMavenSpyUpstream()
			defer up.Close()
			p := newMavenTestProxy(t, up.Server)

			if code, _ := get(t, p, c.path); code == http.StatusForbidden {
				t.Errorf("%s was BLOCKED, but it must pass ungated: %s\n"+
					"  Inverting the gate's default must not swallow the files a resolve needs "+
					"before it can fetch anything at all.", c.path, c.why)
			}
		})
	}
}

// The characterization test that used to live here — TestMavenExtensionAllowlistBypass-
// KnownDefect — asserted, on purpose, that all ten extensions DID deliver a blocked
// package's bytes. Issue #56 is fixed, so it went red, and per its own instructions
// each extension moved into the gated table in TestMavenGatedExtensionIsBlocked above
// rather than the test simply being deleted. The bypass is now a permanent assertion;
// this note is all that remains, so the history stays findable from here.

// ociBlobEvasions' Maven counterpart: TIER-3 (adversarial) coverage for issue #56.
//
// Every entry here is a name an attacker CHOOSES. That is the whole lesson of this
// fix: three separate attempts to decide "is this segment a file or a directory?" from
// the name were each defeated by picking a different name, and each defeat was a live
// bypass serving a blocked package's bytes in full:
//
//	rule tried                      defeated by            measured
//	------------------------------  ---------------------  --------------------
//	extension must look alphabetic  badlib-1.0.0.tar.bz2   200, payload delivered
//	digit-initial name is a version 2FA.jar                200, payload delivered
//	trailing slash means directory  badlib-1.0.0.jar/      200, payload delivered
//	maven-metadata.xml as a PREFIX  maven-metadata.xml.evil.jar  200, payload delivered
//
// They are kept as a table rather than prose because the next person to "simplify"
// mavenUngatedFile will reach for one of these rules again.
var mavenGateEvasions = []struct{ name, file, why string }{
	{"digit-initial filename", "2FA.jar",
		"defeats any 'a name starting with a digit is a version directory' rule"},
	{"numeric extension", "badlib-1.0.0.tar.bz2",
		"defeats any 'extensions are alphabetic' rule (.7z, .bz2, .mp3)"},
	{"trailing slash on an artifact", "badlib-1.0.0.jar/",
		"defeats 'trailing slash means directory'; a CDN that normalizes the slash away " +
			"then serves the jar — the identity-divergence class of issue #59"},
	{"metadata-prefixed filename", "maven-metadata.xml.evil.jar",
		"defeats a PREFIX match on maven-metadata.xml; this is a working artifact URL"},
	{"non-conforming filename", "RANDOM.jar",
		"does not start with '<artifactId>-', so any rule requiring that shape to gate " +
			"would pass it"},
	{"checksum-shaped but not a checksum", "badlib-1.0.0.SHA1",
		"uppercase, so a case-sensitive suffix test must not treat it as a checksum"},
	{"double extension", "badlib-1.0.0.jar.evil",
		"not a checksum or signature, so it must not inherit their exemption"},
	{"classifier artifact", "badlib-1.0.0-linux-x86_64.so",
		"a native binary published under a classifier — a real Maven shape"},
}

// TestMavenGateResistsFilenameEvasion asserts on CONTENT and on UPSTREAM CONTACT, not
// on status: the bypass class being guarded returns an ordinary 200 with the payload.
//
// The DISCRIMINATOR is the second half — every evasion is replayed against a
// deliberately PERMISSIVE firewall in which the same paths demonstrably DO serve the
// payload. Without it, "nothing came back" would also be what a broken proxy produces,
// and the whole table would pass against a firewall that simply refused everything.
func TestMavenGateResistsFilenameEvasion(t *testing.T) {
	// ---- strict: the package is blocked, so no filename may yield its bytes ----
	for _, ev := range mavenGateEvasions {
		t.Run(ev.name, func(t *testing.T) {
			up := newMavenSpyUpstream()
			defer up.Close()
			p := newMavenTestProxy(t, up.Server)

			path := "/" + spyGroupPath + "/" + spyVersion + "/" + ev.file
			code, body := get(t, p, path)

			if strings.Contains(body, artifactBytes) {
				t.Errorf("BYPASS via %s (%q): status %d WITH the artifact payload.\n  %s",
					ev.name, path, code, ev.why)
			}
			if up.contacted(strings.TrimSuffix(ev.file, "/")) {
				t.Errorf("BYPASS via %s (%q): the upstream was asked for it; the bytes left "+
					"the repository even if the client was refused.\n  %s", ev.name, path, ev.why)
			}
		})
	}

	// ---- discriminator: the same paths against a firewall that blocks nothing ----
	up := newMavenSpyUpstream()
	defer up.Close()
	permissive := newTestProxy(t, up.Server, func(c *Config) {
		c.Ecosystem = "maven"
		c.ScoreThreshold = 1.0 // stub 7.5 clears it -> allowed
		c.ByteGate = byteGateEnforce
	})
	served := 0
	for _, ev := range mavenGateEvasions {
		if _, body := get(t, permissive, "/"+spyGroupPath+"/"+spyVersion+"/"+ev.file); strings.Contains(body, artifactBytes) {
			served++
		}
	}
	if served == 0 {
		t.Fatalf("DISCRIMINATOR BROKEN: not one of the %d evasion paths serves the payload "+
			"even when the package is ALLOWED. Every refusal above is then meaningless — it "+
			"could just be a broken proxy rather than the gate.", len(mavenGateEvasions))
	}
	t.Logf("discriminator: %d/%d evasion paths serve real bytes when the package is allowed, "+
		"so the refusals above are the gate acting", served, len(mavenGateEvasions))
}

// TestMavenChecksumExemptionIsBounded pins the one thing that deliberately still passes
// ungated, so the residual risk is a decision on the record rather than an oversight.
//
// Checksums and signatures are exempt because gating them would break resolution at the
// wrong end: "maven-metadata.xml.sha1" sits at a depth where the identity parses to the
// WRONG package, so gating it would refuse the metadata checksum of packages that are
// perfectly allowed, and a resolve fails before it ever reaches an artifact.
//
// The residual: whoever publishes a package controls the bytes served at its .sha1/.asc
// URLs, so a payload can be parked there. It is not an install vector — a resolver
// writes a checksum to the local repository as a checksum and never executes it, and it
// only fetches one for an artifact it was already allowed to fetch. Recorded here so
// the next person weighing "should checksums be gated?" starts from the real tradeoff.
func TestMavenChecksumExemptionIsBounded(t *testing.T) {
	up := newMavenSpyUpstream()
	defer up.Close()
	p := newMavenTestProxy(t, up.Server)

	// Exempt: the checksum/signature suffixes, exactly.
	for _, f := range []string{
		spyArtifact + "-" + spyVersion + ".jar.sha1",
		spyArtifact + "-" + spyVersion + ".jar.asc",
	} {
		if code, _ := get(t, p, "/"+spyGroupPath+"/"+spyVersion+"/"+f); code == http.StatusForbidden {
			t.Errorf("%s was gated; it must stay exempt or metadata checksums break resolution", f)
		}
	}
	// NOT exempt: anything merely resembling one. This is the boundary that keeps the
	// exemption narrow enough to reason about.
	for _, f := range []string{
		spyArtifact + "-" + spyVersion + ".SHA1",     // wrong case
		spyArtifact + "-" + spyVersion + ".jar.evil", // extra extension, not a checksum
		spyArtifact + "-" + spyVersion + ".sha1x",    // suffix-adjacent
	} {
		if code, _ := get(t, p, "/"+spyGroupPath+"/"+spyVersion+"/"+f); code != http.StatusForbidden {
			t.Errorf("%s was NOT gated (status %d) — the checksum exemption is leaking into "+
				"names that are not checksums", f, code)
		}
	}
}
