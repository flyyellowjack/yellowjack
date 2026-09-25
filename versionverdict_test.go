package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Version-scoped verdicts (a pinned advisory, the operator's version deny, a path release
// window) are decided before Evaluate, at the control points where a request names a
// release. They used to be refused and logged but never AUDITED, and an administrator's
// override of one (D312) was refused with a reason saying it had been served. See
// versionVerdict in proxy.go.

func captureAudit(p *proxyServer) *auditEmitter {
	a := &auditEmitter{ch: make(chan auditEvent, 16)}
	p.firewall.audit = a
	return a
}

func drainAudit(a *auditEmitter) []auditEvent {
	var out []auditEvent
	for {
		select {
		case e := <-a.ch:
			out = append(out, e)
		default:
			return out
		}
	}
}

func TestNpmPinnedTarballRefusalIsAudited(t *testing.T) {
	up, _ := npmVersionedUpstream(t, "pkg", "1.0.0", "2.0.0")
	defer up.Close()
	p := pinnedProxy(t, up, pinTwo)
	a := captureAudit(p)

	if rec := getFrom(t, p, "/pkg/-/pkg-2.0.0.tgz"); rec.Code != http.StatusForbidden {
		t.Fatalf("the pinned release was not refused: %d", rec.Code)
	}
	evs := drainAudit(a)
	if len(evs) != 1 {
		t.Fatalf("audit events = %d, want exactly 1 for the refused release: %+v", len(evs), evs)
	}
	e := evs[0]
	if e.Package != "pkg" || e.Action != auditActionBlock || e.DenyKind != string(denyKnownMalware) || e.Rule != "MAL-NPM-PIN" {
		t.Errorf("the record does not describe the refusal: %+v", e)
	}
	if !strings.Contains(e.Reason, `version "2.0.0"`) {
		t.Errorf("the record does not name the release it refused: %q", e.Reason)
	}

	// CONTROL: the clean sibling is served through the byte route, which records nothing
	// (the package's verdict belongs to the metadata route). The fix audits version
	// VERDICTS, not every tarball.
	if rec := getFrom(t, p, "/pkg/-/pkg-1.0.0.tgz"); rec.Code != http.StatusOK {
		t.Fatalf("the clean sibling was refused: %d", rec.Code)
	}
	if evs := drainAudit(a); len(evs) != 0 {
		t.Errorf("a served tarball with no version verdict was audited: %+v", evs)
	}
}

// D312 on npm's byte path: the administrator allowed THIS release, so its bytes are
// served, and the record says it was served over a standing advisory.
func TestNpmTarballOverrideIsServedAndAudited(t *testing.T) {
	up, fetched := npmVersionedUpstream(t, "pkg", "1.0.0", "2.0.0", "3.0.0")
	defer up.Close()
	feed := writeFeed(t, `{"id":"MAL-NPM-PIN","ecosystem":"npm","name":"pkg","versions":["2.0.0","3.0.0"]}`)
	p := newTestProxy(t, up, func(c *Config) {
		c.MalwareListPath = feed
		c.UnscorablePolicy = "allow"
		c.AllowListPath = writeList(t, "allow.txt", "pkg@2.0.0")
	})
	a := captureAudit(p)

	rec := getFrom(t, p, "/pkg/-/pkg-2.0.0.tgz")
	if rec.Code != http.StatusOK || fetched["2.0.0"] != 1 {
		t.Fatalf("the overridden release: status %d, fetched %d, reason %q -- the administrator allowed it, so it is served",
			rec.Code, fetched["2.0.0"], rec.Header().Get("X-Yellowjack-Reason"))
	}
	evs := drainAudit(a)
	if len(evs) != 1 || evs[0].Action != auditActionAllow || !strings.Contains(evs[0].Override, "MAL-NPM-PIN") {
		t.Fatalf("the override is not on the record as an allow over the advisory: %+v", evs)
	}

	// DISCRIMINATOR: the same advisory names 3.0.0, which the allow list does not. It
	// stays refused, so the override is scoped to the release the administrator judged.
	if rec := getFrom(t, p, "/pkg/-/pkg-3.0.0.tgz"); rec.Code != http.StatusForbidden || fetched["3.0.0"] != 0 {
		t.Errorf("a release the advisory names and the allow list does not: status %d, fetched %d", rec.Code, fetched["3.0.0"])
	}
}

func TestNpmOperatorVersionDenyTarballIsAudited(t *testing.T) {
	up, _ := npmVersionedUpstream(t, "pkg", "1.0.0", "2.0.0")
	defer up.Close()
	p := newTestProxy(t, up, func(c *Config) {
		c.UnscorablePolicy = "allow"
		c.DenyListPath = writeList(t, "deny.txt", "pkg@2.0.0")
	})
	a := captureAudit(p)
	if rec := getFrom(t, p, "/pkg/-/pkg-2.0.0.tgz"); rec.Code != http.StatusForbidden {
		t.Fatalf("the operator's version deny did not refuse: %d", rec.Code)
	}
	evs := drainAudit(a)
	if len(evs) != 1 || evs[0].DenyKind != string(denyOperator) || evs[0].Action != auditActionBlock {
		t.Errorf("the operator's version deny is not on the record: %+v", evs)
	}
}

// The request-path control point: Maven names the release in its path.
func TestMavenPinnedRefusalIsAudited(t *testing.T) {
	f, _ := mavenFirewall(t, writeFeed(t, mavenAdvisory))
	p := newProxyServer(f.cfg, f)
	a := captureAudit(p)
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + mavenPoisoned)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want 403", resp.StatusCode)
	}
	evs := drainAudit(a)
	if len(evs) != 1 || evs[0].Package != "org.example:widget" || evs[0].Rule != "MAL-MVN-1" || evs[0].Ecosystem != "maven" {
		t.Errorf("the Maven refusal is not on the record: %+v", evs)
	}
}
