package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The server half of #148: OIDC gating every route, and an override attributed to
// the person who signed in rather than to a shared label.
//
// oidc_test.go proves the protocol. These prove it is WIRED — which is the half a
// protocol test cannot show, and the shape that has bitten this repo before (a
// helper's own test passing while its call site is unreachable).

func oidcServer(t *testing.T, f *fakeIdP, approval approvalClient) *server {
	t.Helper()
	return &server{approval: approval, oidc: newTestOIDC(t, f), listEcosystem: "npm"}
}

// TestOIDCGatesEveryRouteAndRedirectsRatherThanChallenging pins two things at once:
// no console page is readable without a session, and an unauthenticated browser is
// sent to the IdP instead of being shown a Basic-auth prompt. The second is the
// point of SSO — an operator who has wired up an IdP should never see a credential
// box from us.
func TestOIDCGatesEveryRouteAndRedirectsRatherThanChallenging(t *testing.T) {
	f := newFakeIdP(t)
	srv := oidcServer(t, f, &fakeApproval{})

	for _, path := range []string{"/", "/audit", "/lists", "/lookup", "/policy", "/capacity", "/downloads", "/activity"} {
		t.Run(path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
			if rr.Code != http.StatusFound {
				t.Fatalf("%s unauthenticated = %d, want 302 to the IdP; an ungated console page leaks what is "+
					"under review to anyone who can reach it", path, rr.Code)
			}
			loc := rr.Header().Get("Location")
			if !strings.HasPrefix(loc, oidcLoginPath) {
				t.Errorf("%s redirected to %q, want the sign-in path", path, loc)
			}
			if !strings.Contains(loc, "next=") {
				t.Errorf("%s lost the return path, so sign-in dumps the operator on the home page", path)
			}
			if rr.Header().Get("WWW-Authenticate") != "" {
				t.Errorf("%s sent a Basic-auth challenge while OIDC is configured", path)
			}
		})
	}

	// /healthz stays open: orchestrators probe it before anyone has signed in, and
	// it reveals nothing. Without this the test above is satisfied by a server that
	// redirects everything, including its own liveness probe.
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200 — an orchestrator cannot sign in", rr.Code)
	}
}

// TestOIDCSessionOpensTheConsole is the discriminator for the test above: with a
// valid session the same routes must serve. Without it, "everything redirects" is
// indistinguishable from a console nobody can ever use.
func TestOIDCSessionOpensTheConsole(t *testing.T) {
	f := newFakeIdP(t)
	srv := oidcServer(t, f, &fakeApproval{})
	ck := signIn(t, srv.oidc, f, "/")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(ck)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("a signed-in request to / = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "dev@example.com") {
		t.Error("the page does not show who is signed in; the operator cannot tell whose name will be on an override")
	}
}

// TestOverrideIsAttributedToTheSignedInPerson is the reason per-user SSO is worth
// more than a stronger shared password. Before this, every override in the audit
// trail carried the same shared label whoever made it (#41).
func TestOverrideIsAttributedToTheSignedInPerson(t *testing.T) {
	f := newFakeIdP(t)
	fa := &fakeApproval{}
	srv := oidcServer(t, f, fa)
	ck := signIn(t, srv.oidc, f, "/")

	req := overrideRequest("", "", "http://example.com", map[string][]string{
		"package": {"left-pad"}, "verdict": {"denied"},
	})
	req.Header.Del("Authorization")
	req.AddCookie(ck)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("override while signed in = %d, want 303; body %s", rr.Code, rr.Body.String())
	}
	if len(fa.puts) != 1 {
		t.Fatalf("override wrote %d record(s), want 1", len(fa.puts))
	}
	if got := fa.puts[0].DecidedBy; got != "dev@example.com" {
		t.Errorf("decidedBy = %q, want the signed-in person. A shared label here is the defect #41 describes: "+
			"a decision nobody can be asked about", got)
	}
}

// TestWritesAreEnabledByOIDCAlone: writes are gated on SOMEBODY being
// authenticated, not on which mechanism did it. An OIDC-only deployment (no
// CONSOLE_AUTH_USER at all) must still be able to override — otherwise wiring up
// SSO would silently make the console read-only, which is the opposite of what
// the operator asked for.
func TestWritesAreEnabledByOIDCAlone(t *testing.T) {
	f := newFakeIdP(t)
	srv := oidcServer(t, f, &fakeApproval{})
	if srv.auth != nil {
		t.Fatal("precondition: this server has no basic credential")
	}
	if !srv.writesEnabled() {
		t.Fatal("OIDC alone must enable writes; otherwise configuring SSO turns the console read-only")
	}

	// Control: a server with neither is read-only, so the assertion above is about
	// OIDC and not about writesEnabled always answering true.
	if (&server{approval: &fakeApproval{}}).writesEnabled() {
		t.Error("a console with no identity source at all must stay read-only")
	}
}

// TestOIDCWinsOverBasicAuthWhenBothAreSet pins the precedence, which is a
// security choice rather than a coin toss: an operator who has wired up SSO has
// said who their people are, and preferring a shared credential would put a
// generic name in the audit trail instead of a person's.
func TestOIDCWinsOverBasicAuthWhenBothAreSet(t *testing.T) {
	f := newFakeIdP(t)
	srv := oidcServer(t, f, &fakeApproval{})
	srv.auth = newBasicAuth("shared-admin", "pw")

	// Basic credentials alone must NOT open the console once OIDC is configured.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("shared-admin", "pw")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("basic credentials opened the console while OIDC is configured (%d); the shared credential "+
			"is a weaker posture the operator has already replaced", rr.Code)
	}

	// And the session does open it, attributed to the person.
	ck := signIn(t, srv.oidc, f, "/")
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(ck)
	if got := srv.currentUser(req2); got != "dev@example.com" {
		t.Errorf("currentUser = %q, want the OIDC identity rather than the shared label", got)
	}
}

// TestLogoutEndsTheSession — a console on a shared machine needs a way out, and a
// logout that leaves the cookie valid is worse than none because it looks like it
// worked.
func TestLogoutEndsTheSession(t *testing.T) {
	f := newFakeIdP(t)
	srv := oidcServer(t, f, &fakeApproval{})
	ck := signIn(t, srv.oidc, f, "/")

	req := httptest.NewRequest(http.MethodGet, oidcLogoutPath, nil)
	req.AddCookie(ck)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	var cleared bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookie && c.Value == "" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout did not clear the session cookie")
	}
}
