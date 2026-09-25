package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A fake IdP: discovery, an authorization endpoint that records what it was asked,
// and a token endpoint that mints an unsigned-but-well-formed ID token. Unsigned is
// correct for these tests AND for the product: the console never verifies an
// id_token signature, by the §3.1.3.7 argument in oidc.go's header, so a fixture
// that signed one would be testing a code path that does not exist.
type fakeIdP struct {
	srv       *httptest.Server
	clientID  string
	nonce     string // captured from the authorization request
	challenge string // captured PKCE code_challenge
	verifier  string // captured code_verifier at the token endpoint
	claims    map[string]any
	tokenHits int
	basicAuth string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	f := &fakeIdP{clientID: "console-app"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 f.srv.URL,
			"authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint":         f.srv.URL + "/token",
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		f.nonce = r.URL.Query().Get("nonce")
		f.challenge = r.URL.Query().Get("code_challenge")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenHits++
		_ = r.ParseForm()
		f.verifier = r.PostForm.Get("code_verifier")
		f.basicAuth = r.Header.Get("Authorization")
		claims := map[string]any{
			"iss": f.srv.URL, "sub": "user-1", "aud": f.clientID,
			"exp": time.Now().Add(time.Hour).Unix(), "nonce": f.nonce,
			"email": "dev@example.com",
		}
		for k, v := range f.claims {
			claims[k] = v
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": unsignedJWT(claims)})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// flipLastByte changes the final character of a signed cookie to a DIFFERENT one.
//
// ⚠️ IT EXISTS BECAUSE THE OBVIOUS VERSION WAS A 1-IN-64 FLAKE, and it reached CI.
// The case used to be `good.Value[:len(good.Value)-1] + "X"` — but the value ends
// in a base64url MAC, so whenever that MAC happened to end in "X" the "tampered"
// cookie was byte-identical to the real one, check() correctly accepted it, and the
// test failed. 64 characters in the alphabet, so it passed !330's pipeline by luck
// and failed the next one.
//
// The fix is to the MUTATION, not the assertion: pick a replacement that cannot
// equal what is already there, so the input is guaranteed to be a different string
// and the test is deterministic rather than usually-right.
func flipLastByte(v string) string {
	if v == "" {
		return "x"
	}
	repl := byte('X')
	if v[len(v)-1] == repl {
		repl = 'Y'
	}
	return v[:len(v)-1] + string(repl)
}

func unsignedJWT(claims map[string]any) string {
	body, _ := json.Marshal(claims)
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(body) + ".not-checked"
}

func newTestOIDC(t *testing.T, f *fakeIdP) *oidcAuth {
	t.Helper()
	o, err := newOIDCAuth(oidcConfig{
		Issuer: f.srv.URL, ClientID: f.clientID, ClientSecret: "s3cret",
		RedirectURL: "http://console.example/auth/callback", SessionTTL: time.Hour,
	}, f.srv.Client())
	if err != nil {
		t.Fatalf("newOIDCAuth: %v", err)
	}
	return o
}

// signIn drives a full handshake and returns the session cookie.
func signIn(t *testing.T, o *oidcAuth, f *fakeIdP, next string) *http.Cookie {
	t.Helper()
	rr := httptest.NewRecorder()
	o.startLogin(rr, httptest.NewRequest(http.MethodGet, oidcLoginPath+"?next="+url.QueryEscape(next), nil))
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("login redirect: %v", err)
	}
	// Let the fake IdP see the authorization request, so it learns the nonce.
	resp, err := f.srv.Client().Get(loc.String())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()

	state := loc.Query().Get("state")
	cb := httptest.NewRequest(http.MethodGet, oidcCallbackPath+"?code=abc&state="+url.QueryEscape(state), nil)
	for _, c := range rr.Result().Cookies() {
		cb.AddCookie(c)
	}
	rr2 := httptest.NewRecorder()
	o.completeLogin(rr2, cb)
	if rr2.Code != http.StatusFound {
		t.Fatalf("callback = %d, want 302; body %s", rr2.Code, rr2.Body.String())
	}
	for _, c := range rr2.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return c
		}
	}
	t.Fatal("callback set no session cookie")
	return nil
}

// TestOIDCSignInEndToEnd is the happy path, and it asserts the protocol details
// that make the flow safe rather than only that it produced a session.
func TestOIDCSignInEndToEnd(t *testing.T) {
	f := newFakeIdP(t)
	o := newTestOIDC(t, f)

	ck := signIn(t, o, f, "/lists")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(ck)
	if got := o.check(req); got != "dev@example.com" {
		t.Errorf("signed-in user = %q, want the email claim", got)
	}
	if f.challenge == "" {
		t.Error("no PKCE code_challenge was sent; an intercepted authorization code would be redeemable")
	}
	if f.verifier == "" {
		t.Error("no code_verifier was sent to the token endpoint, so the PKCE challenge proves nothing")
	}
	if !strings.HasPrefix(f.basicAuth, "Basic ") {
		t.Errorf("the client secret must authenticate the token request (client_secret_basic); got %q", f.basicAuth)
	}
	if f.tokenHits != 1 {
		t.Errorf("token endpoint called %d times, want exactly 1", f.tokenHits)
	}
	// Session cookie hygiene. Each of these is a real attack if absent: HttpOnly
	// stops a script reading it, SameSite=Lax stops a cross-site form replaying it.
	if !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie must be HttpOnly and SameSite=Lax; got HttpOnly=%v SameSite=%v", ck.HttpOnly, ck.SameSite)
	}
}

// TestOIDCRejectsATamperedOrForgedSession is the negative control for the whole
// session mechanism. Without it, every assertion above is satisfied by a console
// that accepts any cookie at all.
func TestOIDCRejectsATamperedOrForgedSession(t *testing.T) {
	f := newFakeIdP(t)
	o := newTestOIDC(t, f)
	good := signIn(t, o, f, "/")

	forged, _ := json.Marshal(session{User: "attacker@example.com", Expires: time.Now().Add(time.Hour).Unix()})
	for _, tc := range []struct{ name, value string }{
		{"unsigned payload", base64.RawURLEncoding.EncodeToString(forged)},
		{"payload with a junk MAC", base64.RawURLEncoding.EncodeToString(forged) + ".AAAA"},
		{"a valid cookie signed by a DIFFERENT key", func() string {
			other := newTestOIDC(t, f)
			return other.sign(forged)
		}()},
		{"the real cookie with one byte changed", flipLastByte(good.Value)},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.AddCookie(&http.Cookie{Name: sessionCookie, Value: tc.value})
			if got := o.check(req); got != "" {
				t.Fatalf("accepted a session it should have refused, as %q", got)
			}
		})
	}

	// Control: the genuine cookie still works, so the refusals above are the MAC
	// doing its job and not check() rejecting everything.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(good)
	if o.check(req) == "" {
		t.Fatal("control: the genuine session cookie was refused, so nothing above is evidence")
	}
}

// TestOIDCExpiryComesFromTheSignedPayload pins that the cookie's own Expires
// attribute is not what bounds a session. A browser returns whatever it was told
// to keep, so a session trusting that attribute lasts as long as its holder likes.
func TestOIDCExpiryComesFromTheSignedPayload(t *testing.T) {
	f := newFakeIdP(t)
	o := newTestOIDC(t, f)
	ck := signIn(t, o, f, "/")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(ck)
	if o.check(req) == "" {
		t.Fatal("precondition: the fresh session should be valid")
	}
	o.nowFn = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if got := o.check(req); got != "" {
		t.Errorf("an expired session was accepted as %q; the expiry inside the signed payload is not enforced", got)
	}
}

// TestOIDCHandshakeRejections covers the callback's refusals. Each is a distinct
// attack, and the state one in particular is the CSRF defence for sign-in.
func TestOIDCHandshakeRejections(t *testing.T) {
	f := newFakeIdP(t)

	start := func(o *oidcAuth) (state string, cookies []*http.Cookie) {
		rr := httptest.NewRecorder()
		o.startLogin(rr, httptest.NewRequest(http.MethodGet, oidcLoginPath, nil))
		loc, _ := url.Parse(rr.Header().Get("Location"))
		resp, err := f.srv.Client().Get(loc.String())
		if err == nil {
			resp.Body.Close()
		}
		return loc.Query().Get("state"), rr.Result().Cookies()
	}

	t.Run("state mismatch is refused", func(t *testing.T) {
		o := newTestOIDC(t, f)
		_, cookies := start(o)
		req := httptest.NewRequest(http.MethodGet, oidcCallbackPath+"?code=abc&state=not-the-one", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		o.completeLogin(rr, req)
		if rr.Code == http.StatusFound {
			t.Fatal("a callback whose state does not match the handshake was accepted; this is the sign-in CSRF hole")
		}
	})

	t.Run("no handshake cookie is refused", func(t *testing.T) {
		o := newTestOIDC(t, f)
		state, _ := start(o)
		rr := httptest.NewRecorder()
		o.completeLogin(rr, httptest.NewRequest(http.MethodGet, oidcCallbackPath+"?code=abc&state="+state, nil))
		if rr.Code == http.StatusFound {
			t.Fatal("a callback with no handshake cookie was accepted")
		}
	})

	t.Run("nonce mismatch is refused", func(t *testing.T) {
		o := newTestOIDC(t, f)
		state, cookies := start(o)
		f.claims = map[string]any{"nonce": "somebody-elses-nonce"}
		defer func() { f.claims = nil }()
		req := httptest.NewRequest(http.MethodGet, oidcCallbackPath+"?code=abc&state="+state, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		o.completeLogin(rr, req)
		if rr.Code == http.StatusFound {
			t.Fatal("an id_token minted for a different handshake was accepted; nonce is not being checked")
		}
	})

	t.Run("wrong audience is refused", func(t *testing.T) {
		o := newTestOIDC(t, f)
		state, cookies := start(o)
		f.claims = map[string]any{"aud": "some-other-app"}
		defer func() { f.claims = nil }()
		req := httptest.NewRequest(http.MethodGet, oidcCallbackPath+"?code=abc&state="+state, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		o.completeLogin(rr, req)
		if rr.Code == http.StatusFound {
			t.Fatal("a token issued for a DIFFERENT client was accepted; aud is not being checked")
		}
	})
}

// TestAudienceAcceptsBothSpecShapes: `aud` is a string OR an array of strings.
// Treating the array as "no match" would lock out every IdP that emits one.
func TestAudienceAcceptsBothSpecShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		aud  any
		want bool
	}{
		{"string match", "console-app", true},
		{"string mismatch", "other", false},
		{"array containing us", []any{"other", "console-app"}, true},
		{"array without us", []any{"other", "third"}, false},
		{"empty array", []any{}, false},
		{"absent", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := audienceHas(tc.aud, "console-app"); got != tc.want {
				t.Errorf("audienceHas(%v) = %v, want %v", tc.aud, got, tc.want)
			}
		})
	}
}

// TestLoginReturnIsAlwaysSameSite pins the open-redirect defence. A login endpoint
// that forwards to an arbitrary URL is how a phishing link borrows your domain,
// and the protocol-relative form is the one a naive check misses.
func TestLoginReturnIsAlwaysSameSite(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/lists", "/lists"},
		{"/audit?q=left-pad", "/audit?q=left-pad"},
		{"", "/"},
		{"//evil.example/phish", "/"},
		{"https://evil.example/phish", "/"},
		{"http://evil.example", "/"},
		{"javascript:alert(1)", "/"},
		{"evil.example", "/"},
	} {
		if got := safeReturn(tc.in); got != tc.want {
			t.Errorf("safeReturn(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDiscoveryRefusesAMismatchedIssuer: the document's `issuer` must equal what
// the operator configured. This is what stops a mistyped or hijacked issuer URL
// silently federating the console to somebody else's identity provider.
func TestDiscoveryRefusesAMismatchedIssuer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 "https://attacker.example",
			"authorization_endpoint": "https://attacker.example/a",
			"token_endpoint":         "https://attacker.example/t",
		})
	}))
	defer srv.Close()

	_, err := newOIDCAuth(oidcConfig{Issuer: srv.URL, ClientID: "c", ClientSecret: "s",
		RedirectURL: "https://console.example/auth/callback"}, srv.Client())
	if err == nil {
		t.Fatal("discovery advertising a different issuer than the one configured was accepted")
	}
	if !strings.Contains(err.Error(), "issuer mismatch") {
		t.Errorf("the error should name the mismatch so an operator can fix it; got %v", err)
	}
}

// TestSecureCookieFollowsTheRedirectScheme: an https deployment gets Secure
// cookies without a knob, and a plain-http localhost trial is not locked out by a
// cookie the browser refuses to send back.
func TestSecureCookieFollowsTheRedirectScheme(t *testing.T) {
	f := newFakeIdP(t)
	for _, tc := range []struct {
		redirect string
		want     bool
	}{
		{"https://console.example/auth/callback", true},
		{"http://localhost:8085/auth/callback", false},
	} {
		o, err := newOIDCAuth(oidcConfig{Issuer: f.srv.URL, ClientID: f.clientID,
			ClientSecret: "s", RedirectURL: tc.redirect, SessionTTL: time.Hour}, f.srv.Client())
		if err != nil {
			t.Fatalf("newOIDCAuth: %v", err)
		}
		if o.secureCk != tc.want {
			t.Errorf("redirect %q => Secure=%v, want %v", tc.redirect, o.secureCk, tc.want)
		}
	}
}

// TestIDTokenIsOnlyEverReadFromTheTokenEndpoint is the TRIPWIRE for the
// no-dependency decision, and it is the reason that decision is defensible.
//
// The console does not verify id_token signatures. That is safe ONLY because the
// token is fetched by us from the token endpoint over TLS with client
// authentication (OIDC Core §3.1.3.7). If a future change ever reads an id_token
// from the FRONT CHANNEL — an implicit/hybrid response, a token posted to the
// callback, a token in a header — the reasoning collapses and signature
// verification becomes mandatory.
//
// A comment cannot enforce that, so this reads the source: decodeIDTokenClaims
// must have exactly one caller, and that caller must be exchange().
func TestIDTokenIsOnlyEverReadFromTheTokenEndpoint(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(".", "oidc.go"))
	if err != nil {
		t.Fatalf("reading oidc.go: %v", err)
	}
	text := string(src)

	// Anti-vacuity: if the function is ever renamed, this guard must fail loudly
	// rather than pass by finding nothing.
	if !strings.Contains(text, "func decodeIDTokenClaims(") {
		t.Fatal("decodeIDTokenClaims is gone or renamed — this guard is no longer reading the code it protects")
	}
	calls := regexp.MustCompile(`decodeIDTokenClaims\(`).FindAllStringIndex(text, -1)
	// One definition + one call.
	if len(calls) != 2 {
		t.Fatalf("decodeIDTokenClaims appears %d times, want exactly 2 (its definition and ONE call from exchange). "+
			"A second call site means an id_token is being read somewhere other than the token-endpoint response, "+
			"which invalidates the §3.1.3.7 reasoning that lets this console skip signature verification (#148)", len(calls))
	}
	callIdx := calls[1][0]
	fnStart := strings.LastIndex(text[:callIdx], "\nfunc ")
	if fnStart < 0 {
		t.Fatal("could not locate the enclosing function of the decodeIDTokenClaims call")
	}
	enclosing := text[fnStart : fnStart+80]
	if !strings.Contains(enclosing, "func (o *oidcAuth) exchange(") {
		t.Fatalf("decodeIDTokenClaims is called from %q, not from exchange(). The id_token must only ever be "+
			"read from the token endpoint response", strings.TrimSpace(enclosing))
	}
}

func TestDurationEnvFallsBackRatherThanRefusingToBoot(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{"", 12 * time.Hour},
		{"8h", 8 * time.Hour},
		{"3600", time.Hour},
		{"nonsense", 12 * time.Hour},
		{"-5h", 12 * time.Hour},
		{"0", 12 * time.Hour},
	} {
		if got := durationEnv(tc.in, 12*time.Hour); got != tc.want {
			t.Errorf("durationEnv(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestOIDCNeedsAllFourValues(t *testing.T) {
	full := oidcConfig{Issuer: "https://i", ClientID: "c", ClientSecret: "s", RedirectURL: "https://r"}
	if !full.enabled() {
		t.Fatal("a complete config should be enabled")
	}
	for _, drop := range []string{"Issuer", "ClientID", "ClientSecret", "RedirectURL"} {
		c := full
		switch drop {
		case "Issuer":
			c.Issuer = ""
		case "ClientID":
			c.ClientID = ""
		case "ClientSecret":
			c.ClientSecret = ""
		case "RedirectURL":
			c.RedirectURL = ""
		}
		if c.enabled() {
			t.Errorf("config missing %s reported enabled; a half-written deployment must keep its previous posture", drop)
		}
	}
	_ = fmt.Sprint()
}

// TestFlipLastByteAlwaysChangesTheValue pins the property whose absence made the
// tamper case a 1-in-64 flake: the mutation must produce a DIFFERENT string for
// every input, including one that already ends in the replacement character.
func TestFlipLastByteAlwaysChangesTheValue(t *testing.T) {
	for _, in := range []string{"abc", "abcX", "abcY", "X", "Y", ""} {
		if got := flipLastByte(in); got == in {
			t.Errorf("flipLastByte(%q) = %q -- unchanged, so the tamper case would feed check() the REAL "+
				"cookie and fail for the wrong reason", in, got)
		}
	}
}
