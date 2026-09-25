package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// OIDC sign-in for the console (#148), a launch requirement under D280.
//
// WHY NOW, AND WHY IT IS NOT NEW. D19 (2026-07-15) settled the posture:
// "SSO is definitely a target but it's going to be a whole process to develop
// that and I don't think we should prioritize that right now" — so per-user SSO
// was always the target and basic gateway auth was the near-term stand-in.
// D280 un-defers it with a date; it does not introduce it.
//
// ─── WHY THE STANDARD LIBRARY AND NO DEPENDENCY ─────────────────────────────
//
// docs/BUILD_LOG.md's standing rule is "standard library unless there's a strong
// reason not to", and this project has exactly one direct dependency (pgx), which
// is justified in writing. The usual reason to take go-oidc + x/oauth2 is ID-token
// SIGNATURE verification: JWKS fetch and rotation, key selection, and the `alg`
// confusion family. That is genuinely worth a dependency — and this design does
// not need it.
//
// We are a CONFIDENTIAL client running the AUTHORIZATION CODE flow, and we read
// the ID token from the TOKEN ENDPOINT RESPONSE, fetched by us, directly, over
// TLS, with client authentication. OIDC Core §3.1.3.7 permits skipping ID-token
// signature validation in exactly that case, and the reason is not a loophole:
// the only adversary who could substitute a token there is one who can MITM our
// TLS connection to the IdP — and that same adversary could serve a forged JWKS,
// so verifying a signature buys nothing against them. The trust comes from the
// channel, and the channel is the thing we would have had to trust anyway.
//
// ⚠️ THE CONSTRAINT THIS CREATES. The ID token may ONLY ever be consumed from a
// token-endpoint response. If any future change accepts one from the FRONT
// CHANNEL — an implicit or hybrid flow, a token posted to the callback, a token
// in a header — signature verification becomes MANDATORY and this decision must
// be revisited. That is a tripwire, not a style note, and it is guarded by
// TestIDTokenIsOnlyEverReadFromTheTokenEndpoint rather than by this comment.
//
// What remains is discovery (one JSON GET), a redirect, a POST, and claim checks.
// No hand-rolled crypto: crypto/rand for the random values, crypto/hmac for the
// session cookie, crypto/subtle for the comparisons.

const (
	oidcLoginPath    = "/auth/login"
	oidcCallbackPath = "/auth/callback"
	oidcLogoutPath   = "/auth/logout"

	sessionCookie = "yj_session"
	stateCookie   = "yj_oidc_state"

	// The handshake cookie lives only for the round trip to the IdP. Long enough
	// for a human to type a password and clear an MFA prompt, short enough that a
	// stolen one is useless by the time it is found.
	handshakeTTL = 10 * time.Minute
)

// oidcConfig is the operator-facing surface. All five values come from the
// environment; the console has no config file (D19's "same binary everywhere").
type oidcConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// SessionTTL bounds how long a sign-in lasts before the IdP is consulted
	// again. It is OUR bound, not the IdP's: we do not hold a refresh token, so
	// re-authentication is a fresh redirect, which is also how a revoked account
	// stops being able to act.
	SessionTTL time.Duration
}

func (c oidcConfig) enabled() bool {
	return c.Issuer != "" && c.ClientID != "" && c.ClientSecret != "" && c.RedirectURL != ""
}

// providerMetadata is the subset of the OIDC discovery document we use. Decoded
// leniently: an IdP may advertise a great deal more, and a field we do not read
// must never be able to break sign-in.
type providerMetadata struct {
	Issuer        string `json:"issuer"`
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
}

// oidcAuth is the relying party. It holds no user store and no refresh tokens:
// a session is a signed cookie this process can verify, and nothing else.
type oidcAuth struct {
	cfg      oidcConfig
	meta     providerMetadata
	client   *http.Client
	sessKey  []byte
	nowFn    func() time.Time
	secureCk bool
}

// newOIDCAuth fetches the discovery document and returns a ready relying party.
//
// Discovery happens ONCE, AT STARTUP, and a failure is fatal to configuring OIDC
// rather than deferred to the first sign-in. An operator who mistypes the issuer
// should learn at boot, in the logs, not when someone tries to log in — the same
// argument the firewall's trust preflight makes (refuse before the listener binds
// rather than fail per-request).
func newOIDCAuth(cfg oidcConfig, client *http.Client) (*oidcAuth, error) {
	if !cfg.enabled() {
		return nil, fmt.Errorf("OIDC needs CONSOLE_OIDC_ISSUER, _CLIENT_ID, _CLIENT_SECRET and _REDIRECT_URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	wellKnown := strings.TrimRight(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	resp, err := client.Get(wellKnown)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery at %s: %w", wellKnown, err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery at %s returned %d", wellKnown, resp.StatusCode)
	}
	var meta providerMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&meta); err != nil {
		return nil, fmt.Errorf("OIDC discovery at %s: %w", wellKnown, err)
	}
	// The issuer in the document must match the one configured. This is the check
	// that stops a mis-set issuer silently federating the console to somebody
	// else's IdP, and it is cheap: one string compare against a value the operator
	// typed rather than against anything the network chose.
	if meta.Issuer != strings.TrimRight(cfg.Issuer, "/") && meta.Issuer != cfg.Issuer {
		return nil, fmt.Errorf("OIDC discovery issuer mismatch: configured %q, document says %q", cfg.Issuer, meta.Issuer)
	}
	if meta.AuthEndpoint == "" || meta.TokenEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery at %s advertises no authorization_endpoint or token_endpoint", wellKnown)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating the session key: %w", err)
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	return &oidcAuth{
		cfg:     cfg,
		meta:    meta,
		client:  client,
		sessKey: key,
		nowFn:   time.Now,
		// Secure is driven by the REDIRECT URL's scheme rather than by a knob: an
		// operator who has deployed behind TLS gets a Secure cookie without asking,
		// and one testing on http://localhost is not locked out by a cookie the
		// browser will refuse to send back.
		secureCk: strings.HasPrefix(strings.ToLower(cfg.RedirectURL), "https://"),
	}, nil
}

func (o *oidcAuth) now() time.Time {
	if o.nowFn != nil {
		return o.nowFn()
	}
	return time.Now()
}

// randomValue returns a URL-safe random string for state, nonce and the PKCE
// verifier. 32 bytes from crypto/rand — the same source and size for all three,
// because there is no reason for any of them to be weaker than the others.
func randomValue() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ─── the handshake ──────────────────────────────────────────────────────────

// handshake is the state carried across the redirect to the IdP, in a signed
// cookie rather than in server memory. Stateless on purpose: the console is
// meant to run as several replicas behind one address, and a handshake held in
// one process's map is a sign-in that fails whenever the callback lands on a
// different replica. D257 halted multi-replica propagation work; this is the
// cheap way to not create the problem in the first place.
type handshake struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Expires  int64  `json:"e"`
	Return   string `json:"r"`
}

// sign returns value|hex(HMAC-SHA256(value)). The MAC covers the whole encoded
// payload, so neither the expiry nor the identity inside it can be edited by
// whoever holds the cookie.
func (o *oidcAuth) sign(payload []byte) string {
	mac := hmac.New(sha256.New, o.sessKey)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// cookieEncoding decodes STRICTLY: a value whose final character carries non-zero unused
// bits is an error, not a second spelling of the same bytes. Unpadded base64 leaves 2 or 4
// slack bits in the last character of most lengths and the default decoder ignores them, so
// without this a cookie has several accepted spellings -- three extra for every 32-byte MAC.
// None is a forgery (the bytes, and so the MAC, are identical), but a security token should
// have exactly one form: the one we issued. It also made "change the last character" a
// vacuous tamper test about 1 time in 16, which is how this was found (e2e leg 27).
// Encoding is unchanged; sign() already emits the canonical spelling.
var cookieEncoding = base64.RawURLEncoding.Strict()

// unsign verifies the MAC in constant time and returns the payload.
func (o *oidcAuth) unsign(s string) ([]byte, bool) {
	dot := strings.LastIndexByte(s, '.')
	if dot <= 0 {
		return nil, false
	}
	payload, err := cookieEncoding.DecodeString(s[:dot])
	if err != nil {
		return nil, false
	}
	got, err := cookieEncoding.DecodeString(s[dot+1:])
	if err != nil {
		return nil, false
	}
	mac := hmac.New(sha256.New, o.sessKey)
	mac.Write(payload)
	if subtle.ConstantTimeCompare(got, mac.Sum(nil)) != 1 {
		return nil, false
	}
	return payload, true
}

// startLogin sends the browser to the IdP with state, nonce and a PKCE challenge.
func (o *oidcAuth) startLogin(w http.ResponseWriter, r *http.Request) {
	state, err1 := randomValue()
	nonce, err2 := randomValue()
	verifier, err3 := randomValue()
	if err1 != nil || err2 != nil || err3 != nil {
		http.Error(w, "could not start sign-in", http.StatusInternalServerError)
		return
	}
	hs := handshake{
		State: state, Nonce: nonce, Verifier: verifier,
		Expires: o.now().Add(handshakeTTL).Unix(),
		// Where to land after sign-in. Only a PATH is ever kept (see safeReturn):
		// an open redirect on a login endpoint is how a phishing link borrows your
		// domain, and the console has no reason to send anyone off-site.
		Return: safeReturn(r.URL.Query().Get("next")),
	}
	blob, err := json.Marshal(hs)
	if err != nil {
		http.Error(w, "could not start sign-in", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie, Value: o.sign(blob), Path: "/",
		HttpOnly: true, Secure: o.secureCk, SameSite: http.SameSiteLaxMode,
		Expires: o.now().Add(handshakeTTL),
	})

	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {o.cfg.ClientID},
		"redirect_uri":          {o.cfg.RedirectURL},
		"scope":                 {"openid profile email"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(o.meta.AuthEndpoint, "?") {
		sep = "&"
	}
	http.Redirect(w, r, o.meta.AuthEndpoint+sep+q.Encode(), http.StatusFound)
}

// safeReturn reduces a caller-supplied "next" to a same-site absolute path, or
// "/" when it is anything else. "//evil.example" is rejected as well as
// "https://evil.example": a protocol-relative URL is an off-site redirect that
// looks like a path, and it is the form an open-redirect check usually misses.
func safeReturn(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	if u, err := url.Parse(next); err != nil || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return next
}

// tokenResponse is the subset of the token endpoint's reply we read.
type tokenResponse struct {
	IDToken string `json:"id_token"`
}

// idClaims are the ID-token claims the console acts on.
type idClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience any    `json:"aud"`
	Expiry   int64  `json:"exp"`
	Nonce    string `json:"nonce"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Username string `json:"preferred_username"`
}

// who is the identity the console shows and stamps on an override. Falling back
// down the chain rather than insisting on `email`: an IdP configured without the
// email scope still yields an accountable identity, and `sub` always exists.
func (c idClaims) who() string {
	for _, v := range []string{c.Email, c.Username, c.Name, c.Subject} {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// decodeIDTokenClaims reads the payload of a JWT WITHOUT verifying its signature.
//
// ⚠️ Safe here and ONLY here — see the file header. The caller must have obtained
// this token from the token endpoint over TLS with client authentication
// (OIDC Core §3.1.3.7). This function is deliberately unexported and takes no
// request, so it cannot be reached from a front-channel handler by accident.
func decodeIDTokenClaims(idToken string) (idClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return idClaims{}, fmt.Errorf("id_token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return idClaims{}, fmt.Errorf("id_token payload is not base64url: %w", err)
	}
	var c idClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return idClaims{}, fmt.Errorf("id_token payload is not JSON: %w", err)
	}
	return c, nil
}

// audienceHas reports whether aud contains our client id. The claim is a string
// OR an array of strings per the spec, and treating the array case as "no match"
// would lock out every IdP that emits one.
func audienceHas(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

// completeLogin handles the IdP's redirect back: verify state, exchange the code,
// check the claims, and set the session cookie.
func (o *oidcAuth) completeLogin(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie(stateCookie)
	if err != nil {
		http.Error(w, "sign-in has no handshake cookie; start again at "+oidcLoginPath, http.StatusBadRequest)
		return
	}
	// Clear the handshake immediately, whatever happens next: it is single-use, and
	// leaving it set turns a failed sign-in into a replayable one.
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: o.secureCk, SameSite: http.SameSiteLaxMode})

	blob, ok := o.unsign(ck.Value)
	if !ok {
		http.Error(w, "sign-in handshake failed verification", http.StatusBadRequest)
		return
	}
	var hs handshake
	if err := json.Unmarshal(blob, &hs); err != nil {
		http.Error(w, "sign-in handshake is malformed", http.StatusBadRequest)
		return
	}
	if o.now().Unix() > hs.Expires {
		http.Error(w, "sign-in took too long; start again at "+oidcLoginPath, http.StatusBadRequest)
		return
	}
	// CSRF: the state we issued must be the state that came back. Constant-time
	// because it is a secret comparison like any other.
	if subtle.ConstantTimeCompare([]byte(hs.State), []byte(r.URL.Query().Get("state"))) != 1 {
		http.Error(w, "sign-in state mismatch", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		// The IdP reports a refusal here (access_denied and friends). Surfaced rather
		// than turned into a generic failure, because "your admin has not assigned you
		// this app" is a different problem from "the console is broken".
		if e := r.URL.Query().Get("error"); e != "" {
			http.Error(w, "the identity provider refused the sign-in: "+e, http.StatusForbidden)
			return
		}
		http.Error(w, "sign-in returned no authorization code", http.StatusBadRequest)
		return
	}

	claims, err := o.exchange(code, hs.Verifier)
	if err != nil {
		http.Error(w, "could not complete sign-in", http.StatusBadGateway)
		return
	}
	// Nonce binds the ID token to THIS browser's handshake, so a token minted for
	// someone else's sign-in cannot be replayed into ours.
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(hs.Nonce)) != 1 {
		http.Error(w, "sign-in nonce mismatch", http.StatusBadRequest)
		return
	}
	if claims.Issuer != o.meta.Issuer {
		http.Error(w, "sign-in issuer mismatch", http.StatusBadRequest)
		return
	}
	if !audienceHas(claims.Audience, o.cfg.ClientID) {
		http.Error(w, "sign-in audience mismatch", http.StatusBadRequest)
		return
	}
	if claims.Expiry > 0 && o.now().Unix() > claims.Expiry {
		http.Error(w, "the identity provider returned an expired token", http.StatusBadRequest)
		return
	}
	user := claims.who()
	if user == "" {
		http.Error(w, "the identity provider returned no usable identity", http.StatusBadRequest)
		return
	}

	o.setSession(w, user)
	http.Redirect(w, r, safeReturn(hs.Return), http.StatusFound)
}

// exchange POSTs the code to the token endpoint and returns the ID token's claims.
//
// This is the ONLY place an id_token enters the process, which is what makes the
// §3.1.3.7 reasoning in the file header hold.
func (o *oidcAuth) exchange(code, verifier string) (idClaims, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {o.cfg.RedirectURL},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequest(http.MethodPost, o.meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return idClaims{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// client_secret_basic: the most widely supported client authentication method,
	// and it keeps the secret out of the body (and therefore out of any IdP access
	// log that records form parameters).
	req.SetBasicAuth(url.QueryEscape(o.cfg.ClientID), url.QueryEscape(o.cfg.ClientSecret))

	resp, err := o.client.Do(req)
	if err != nil {
		return idClaims{}, err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return idClaims{}, fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}
	var tr tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return idClaims{}, err
	}
	if tr.IDToken == "" {
		return idClaims{}, fmt.Errorf("token endpoint returned no id_token")
	}
	return decodeIDTokenClaims(tr.IDToken)
}

// ─── the session ────────────────────────────────────────────────────────────

type session struct {
	User    string `json:"u"`
	Expires int64  `json:"e"`
}

func (o *oidcAuth) setSession(w http.ResponseWriter, user string) {
	exp := o.now().Add(o.cfg.SessionTTL)
	blob, err := json.Marshal(session{User: user, Expires: exp.Unix()})
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: o.sign(blob), Path: "/",
		HttpOnly: true, Secure: o.secureCk, SameSite: http.SameSiteLaxMode,
		Expires: exp,
	})
}

// check returns the signed-in user, or "" when the request carries no valid
// session. The expiry is read from the SIGNED payload, never from the cookie's
// own Expires attribute — a browser sends back whatever it was told to keep, so
// trusting that attribute would make a session last as long as its holder liked.
func (o *oidcAuth) check(r *http.Request) string {
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	blob, ok := o.unsign(ck.Value)
	if !ok {
		return ""
	}
	var s session
	if err := json.Unmarshal(blob, &s); err != nil {
		return ""
	}
	if o.now().Unix() > s.Expires {
		return ""
	}
	return s.User
}

func (o *oidcAuth) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: o.secureCk, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusFound)
}

// handles reports whether a path belongs to the sign-in flow. These are the only
// console paths reachable without a session, which is why the set is explicit
// rather than a prefix match: "/auth/" as a prefix would open anything anyone
// later hung under it.
func oidcOwnsPath(p string) bool {
	return p == oidcLoginPath || p == oidcCallbackPath || p == oidcLogoutPath
}

// durationEnv parses a session TTL like "8h". Invalid values fall back rather
// than refusing to boot: a mistyped TTL should not be the reason a console that
// was working stops, and the default is the conservative end.
func durationEnv(raw string, fallback time.Duration) time.Duration {
	if raw == "" {
		return fallback
	}
	if d, err := time.ParseDuration(raw); err == nil && d > 0 {
		return d
	}
	if n, err := strconv.Atoi(raw); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return fallback
}
