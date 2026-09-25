"""A stub OpenID Provider for the console's sign-in leg (#149).

WHY A STUB AND NOT A REAL IdP. Tier 2 asks whether OUR console completes a real
authorization-code flow and attributes writes to the signed-in person. It does not ask
whether Keycloak works. A stub keeps the leg hermetic (no network, no account) and lets
the test drive the one thing that matters: what claims come back, and what the console
does with them.

WHAT IT DELIBERATELY DOES NOT DO. It does not sign the ID token. !330's design reads the
token from the TOKEN ENDPOINT over TLS with client auth and skips signature validation,
which OIDC Core section 3.1.3.7 permits for exactly that flow -- so an unsigned token is
the CORRECT fixture here. Signing it would test a code path the console does not have and
would hide the one it does.

WHAT IT MUST DO, because the console's completeLogin verifies each of these in
constant time and refuses the sign-in otherwise:
  - echo the NONCE the console sent to /authorize back inside the ID token;
  - set `iss` to exactly the issuer the console was configured with;
  - set `aud` to exactly the console's client_id;
  - set `exp` in the future.
The nonce is carried INSIDE the authorization code rather than in stub memory, so the
stub is stateless per request and two concurrent sign-ins cannot cross wires.

CONTACT COUNTERS ARE THE POINT. Every endpoint records a hit. A sign-in leg whose pass
condition is "the console showed a username" can pass while never reaching the IdP at all
-- the console could be falling back to basic auth, or serving a cached session. The leg
asserts /authorize AND /token were both hit, so "it worked" cannot be confused with "it
never asked". That is the !312 lesson: a success leg that loses contact goes GREEN.

Runs as the `oidcstub` compose service (e2e/oidcstub/Dockerfile), like fakesmtp: the
console reaches it at oidcstub:9000 inside the stack; the rig's curl reaches it at the
published port. A host process would not be reachable under dind, where the stack runs
inside a daemon container and neither side can resolve the other by "localhost".
ThreadingHTTPServer because a single-threaded stub deadlocks the moment the console holds
a keep-alive connection open ([[single-threaded-keepalive-stub-deadlock]]).
"""
import base64
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, urlencode

ISSUER = os.environ.get("IDP_ISSUER", "http://oidcstub:9000")
SUBJECT = os.environ.get("IDP_SUBJECT", "alice@example.test")
CLIENT_ID = os.environ.get("IDP_CLIENT_ID", "yellowjack-console")
# The console dials ISSUER (discovery, token) from inside the compose network; the
# harness's curl -- playing the browser -- follows the 302 to /authorize from OUTSIDE
# it. Those are different addresses for the same stub, which OIDC permits: only `iss`
# and the token endpoint must match what the client was configured with.
AUTHZ_BASE = os.environ.get("IDP_AUTHZ_BASE", ISSUER)
STATE_PATH = os.environ.get("IDP_STATE", "/tmp/oidcstub-state.json")

HITS = {"discovery": 0, "authorize": 0, "token": 0, "jwks": 0,
        "token_client_auth_basic": 0, "token_nonce_echoed": 0}
LOCK = threading.Lock()


def flush():
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(HITS, f)
    os.replace(tmp, STATE_PATH)


def record(name, detail=""):
    """Log at handler ENTRY, before any work, and flush to disk immediately.

    The file is how the shell leg reads the counters; an in-memory count the test
    cannot see is not an assertion, it is a comment.
    """
    with LOCK:
        HITS[name] += 1
        flush()
    print("IDP %s %s" % (name, detail), flush=True)


def b64url(raw):
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")


def id_token(nonce):
    """An UNSIGNED JWT: header.payload.<empty signature>.

    The empty third segment is deliberate and is what makes a regression loud: if anyone
    later adds signature verification without adding a key, this fixture fails rather
    than silently passing on a token nobody checked.
    """
    now = int(time.time())
    header = {"alg": "none", "typ": "JWT"}
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": SUBJECT,
        "email": SUBJECT,
        "iat": now,
        "exp": now + 600,
    }
    if nonce:
        claims["nonce"] = nonce
    return "%s.%s." % (b64url(json.dumps(header, separators=(",", ":"))),
                       b64url(json.dumps(claims, separators=(",", ":"))))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _json(self, payload, code=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _empty(self, code, location=None):
        self.send_response(code)
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/.well-known/openid-configuration":
            record("discovery")
            self._json({
                "issuer": ISSUER,
                "authorization_endpoint": AUTHZ_BASE + "/authorize",
                "token_endpoint": ISSUER + "/token",
                "jwks_uri": ISSUER + "/jwks",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["none"],
                "grant_types_supported": ["authorization_code"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                "code_challenge_methods_supported": ["S256"],
            })
            return
        if u.path == "/authorize":
            q = parse_qs(u.query)
            redirect = (q.get("redirect_uri") or [""])[0]
            state = (q.get("state") or [""])[0]
            nonce = (q.get("nonce") or [""])[0]
            record("authorize", "nonce=%s redirect_uri=%s" % ("set" if nonce else "MISSING", redirect))
            # No login page: this stub authenticates nobody and asserts nothing about
            # the user. It hands back a code immediately, which keeps the leg about OUR
            # console rather than about a form. The nonce rides inside the code so
            # /token can echo it with no shared state.
            code = "stub-code." + b64url(nonce)
            self._empty(302, redirect + "?" + urlencode({"code": code, "state": state}))
            return
        if u.path == "/_hits":
            # Deliberately NOT counted: reading the evidence must not manufacture it.
            with LOCK:
                snap = dict(HITS)
            self._json(snap)
            return
        if u.path == "/jwks":
            record("jwks")
            self._json({"keys": []})
            return
        self._empty(404)

    def do_POST(self):
        if urlparse(self.path).path != "/token":
            self._empty(404)
            return
        n = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(n).decode("utf-8", "replace")) if n else {}
        code = (form.get("code") or [""])[0]
        nonce = unb64url(code[len("stub-code."):]) if code.startswith("stub-code.") else ""
        basic = self.headers.get("Authorization", "").startswith("Basic ")
        with LOCK:
            HITS["token"] += 1
            if basic:
                HITS["token_client_auth_basic"] += 1
            if nonce:
                HITS["token_nonce_echoed"] += 1
            flush()
        print("IDP token client_auth=%s nonce=%s" % ("basic" if basic else "NONE",
                                                   "echoed" if nonce else "MISSING"), flush=True)
        self._json({
            "access_token": "stub-access-token",
            "token_type": "Bearer",
            "expires_in": 600,
            "id_token": id_token(nonce),
        })

    def log_message(self, *a):
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
    # Zero the counters on start so a stale file from a previous run cannot be read
    # as this run's contact evidence.
    with LOCK:
        for k in HITS:
            HITS[k] = 0
        flush()
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print("IDP READY on %d as %s (authorize via %s; subject %s, client_id %s)" % (
        port, ISSUER, AUTHZ_BASE, SUBJECT, CLIENT_ID), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
