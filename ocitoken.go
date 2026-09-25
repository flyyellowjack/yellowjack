package main

import (
	"errors"
	"time"
)

// The OCI bearer-token cache (#93 follow-on named in D320).
//
// Revalidating a tag costs one HEAD on an anonymous registry and THREE on a registry that
// demands a bearer token (Docker Hub's shape): the HEAD refused 401, a token fetch, the
// HEAD repeated. The token was fetched again on every request because nothing kept it. A
// token is scoped to one repository and is valid for the `expires_in` the token endpoint
// states (60 s when it states nothing, per the distribution auth spec), so keeping it for
// that long, per image, returns a warm pull to one request.
//
// Two properties are load-bearing:
//   - Keyed by IMAGE. A token's scope is repository:<image>:pull; presenting image A's
//     token for image B is at best a 401 and at worst a registry that accepts it and
//     audits the wrong principal.
//   - A rejected token is FORGOTTEN and fetched once more, and the request succeeds.
//     Expiry is honoured from expires_in, so this is the recovery path for revocation or
//     clock skew, not the normal one; it costs that one pull three requests and the next
//     pull is back to one.

type ociTokenEntry struct {
	token string // "" is a real answer: this registry needs no auth for this image
	exp   time.Time
}

// ociTokenCacheBound is the outer TTL of the cache; per-entry expiry is shorter and is
// what actually governs reuse.
const ociTokenCacheBound = time.Hour

// ociTokenDefaultLife is the spec's default when the token endpoint gives no expires_in.
const ociTokenDefaultLife = 60 * time.Second

// ociTokenMargin is subtracted from every lifetime so a token is never presented in the
// last moments before the registry stops accepting it.
const ociTokenMargin = 5 * time.Second

// errOCIUnauthorized is the sentinel for a 401 answered to a request that CARRIED a
// token: the token is stale or revoked and the caller should forget it and try once more.
var errOCIUnauthorized = errors.New("oci: registry refused the bearer token")

func (e ociEcosystem) cachedToken(image string) (string, bool) {
	if e.tokens == nil {
		return "", false
	}
	ent, ok := e.tokens.get(image)
	if !ok || !time.Now().Before(ent.exp) {
		return "", false
	}
	return ent.token, true
}

func (e ociEcosystem) rememberToken(image, token string, expiresIn int) {
	if e.tokens == nil {
		return
	}
	life := ociTokenDefaultLife
	if expiresIn > 0 {
		life = time.Duration(expiresIn) * time.Second
	}
	life -= ociTokenMargin
	if life <= 0 {
		return // too short to be worth presenting again
	}
	e.tokens.put(image, ociTokenEntry{token: token, exp: time.Now().Add(life)})
}

// forgetToken invalidates by storing an already-expired entry: ttlLRU has no delete, and
// an expired entry reads as a miss.
func (e ociEcosystem) forgetToken(image string) {
	if e.tokens == nil {
		return
	}
	e.tokens.put(image, ociTokenEntry{exp: time.Time{}})
}
