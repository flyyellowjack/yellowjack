package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// OCI tag revalidation (#93 question 1, restoring what D164 ruled).
//
// The repo cache is keyed by PACKAGE IDENTITY, and for OCI that identity is image:ref.
// A tag ref is mutable: the same key can describe different bytes an hour apart, and a
// cached verdict then answers for an image it never judged. Measured on #93 (!309): a
// moved tag is served on the previous image's approval for the whole FW_SCORE_CACHE_TTL.
// D164 ruled that verdicts are per VERSION, so this is a regression against a ruling.
//
// The repair is not "never cache a tag" (that re-runs the whole resolve on every pull,
// the fan-out D25/#16/D43 were about). It is REVALIDATION: one HEAD on the manifest,
// which every registry answers with Docker-Content-Digest and zero body bytes (measured
// on #93), and the cache keyed on image@digest. A warm pull of an unmoved tag then costs
// one request; a moved tag is a cache miss on its first pull.
//
// cacheIdentity is the seam: an ecosystem whose package identity can be mutable returns
// the immutable identity behind it, contacting upstream if it must. The firewall keys its
// repo cache on that. Ecosystems whose identities are immutable do not implement it.
type cacheIdentityResolver interface {
	cacheIdentity(c *http.Client, pkg string) (string, error)
}

// cacheIdentity returns image@sha256:... for a tag ref, and pkg unchanged for a ref that
// is already a digest. An error is transient (errUpstreamUnavailable, via ociTransient)
// or a plain failure; the firewall treats both as "cannot cache by name": it re-resolves
// through LookupRepo, which classifies the failure itself, and caches nothing under the
// tag. Failing toward cost, never toward a stale verdict.
func (e ociEcosystem) cacheIdentity(c *http.Client, pkg string) (string, error) {
	image, ref := ociSplitRef(pkg)
	if strings.Contains(ref, ":") {
		return pkg, nil // a digest names immutable content; nothing to revalidate
	}
	if err := checkOCITarget(image, ref); err != nil {
		return "", err
	}
	// Present a cached token straight away if there is one (ocitoken.go): on a
	// challenged registry that turns three requests into one. With no cached token
	// the HEAD goes out bare; a 401 then costs a token fetch and one retry.
	token, _ := e.cachedToken(image)
	digest, err := e.ociHeadDigest(c, image, ref, token)
	if errors.Is(err, errOCIUnauthorized) {
		if token != "" {
			e.forgetToken(image) // the cached token is stale; fetchToken will replace it
		}
		if token, err = e.ociToken(c, image, ref); err != nil {
			return "", err
		}
		digest, err = e.ociHeadDigest(c, image, ref, token)
	}
	if err != nil {
		return "", err
	}
	return ociJoinRef(image, digest), nil
}

// ociHeadDigest asks the registry what a tag points at right now, without the body.
func (e ociEcosystem) ociHeadDigest(c *http.Client, image, ref, token string) (string, error) {
	u := fmt.Sprintf("%s/v2/%s/manifests/%s", e.base, image, ref)
	req, err := http.NewRequest(http.MethodHead, u, nil)
	if err != nil {
		return "", fmt.Errorf("%w: building manifest HEAD for %q@%q: %v", errOCIMalformedRef, image, ref, err)
	}
	req.Header.Set("Accept", ociManifestAccept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("oci manifest HEAD: %w: %v", errUpstreamUnavailable, err)
	}
	closeDrained(resp.Body)
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return "", fmt.Errorf("manifest HEAD for %s:%s: %w", image, ref, errOCIUnauthorized)
	case resp.StatusCode == http.StatusNotFound:
		return "", errPkgNotFound
	case resp.StatusCode != http.StatusOK:
		if err := ociTransient(resp.StatusCode); err != nil {
			return "", err
		}
		return "", fmt.Errorf("manifest HEAD returned %d", resp.StatusCode)
	}
	d := resp.Header.Get("Docker-Content-Digest")
	if !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
		// The spec requires the header on a HEAD, and every registry measured sends
		// it; one that does not cannot be revalidated cheaply. Report it as a plain
		// failure so the caller bypasses the name cache rather than trusting it.
		return "", fmt.Errorf("manifest HEAD for %s:%s carried no usable Docker-Content-Digest (%q)", image, ref, d)
	}
	return d, nil
}
