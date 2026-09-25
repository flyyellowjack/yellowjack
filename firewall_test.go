package main

import "testing"

// TestNormalizeGitHub covers the many repository-URL shapes the firewall must
// reduce to a bare "github.com/owner/name" — including the OCI source-label form
// (".../repo.git#<commit>:<tag>") that Layer 4.7 hardened the normalizer for.
func TestNormalizeGitHub(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"npm git+https .git", "git+https://github.com/lodash/lodash.git", "github.com/lodash/lodash"},
		{"plain https", "https://github.com/owner/name", "github.com/owner/name"},
		{"git protocol", "git://github.com/owner/name.git", "github.com/owner/name"},
		{"ssh form", "ssh://git@github.com/owner/name.git", "github.com/owner/name"},
		{"deeper path dropped", "https://github.com/owner/name/tree/main", "github.com/owner/name"},
		{"oci label fragment", "https://github.com/traefik/traefik-library-image.git#5f3401:v3.7", "github.com/traefik/traefik-library-image"},
		{"oci label no scheme", "github.com/nginx/docker-nginx.git#abc:mainline", "github.com/nginx/docker-nginx"},
		{"non-github", "https://gitlab.com/foo/bar", ""},
		{"empty", "", ""},
		{"too few parts", "https://github.com/owner", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := normalizeGitHub(c.in); got != c.want {
				t.Errorf("normalizeGitHub(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestPackageNameFromPath checks each ecosystem extracts the right package identity
// from its own URL conventions (and returns "" for non-package/infra paths).
func TestPackageNameFromPath(t *testing.T) {
	cases := []struct {
		name string
		eco  Ecosystem
		path string
		want string
	}{
		{"npm plain", npmEcosystem{}, "/lodash", "lodash"},
		// "/-/" is the registry control plane (tarballs, audit, login) — ungated,
		// so it must NOT resolve to a package name.
		{"npm tarball", npmEcosystem{}, "/lodash/-/lodash-4.17.21.tgz", ""},
		{"npm scoped tarball", npmEcosystem{}, "/@babel/core/-/core-7.0.0.tgz", ""},
		{"npm audit endpoint", npmEcosystem{}, "/-/npm/v1/security/advisories/bulk", ""},
		{"npm scoped", npmEcosystem{}, "/@scope/name", "@scope/name"},
		{"npm root", npmEcosystem{}, "/", ""},
		{"pypi simple", pypiEcosystem{}, "/simple/requests/", "requests"},
		{"pypi index root", pypiEcosystem{}, "/simple/", ""},
		// The reference is PART of the identity (D164): verdicts attach to versions,
		// not to a mutable tag pointer. Both spellings are Docker's own, so the
		// identity in a log or an approval queue is what an operator would type.
		{"oci manifest", ociEcosystem{}, "/v2/library/nginx/manifests/latest", "library/nginx:latest"},
		{"oci manifest by tag", ociEcosystem{}, "/v2/library/nginx/manifests/1.25", "library/nginx:1.25"},
		{"oci manifest by digest", ociEcosystem{}, "/v2/library/nginx/manifests/sha256:abc", "library/nginx@sha256:abc"},
		// A bare "/manifests/" carries no version. It must not become a NEW ungated
		// path, so it resolves to the image at "latest" rather than to "".
		{"oci manifest no ref", ociEcosystem{}, "/v2/library/nginx/manifests/", "library/nginx:latest"},
		{"oci version handshake", ociEcosystem{}, "/v2/", ""},
		{"oci blob (not gated)", ociEcosystem{}, "/v2/library/nginx/blobs/sha256:abc", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.eco.PackageNameFromPath(c.path); got != c.want {
				t.Errorf("%s.PackageNameFromPath(%q) = %q, want %q", c.eco.Name(), c.path, got, c.want)
			}
		})
	}
}

// TestParseBearerChallenge verifies we extract realm/service/scope from the OCI
// registry's WWW-Authenticate header (the basis of the token auth dance).
func TestParseBearerChallenge(t *testing.T) {
	h := `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"`
	realm, service, scope := parseBearerChallenge(h)
	if realm != "https://auth.docker.io/token" {
		t.Errorf("realm = %q", realm)
	}
	if service != "registry.docker.io" {
		t.Errorf("service = %q", service)
	}
	if scope != "repository:library/nginx:pull" {
		t.Errorf("scope = %q", scope)
	}
	if r, _, _ := parseBearerChallenge("Basic realm=\"x\""); r != "" {
		t.Errorf("non-Bearer challenge should yield empty realm, got %q", r)
	}
}
