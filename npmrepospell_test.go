package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// #162: npm spells a GitHub repository three ways the shared normalizer does not read, and
// the registry serves them verbatim. E109 measured the cost: 0.33% of benign weekly npm
// download volume refused as "does not declare a usable source repository" although each of
// these packages declares one. Every example below is a real `repository` value from that
// harvest.
func TestNpmGitHubSpellingsResolve(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		// the three spellings npm resolves to GitHub, as the registry serves them
		{"node-formidable/formidable", "github.com/node-formidable/formidable"},      // formidable, 24 M/week
		{"formatjs/formatjs.git", "github.com/formatjs/formatjs"},                    // @formatjs/intl-locale
		{"github:donmccurdy/ndarray-pixels", "github.com/donmccurdy/ndarray-pixels"}, // ndarray-pixels
		{"git@github.com:formatjs/formatjs.git", "github.com/formatjs/formatjs"},     // react-intl
		{"git+ssh://git@github.com:voodoocreation/ts-deepmerge.git", "github.com/voodoocreation/ts-deepmerge"},
		{"github:kriasoft/web-auth-library#main", "github.com/kriasoft/web-auth-library"},
		// already-readable URLs are untouched
		{"git+https://github.com/lodash/lodash.git", "github.com/lodash/lodash"},
		{"https://github.com/o/r", "github.com/o/r"},

		// ── controls: none of these may start resolving ──
		{"gitlab:o/r", ""},             // another forge's shorthand: #14's scope, not this one
		{"bitbucket:o/r", ""},          //
		{"https://gitlab.com/o/r", ""}, // a real non-GitHub URL
		{"o/r/extra", ""},              // three segments is a path, not owner/repo
		{"../evil", ""},                // must never become github.com/../evil
		{"o/..", ""},                   //
		{"@hostlink/nuxt-light", ""},   // an npm package name is not a repository
		{"nuxt-easy-lightbox", ""},     // one segment
		{"sponsors/someone", ""},       // expands, then GitHub's reserved route still refuses
		{"own_er/repo", ""},            // GitHub owners take no underscore
		{"", ""},                       //
		{"ssb://%amdvACBM0lDEDdFDdw3E9Gzx1PbcFVi17ojmrwR45uY=.sha256", ""},
	} {
		if got := normalizeGitHub(npmGitHubSpelling(tc.raw)); got != tc.want {
			t.Errorf("npm repository %q -> %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// The expansion is npm's alone. normalizeGitHub is shared with PyPI's project_urls and
// OCI's source label, where a bare "a/b" is a docs path or a relative link; if the shared
// function started reading it as a repository, an arbitrary string could name the repo a
// package borrows its score from (#10). This pins that the fix did not leak.
func TestSharedNormalizerStillRefusesShorthand(t *testing.T) {
	for _, raw := range []string{"node-formidable/formidable", "github:o/r", "git@github.com:o/r.git"} {
		if got := normalizeGitHub(raw); got != "" {
			t.Errorf("normalizeGitHub(%q) = %q: the npm-only spelling leaked into the function PyPI and OCI share", raw, got)
		}
	}
}

// The helper passing its own table does not prove the lookup calls it. This drives the
// REAL npmEcosystem.LookupRepo against a registry serving the string form exactly as npm's
// registry serves formidable, and asserts the repository comes back.
func TestNpmLookupResolvesAShorthandRepository(t *testing.T) {
	for _, tc := range []struct {
		name string
		repo any
		want string
	}{
		{"bare shorthand string", "node-formidable/formidable", "github.com/node-formidable/formidable"},
		{"scp form in the object shape", map[string]string{"type": "git", "url": "git@github.com:formatjs/formatjs.git"}, "github.com/formatjs/formatjs"},
		{"control: another forge stays unresolved", "gitlab:o/r", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"repository": tc.repo})
			}))
			t.Cleanup(ts.Close)
			got, err := npmEcosystem{base: ts.URL}.LookupRepo(&http.Client{}, "somepkg")
			if err != nil {
				t.Fatalf("LookupRepo: %v", err)
			}
			if got != tc.want {
				t.Fatalf("LookupRepo resolved %q, want %q", got, tc.want)
			}
		})
	}
}
