package main

import (
	"net/http"
	"strings"
	"testing"
)

// Issue #14's second bullet: when a forge is unsupported, keep the package
// unscorable but NAME the forge, so the coverage gap is measurable rather than
// silent.
//
// The load-bearing property is not "it logs". It is that the report separates
// three things the unscorable branch currently renders identically:
//
//	1. a package that declares NOTHING              -> silent, nothing to report
//	2. a package whose repository is on GitLab      -> reportable gap
//	3. a package whose homepage is a marketing site -> silent, NOT a gap
//
// Get (3) wrong and the signal drowns in every project with a website; get (1)
// wrong and the gap looks bigger than it is. Both are pinned below.

func TestForgeOfNamesOnlyRealForges(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		// ── reportable: a repository on a forge we do not score ──────────────
		{"gitlab https", "https://gitlab.com/gitlab-org/gitlab-runner", "gitlab.com"},
		{"gitlab git+", "git+https://gitlab.com/inkscape/inkscape.git", "gitlab.com"},
		{"gitlab ssh", "ssh://git@gitlab.com/owner/name.git", "gitlab.com"},
		{"bitbucket", "https://bitbucket.org/atlassian/python-api", "bitbucket.org"},
		{"codeberg", "https://codeberg.org/forgejo/forgejo", "codeberg.org"},
		{"self-hosted forge", "https://git.example.com/team/project", "git.example.com"},
		{"host case is folded", "https://GitLab.com/Owner/Name", "gitlab.com"},
		// A ref fragment must not become part of the host, the same way
		// normalizeGitHub handles the OCI source-label shape.
		{"fragment dropped", "https://gitlab.com/o/n.git#abc123:v1", "gitlab.com"},

		// ── supported: nothing to report ─────────────────────────────────────
		{"github is supported", "https://github.com/lodash/lodash", ""},
		{"github git+ suffix", "git+https://github.com/lodash/lodash.git", ""},

		// ── NOT a gap: these must stay silent ────────────────────────────────
		{"empty", "", ""},
		{"a marketing homepage", "https://lodash.com", ""},
		{"a homepage with one path segment", "https://example.com/docs", ""},
		{"no dot in host is not a forge", "some/relative/path", ""},
		{"bare junk", "not a url at all", ""},

		// ── forgeOf alone still cannot tell a repo from a docs site ──────────
		// It never will: nothing in the STRING separates docs.python.org/3/library
		// from git.example.com/team/project. That is a property of the input.
		//
		// The FIX is at the caller, and it landed once #134 supplied the evidence:
		// the LABEL is the discriminator, so every caller now passes only source-ish
		// candidates. See TestTheForgeReportOnlyCountsSourceishURLs, which pins that
		// a "Documentation" entry no longer produces a coverage line.
		{"forgeOf alone still names a docs host -- the caller is what filters", "https://docs.python.org/3/library/", "docs.python.org"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := forgeOf(tc.raw); got != tc.want {
				t.Errorf("forgeOf(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestForgeOfAndNormalizeGitHubCannotDisagree is the anti-drift guard.
//
// The two functions read the same publisher-written soup, and the report is only
// meaningful if it describes the SAME string the GitHub check rejected. They share
// stripRepoURLDecoration for exactly this reason; this asserts the invariant that
// sharing exists to produce, so splitting them again fails here.
func TestForgeOfAndNormalizeGitHubCannotDisagree(t *testing.T) {
	for _, raw := range []string{
		"https://github.com/lodash/lodash",
		"git+https://github.com/lodash/lodash.git",
		"ssh://git@github.com/o/n.git",
		"git://github.com/o/n",
		"https://github.com/o/n.git#deadbeef:v1",
		"https://gitlab.com/o/n",
		"https://lodash.com",
		"",
	} {
		gh := normalizeGitHub(raw)
		forge := forgeOf(raw)
		if gh != "" && forge != "" {
			t.Errorf("%q: normalizeGitHub says %q AND forgeOf says %q — a URL cannot be "+
				"both supported and a coverage gap; the two parsers have drifted", raw, gh, forge)
		}
	}
}

// TestUnsupportedForgeReportIsOncePerLookupAndNamesTheFirstForge pins the
// reporting contract at the give-up point.
//
// The candidates are passed together precisely so a lookup that SUCCEEDS on a
// later candidate never reports a gap. That case is the one worth protecting: a
// PyPI project listing a GitHub repo in project_urls and a GitLab mirror in
// home_page resolves fine, and counting it would inflate the gap with packages
// that are scored perfectly well.
func TestUnsupportedForgeReportIsOncePerLookupAndNamesTheFirstForge(t *testing.T) {
	for _, tc := range []struct {
		name       string
		candidates []string
		want       string // "" means: must report nothing
	}{
		{"nothing declared", []string{"", ""}, ""},
		{"only a homepage", []string{"https://lodash.com"}, ""},
		{"one gitlab repo", []string{"https://gitlab.com/o/n"}, "gitlab.com"},
		{
			// Order matters and is the ecosystem's own preference order.
			name:       "first forge wins, and only one line is emitted",
			candidates: []string{"https://bitbucket.org/a/b", "https://gitlab.com/o/n"},
			want:       "bitbucket.org",
		},
		{
			name:       "a homepage before the repo does not mask it",
			candidates: []string{"https://example.com", "https://gitlab.com/o/n"},
			want:       "gitlab.com",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureStdLog(t)
			noteUnsupportedForge("pypi", "somepkg", tc.candidates...)
			out := buf.String()
			if tc.want == "" {
				if strings.Contains(out, "coverage") {
					t.Errorf("reported a coverage gap for %v, but there is none to report: %q",
						tc.candidates, strings.TrimSpace(out))
				}
				return
			}
			if n := strings.Count(out, "coverage"); n != 1 {
				t.Fatalf("emitted %d coverage lines for one lookup, want exactly 1: %q", n, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("line does not name %s: %q", tc.want, strings.TrimSpace(out))
			}
			// The package and the ecosystem must both be there, or an operator
			// counting the gap cannot tell which tree it came from.
			if !strings.Contains(out, "somepkg") || !strings.Contains(out, "pypi") {
				t.Errorf("line does not identify the package and ecosystem: %q", strings.TrimSpace(out))
			}
			// And it must say what happened, not merely what was seen.
			if !strings.Contains(out, "unscorable") {
				t.Errorf("line does not say the package was treated as unscorable, so a reader "+
					"cannot tell a report from a behaviour change: %q", strings.TrimSpace(out))
			}
		})
	}
}

// TestNamingTheForgeChangesNoVerdict is the reason this increment is safe to ship
// without a ruling: normalizeGitHub's answer is what every caller acts on, and it
// must be byte-identical to what it was before the refactor that introduced
// stripRepoURLDecoration.
func TestNamingTheForgeChangesNoVerdict(t *testing.T) {
	for raw, want := range map[string]string{
		"https://github.com/lodash/lodash":            "github.com/lodash/lodash",
		"git+https://github.com/lodash/lodash.git":    "github.com/lodash/lodash",
		"git://github.com/owner/name":                 "github.com/owner/name",
		"ssh://git@github.com/owner/name.git":         "github.com/owner/name",
		"https://github.com/owner/name.git#abc:v1":    "github.com/owner/name",
		"https://github.com/owner/name/tree/main/sub": "github.com/owner/name",
		"https://github.com/owner/name@v2":            "github.com/owner/name",
		"https://gitlab.com/owner/name":               "",
		"https://github.com":                          "",
		"":                                            "",
	} {
		if got := normalizeGitHub(raw); got != want {
			t.Errorf("normalizeGitHub(%q) = %q, want %q — this increment must not move a "+
				"single verdict", raw, got, want)
		}
	}
}

// TestTheForgeReportActuallyFiresOnTheRealNpmLookup is the path test.
//
// Every assertion above calls noteUnsupportedForge directly, which proves the
// helper and proves nothing about whether the four ecosystems ever reach it. A
// report nobody emits is the same as no report, and this project has shipped that
// shape before — a marker whose rate was read as evidence the path had fired.
//
// So this drives the REAL npmEcosystem.LookupRepo against a registry serving a
// GitLab repository, and asserts the line appears. The discriminator underneath it
// is the same lookup against a GitHub repo, which must stay silent — without that
// half, a helper that logged unconditionally would pass this test.
func TestTheForgeReportActuallyFiresOnTheRealNpmLookup(t *testing.T) {
	for _, tc := range []struct {
		name      string
		declared  string
		wantForge string // "" = must stay silent
	}{
		{"gitlab-hosted package", "git+https://gitlab.com/inkscape/inkscape.git", "gitlab.com"},
		{"github-hosted package (the discriminator)", "git+https://github.com/lodash/lodash.git", ""},
		{"declares nothing at all", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eco := npmEcosystem{base: npmRegistry(t, tc.declared)}
			buf := captureStdLog(t)
			repo, err := eco.LookupRepo(&http.Client{}, "somepkg")
			if err != nil {
				t.Fatalf("LookupRepo: %v", err)
			}
			out := buf.String()

			if tc.wantForge == "" {
				if strings.Contains(out, "coverage npm") {
					t.Errorf("reported a coverage gap for %q, which is not one: %q",
						tc.declared, strings.TrimSpace(out))
				}
				return
			}
			// The verdict is unchanged: still no repo, still unscorable downstream.
			if repo != "" {
				t.Fatalf("LookupRepo returned %q; this increment must not start accepting "+
					"another forge -- only name it", repo)
			}
			if !strings.Contains(out, "coverage npm") || !strings.Contains(out, tc.wantForge) {
				t.Errorf("the real npm lookup did not emit the coverage line for %s; the helper "+
					"is wired nowhere: %q", tc.wantForge, strings.TrimSpace(out))
			}
		})
	}
}

// TestTheForgeReportOnlyCountsSourceishURLs closes the false positive this report
// shipped with (!289): any "host/a/b" shape reads as a forge, so a PyPI
// "Documentation" entry announced docs.python.org as an unsupported FORGE.
//
// #134 supplied what was missing — the LABEL is what separates a source URL from a
// docs, funding or tracker URL — so the report now filters by the same rank the repo
// chooser uses. The two agree by construction: the report names the forge of a URL
// that WOULD have been chosen, which is the only kind that is a real gap.
func TestTheForgeReportOnlyCountsSourceishURLs(t *testing.T) {
	for _, tc := range []struct {
		name string
		urls map[string]string
		want string // "" = must report nothing
	}{
		{
			name: "a docs URL is NOT a coverage gap",
			urls: map[string]string{"Documentation": "https://docs.python.org/3/library/"},
			want: "",
		},
		{
			name: "a funding URL on another forge is not a gap either",
			urls: map[string]string{"Funding": "https://opencollective.com/some/project"},
			want: "",
		},
		{
			name: "a bug tracker on a self-hosted forge is not a gap",
			urls: map[string]string{"Bug Tracker": "https://git.example.com/team/project/issues"},
			want: "",
		},
		{
			name: "a SOURCE url on an unsupported forge IS the gap",
			urls: map[string]string{"Source": "https://gitlab.com/inkscape/inkscape"},
			want: "gitlab.com",
		},
		{
			name: "Homepage counts too -- it is often the repo",
			urls: map[string]string{"Homepage": "https://gitlab.com/owner/name"},
			want: "gitlab.com",
		},
		{
			name: "an unrecognised label counts: it might be the source",
			urls: map[string]string{"Upstream": "https://codeberg.org/owner/name"},
			want: "codeberg.org",
		},
		{
			name: "the SOURCE wins over a docs URL on a different host",
			urls: map[string]string{
				"Documentation": "https://docs.example.com/a/b",
				"Source":        "https://bitbucket.org/team/repo",
			},
			want: "bitbucket.org",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Repeated: project_urls is a map, so a single pass can pick the right
			// candidate by accident.
			for i := 0; i < 50; i++ {
				buf := captureStdLog(t)
				noteUnsupportedForge("pypi", "somepkg", append(pypiSourceish(tc.urls), "")...)
				out := buf.String()
				if tc.want == "" {
					if strings.Contains(out, "coverage pypi") {
						t.Fatalf("iteration %d reported a gap for %v, which is not one: %q",
							i, tc.urls, strings.TrimSpace(out))
					}
					continue
				}
				if !strings.Contains(out, tc.want) {
					t.Fatalf("iteration %d did not name %s for %v: %q",
						i, tc.want, tc.urls, strings.TrimSpace(out))
				}
			}
		})
	}
}

// TestTheRealPypiLookupReportsOnlySourceishForges is the PATH test, and it exists
// because the sabotage demanded it.
//
// TestTheForgeReportOnlyCountsSourceishURLs calls pypiSourceish directly, so
// unwiring it AT THE CALL SITE — restoring the "pass every project_urls value" loop
// in LookupRepo — left that test green. Same shape as #134's own path test, and the
// same rule: a helper's test proves the helper, never that anything calls it.
//
// So this drives the real pypiEcosystem.LookupRepo. The fixture has no source repo
// at all, and its Documentation entry is on a host that LOOKS like a forge — which
// is precisely what the old code announced.
func TestTheRealPypiLookupReportsOnlySourceishForges(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      string
		wantForge string // "" = must stay silent
	}{
		{
			name: "a docs URL must not be announced as a forge",
			body: `{"info":{"home_page":"https://example.com","project_urls":{
				"Documentation":"https://docs.example.com/3/library/",
				"Bug Tracker":"https://tracker.example.com/team/proj"}}}`,
			wantForge: "",
		},
		{
			name: "a SOURCE url on an unsupported forge is still reported",
			body: `{"info":{"home_page":"https://example.com","project_urls":{
				"Documentation":"https://docs.example.com/3/library/",
				"Source":"https://gitlab.com/inkscape/inkscape"}}}`,
			wantForge: "gitlab.com",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eco := pypiEcosystem{base: stubPypiIndex(t, tc.body)}
			for i := 0; i < 30; i++ {
				buf := captureStdLog(t)
				repo, err := eco.LookupRepo(&http.Client{}, "somepkg")
				if err != nil {
					t.Fatalf("LookupRepo: %v", err)
				}
				if repo != "" {
					t.Fatalf("LookupRepo returned %q; the fixture declares no scorable repo, "+
						"so this test is not exercising the give-up path", repo)
				}
				out := buf.String()
				if tc.wantForge == "" {
					if strings.Contains(out, "coverage pypi") {
						t.Fatalf("iteration %d: the real lookup announced a coverage gap for a "+
							"docs/tracker URL: %q", i, strings.TrimSpace(out))
					}
					continue
				}
				if !strings.Contains(out, tc.wantForge) {
					t.Fatalf("iteration %d: the real lookup did not report %s: %q",
						i, tc.wantForge, strings.TrimSpace(out))
				}
			}
		})
	}
}
