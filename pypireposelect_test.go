package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// #134: the repo PyPI packages get scored against was chosen by Go's RANDOMISED
// map iteration over project_urls.
//
// Measured across 124 popular packages: 10 (8.1%) declare two or more URLs that
// normalise to a GitHub repo, and the loser is not a harmless near-miss —
// attrs/pydantic/starlette/uvicorn/hatchling all resolve either to their real repo
// or to a github.com/sponsors/<user> funding page, and the aio-libs trio to the
// org's shared .github repo. Under the shipped defaults the wrong one disagrees
// with deps.dev's SOURCE_REPO, so verifyRepo fires the borrow-a-score tripwire and
// REFUSES the package.
//
// So the property under test is not "it finds a repo". It is:
//
//	1. the SAME metadata always yields the SAME repo (determinism), and
//	2. the one it yields is the one the LABEL says is the source.

// attrsProjectURLs is attrs' real project_urls as PyPI serves them, which is the
// sharpest case in the sample: exactly two GitHub-normalising entries, so a random
// chooser gets it wrong half the time.
var attrsProjectURLs = map[string]string{
	"Documentation": "https://www.attrs.org/",
	"Changelog":     "https://www.attrs.org/en/stable/changelog.html",
	"GitHub":        "https://github.com/python-attrs/attrs",
	"Funding":       "https://github.com/sponsors/hynek",
	"Tidelift":      "https://tidelift.com/subscription/pkg/pypi-attrs",
}

func TestPypiRepoSelectionIsDeterministic(t *testing.T) {
	// One pass proves nothing: a random chooser is right half the time, so a single
	// call passes by luck. Go re-seeds map iteration per range statement, so many
	// passes over the same map is exactly the thing that catches it.
	const iterations = 400
	first := pypiRepoFromProjectURLs(attrsProjectURLs)
	if first == "" {
		t.Fatal("no repo selected from attrs' real project_urls")
	}
	for i := 0; i < iterations; i++ {
		if got := pypiRepoFromProjectURLs(attrsProjectURLs); got != first {
			t.Fatalf("iteration %d returned %q after %q — the selection is not "+
				"deterministic, so the same package can be allowed on one replica and "+
				"refused on another (#134)", i, got, first)
		}
	}
	if first != "github.com/python-attrs/attrs" {
		t.Errorf("selected %q, want github.com/python-attrs/attrs — stable but WRONG is "+
			"still a refused package: deps.dev names python-attrs/attrs, so anything else "+
			"trips the borrow-a-score check", first)
	}
}

// TestTheLabelDecides walks every measured wrong-repo class from #134.
func TestTheLabelDecides(t *testing.T) {
	for _, tc := range []struct {
		name string
		urls map[string]string
		want string
	}{
		{
			name: "Funding loses to GitHub (attrs)",
			urls: attrsProjectURLs,
			want: "github.com/python-attrs/attrs",
		},
		{
			name: "Funding loses to Source (pydantic)",
			urls: map[string]string{
				"Homepage": "https://github.com/pydantic/pydantic",
				"Source":   "https://github.com/pydantic/pydantic",
				"Funding":  "https://github.com/sponsors/samuelcolvin",
			},
			want: "github.com/pydantic/pydantic",
		},
		{
			name: "Sponsor loses to Source (hatchling)",
			urls: map[string]string{
				"Source":  "https://github.com/pypa/hatch",
				"Tracker": "https://github.com/pypa/hatch",
				"Sponsor": "https://github.com/sponsors/ofek",
			},
			want: "github.com/pypa/hatch",
		},
		{
			name: "Code of Conduct loses to GitHub: repo (yarl)",
			urls: map[string]string{
				"Homepage":        "https://github.com/aio-libs/yarl",
				"GitHub: repo":    "https://github.com/aio-libs/yarl",
				"GitHub: issues":  "https://github.com/aio-libs/yarl/issues",
				"Code of Conduct": "https://github.com/aio-libs/.github/blob/master/CODE_OF_CONDUCT.md",
			},
			want: "github.com/aio-libs/yarl",
		},
		{
			name: "Q & A loses to Repository (typing-extensions)",
			urls: map[string]string{
				"Repository":  "https://github.com/python/typing_extensions",
				"Bug Tracker": "https://github.com/python/typing_extensions/issues",
				"Q & A":       "https://github.com/python/typing",
			},
			want: "github.com/python/typing_extensions",
		},
		{
			name: "Bug Tracker loses to Repository (poetry-core)",
			urls: map[string]string{
				"Homepage":    "https://github.com/python-poetry/poetry-core",
				"Repository":  "https://github.com/python-poetry/poetry-core",
				"Bug Tracker": "https://github.com/python-poetry/poetry/issues",
			},
			want: "github.com/python-poetry/poetry-core",
		},
		{
			name: "no project_urls at all",
			urls: map[string]string{},
			want: "",
		},
		{
			name: "nothing that normalises to a repo",
			urls: map[string]string{"Homepage": "https://example.com", "Docs": "https://docs.example.com/a/b"},
			want: "",
		},
		{
			name: "an unlabelled-but-only candidate still wins",
			urls: map[string]string{"Weird Label": "https://github.com/owner/name"},
			want: "github.com/owner/name",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Repeat: several of these differ only by rank, and a single pass over a
			// map can pick the right one by accident.
			for i := 0; i < 50; i++ {
				if got := pypiRepoFromProjectURLs(tc.urls); got != tc.want {
					t.Fatalf("iteration %d: got %q, want %q", i, got, tc.want)
				}
			}
		})
	}
}

// TestASponsorsPageIsNotARepository pins fix 2, which is independent of the label
// ranking: even if a package declares ONLY a Sponsors URL, it must not be scored
// against it. Otherwise the deterministic chooser would faithfully and repeatably
// select a repo that does not exist.
func TestASponsorsPageIsNotARepository(t *testing.T) {
	for _, raw := range []string{
		"https://github.com/sponsors/hynek",
		"https://github.com/SPONSORS/hynek",
		"https://github.com/orgs/python-attrs",
		"https://github.com/apps/dependabot",
		"https://github.com/marketplace/actions/checkout",
	} {
		if got := normalizeGitHub(raw); got != "" {
			t.Errorf("normalizeGitHub(%q) = %q; that is one of GitHub's own reserved "+
				"routes, not a repository — scoring it cannot work, and deps.dev's "+
				"disagreement turns into a borrow-a-score refusal (#134)", raw, got)
		}
	}
	// The other direction matters just as much: a real owner whose name merely
	// resembles one must still work, or the fix makes packages unscorable.
	for raw, want := range map[string]string{
		"https://github.com/sponsorship/tool":   "github.com/sponsorship/tool",
		"https://github.com/appseed/starter":    "github.com/appseed/starter",
		"https://github.com/about-time/lib":     "github.com/about-time/lib",
		"https://github.com/python-attrs/attrs": "github.com/python-attrs/attrs",
	} {
		if got := normalizeGitHub(raw); got != want {
			t.Errorf("normalizeGitHub(%q) = %q, want %q — the reserved list must not "+
				"swallow real owners", raw, got, want)
		}
	}
	// And a Sponsors URL must not be reported as an unsupported FORGE either: it is
	// on github.com, which we support. It is simply not a repo.
	if f := forgeOf("https://github.com/sponsors/hynek"); f != "" {
		t.Errorf("forgeOf said %q — a Sponsors page is not a coverage gap on another forge", f)
	}
}

// TestTheRealPypiLookupPicksTheSourceRepo drives the actual ecosystem against a
// stub index, because everything above tests the chooser and would pass just as
// happily if LookupRepo still ranged over the map itself.
//
// THE FIXTURE IS NOT attrs, AND THAT IS THE POINT -- found by sabotage, not by
// design. The first version used attrs (GitHub vs Funding), restored the original
// `for _, u := range m.Info.ProjectURLs` defect, and the test STAYED GREEN: the
// reserved-route fix already rejects github.com/sponsors/hynek, so only one
// candidate normalised and the random loop could not go wrong. A test that passes
// against the bug it was written for is not a test.
//
// So this uses typing-extensions, where BOTH candidates are real, existing repos of
// the same shape -- python/typing_extensions (Repository) and python/typing (Q & A).
// Nothing but the LABEL separates them, so only fix 1 can get it right, and the map
// loop reliably will not.
func TestTheRealPypiLookupPicksTheSourceRepo(t *testing.T) {
	body := `{"info":{"home_page":"https://typing-extensions.readthedocs.io/","project_urls":{
		"Documentation":"https://typing-extensions.readthedocs.io/",
		"Repository":"https://github.com/python/typing_extensions",
		"Bug Tracker":"https://github.com/python/typing_extensions/issues",
		"Q & A":"https://github.com/python/typing"}}}`

	srv := stubPypiIndex(t, body)
	eco := pypiEcosystem{base: srv}

	for i := 0; i < 100; i++ {
		repo, err := eco.LookupRepo(&http.Client{}, "typing-extensions")
		if err != nil {
			t.Fatalf("LookupRepo: %v", err)
		}
		if repo != "github.com/python/typing_extensions" {
			t.Fatalf("iteration %d: LookupRepo returned %q, want github.com/python/typing_extensions "+
				"— the real lookup is still picking at random, whatever the chooser does", i, repo)
		}
	}
}

// TestHomePageFallbackStillWorks: the project_urls path is now a function call, so
// the "no usable project_urls, fall back to home_page" behaviour is worth pinning
// rather than assuming the refactor preserved it.
func TestHomePageFallbackStillWorks(t *testing.T) {
	body := `{"info":{"home_page":"https://github.com/owner/fallback","project_urls":{
		"Documentation":"https://example.com/docs"}}}`
	eco := pypiEcosystem{base: stubPypiIndex(t, body)}
	repo, err := eco.LookupRepo(&http.Client{}, "somepkg")
	if err != nil {
		t.Fatalf("LookupRepo: %v", err)
	}
	if repo != "github.com/owner/fallback" {
		t.Errorf("LookupRepo = %q, want github.com/owner/fallback", repo)
	}
}

// TestURLRankOrdersTheFourTiers pins the ranking itself, so a later edit that
// makes two tiers equal -- which would silently hand the choice back to sort
// order -- fails here rather than in a package nobody is looking at.
func TestURLRankOrdersTheFourTiers(t *testing.T) {
	source, home, unknown, notSource := pypiURLRank("Source"), pypiURLRank("Homepage"),
		pypiURLRank("Weird Label"), pypiURLRank("Funding")
	if !(source < home && home < unknown && unknown < notSource) {
		t.Errorf("ranks are source=%d home=%d unknown=%d not-source=%d; want strictly "+
			"increasing, or the label stops deciding", source, home, unknown, notSource)
	}
	// Spelling must not matter: publishers write these freely.
	for _, spelling := range []string{"Source", "source", "Source Code", "GitHub: repo", "Repository"} {
		if got := pypiURLRank(spelling); got != 0 {
			t.Errorf("pypiURLRank(%q) = %d, want 0 -- a source label spelled another way "+
				"must still win", spelling, got)
		}
	}
	for _, spelling := range []string{"Funding", "Sponsor", "Code of Conduct", "Q & A", "Bug Tracker", "Documentation"} {
		if got := pypiURLRank(spelling); got != 3 {
			t.Errorf("pypiURLRank(%q) = %d, want 3 -- each of these produced a MEASURED "+
				"wrong-repo pick in #134", spelling, got)
		}
	}
}

// stubPypiIndex serves `body` as the project JSON at the path pypiEcosystem builds.
func stubPypiIndex(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
