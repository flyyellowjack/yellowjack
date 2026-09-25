package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestPypiWheelFilenameVersion pins the filename half. The grammar is fixed (PEP 427),
// so the interesting cases are the ones that are NOT wheels: they must yield "no
// opinion" rather than a guess, because a guess here becomes a refusal.
func TestPypiWheelFilenameVersion(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want string
		ok   bool
	}{
		{"plain wheel", "/packages/aa/bb/requests-2.31.0-py3-none-any.whl", "2.31.0", true},
		{"with build tag", "/packages/x/numpy-1.26.4-1-cp312-cp312-manylinux_x86_64.whl", "1.26.4", true},
		{"pre-release", "/packages/x/torch-2.0.0rc1-cp39-cp39-linux_x86_64.whl", "2.0.0rc1", true},
		{"epoch and local", "/packages/x/pkg-1!2.0+ubuntu1-py3-none-any.whl", "1!2.0+ubuntu1", true},
		{"underscored name", "/packages/x/python_dateutil-2.8.2-py2.py3-none-any.whl", "2.8.2", true},
		{"bare filename, no directory", "six-1.16.0-py2.py3-none-any.whl", "1.16.0", true},

		// Not wheels: there is no PEP 658 sibling to compare against, so these must be
		// silently uncovered rather than half-parsed.
		{"sdist is not covered", "/packages/x/six-1.16.0.tar.gz", "", false},
		{"zip sdist", "/packages/x/attrs-17.1.0.zip", "", false},
		{"egg", "/packages/x/MarkupSafe-0.11-py2.5-win32.egg", "", false},
		{"metadata sibling itself", "/packages/x/six-1.16.0-py3-none-any.whl.metadata", "", false},

		// Malformed wheel names. Too few fields means we do not understand it; guessing
		// is how a reader becomes confidently wrong (#122).
		{"too few fields", "/packages/x/six-1.16.0-py3.whl", "", false},
		{"no version field", "/packages/x/six.whl", "", false},
		{"empty version field", "/packages/x/six--py3-none-any.whl", "", false},
		{"too many fields", "/packages/x/a-1-2-3-4-5-6.whl", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := pypiWheelFilenameVersion(tc.path)
			if got != tc.want || ok != tc.ok {
				t.Errorf("pypiWheelFilenameVersion(%q) = %q,%v; want %q,%v", tc.path, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestPypiDeclaredVersion pins the metadata reader, including the two ways it must
// decline to have an opinion.
func TestPypiDeclaredVersion(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
		want string
		ok   bool
	}{
		{"ordinary", "Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\n\nA description.\n", "1.16.0", true},
		{"crlf", "Metadata-Version: 2.1\r\nName: six\r\nVersion: 1.16.0\r\n\r\nbody\r\n", "1.16.0", true},
		{"metadata-version is not version", "Metadata-Version: 2.1\nName: six\nVersion: 3.0\n", "3.0", true},
		{"case insensitive field", "VERSION: 1.2.3\n", "1.2.3", true},
		{"no trailing blank line", "Name: six\nVersion: 1.16.0", "1.16.0", true},

		// The body must not be read as headers: a README containing "Version: 9.9.9"
		// is extremely ordinary, and reading it would invent a mismatch.
		{"body mentions a version", "Name: six\nVersion: 1.0.0\n\nChangelog\nVersion: 9.9.9\n", "1.0.0", true},
		// A folded continuation belongs to the previous header, not a new one.
		{"folded continuation", "Name: six\nSummary: a long\n Version: 9.9.9\nVersion: 1.0.0\n", "1.0.0", true},

		// No opinion, rather than a guess.
		{"absent", "Metadata-Version: 2.1\nName: six\n\nbody", "", false},
		{"empty value", "Name: six\nVersion:   \n", "", false},
		{"declared twice", "Name: six\nVersion: 1.0.0\nVersion: 9.9.9\n", "", false},
		{"empty document", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := pypiDeclaredVersion(strings.NewReader(tc.doc))
			if got != tc.want || ok != tc.ok {
				t.Errorf("pypiDeclaredVersion(%q) = %q,%v; want %q,%v", tc.doc, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestPypiVersionsNameDifferentReleases is the heart of the false-positive argument.
//
// The "same" rows are the expensive failure: each is a LEGITIMATE wheel, and a refusal
// on any of them breaks a real install. They are the whole reason this compares release
// segments rather than strings — an exact compare fails every normalisation row below,
// and a wheel filename cannot contain "-" at all, so "1.0.0-rc1" in metadata becomes
// "1.0.0rc1" in the name for reasons that have nothing to do with misrepresentation.
func TestPypiVersionsNameDifferentReleases(t *testing.T) {
	for _, tc := range []struct {
		name             string
		served, declared string
		differ           bool
	}{
		// ── Legitimate. None of these may ever refuse.
		{"identical", "1.2.3", "1.2.3", false},
		{"trailing zero", "1.0", "1.0.0", false},
		{"trailing zeros both ways", "2.0.0.0", "2.0", false},
		{"prerelease separator normalised", "1.0.0rc1", "1.0.0-rc1", false},
		{"prerelease dot separator", "1.0.0a1", "1.0.0.a1", false},
		{"post release spelled differently", "1.0.0.post1", "1.0.0-post1", false},
		{"dev release", "1.0.0.dev3", "1.0.0dev3", false},
		{"local version differs in separator", "1.0+ubuntu.1", "1.0+ubuntu-1", false},
		{"epoch present", "1!2.0", "1!2.0", false},
		{"epoch vs none is not a release difference", "1!2.0", "2.0", false},
		{"case and v prefix", "1.0.0RC1", "v1.0.0rc1", false},
		{"suffix only disagreement is not refused", "1.0.0", "1.0.0rc1", false},

		// ── Genuine misrepresentation: a different release.
		{"wholly different", "1.0.0", "9.9.9", true},
		{"major differs", "1.2.3", "2.2.3", true},
		{"minor differs", "1.2.3", "1.3.3", true},
		{"patch differs", "1.2.3", "1.2.4", true},
		{"extra nonzero component", "1.2", "1.2.1", true},
		{"the measured chainguard shape", "10.0.0", "7.0.20", true},

		// ── No opinion when either side is unreadable.
		{"served unparseable", "notaversion", "1.0.0", false},
		{"declared unparseable", "1.0.0", "notaversion", false},
		{"both empty", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pypiVersionsNameDifferentReleases(tc.served, tc.declared); got != tc.differ {
				t.Errorf("pypiVersionsNameDifferentReleases(%q, %q) = %v; want %v",
					tc.served, tc.declared, got, tc.differ)
			}
		})
	}
}

// pypiVersionRig serves a /simple/ index, a PEP 658 metadata sibling declaring
// `declared`, and the wheel itself. It returns the proxy and the object path.
func pypiVersionRig(t *testing.T, servedVersion, declared string) (*proxyServer, string) {
	t.Helper()
	object := "/packages/ab/cd/six-" + servedVersion + "-py3-none-any.whl"
	files := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, pep658MetadataSuffix) {
			w.Write([]byte("Metadata-Version: 2.1\nName: six\nVersion: " + declared + "\n\nbody\n"))
			return
		}
		w.Write([]byte("WHEEL-BYTES"))
	}))
	t.Cleanup(files.Close)

	index := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="` + files.URL + object + `">six</a>`))
	}))
	t.Cleanup(index.Close)

	p := newTestProxy(t, index, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = files.URL
		c.ScoreThreshold = 0
		c.UnscorablePolicy = "allow"
		c.UnverifiedPolicy = "open-with-visibility"
		c.ScoreCacheTTL = time.Minute
	})
	return p, object
}

func getFiles(t *testing.T, p *proxyServer, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// TestAWheelServedUnderAnotherVersionIsRefused drives the real request path: the
// metadata sibling is fetched first (as pip does), then the wheel. The control is the
// same rig with agreeing versions, so a refusal proves the check rather than a broken rig.
func TestAWheelServedUnderAnotherVersionIsRefused(t *testing.T) {
	t.Run("mismatch refused", func(t *testing.T) {
		p, object := pypiVersionRig(t, "1.0.0", "9.9.9")

		if rec := getFiles(t, p, "/_files/six"+object+pep658MetadataSuffix); rec.Code != http.StatusOK {
			t.Fatalf("control: the metadata sibling must relay (got %d), or nothing below is measured", rec.Code)
		}
		rec := getFiles(t, p, "/_files/six"+object)
		if rec.Code == http.StatusOK {
			t.Fatalf("the wheel was SERVED under a version its own metadata contradicts: %d %q", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "WHEEL-BYTES") {
			t.Error("refused with a status but the artifact bytes were still written")
		}
		if !strings.Contains(rec.Body.String(), "different version") {
			t.Errorf("the refusal does not say WHY; an operator cannot tell it from the could-not-verify 403:\n%s", rec.Body.String())
		}
	})

	// The negative control. Without it a check that refused everything would look
	// identical to a correct one.
	t.Run("agreeing versions still serve", func(t *testing.T) {
		p, object := pypiVersionRig(t, "1.0.0", "1.0.0")
		getFiles(t, p, "/_files/six"+object+pep658MetadataSuffix)
		rec := getFiles(t, p, "/_files/six"+object)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "WHEEL-BYTES") {
			t.Fatalf("an honest wheel was refused: %d %q", rec.Code, rec.Body.String())
		}
	})

	// Normalisation must never refuse. This is the row that would break real installs.
	t.Run("normalisation difference still serves", func(t *testing.T) {
		p, object := pypiVersionRig(t, "1.0.0rc1", "1.0.0-rc1")
		getFiles(t, p, "/_files/six"+object+pep658MetadataSuffix)
		rec := getFiles(t, p, "/_files/six"+object)
		if rec.Code != http.StatusOK {
			t.Fatalf("a legitimate wheel was refused over a PEP 440 normalisation difference: %d %q", rec.Code, rec.Body.String())
		}
	})

	// No sibling seen: the check has no opinion and must not refuse. Measured at roughly
	// 3 in 20,000 wheels, plus any client resolving from its own cache.
	t.Run("no metadata seen serves unverified", func(t *testing.T) {
		p, object := pypiVersionRig(t, "1.0.0", "9.9.9")
		rec := getFiles(t, p, "/_files/six"+object) // the sibling is never fetched
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "WHEEL-BYTES") {
			t.Fatalf("a wheel with no observed metadata must be served, not refused: %d %q", rec.Code, rec.Body.String())
		}
	})
}

// TestMetadataRequestsAreNotThemselvesVersionChecked closes a gap a sabotage found: with
// signing OFF the PEP 658 suffix stays on the object path, so a metadata request never
// looks like a wheel and the comparison skips it for free. With signing ON the suffix
// rides on the signature instead, leaving an object path ending ".whl" — so a metadata
// request DOES look like a wheel, and once a version has been recorded a second fetch of
// the same metadata would be refused by its own recording.
//
// Removing the isMetadataRequest guard reddens nothing in the unsigned rig above, which
// is exactly why this exists: an unexercised guard is an untested one.
func TestMetadataRequestsAreNotThemselvesVersionChecked(t *testing.T) {
	object := "/packages/ab/cd/six-1.0.0-py3-none-any.whl"
	files := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, pep658MetadataSuffix) {
			w.Write([]byte("Metadata-Version: 2.1\nName: six\nVersion: 9.9.9\n\nbody\n"))
			return
		}
		w.Write([]byte("WHEEL-BYTES"))
	}))
	defer files.Close()
	index := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="` + files.URL + object + `">six</a>`))
	}))
	defer index.Close()

	p := newTestProxy(t, index, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = files.URL
		c.URLSigningKey = testKey
		c.ScoreThreshold = 0
		c.UnscorablePolicy = "allow"
		c.UnverifiedPolicy = "open-with-visibility"
		c.ScoreCacheTTL = time.Minute
	})

	idx := getFiles(t, p, "/simple/six/")
	if idx.Code != http.StatusOK {
		t.Fatalf("index did not relay: %d", idx.Code)
	}
	m := regexp.MustCompile(`/_files/six[^"]*`).FindString(idx.Body.String())
	if m == "" {
		t.Fatalf("index carries no signed /_files/ link:\n%s", idx.Body.String())
	}
	// pip appends the suffix to the WHOLE url, so on a signed link it lands on the
	// signature — this is the shape the guard exists for.
	for i := 1; i <= 2; i++ {
		rec := getFiles(t, p, m+pep658MetadataSuffix)
		if rec.Code != http.StatusOK {
			t.Fatalf("metadata fetch %d was refused (%d) — a PEP 658 request must never be version-checked against its own recording:\n%s",
				i, rec.Code, rec.Body.String())
		}
	}
	// And the wheel itself is still refused, so the guard did not disable the check.
	if rec := getFiles(t, p, m); rec.Code == http.StatusOK {
		t.Fatalf("the mismatched wheel was served under signing: %d %q", rec.Code, rec.Body.String())
	}
}

// TestPypiVersionsDisagreeInSuffixOnly pins the gate's leniency against pip's OWN,
// measured against real pip 26.2.1 resolving from an index (see the function comment).
//
// Both directions matter. Rows pip INSTALLS must not be reported, or the gate cries wolf
// on legitimate builds; the row pip REJECTS must be reported, or the operator hears
// nothing about a build their developers cannot install. A gate whose leniency does not
// match the installer's is the parser-differential failure of #122, and the false-refusal
// direction is the expensive one.
func TestPypiVersionsDisagreeInSuffixOnly(t *testing.T) {
	for _, tc := range []struct {
		name             string
		served, declared string
		pipInstalls      bool // MEASURED, not assumed
		report           bool
	}{
		{"identical", "1.0.0", "1.0.0", true, false},
		{"trailing zero", "1.0", "1.0.0", true, false},
		{"prerelease separator", "1.0.0rc1", "1.0.0-rc1", true, false},
		{"prerelease dot separator", "1.0.0a1", "1.0.0.a1", true, false},
		{"post separator", "1.0.0.post1", "1.0.0-post1", true, false},
		// MEASURED: pip installs both of these. The dot one is the row that makes the
		// separator-stripping CONTROLLABLE -- in "1.0.0a1" vs "1.0.0.a1" the dot is
		// consumed by the leading numeric run, so that row is insensitive to the stripping
		// and cannot fail when it is removed. A control that cannot fail pads the count.
		{"dot between suffix segments", "1.0.0rc1.post2", "1.0.0rc1post2", true, false},
		{"dot before dev", "1.0.0.dev1", "1.0.0dev1", true, false},

		// The one pip refuses and the gate does not: report it, do not refuse it.
		{"suffix present vs absent", "1.0.0", "1.0.0rc1", false, true},
		{"different prerelease number", "1.0.0rc1", "1.0.0rc2", false, true},
		{"different post number", "1.0.0rc1.post2", "1.0.0rc1.post3", false, true},

		// A release difference is the stronger report, handled by the other predicate.
		{"different release is not this case", "1.0.0", "9.9.9", false, false},

		// No opinion when either side is unreadable.
		{"unparseable served", "notaversion", "1.0.0", false, false},
		{"unparseable declared", "1.0.0", "notaversion", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := pypiVersionsDisagreeInSuffixOnly(tc.served, tc.declared)
			if got != tc.report {
				t.Errorf("pypiVersionsDisagreeInSuffixOnly(%q, %q) = %v; want %v",
					tc.served, tc.declared, got, tc.report)
			}
			// The load-bearing half: a row pip installs must never be reported at all,
			// by EITHER predicate, or the gate is noisier than the client is strict.
			if tc.pipInstalls {
				if got || pypiVersionsNameDifferentReleases(tc.served, tc.declared) {
					t.Errorf("real pip INSTALLS %q/%q, but the gate reports a disagreement",
						tc.served, tc.declared)
				}
			}
		})
	}
}
