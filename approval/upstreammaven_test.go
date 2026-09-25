package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Maven's half of D158's protocol-scraping step.
//
// The npm and PyPI tests pin the shape of the contract; these pin what is DIFFERENT
// about Maven, because that is where a copy of either fetcher would go wrong:
//
//   - the identity is a COORDINATE, "group:artifact", not a single name, and the
//     group's dots are path segments
//   - the document is XML (maven-metadata.xml), not JSON
//   - <lastUpdated> exists, is a plausible-looking timestamp, and is the WRONG answer
//     for "when was this version published" — it describes the artifact, not a version
//   - the right answer needs a SECOND request, and is a response HEADER the repository
//     sets, not a field the publisher wrote
//   - there is no deprecation signal at all, and no countable maintainer list

// mavenStub serves maven-metadata.xml for any GET and, for a HEAD, whatever
// Last-Modified the caller asked for. It records every path it was asked for, so a
// test can assert on the REQUEST the fetcher made and not only on what came back.
type mavenStub struct {
	metadata     string
	metaStatus   int
	lastModified string
	headStatus   int

	gets  int64
	heads int64

	mu    chan struct{}
	paths []string
}

func newMavenStub(t *testing.T, metadata string) (*mavenUpstream, *mavenStub) {
	t.Helper()
	s := &mavenStub{
		metadata:   metadata,
		metaStatus: http.StatusOK,
		headStatus: http.StatusOK,
		mu:         make(chan struct{}, 1),
	}
	s.mu <- struct{}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-s.mu
		s.paths = append(s.paths, r.Method+" "+r.URL.Path)
		s.mu <- struct{}{}

		if r.Method == http.MethodHead {
			atomic.AddInt64(&s.heads, 1)
			if s.lastModified != "" {
				w.Header().Set("Last-Modified", s.lastModified)
			}
			w.WriteHeader(s.headStatus)
			return
		}
		atomic.AddInt64(&s.gets, 1)
		w.WriteHeader(s.metaStatus)
		_, _ = w.Write([]byte(s.metadata))
	}))
	t.Cleanup(srv.Close)
	return &mavenUpstream{base: srv.URL, http: srv.Client()}, s
}

func (s *mavenStub) asked(method, substr string) bool {
	<-s.mu
	defer func() { s.mu <- struct{}{} }()
	for _, p := range s.paths {
		if strings.HasPrefix(p, method+" ") && strings.Contains(p, substr) {
			return true
		}
	}
	return false
}

// guavaMetadata is the shape Central actually serves, trimmed: several versions, a
// <release> and a <latest> that disagree, and ONE <lastUpdated> for the whole artifact.
const guavaMetadata = `<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.google.guava</groupId>
  <artifactId>guava</artifactId>
  <versioning>
    <latest>33.5.0-SNAPSHOT</latest>
    <release>33.4.0-jre</release>
    <versions>
      <version>32.0.0-jre</version>
      <version>33.3.1-jre</version>
      <version>33.4.0-jre</version>
    </versions>
    <lastUpdated>20260101093000</lastUpdated>
  </versioning>
</metadata>`

func TestMavenHarvestReadsWhatTheRepositoryReports(t *testing.T) {
	f, s := newMavenStub(t, guavaMetadata)
	s.lastModified = "Mon, 16 Dec 2024 18:04:11 GMT"

	h, avail := harvestUpstream(f, "com.google.guava:guava")
	if avail != availPresent || h == nil {
		t.Fatalf("availability = %q, harvest = %v; want a present harvest", avail, h)
	}

	// <release> wins over <latest>. A <latest> pointing at a SNAPSHOT is the common
	// case on an artifact with an active development line, and rendering it would tell
	// a developer to depend on something no release build will resolve.
	if h.LatestVersion != "33.4.0-jre" {
		t.Errorf("LatestVersion = %q, want 33.4.0-jre (the <release>, not the SNAPSHOT <latest>)", h.LatestVersion)
	}
	if h.VersionCount != 3 {
		t.Errorf("VersionCount = %d, want 3", h.VersionCount)
	}

	// The group's dots became path segments. If they did not, the request went to a
	// path Central does not serve and every real lookup would 404.
	if !s.asked(http.MethodGet, "/com/google/guava/guava/maven-metadata.xml") {
		t.Errorf("metadata was not requested at the GAV path; asked: %v", s.paths)
	}
}

// TestMavenPublishedAtIsNotLastUpdated is the load-bearing test in this file.
//
// <lastUpdated> is present, parseable, and describes the artifact as a whole —
// mavenage.go measured guava at 158 versions and one timestamp. A fetcher that read it
// would produce a page that looks entirely correct and dates every version identically.
// So the assertion is not "PublishedAt is set", it is "PublishedAt is the REPOSITORY's
// Last-Modified and specifically is not the document's own timestamp".
func TestMavenPublishedAtIsNotLastUpdated(t *testing.T) {
	f, s := newMavenStub(t, guavaMetadata)
	s.lastModified = "Mon, 16 Dec 2024 18:04:11 GMT"

	h, avail := harvestUpstream(f, "com.google.guava:guava")
	if avail != availPresent || h == nil {
		t.Fatalf("availability = %q; want a present harvest", avail)
	}

	want := time.Date(2024, 12, 16, 18, 4, 11, 0, time.UTC)
	if !h.PublishedAt.Equal(want) {
		t.Errorf("PublishedAt = %v, want %v (the POM's Last-Modified)", h.PublishedAt, want)
	}
	// The trap, asserted directly: <lastUpdated> is 2026-01-01, so a fetcher that used
	// it would land in 2026 and this would catch it by YEAR alone.
	if h.PublishedAt.Year() == 2026 {
		t.Errorf("PublishedAt = %v — that is <lastUpdated>, which describes the ARTIFACT, "+
			"not this version; every version would carry the same date (see mavenage.go)", h.PublishedAt)
	}
	// And it must have asked the right file: the POM of the resolved release, which
	// every artifact has whatever its packaging (!80 is the record of what guessing at
	// Maven extensions costs).
	if !s.asked(http.MethodHead, "/com/google/guava/guava/33.4.0-jre/guava-33.4.0-jre.pom") {
		t.Errorf("the date probe did not HEAD the release POM; asked: %v", s.paths)
	}
	if got := atomic.LoadInt64(&s.heads); got != 1 {
		t.Errorf("heads = %d, want exactly 1 — the date costs one extra request per lookup "+
			"and that price is stated in the code; more than one is a fan-out nobody agreed to", got)
	}
}

// TestMavenUndatedReleaseKeepsTheRestOfThePage pins the failure posture. Three of the
// five fields come from the metadata document and are already in hand when the date
// probe runs, so losing the date must not lose them — and must not turn a working
// lookup into an "upstream unreachable" marker.
func TestMavenUndatedReleaseKeepsTheRestOfThePage(t *testing.T) {
	for _, tc := range []struct {
		name         string
		headStatus   int
		lastModified string
	}{
		{"repository forbids HEAD", http.StatusMethodNotAllowed, ""},
		{"200 with no Last-Modified", http.StatusOK, ""},
		{"200 with an unparseable date", http.StatusOK, "the 16th of December, 2024"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, s := newMavenStub(t, guavaMetadata)
			s.headStatus = tc.headStatus
			s.lastModified = tc.lastModified

			h, avail := harvestUpstream(f, "com.google.guava:guava")
			if avail != availPresent || h == nil {
				t.Fatalf("availability = %q; a missing DATE must not become a missing PAGE", avail)
			}
			if !h.PublishedAt.IsZero() {
				t.Errorf("PublishedAt = %v, want the zero time — an unknown date must never be a guessed one", h.PublishedAt)
			}
			if h.LatestVersion != "33.4.0-jre" || h.VersionCount != 3 {
				t.Errorf("lost the fields we already had: version=%q count=%d", h.LatestVersion, h.VersionCount)
			}
		})
	}
}

// TestMavenCannotSayDeprecatedOrMaintainers records two ABSENCES as assertions.
//
// They are here so the gap is visible rather than inferred from an empty render: Maven
// has no deprecation signal, and maven-metadata.xml has no maintainer list. An empty
// Deprecated renders identically to "not deprecated", which is the part a reader could
// get wrong, so the limitation is pinned rather than left to the comment alone.
func TestMavenCannotSayDeprecatedOrMaintainers(t *testing.T) {
	f, s := newMavenStub(t, guavaMetadata)
	s.lastModified = "Mon, 16 Dec 2024 18:04:11 GMT"

	h, _ := harvestUpstream(f, "com.google.guava:guava")
	if h == nil {
		t.Fatal("no harvest")
	}
	if h.Deprecated != "" {
		t.Errorf("Deprecated = %q; Maven publishes no deprecation signal, so anything here "+
			"was invented by us", h.Deprecated)
	}
	if h.Maintainers != 0 {
		t.Errorf("Maintainers = %d; a POM's <developers> is publisher-authored prose, not the "+
			"repository's publisher list — counting it is a confident wrong number", h.Maintainers)
	}
}

// TestMavenThreeNoDataCasesStayDistinct mirrors the npm and PyPI tests of the same
// name: the marker is the contract, and a fetch that failed must never render like one
// that was never configured or like a clean result.
func TestMavenThreeNoDataCasesStayDistinct(t *testing.T) {
	if _, avail := harvestUpstream(nil, "com.google.guava:guava"); avail != availNotCollected {
		t.Errorf("unconfigured = %q, want %q", avail, availNotCollected)
	}

	f404, s404 := newMavenStub(t, "")
	s404.metaStatus = http.StatusNotFound
	if _, avail := harvestUpstream(f404, "com.google.guava:guava"); avail != availNotInRegistry {
		t.Errorf("404 = %q, want %q", avail, availNotInRegistry)
	}

	f500, s500 := newMavenStub(t, "")
	s500.metaStatus = http.StatusInternalServerError
	if _, avail := harvestUpstream(f500, "com.google.guava:guava"); avail != availUpstreamUnreachable {
		t.Errorf("500 = %q, want %q", avail, availUpstreamUnreachable)
	}

	fbad, sbad := newMavenStub(t, "<metadata><versioning>")
	sbad.lastModified = "Mon, 16 Dec 2024 18:04:11 GMT"
	if _, avail := harvestUpstream(fbad, "com.google.guava:guava"); avail != availUpstreamUnreachable {
		t.Errorf("malformed XML = %q, want %q — an undecodable document is a broken upstream, "+
			"not an absent package", avail, availUpstreamUnreachable)
	}
}

// TestANameThatIsNotACoordinateIsAnAnswer: the console can be asked about any string.
// "lodash" is a real package name in a different ecosystem and cannot name a Maven
// artifact, so the honest render is "not in the registry" — and, critically, NO request
// is made, because there is no URL to make it to.
func TestANameThatIsNotACoordinateIsAnAnswer(t *testing.T) {
	for _, name := range []string{"lodash", "", ":", "com.google.guava:", ":guava"} {
		f, s := newMavenStub(t, guavaMetadata)
		h, avail := harvestUpstream(f, name)
		if avail != availNotInRegistry || h != nil {
			t.Errorf("%q: availability = %q, harvest = %v; want %q and no harvest",
				name, avail, h, availNotInRegistry)
		}
		if g, hd := atomic.LoadInt64(&s.gets), atomic.LoadInt64(&s.heads); g != 0 || hd != 0 {
			t.Errorf("%q: made %d GET(s) and %d HEAD(s) for a string that cannot be a Maven "+
				"coordinate; the fetcher must not build a URL out of it", name, g, hd)
		}
	}
}

// TestAHostileMavenRepositoryCannotExhaustUs: this service reads an untrusted
// third-party document while an operator waits on a page render, so the read is bounded
// by upstreamMaxBytes.
//
// Deliberately built on the SAME instrument as the PyPI twin rather than on a timeout.
// A wall-clock assertion would pass on a fast loopback that streamed every byte, which
// is the outcome it exists to catch; and "how many bytes did the peer send" is not the
// quantity a read cap bounds — that confusion is what made the PyPI test flaky (#111).
// countingTransport measures what WE read, which is exactly what the cap states.
func TestAHostileMavenRepositoryCannotExhaustUs(t *testing.T) {
	const offered = upstreamMaxBytes * 4
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		// A well-formed prologue, so the read is ended by the cap rather than by a
		// parse error arriving early.
		_, _ = w.Write([]byte(`<?xml version="1.0"?><metadata><versioning><release>1.0</release><versions>`))
		chunk := []byte(strings.Repeat("<version>1.0</version>", 2048))
		for written := 0; written < offered; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	var consumed int64
	client := srv.Client()
	client.Transport = countingTransport{base: client.Transport, n: &consumed}

	f := &mavenUpstream{base: srv.URL, http: client}
	_, _, _ = f.Fetch("com.google.guava:guava")

	// THE REAL ASSERTION. io.LimitReader stops at exactly upstreamMaxBytes, so anything
	// above it means the cap is not in the read path at all — no slack needed.
	got := atomic.LoadInt64(&consumed)
	if got > upstreamMaxBytes {
		t.Errorf("consumed %d bytes of the %d offered; the %d-byte cap is not bounding the read",
			got, offered, upstreamMaxBytes)
	}
	// ANTI-VACUITY: "consumed <= cap" is also satisfied by consuming NOTHING, so a
	// connection that failed for an unrelated reason would pass while proving nothing.
	// io.ReadAll reads until LimitReader reports EOF, so a healthy run lands ON the cap.
	if got < upstreamMaxBytes/2 {
		t.Errorf("consumed only %d bytes, far below the %d-byte cap: the read stopped for "+
			"some reason OTHER than the cap, so this test is not exercising it", got, upstreamMaxBytes)
	}
}
