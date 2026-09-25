package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Tier 1 for issue #35 (npm version-level soft block) and the npm half of #103.

func TestSemverCompare(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.9.0", "1.10.0", -1}, // numeric, not lexical
		{"2.0.0", "1.99.99", 1},
		{"2.0.0-beta.1", "2.0.0", -1}, // a release outranks its prereleases
		{"2.0.0-alpha", "2.0.0-beta", -1},
		{"2.0.0-beta.2", "2.0.0-beta.11", -1}, // numeric identifiers compare as numbers
		{"2.0.0-rc.1", "2.0.0-rc.1.1", -1},    // the longer list wins a tie
		{"1.0.0-1", "1.0.0-alpha", -1},        // numeric < alphanumeric
		{"1.0.0+build.7", "1.0.0", 0},         // build metadata is ignored
		{"v1.2.3", "1.2.3", 0},
		{"garbage", "0.0.1", -1}, // unparsable sorts below everything parsable
		{"garbage", "junk", -1},  // and lexically among themselves
	} {
		if got := semverCompare(tc.a, tc.b); got != tc.want {
			t.Errorf("semverCompare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := semverCompare(tc.b, tc.a); got != -tc.want {
			t.Errorf("semverCompare(%q, %q) = %d, want %d (antisymmetry)", tc.b, tc.a, got, -tc.want)
		}
	}
	for v, want := range map[string]bool{"1.0.0": false, "1.0.0-beta.1": true, "nope": true, "1.0.0+b": false} {
		if got := semverIsPrerelease(v); got != want {
			t.Errorf("semverIsPrerelease(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestNpmRepointTag(t *testing.T) {
	for _, tc := range []struct {
		removed   string
		remaining []string
		want      string
	}{
		{"2.0.0", []string{"1.0.0", "1.1.0", "2.1.0-beta.1"}, "1.1.0"},      // roll back to the previous release
		{"2.1.0-beta.1", []string{"2.1.0-beta.0", "2.0.0"}, "2.1.0-beta.0"}, // same class preferred
		{"2.1.0-beta.2", []string{"2.0.0", "1.0.0"}, "2.0.0"},               // no same-class predecessor: newest older
		{"2.0.0", []string{"1.5.0", "2.0.1-rc.1"}, "1.5.0"},                 // never forward onto something newer
		{"1.0.0", []string{"2.0.0", "3.0.0"}, "3.0.0"},                      // nothing older: newest remaining
		{"1.0.0", nil, ""}, // nothing at all: drop the tag
	} {
		if got := npmRepointTag(tc.removed, tc.remaining); got != tc.want {
			t.Errorf("npmRepointTag(%q, %v) = %q, want %q", tc.removed, tc.remaining, got, tc.want)
		}
	}
}

const fixturePackument = `{"name":"pkg",
 "dist-tags":{"latest":"2.0.0","next":"2.1.0-beta.1","old":"1.0.0"},
 "versions":{
   "1.0.0":{"name":"pkg","version":"1.0.0","dist":{"tarball":"http://up/pkg/-/pkg-1.0.0.tgz"}},
   "1.1.0":{"name":"pkg","version":"1.1.0","dist":{"tarball":"http://up/pkg/-/pkg-1.1.0.tgz"}},
   "2.0.0":{"name":"pkg","version":"2.0.0","dist":{"tarball":"http://up/pkg/-/pkg-2.0.0.tgz"}},
   "2.1.0-beta.1":{"name":"pkg","version":"2.1.0-beta.1","dist":{"tarball":"http://up/pkg/-/pkg-2.1.0-beta.1.tgz"}}},
 "time":{"1.0.0":"2020-01-01T00:00:00.000Z","2.0.0":"2024-01-01T00:00:00.000Z"}}`

func refuseVersions(bad ...string) npmVersionRefuser {
	return func(f npmVersionFacts) (string, npmRefusalCause) {
		for _, b := range bad {
			if f.Version == b {
				return "known malware: MAL-" + b, causeMalware
			}
		}
		return "", causeWindow
	}
}

func decodeDoc(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("filtered body is not JSON: %v\n%s", err, body)
	}
	return doc
}

func TestNpmFilterMetadataRemovesOnlyTheRefusedVersionAndRepointsItsTag(t *testing.T) {
	out, res, err := npmFilterMetadata([]byte(fixturePackument), refuseVersions("2.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != "packument" || len(res.Removed) != 1 || res.Removed[0].Version != "2.0.0" || res.Remaining != 3 {
		t.Fatalf("result = %+v, want one removal (2.0.0) with 3 remaining", res)
	}
	doc := decodeDoc(t, out)
	versions := doc["versions"].(map[string]any)
	if _, still := versions["2.0.0"]; still {
		t.Error("2.0.0 is still in the packument")
	}
	for _, v := range []string{"1.0.0", "1.1.0", "2.1.0-beta.1"} {
		if _, ok := versions[v]; !ok {
			t.Errorf("clean version %s vanished with the refused one", v)
		}
	}
	tags := doc["dist-tags"].(map[string]any)
	if tags["latest"] != "1.1.0" {
		t.Errorf("latest = %v, want 1.1.0 (the newest compliant release not newer than the refused one)", tags["latest"])
	}
	if tags["next"] != "2.1.0-beta.1" || tags["old"] != "1.0.0" {
		t.Errorf("tags that did not name the refused version were disturbed: %v", tags)
	}
	if got := res.Repointed["latest"]; got != [2]string{"2.0.0", "1.1.0"} {
		t.Errorf("Repointed[latest] = %v", got)
	}
	if _, still := doc["time"].(map[string]any)["2.0.0"]; still {
		t.Error("the refused version's time entry survived")
	}
}

func TestNpmFilterMetadataLeavesAnUntouchedDocumentByteIdentical(t *testing.T) {
	out, res, err := npmFilterMetadata([]byte(fixturePackument), refuseVersions("9.9.9"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte(fixturePackument)) {
		t.Error("a packument with nothing to remove was re-encoded — the regex rewrites before it would not survive")
	}
	if res.Remaining != 4 || len(res.Removed) != 0 {
		t.Errorf("result = %+v", res)
	}
}

func TestNpmFilterMetadataReportsWhenNothingCompliantRemains(t *testing.T) {
	out, res, err := npmFilterMetadata([]byte(fixturePackument), refuseVersions("1.0.0", "1.1.0", "2.0.0", "2.1.0-beta.1"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Remaining != 0 || len(res.Removed) != 4 {
		t.Fatalf("result = %+v, want everything removed", res)
	}
	if got := res.Repointed["latest"]; got != [2]string{"2.0.0", ""} {
		t.Errorf("a tag with nothing left to point at should be dropped, got %v", got)
	}
	if _, ok := decodeDoc(t, out)["dist-tags"].(map[string]any)["latest"]; ok {
		t.Error("the dangling latest tag is still in the document")
	}
}

func TestNpmFilterMetadataVersionDocument(t *testing.T) {
	doc := []byte(`{"name":"pkg","version":"2.0.0","dist":{"tarball":"http://up/pkg/-/pkg-2.0.0.tgz"}}`)
	out, res, err := npmFilterMetadata(doc, refuseVersions("2.0.0"))
	if err != nil || res.Kind != "version" || res.Refused == nil || res.Refused.Version != "2.0.0" {
		t.Fatalf("result = %+v, err = %v; want the version document refused", res, err)
	}
	if !bytes.Equal(out, doc) {
		t.Error("a version document must be returned untouched; the caller refuses the request")
	}
	_, res, _ = npmFilterMetadata(doc, refuseVersions("1.0.0"))
	if res.Refused != nil {
		t.Errorf("a version document of a clean version was refused: %+v", res.Refused)
	}
	if _, res, err := npmFilterMetadata([]byte(`not json`), refuseVersions("2.0.0")); err == nil || res.Kind != "other" {
		t.Errorf("non-JSON should be an error the caller serves through, got kind=%q err=%v", res.Kind, err)
	}
}

// ---- through the proxy ---------------------------------------------------------------

// npmVersionedUpstream serves a two-version package the way a registry does: the
// packument, the version documents, and a real tarball per version whose package.json
// agrees with its filename (so the #52 check passes and only the advisory can refuse).
// It reports which tarballs were actually fetched.
func npmVersionedUpstream(t *testing.T, pkg string, versions ...string) (*httptest.Server, map[string]int) {
	t.Helper()
	fetched := map[string]int{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		w.Header().Set("ETag", `"upstream-etag"`)
		switch {
		case strings.Contains(p, "/-/"):
			v := strings.TrimSuffix(strings.TrimPrefix(p, "/"+pkg+"/-/"+pkg+"-"), ".tgz")
			fetched[v]++
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(npmTgz(t, tgzEntry{"package/package.json", []byte(`{"name":"` + pkg + `","version":"` + v + `"}`)}))
		case p == "/"+pkg:
			w.Header().Set("Content-Type", "application/json")
			vs := make([]string, 0, len(versions))
			for _, v := range versions {
				vs = append(vs, `"`+v+`":{"name":"`+pkg+`","version":"`+v+`","dist":{"tarball":"`+srv.URL+`/`+pkg+`/-/`+pkg+`-`+v+`.tgz"}}`)
			}
			latest := versions[len(versions)-1]
			w.Write([]byte(`{"name":"` + pkg + `","dist-tags":{"latest":"` + latest + `"},"versions":{` + strings.Join(vs, ",") + `}}`))
		case p == "/"+pkg+"/latest" || strings.HasPrefix(p, "/"+pkg+"/"):
			v := strings.TrimPrefix(p, "/"+pkg+"/")
			if v == "latest" {
				v = versions[len(versions)-1]
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"name":"` + pkg + `","version":"` + v + `","repository":"github.com/acme/` + pkg + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	return srv, fetched
}

func pinnedProxy(t *testing.T, upstream *httptest.Server, feedLines ...string) *proxyServer {
	t.Helper()
	feed := writeFeed(t, feedLines...)
	return newTestProxy(t, upstream, func(c *Config) {
		c.MalwareListPath = feed
		c.UnscorablePolicy = "allow" // isolate: the only refusal under test is the advisory
	})
}

func getFrom(t *testing.T, p *proxyServer, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://fw.local"+path, nil))
	return rec
}

const pinTwo = `{"id":"MAL-NPM-PIN","ecosystem":"npm","name":"pkg","versions":["2.0.0"]}`

func TestNpmPinnedAdvisoryFiltersOnlyTheNamedVersion(t *testing.T) {
	up, _ := npmVersionedUpstream(t, "pkg", "1.0.0", "2.0.0")
	defer up.Close()
	logs := captureStdLog(t)
	p := pinnedProxy(t, up, pinTwo)

	rec := getFrom(t, p, "/pkg")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a pinned advisory must NOT refuse the package (that is the whole point); body: %s", rec.Code, rec.Body.String())
	}
	doc := decodeDoc(t, rec.Body.Bytes())
	versions := doc["versions"].(map[string]any)
	if _, still := versions["2.0.0"]; still {
		t.Error("the poisoned version is still offered to the client")
	}
	clean, ok := versions["1.0.0"].(map[string]any)
	if !ok {
		t.Fatal("the clean version vanished with the poisoned one")
	}
	if doc["dist-tags"].(map[string]any)["latest"] != "1.0.0" {
		t.Errorf("latest = %v, want 1.0.0 — npm would otherwise ask for a version we removed", doc["dist-tags"])
	}
	// The tarball rewrite that ran BEFORE the filter must survive the re-encode.
	if tb := clean["dist"].(map[string]any)["tarball"]; !strings.Contains(tb.(string), "/_tarball/pkg/") {
		t.Errorf("the surviving version's tarball URL lost its rewrite: %v", tb)
	}
	for _, want := range []string{
		"[known-malware] pkg -> version 2.0.0 removed from the packument (known malware: MAL-NPM-PIN); 1 versions remain",
		`dist-tag "latest" repointed from refused version 2.0.0 to 1.0.0`,
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("operator log lacks %q:\n%s", want, logs.String())
		}
	}
}

func TestNpmPackageWithoutAPinnedAdvisoryIsUntouched(t *testing.T) {
	up, _ := npmVersionedUpstream(t, "innocent", "1.0.0", "2.0.0")
	defer up.Close()
	logs := captureStdLog(t)
	p := pinnedProxy(t, up, pinTwo)
	rec := getFrom(t, p, "/innocent")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	doc := decodeDoc(t, rec.Body.Bytes())
	if n := len(doc["versions"].(map[string]any)); n != 2 {
		t.Errorf("%d versions, want 2 — a package no advisory names lost a version", n)
	}
	if doc["dist-tags"].(map[string]any)["latest"] != "2.0.0" {
		t.Errorf("latest moved on a package no advisory names: %v", doc["dist-tags"])
	}
	if strings.Contains(logs.String(), "[known-malware]") {
		t.Errorf("a refusal was logged for a package no advisory names:\n%s", logs.String())
	}
}

func TestNpmPackumentWithNoCompliantVersionIsRefusedLegibly(t *testing.T) {
	up, _ := npmVersionedUpstream(t, "pkg", "1.0.0", "2.0.0")
	defer up.Close()
	p := pinnedProxy(t, up, `{"id":"MAL-NPM-ALL","ecosystem":"npm","name":"pkg","versions":["1.0.0","2.0.0"]}`)
	rec := getFrom(t, p, "/pkg")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — an EMPTY packument is what npm reports as 'no matching version', which tells the developer nothing; body: %s", rec.Code, rec.Body.String())
	}
	reason := rec.Header().Get("X-Yellowjack-Reason")
	for _, want := range []string{`every version of "pkg" is listed as known malware`, "1.0.0 (MAL-NPM-ALL)", "2.0.0 (MAL-NPM-ALL)"} {
		if !strings.Contains(reason, want) {
			t.Errorf("X-Yellowjack-Reason = %q, want it to contain %q", reason, want)
		}
	}
	if !strings.Contains(rec.Body.String(), blockErrMsg) {
		t.Errorf("body lacks the %q marker real clients print: %s", blockErrMsg, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("X-Yellowjack-Next-Step"), "published advisory") {
		t.Errorf("next step does not say this is an advisory, not a policy threshold: %q", rec.Header().Get("X-Yellowjack-Next-Step"))
	}
	if et := rec.Header().Get("ETag"); et != "" {
		t.Errorf("upstream's ETag %q leaked onto our refusal — a client could cache the 403 against upstream's validator", et)
	}
}

func TestNpmVersionDocumentOfAPinnedVersionIsRefused(t *testing.T) {
	up, _ := npmVersionedUpstream(t, "pkg", "1.0.0", "2.0.0")
	defer up.Close()
	p := pinnedProxy(t, up, pinTwo)
	if rec := getFrom(t, p, "/pkg/2.0.0"); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Header().Get("X-Yellowjack-Reason"), `version "2.0.0" of "pkg" is listed as known malware (MAL-NPM-PIN)`) {
		t.Errorf("GET /pkg/2.0.0: status %d, reason %q — the version document names the refused version and must be refused", rec.Code, rec.Header().Get("X-Yellowjack-Reason"))
	}
	if rec := getFrom(t, p, "/pkg/1.0.0"); rec.Code != http.StatusOK {
		t.Errorf("GET /pkg/1.0.0: status %d, want 200 — the clean version's document was refused", rec.Code)
	}
}

// TestNpmPinnedVersionTarballIsRefusedOnTheBytePath is the second control point: a
// lockfile-driven fetch never reads the filtered packument, so the tarball's own
// filename carries the version (#52) and the same advisory refuses it — WITHOUT asking
// upstream for the bytes. Both URL shapes, because both arrive (bytegate_test.go).
func TestNpmPinnedVersionTarballIsRefusedOnTheBytePath(t *testing.T) {
	up, fetched := npmVersionedUpstream(t, "pkg", "1.0.0", "2.0.0")
	defer up.Close()
	p := pinnedProxy(t, up, pinTwo)
	for _, path := range []string{"/pkg/-/pkg-2.0.0.tgz", "/_tarball/pkg/pkg/-/pkg-2.0.0.tgz"} {
		rec := getFrom(t, p, path)
		if rec.Code != http.StatusForbidden {
			t.Errorf("GET %s: status %d, want 403 (%d bytes served)", path, rec.Code, rec.Body.Len())
		}
		if reason := rec.Header().Get("X-Yellowjack-Reason"); !strings.Contains(reason, "MAL-NPM-PIN") {
			t.Errorf("GET %s: reason %q does not name the advisory", path, reason)
		}
	}
	if fetched["2.0.0"] != 0 {
		t.Errorf("the poisoned tarball was fetched from upstream %d time(s) — refused without contacting upstream is the contract", fetched["2.0.0"])
	}
	rec := getFrom(t, p, "/pkg/-/pkg-1.0.0.tgz")
	if rec.Code != http.StatusOK || fetched["1.0.0"] != 1 {
		t.Errorf("the clean sibling: status %d, fetched %d — must be served", rec.Code, fetched["1.0.0"])
	}
	// Fail closed on a pinned package whose tarball filename carries no readable
	// version (the rule PyPI's /_files/ gate and Maven's path already follow) — and
	// only on a pinned package: an unpinned one with an odd filename is simply relayed.
	if rec := getFrom(t, p, "/pkg/-/oddly-named.tgz"); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Header().Get("X-Yellowjack-Reason"), "could not be determined") {
		t.Errorf("pinned package, unreadable version: status %d reason %q; want a fail-closed 403", rec.Code, rec.Header().Get("X-Yellowjack-Reason"))
	}
}

func TestNpmVersionFilterRefusalIsReportedNotRefusedInReportMode(t *testing.T) {
	up, _ := npmVersionedUpstream(t, "pkg", "1.0.0", "2.0.0")
	defer up.Close()
	logs := captureStdLog(t)
	feed := writeFeed(t, `{"id":"MAL-NPM-ALL","ecosystem":"npm","name":"pkg","versions":["1.0.0","2.0.0"]}`)
	p := newTestProxy(t, up, func(c *Config) {
		c.MalwareListPath = feed
		c.UnscorablePolicy = "allow"
		c.Mode = modeReport
	})
	rec := getFrom(t, p, "/pkg")
	if rec.Code != http.StatusOK {
		t.Fatalf("report mode: status %d, want 200 (relayed anyway); body: %s", rec.Code, rec.Body.String())
	}
	doc := decodeDoc(t, rec.Body.Bytes())
	if n := len(doc["versions"].(map[string]any)); n != 2 {
		t.Errorf("report mode served %d versions, want the UNFILTERED 2 — report mode relays what enforce would have refused", n)
	}
	if got, want := rec.Header().Get("Content-Length"), strconv.Itoa(rec.Body.Len()); got != want {
		t.Errorf("Content-Length %q does not match the %s-byte body served", got, want)
	}
	if !strings.Contains(logs.String(), "REPORT MODE: WOULD HAVE REFUSED pkg -> every version of \"pkg\" is listed as known malware") {
		t.Errorf("report mode did not record what it would have refused:\n%s", logs.String())
	}
}

// A whole-packument refusal is logged under the token of its CAUSE (D335). The literal
// "[known-malware]" on every cause mislabelled every cooldown refusal as malware.
func TestNpmRefusalTokenNamesTheCause(t *testing.T) {
	for want, d := range map[string]Decision{
		"[release-window]":  {Deny: denyReleaseWindow},
		"[operator-denied]": {Deny: denyOperator},
		"[known-malware]":   {Deny: denyKnownMalware},
	} {
		if got := npmRefusalToken(d); got != want {
			t.Errorf("deny kind %v logged as %s, want %s", d.Deny, got, want)
		}
	}
}
