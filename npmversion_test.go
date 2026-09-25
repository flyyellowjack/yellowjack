package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Tier 1 for issue #52: the version a tarball is served as must be the version inside it.
//
// The two headline tests differ in exactly one string — the version the fixture's
// package.json declares — so each is the other's negative control: a check that had
// silently stopped running would turn the refusal test red, and a check that refused
// everything would turn the verbatim test red.

type tgzEntry struct {
	name string
	body []byte
}

// tgzLinkEntry is a tar entry that is either a regular file (link == 0) or a link entry
// (tar.TypeSymlink / tar.TypeLink) pointing at target with no body. A separate type
// rather than new tgzEntry fields, because every existing fixture builds tgzEntry
// positionally.
type tgzLinkEntry struct {
	name   string
	body   []byte
	link   byte
	target string
}

// npmTgzLinks is npmTgz for fixtures that need link entries.
func npmTgzLinks(t *testing.T, entries ...tgzLinkEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body))}
		if e.link != 0 {
			h = &tar.Header{Name: e.name, Mode: 0o777, Typeflag: e.link, Linkname: e.target}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// npmTgz builds a tarball the way `npm pack` does — every file under "package/", in the
// order given, gzip-compressed — or in whatever layout the entries spell out.
func npmTgz(t *testing.T, entries ...tgzEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func packageJSON(version string) []byte {
	return []byte(`{"name":"lodash","version":"` + version + `","main":"index.js"}`)
}

// lodashTgz is what the registry serves at /lodash/-/lodash-<served>.tgz: an npm-pack
// layout whose package.json declares `declared`.
func lodashTgz(t *testing.T, declared string) []byte {
	t.Helper()
	return npmTgz(t,
		tgzEntry{"package/package.json", packageJSON(declared)},
		tgzEntry{"package/index.js", []byte("module.exports = 1;\n")},
	)
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// incompressible is a blob gzip cannot shrink, so a tarball that puts it before
// package.json keeps package.json past the inspection window in COMPRESSED bytes,
// which is the quantity the window is measured in.
func incompressible(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func captureStdLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// fetchTarball drives one request through a proxy in front of an upstream serving `tgz`
// on every "/-/" path, and reports whether the upstream was asked for the bytes at all.
func fetchTarball(t *testing.T, method, path string, tgz []byte, mutate func(*Config)) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	fetched := false
	upstream := npmTarballUpstream(t, "lodash", string(tgz), func() { fetched = true })
	defer upstream.Close()
	p := newTestProxy(t, upstream, mutate)
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec, fetched
}

const lodashTarballPath = "http://fw.local/lodash/-/lodash-1.0.0.tgz"

func TestNpmTarballVersionFromPath(t *testing.T) {
	for _, tc := range []struct {
		pkg, path, want string
		ok              bool
	}{
		{"lodash", "/lodash/-/lodash-4.17.21.tgz", "4.17.21", true},
		{"@babel/core", "/@babel/core/-/core-7.24.0.tgz", "7.24.0", true},
		{"@babel/core", "/@babel%2Fcore/-/core-7.24.0.tgz", "7.24.0", true},
		{"lodash", "/lodash/-/lodash-5.0.0-beta.1.tgz", "5.0.0-beta.1", true},
		{"lodash", "/lodash/-/lodash-1.0.0%2Bbuild.7.tgz", "1.0.0+build.7", true},
		{"my-pkg", "/my-pkg/-/my-pkg-2.0.0.tgz", "2.0.0", true}, // hyphen in the base name
		{"lodash", "/lodash/-/underscore-1.0.0.tgz", "", false}, // someone else's filename
		{"lodash", "/lodash/-/lodash-1.0.0.tar.gz", "", false},  // not the registry's extension
		{"lodash", "/lodash/-/lodash-.tgz", "", false},          // empty version
		{"lodash", "/lodash/-/lodash-1.0.0.tgz/x", "", false},   // a path, not a filename
		{"lodash", "/-/lodash-1.0.0.tgz", "", false},            // control plane, no package
		{"lodash", "/lodash/lodash-1.0.0.tgz", "", false},       // no "/-/" boundary
	} {
		got, ok := npmTarballVersionFromPath(tc.pkg, tc.path)
		if got != tc.want || ok != tc.ok {
			t.Errorf("npmTarballVersionFromPath(%q, %q) = (%q, %v), want (%q, %v)",
				tc.pkg, tc.path, got, ok, tc.want, tc.ok)
		}
	}
}

// TestNpmDeclaredVersion pins the reader to npm's own extractor. Every expectation
// below was MEASURED by installing the identical bytes with a real npm (node:22-alpine,
// `npm install ./fixture.tgz`) and reading the version that landed in node_modules --
// see issue #122. Where the two ever disagreed, npm is right by definition: it is the
// thing the developer runs, and a reader that is confidently different from it produces
// confidently wrong verdicts.
//
// The npm column is the negative control for the whole table. "not a manifest" rows are
// tarballs npm REFUSES to install (ENOENT), so treating them as unreadable costs nothing;
// "manifest" rows are tarballs npm installs, so missing one is a hole.
func TestNpmDeclaredVersion(t *testing.T) {
	big := incompressible(t, npmTarballInspectBytes+1)
	beyond := npmTgz(t, tgzEntry{"package/blob.bin", big}, tgzEntry{"package/package.json", packageJSON("1.0.0")})
	for _, tc := range []struct {
		name        string
		head        []byte
		want        string
		wantEntries int
		wantErr     string
	}{
		{name: "npm pack layout, package.json first", head: lodashTgz(t, "1.2.3"), want: "1.2.3", wantEntries: 1},
		{name: "package.json after other entries",
			head: npmTgz(t, tgzEntry{"package/README.md", []byte("# hi")}, tgzEntry{"package/package.json", packageJSON("2.0.0")}),
			want: "2.0.0", wantEntries: 1},
		{name: "root directory named otherwise (one component is stripped, whatever it is)",
			head: npmTgz(t, tgzEntry{"lodash-1.0.0/package.json", packageJSON("1.0.0")}), want: "1.0.0", wantEntries: 1},

		// The three shapes npm installs that a "strip ./ then require one directory"
		// reader missed entirely, and therefore served unchecked before #122.
		{name: "dot-slash is itself the stripped component, so this IS the manifest",
			head: npmTgz(t, tgzEntry{"./package.json", packageJSON("4.0.0")}), want: "4.0.0", wantEntries: 1},
		{name: "leading slash likewise",
			head: npmTgz(t, tgzEntry{"/package.json", packageJSON("5.0.0")}), want: "5.0.0", wantEntries: 1},
		{name: "repeated slashes collapse",
			head: npmTgz(t, tgzEntry{"package//package.json", packageJSON("6.0.0")}), want: "6.0.0", wantEntries: 1},

		// LINK ENTRIES (#47's open question, measured 2026-09-23 with a real `npm install`
		// on node:22-alpine): npm SKIPS symlink and hardlink entries when it extracts. A real
		// package.json followed by a link NAMED package/package.json installs the real
		// one's version as a plain file. Counting the link as the manifest made the scan
		// error and the tarball be served unchecked, so appending one link entry turned a
		// refused version mismatch into a served one.
		{name: "a symlink named package.json after the real one is skipped, as npm skips it",
			head: npmTgzLinks(t, tgzLinkEntry{name: "package/package.json", body: packageJSON("9.9.9")},
				tgzLinkEntry{name: "package/package.json", link: tar.TypeSymlink, target: "other.json"}),
			want: "9.9.9", wantEntries: 1},
		{name: "a hardlink named package.json after the real one is skipped likewise",
			head: npmTgzLinks(t, tgzLinkEntry{name: "package/package.json", body: packageJSON("9.9.9")},
				tgzLinkEntry{name: "package/other.json", body: packageJSON("1.0.0")},
				tgzLinkEntry{name: "package/package.json", link: tar.TypeLink, target: "package/other.json"}),
			want: "9.9.9", wantEntries: 1},
		{name: "a link as the ONLY manifest is no manifest (npm fails to install it: ENOENT)",
			head: npmTgzLinks(t, tgzLinkEntry{name: "package/real.json", body: packageJSON("9.9.9")},
				tgzLinkEntry{name: "package/package.json", link: tar.TypeSymlink, target: "real.json"}),
			wantErr: "no package.json"},

		// The shapes npm REFUSES: one component is stripped, so anything still nested
		// after that is not the tarball's own manifest.
		{name: "dot-slash prefix ON TOP of a directory leaves it nested (npm: ENOENT)",
			head: npmTgz(t, tgzEntry{"./package/package.json", packageJSON("3.0.0")}), wantErr: "no package.json in the tarball"},
		{name: "leading slash on top of a directory likewise (npm: ENOENT)",
			head: npmTgz(t, tgzEntry{"/package/package.json", packageJSON("3.0.0")}), wantErr: "no package.json in the tarball"},
		{name: "bare package.json has no component to strip (npm: ENOENT)",
			head: npmTgz(t, tgzEntry{"package.json", packageJSON("3.0.0")}), wantErr: "no package.json in the tarball"},
		{name: "nested package.json is a workspace member's, not the tarball's (npm: ENOENT)",
			head: npmTgz(t, tgzEntry{"package/sub/package.json", packageJSON("9.9.9")}), wantErr: "no package.json in the tarball"},

		// Duplicates. An extractor writes in order, so the LAST entry is the one that
		// survives in node_modules -- measured both ways round so neither direction is
		// an assumption.
		{name: "two manifests: the last one is what npm installs",
			head: npmTgz(t,
				tgzEntry{"package/package.json", packageJSON("1.0.0")},
				tgzEntry{"package/index.js", []byte("module.exports=1;")},
				tgzEntry{"package/package.json", packageJSON("9.9.9")}),
			want: "9.9.9", wantEntries: 2},
		{name: "two manifests, the other way round",
			head: npmTgz(t,
				tgzEntry{"package/package.json", packageJSON("9.9.9")},
				tgzEntry{"package/package.json", packageJSON("1.0.0")}),
			want: "1.0.0", wantEntries: 2},
		{name: "three manifests: still the last",
			head: npmTgz(t,
				tgzEntry{"package/package.json", packageJSON("1.0.0")},
				tgzEntry{"package/package.json", packageJSON("5.5.5")},
				tgzEntry{"package/package.json", packageJSON("9.9.9")}),
			want: "9.9.9", wantEntries: 3},
		{name: "a broken last manifest is not rescued by a good earlier one (npm: EJSONPARSE)",
			head: npmTgz(t,
				tgzEntry{"package/package.json", packageJSON("1.0.0")},
				tgzEntry{"package/package.json", []byte("not json at all")}),
			wantEntries: 2, wantErr: "not JSON"},
		{name: "a last manifest with no version is not rescued either (npm installs version undefined)",
			head: npmTgz(t,
				tgzEntry{"package/package.json", packageJSON("1.0.0")},
				tgzEntry{"package/package.json", []byte(`{"name":"lodash"}`)}),
			wantEntries: 2, wantErr: "declares no version"},

		{name: "not gzip", head: []byte("raw-tarball-bytes"), wantErr: "not a gzip stream"},
		{name: "gzip but not tar", head: gzipBytes(t, []byte("hello")), wantErr: "tar stream unreadable"},
		{name: "no version field", head: npmTgz(t, tgzEntry{"package/package.json", []byte(`{"name":"lodash"}`)}), wantEntries: 1, wantErr: "declares no version"},
		{name: "package.json is not JSON", head: npmTgz(t, tgzEntry{"package/package.json", []byte("nope")}), wantEntries: 1, wantErr: "not JSON"},
		{name: "cut short before package.json (the caller names the window)", head: beyond[:npmTarballInspectBytes], wantErr: "unexpected EOF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := npmDeclaredVersion(bytes.NewReader(tc.head))
			if tc.wantEntries != 0 && got.Entries != tc.wantEntries {
				t.Errorf("counted %d package.json entries, want %d -- the count is what tells an "+
					"operator a tarball was built to read differently to different parsers", got.Entries, tc.wantEntries)
			}
			if tc.wantErr == "" {
				if got.Err != nil || got.Version != tc.want {
					t.Fatalf("npmDeclaredVersion = (%q, %v), want (%q, nil)", got.Version, got.Err, tc.want)
				}
				if !got.Final {
					t.Errorf("a whole tarball was read but Final is false, so the caller will refuse to " +
						"call it verified")
				}
				return
			}
			if got.Err == nil || !strings.Contains(got.Err.Error(), tc.wantErr) {
				t.Fatalf("npmDeclaredVersion = (%q, %v), want an error containing %q", got.Version, got.Err, tc.wantErr)
			}
		})
	}
}

// TestNpmDeclaredVersionStopsAtTheWindowWithoutClaimingFinal is the prefix case: the
// manifest is readable and agrees, but the archive runs on past what the caller fed in.
// Final must be false, because "the versions matched in the part I read" is a different
// statement from "the versions match" -- the conflation #47 exists to prevent.
func TestNpmDeclaredVersionStopsAtTheWindowWithoutClaimingFinal(t *testing.T) {
	tgz := npmTgz(t,
		tgzEntry{"package/package.json", packageJSON("1.0.0")},
		tgzEntry{"package/blob.bin", incompressible(t, npmTarballInspectBytes+1)})
	got := npmDeclaredVersion(bytes.NewReader(tgz[:npmTarballInspectBytes]))
	if got.Err != nil || got.Version != "1.0.0" {
		t.Fatalf("npmDeclaredVersion = (%q, %v), want 1.0.0 and no error", got.Version, got.Err)
	}
	if got.Final {
		t.Fatal("Final is true for a stream that stopped mid-archive: the reader is claiming a " +
			"whole-file property it measured on a prefix")
	}
	// Control: the same archive read whole DOES reach the end, so Final is measuring the
	// stream and not simply hard-coded false for large tarballs.
	if whole := npmDeclaredVersion(bytes.NewReader(tgz)); !whole.Final || whole.Version != "1.0.0" {
		t.Fatalf("reading the whole archive gave (%q, final=%v), want 1.0.0 and final=true -- "+
			"the prefix assertion above proves nothing if Final is never true", whole.Version, whole.Final)
	}
}

// TestNpmTarballDeclaringAnotherVersionIsRefused is the acceptance criterion for #52:
// a tarball served as 1.0.0 whose package.json says 9.9.9 is refused, with a reason
// that names both versions and is NOT the unscorable one. Both URL shapes are driven,
// because both really arrive (bytegate_test.go), and the byte-gate mode is varied
// because the check is an integrity property of the fetch, not a policy the mode ladder
// decides — FW_BYTE_GATE=off is the pre-#11 passthrough for VERDICTS and does not turn
// a wrong file under a right name into a right one.
func TestNpmTarballDeclaringAnotherVersionIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		mode func(*Config)
	}{
		{"native lockfile URL", lodashTarballPath, nil},
		{"rewritten URL", "http://fw.local/_tarball/lodash/lodash/-/lodash-1.0.0.tgz", nil},
		{"enforce", lodashTarballPath, func(c *Config) { c.ByteGate = byteGateEnforce }},
		{"off", lodashTarballPath, func(c *Config) { c.ByteGate = byteGateOff }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureStdLog(t)
			rec, fetched := fetchTarball(t, http.MethodGet, tc.path, lodashTgz(t, "9.9.9"), tc.mode)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (body is %d bytes: the tarball was served)", rec.Code, rec.Body.Len())
			}
			// Which LAYER refused matters (docs/E2E_TESTING.md item 12): a 403 from the
			// policy would satisfy a status check while the version check was not
			// running at all. The reason header names the layer; the upstream having
			// been asked for the bytes proves the refusal came from READING them.
			if !fetched {
				t.Fatalf("the upstream was never asked for the tarball — the refusal came from a layer that never read the bytes")
			}
			reason := rec.Header().Get("X-Yellowjack-Reason")
			for _, want := range []string{"declares version 9.9.9", "served as version 1.0.0"} {
				if !strings.Contains(reason, want) {
					t.Errorf("X-Yellowjack-Reason = %q, want it to contain %q", reason, want)
				}
			}
			if strings.Contains(strings.ToLower(reason), "unscorable") {
				t.Errorf("the reason reads as unscorable (%q); #52 requires a DISTINCT reason for misrepresentation", reason)
			}
			if !strings.Contains(rec.Body.String(), blockErrMsg) {
				t.Errorf("body = %q, want the %q marker every real client prints", rec.Body.String(), blockErrMsg)
			}
			if next := rec.Header().Get("X-Yellowjack-Next-Step"); !strings.Contains(next, "no approval will clear this") {
				t.Errorf("X-Yellowjack-Next-Step = %q — a mismatch is not a review item, and the developer must be told so", next)
			}
			if !strings.Contains(logs.String(), "refused: tarball declares version 9.9.9 but was served as version 1.0.0") {
				t.Errorf("the operator's log does not say what was refused or why:\n%s", logs.String())
			}
		})
	}
}

// TestNpmTarballDeclaringTheServedVersionIsRelayedVerbatim is the negative control: the
// same fixture with a truthful package.json is served, byte for byte, so dist.integrity
// still verifies on the client — and the log shows the check RAN rather than being
// skipped, which is what separates "passed" from "never looked".
func TestNpmTarballDeclaringTheServedVersionIsRelayedVerbatim(t *testing.T) {
	logs := captureStdLog(t)
	tgz := lodashTgz(t, "1.0.0")
	rec, fetched := fetchTarball(t, http.MethodGet, lodashTarballPath, tgz, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if !fetched {
		t.Fatal("the upstream was never asked for the tarball")
	}
	if !bytes.Equal(rec.Body.Bytes(), tgz) {
		t.Fatalf("the relayed bytes differ from the upstream's (%d vs %d bytes) — the client's integrity check would fail on a good tarball",
			rec.Body.Len(), len(tgz))
	}
	if !strings.Contains(logs.String(), "version verified: 1.0.0") {
		t.Errorf("the tarball was served but the check never ran:\n%s", logs.String())
	}
}

// TestNpmTarballWithoutAReadableVersionIsServedAndSaidSo pins the deliberate limit of
// the check (see the file comment in npmversion.go): when the version cannot be read,
// the bytes are served and the reason is logged. The third case is the honest record of
// the one way past the check — a package.json placed beyond the inspection window — and
// it is served even though it lies, which is the documented cost of not buffering whole
// artifacts. npm itself cannot install a tarball without a readable package.json, so
// the first two cases refuse nothing a client could have used.
func TestNpmTarballWithoutAReadableVersionIsServedAndSaidSo(t *testing.T) {
	big := incompressible(t, npmTarballInspectBytes+1)
	for _, tc := range []struct {
		name string
		tgz  []byte
		why  string
	}{
		{"not a tarball at all", []byte("raw-tarball-bytes"), "not a gzip stream"},
		{"no package.json", npmTgz(t, tgzEntry{"package/index.js", []byte("1")}), "no package.json in the tarball"},
		{"package.json beyond the inspection window, and lying",
			npmTgz(t, tgzEntry{"package/blob.bin", big}, tgzEntry{"package/package.json", packageJSON("9.9.9")}),
			"no package.json in the first"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureStdLog(t)
			rec, _ := fetchTarball(t, http.MethodGet, lodashTarballPath, tc.tgz, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (served with the reason logged); body: %s", rec.Code, rec.Body.String())
			}
			if !bytes.Equal(rec.Body.Bytes(), tc.tgz) {
				t.Fatalf("the relayed bytes differ from the upstream's (%d vs %d bytes)", rec.Body.Len(), len(tc.tgz))
			}
			for _, want := range []string{"version unverified", tc.why} {
				if !strings.Contains(logs.String(), want) {
					t.Errorf("log lacks %q — served without saying why is a hole, served with the reason is visibility:\n%s", want, logs.String())
				}
			}
		})
	}
}

// A HEAD carries no body, so there is nothing to inspect and nothing to say.
func TestNpmTarballHeadIsRelayedWithoutInspection(t *testing.T) {
	logs := captureStdLog(t)
	rec, _ := fetchTarball(t, http.MethodHead, lodashTarballPath, lodashTgz(t, "9.9.9"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200", rec.Code)
	}
	if strings.Contains(logs.String(), "version unverified") || strings.Contains(logs.String(), "refused:") {
		t.Errorf("a HEAD was inspected as if it had a body:\n%s", logs.String())
	}
}

// Report mode turns the refusal into the same WOULD HAVE REFUSED line every other
// refusal gets, and serves the bytes — through p.refuse, so it cannot drift from them.
func TestNpmTarballVersionMismatchIsReportedNotRefusedInReportMode(t *testing.T) {
	logs := captureStdLog(t)
	tgz := lodashTgz(t, "9.9.9")
	rec, _ := fetchTarball(t, http.MethodGet, lodashTarballPath, tgz, func(c *Config) { c.Mode = modeReport })
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 in report mode; body: %s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(rec.Body.Bytes(), tgz) {
		t.Fatal("report mode served different bytes from the upstream's")
	}
	if !strings.Contains(logs.String(), "REPORT MODE: WOULD HAVE REFUSED lodash -> tarball declares version 9.9.9") {
		t.Errorf("report mode did not record what it would have refused:\n%s", logs.String())
	}
}

// TestNpmTarballWithTwoManifestsIsJudgedByTheOneNpmInstalls is the regression for the
// bypass in issue #122: a tarball carrying two package.json entries reads as 1.0.0 to a
// first-match reader and installs as 9.9.9, so the check that exists to catch exactly
// this logged "version verified: 1.0.0" and served it.
//
// The two legs differ only in the ORDER of the same two manifests, so each is the
// other's control: a reader that went back to first-match fails the refusal leg, and a
// reader that simply refuses anything with a duplicate fails the serve leg. Nothing
// about "a duplicate exists" decides this -- only which one the installer would use.
func TestNpmTarballWithTwoManifestsIsJudgedByTheOneNpmInstalls(t *testing.T) {
	t.Run("served version first, another last: npm would install the last, so refuse", func(t *testing.T) {
		logs := captureStdLog(t)
		tgz := npmTgz(t,
			tgzEntry{"package/package.json", packageJSON("1.0.0")},
			tgzEntry{"package/index.js", []byte("module.exports = 1;")},
			tgzEntry{"package/package.json", packageJSON("9.9.9")})
		rec, fetched := fetchTarball(t, http.MethodGet, lodashTarballPath, tgz, nil)
		if !fetched {
			t.Fatal("the upstream was never asked for the tarball, so nothing read the bytes")
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: npm installs the LAST package.json, which declares 9.9.9 "+
				"under a 1.0.0 URL -- the misrepresentation this check exists for", rec.Code)
		}
		reason := rec.Header().Get("X-Yellowjack-Reason")
		for _, want := range []string{"declares version 9.9.9", "served as version 1.0.0", "npm installs the last"} {
			if !strings.Contains(reason, want) {
				t.Errorf("X-Yellowjack-Reason = %q, want it to contain %q -- a 403 whose reason names the "+
					"wrong version is indistinguishable from one that fired for another cause", reason, want)
			}
		}
		if !strings.Contains(logs.String(), "carries 2 package.json entries") {
			t.Errorf("the operator's log does not mention the duplicate, so the odd thing about this "+
				"tarball is invisible:\n%s", logs.String())
		}
	})

	t.Run("another version first, served version last: npm installs the right one, so serve", func(t *testing.T) {
		logs := captureStdLog(t)
		tgz := npmTgz(t,
			tgzEntry{"package/package.json", packageJSON("9.9.9")},
			tgzEntry{"package/package.json", packageJSON("1.0.0")})
		rec, _ := fetchTarball(t, http.MethodGet, lodashTarballPath, tgz, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: npm installs the LAST package.json, which declares the "+
				"served version -- refusing here blocks a package the developer can correctly install "+
				"(reason %q)", rec.Code, rec.Header().Get("X-Yellowjack-Reason"))
		}
		if !strings.Contains(logs.String(), "version verified: 1.0.0") {
			t.Errorf("the tarball was served without the check being seen to run:\n%s", logs.String())
		}
	})
}

// TestNpmTarballManifestAtTheArchiveRootIsRead closes the other half of #122: three entry
// shapes that a real npm installs but the reader could not see at all, so the tarball was
// served with "version unverified" and the mismatch never noticed.
//
// Each fixture declares 9.9.9 under a 1.0.0 URL, so a reader that finds the manifest
// refuses and a reader that misses it serves -- the assertion cannot pass by accident.
func TestNpmTarballManifestAtTheArchiveRootIsRead(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry string
	}{
		{"dot-slash root", "./package.json"},
		{"leading slash", "/package.json"},
		{"repeated slashes", "package//package.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureStdLog(t)
			rec, _ := fetchTarball(t, http.MethodGet, lodashTarballPath,
				npmTgz(t, tgzEntry{tc.entry, packageJSON("9.9.9")}), nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d for an entry named %q, want 403: a real npm installs this tarball "+
					"as 9.9.9 under a 1.0.0 URL\n%s", rec.Code, tc.entry, logs.String())
			}
			if reason := rec.Header().Get("X-Yellowjack-Reason"); !strings.Contains(reason, "declares version 9.9.9") {
				t.Errorf("X-Yellowjack-Reason = %q, want it to name 9.9.9", reason)
			}
			if strings.Contains(logs.String(), "unverified") {
				t.Errorf("the tarball was logged as unverified, which is what the bug looked like:\n%s", logs.String())
			}
		})
	}
}

// TestNpmTarballPastTheWindowIsNotCalledVerified is the #47 constraint at this layer: a
// check that saw a PREFIX must not report a whole-file property. The versions agree
// across everything read, and the archive runs on past the inspection window, so the
// tarball is served -- but the operator's line says what was actually established.
func TestNpmTarballPastTheWindowIsNotCalledVerified(t *testing.T) {
	logs := captureStdLog(t)
	tgz := npmTgz(t,
		tgzEntry{"package/package.json", packageJSON("1.0.0")},
		tgzEntry{"package/blob.bin", incompressible(t, npmTarballInspectBytes+1)})
	rec, _ := fetchTarball(t, http.MethodGet, lodashTarballPath, tgz, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: a large tarball whose manifest agrees is not a refusal", rec.Code)
	}
	if strings.Contains(logs.String(), "version verified") {
		t.Fatalf("the log says VERIFIED for a tarball the check could only read part of -- "+
			"that is the \"our parser saw nothing\" conflation #47 forbids:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "continues past the inspection window") {
		t.Errorf("the log does not tell the operator the archive outran the window:\n%s", logs.String())
	}
	// Control: a SMALL tarball with the same manifest is read whole and does say verified,
	// so the assertion above is about the window and not about the log line vanishing.
	small := captureStdLog(t)
	if _, _ = fetchTarball(t, http.MethodGet, lodashTarballPath, lodashTgz(t, "1.0.0"), nil); !strings.Contains(small.String(), "version verified: 1.0.0") {
		t.Errorf("a small truthful tarball was not reported verified either, so the window assertion "+
			"proves nothing:\n%s", small.String())
	}
}
