package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Tier 1 for the npm half of #26: the release window (cooldown / age floor) judged from
// the packument's `time` map, and the full-packument fetch it depends on.

func TestNpmWindowRefuserHoldsOnlyWhatTheWindowSays(t *testing.T) {
	now := time.Now()
	w := ageWindow{
		tooNewAfter: now.AddDate(0, 0, -7), tooNewReason: "within the 7-day cooldown",
		tooOldBefore: now.AddDate(0, 0, -365), tooOldReason: "older than the floor",
	}
	refuse := npmWindowRefuser(w)
	for _, tc := range []struct {
		name string
		f    npmVersionFacts
		want string
	}{
		{"ancient", npmVersionFacts{Version: "1.0.0", Published: now.AddDate(0, 0, -400), HasTime: true, InPackument: true}, "older than the floor"},
		{"comfortably in the middle", npmVersionFacts{Version: "2.0.0", Published: now.AddDate(0, 0, -30), HasTime: true, InPackument: true}, ""},
		{"published yesterday", npmVersionFacts{Version: "3.0.0", Published: now.AddDate(0, 0, -1), HasTime: true, InPackument: true}, "within the 7-day cooldown"},
		{"no publish time: fails closed while a window is active (D100)", npmVersionFacts{Version: "4.0.0", InPackument: true}, "release age could not be verified"},
		{"a version document is not judged by the window", npmVersionFacts{Version: "3.0.0", Published: now.AddDate(0, 0, -1), HasTime: true}, ""},
	} {
		reason, cause := refuse(tc.f)
		if !strings.Contains(reason, tc.want) || (tc.want == "" && reason != "") {
			t.Errorf("%s: reason %q, want %q", tc.name, reason, tc.want)
		}
		if cause != causeWindow {
			t.Errorf("%s: the window's refusal was attributed to cause %v — that chooses the wrong next step for the developer", tc.name, cause)
		}
	}
	if reason, _ := npmWindowRefuser(ageWindow{})(npmVersionFacts{Version: "1.0.0", InPackument: true}); reason != "" {
		t.Errorf("an INACTIVE window refused %q — with no window configured, a missing publish time must not matter", reason)
	}
}

func TestNpmPublishTimesReadsVersionsOnly(t *testing.T) {
	doc := map[string]any{"time": map[string]any{
		"created":  "2020-01-01T00:00:00.000Z",
		"modified": "2024-06-01T00:00:00.000Z",
		"1.0.0":    "2020-01-01T00:00:00.000Z",
		"2.0.0":    "not a date",
	}}
	times := npmPublishTimes(doc)
	if _, ok := times["1.0.0"]; !ok {
		t.Error("1.0.0's publish time was not read")
	}
	if _, ok := times["2.0.0"]; ok {
		t.Error("an unparsable publish time was accepted — under a window that must read as unknown, not as a date")
	}
	if npmPublishTimes(map[string]any{}) != nil {
		t.Error("a document without a time map should yield nil")
	}
}

// npmTimedUpstream models registry.npmjs.org: the `time` map is present ONLY in the
// full packument (Accept: application/json), never in the abbreviated one npm asks
// for. It records the Accept header it last saw, so tests can assert which document the
// firewall requested. With honourAccept=false it never serves `time` at all — a
// registry that cannot supply dates.
func npmTimedUpstream(t *testing.T, pkg string, times map[string]time.Time, honourAccept bool) (*httptest.Server, *string) {
	t.Helper()
	lastAccept := new(string)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case p == "/"+pkg:
			*lastAccept = r.Header.Get("Accept")
			w.Header().Set("Content-Type", "application/json")
			body := `{"name":"` + pkg + `","dist-tags":{"latest":"2.0.0"},"versions":{`
			vs := []string{}
			for v := range times {
				vs = append(vs, `"`+v+`":{"name":"`+pkg+`","version":"`+v+`","dist":{"tarball":"`+srv.URL+`/`+pkg+`/-/`+pkg+`-`+v+`.tgz"}}`)
			}
			body += strings.Join(vs, ",") + `}`
			if honourAccept && r.Header.Get("Accept") == "application/json" {
				ts := []string{}
				for v, at := range times {
					ts = append(ts, `"`+v+`":"`+at.UTC().Format(time.RFC3339Nano)+`"`)
				}
				body += `,"time":{` + strings.Join(ts, ",") + `}`
			}
			w.Write([]byte(body + `}`))
		case strings.HasPrefix(p, "/"+pkg+"/"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"name":"` + pkg + `","version":"2.0.0","repository":"github.com/acme/` + pkg + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	return srv, lastAccept
}

const npmCorgiAccept = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"

func getAsNpm(t *testing.T, p *proxyServer, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://fw.local"+path, nil)
	req.Header.Set("Accept", npmCorgiAccept)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec
}

func twoVersionsTimed(now time.Time) map[string]time.Time {
	return map[string]time.Time{
		"1.0.0": now.AddDate(0, 0, -400), // an old, settled release
		"2.0.0": now.Add(-2 * time.Hour), // published this morning
	}
}

func TestNpmCooldownStepsResolutionBackToTheSettledRelease(t *testing.T) {
	up, seenAccept := npmTimedUpstream(t, "pkg", twoVersionsTimed(time.Now()), true)
	defer up.Close()
	logs := captureStdLog(t)
	p := newTestProxy(t, up, func(c *Config) {
		c.MinReleaseAgeDays = 7
		c.UnscorablePolicy = "allow"
	})
	rec := getAsNpm(t, p, "/pkg")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a cooldown steers resolution, it does not refuse the package; body: %s", rec.Code, rec.Body.String())
	}
	if *seenAccept != "application/json" {
		t.Fatalf("upstream saw Accept %q — with a window active the firewall must ask for the FULL packument, the only one with a time map", *seenAccept)
	}
	doc := decodeDoc(t, rec.Body.Bytes())
	versions := doc["versions"].(map[string]any)
	if _, still := versions["2.0.0"]; still {
		t.Error("the release published this morning is still offered under a 7-day cooldown")
	}
	if _, ok := versions["1.0.0"]; !ok {
		t.Error("the settled release vanished with the new one")
	}
	if doc["dist-tags"].(map[string]any)["latest"] != "1.0.0" {
		t.Errorf("latest = %v, want 1.0.0 — npm would otherwise ask for the version we held back", doc["dist-tags"])
	}
	for _, want := range []string{
		"[release-window] pkg -> version 2.0.0 removed from the packument (release is within the 7-day cooldown",
		`dist-tag "latest" repointed from refused version 2.0.0 to 1.0.0`,
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("operator log lacks %q:\n%s", want, logs.String())
		}
	}
}

func TestNpmWithoutAWindowKeepsTheClientsAcceptAndEveryVersion(t *testing.T) {
	up, seenAccept := npmTimedUpstream(t, "pkg", twoVersionsTimed(time.Now()), true)
	defer up.Close()
	p := newTestProxy(t, up, func(c *Config) { c.UnscorablePolicy = "allow" })
	rec := getAsNpm(t, p, "/pkg")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if *seenAccept != npmCorgiAccept {
		t.Errorf("upstream saw Accept %q — with no window the client's own Accept must be forwarded untouched (the abbreviated document is what npm asked for)", *seenAccept)
	}
	if n := len(decodeDoc(t, rec.Body.Bytes())["versions"].(map[string]any)); n != 2 {
		t.Errorf("%d versions, want 2 — nothing should be held back without a window", n)
	}
}

func TestNpmCooldownFailsClosedWhenTheRegistryHasNoPublishTimes(t *testing.T) {
	up, _ := npmTimedUpstream(t, "pkg", twoVersionsTimed(time.Now()), false) // never serves `time`
	defer up.Close()
	p := newTestProxy(t, up, func(c *Config) {
		c.MinReleaseAgeDays = 7
		c.UnscorablePolicy = "allow"
	})
	rec := getAsNpm(t, p, "/pkg")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — with a window active and no dates to judge by, serving the packument would switch the cooldown off silently (D100); body: %s", rec.Code, rec.Body.String())
	}
	reason := rec.Header().Get("X-Yellowjack-Reason")
	for _, want := range []string{`every version of "pkg" is outside the configured release window`, "release age could not be verified"} {
		if !strings.Contains(reason, want) {
			t.Errorf("X-Yellowjack-Reason = %q, want it to contain %q", reason, want)
		}
	}
	if next := rec.Header().Get("X-Yellowjack-Next-Step"); !strings.Contains(next, "release window") || strings.Contains(next, "deny list") {
		t.Errorf("next step %q — a window refusal must be explained as the window, not as an advisory or the operator's deny list", next)
	}
}

func TestNpmWindowAndAdvisoryComposeIntoOneLegibleRefusal(t *testing.T) {
	up, _ := npmTimedUpstream(t, "pkg", twoVersionsTimed(time.Now()), true)
	defer up.Close()
	feed := writeFeed(t, `{"id":"MAL-OLD","ecosystem":"npm","name":"pkg","versions":["1.0.0"]}`)
	p := newTestProxy(t, up, func(c *Config) {
		c.MinReleaseAgeDays = 7  // holds 2.0.0
		c.MalwareListPath = feed // refuses 1.0.0
		c.UnscorablePolicy = "allow"
	})
	rec := getAsNpm(t, p, "/pkg")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — nothing compliant remains; body: %s", rec.Code, rec.Body.String())
	}
	reason := rec.Header().Get("X-Yellowjack-Reason")
	for _, want := range []string{"1 of 2 as known malware", "1.0.0 (MAL-OLD)", "2.0.0 (release is within the 7-day cooldown"} {
		if !strings.Contains(reason, want) {
			t.Errorf("X-Yellowjack-Reason = %q, want it to contain %q", reason, want)
		}
	}
	if !strings.Contains(rec.Header().Get("X-Yellowjack-Next-Step"), "published advisory") {
		t.Errorf("with an advisory among the causes the next step must say so: %q", rec.Header().Get("X-Yellowjack-Next-Step"))
	}
}
