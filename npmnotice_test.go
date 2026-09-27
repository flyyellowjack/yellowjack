package main

import (
	"strings"
	"testing"
	"time"
)

// Tier 1 for #164: a release the cooldown holds tells the developer so, and when it
// clears, in the one place npm prints a registry's words (the npm-notice header). The
// real-client proof that npm prints it is e2e/npm_cooldown_test.go.

func TestAHeldReleaseIsAnnouncedWithTheDayItClears(t *testing.T) {
	now := time.Now()
	times := twoVersionsTimed(now)
	up, _ := npmTimedUpstream(t, "pkg", times, true)
	defer up.Close()
	p := newTestProxy(t, up, func(c *Config) {
		c.MinReleaseAgeDays = 7
		c.UnscorablePolicy = "allow"
	})
	rec := getAsNpm(t, p, "/pkg")
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	clears := times["2.0.0"].UTC().AddDate(0, 0, 7).Format(npmClearsFormat)
	notice := rec.Header().Get("npm-notice")
	for _, want := range []string{"7-day release cooldown", "pkg@2.0.0 until " + clears, "ETARGET"} {
		if !strings.Contains(notice, want) {
			t.Errorf("npm-notice = %q, want it to contain %q", notice, want)
		}
	}
	// Without no-store npm never prints the notice: its cache layer stores the response,
	// and npm-registry-fetch skips the notice on anything the cache layer stored.
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store — npm stays silent about a notice on a response it caches", cc)
	}
	// The operator's log line carries the same day, so the log and the client agree.
	logs := captureStdLog(t)
	getAsNpm(t, p, "/pkg")
	if !strings.Contains(logs.String(), "it clears "+clears) {
		t.Errorf("the operator log does not name the clear date %s:\n%s", clears, logs.String())
	}
}

func TestNothingHeldMeansNoNoticeAndUpstreamCachingIsKept(t *testing.T) {
	now := time.Now()
	settled := map[string]time.Time{"1.0.0": now.AddDate(0, 0, -400), "2.0.0": now.AddDate(0, 0, -30)}
	up, _ := npmTimedUpstream(t, "pkg", settled, true)
	defer up.Close()
	p := newTestProxy(t, up, func(c *Config) {
		c.MinReleaseAgeDays = 7
		c.UnscorablePolicy = "allow"
	})
	rec := getAsNpm(t, p, "/pkg")
	if n := rec.Header().Get("npm-notice"); n != "" {
		t.Errorf("npm-notice = %q on a packument the cooldown held nothing from — every install would print it", n)
	}
	if rec.Header().Get("Cache-Control") == "no-store" {
		t.Error("no-store on a packument with nothing held: the client's cache was switched off for no notice")
	}
}

func TestTheNoticeSpeaksOnlyForTheCooldown(t *testing.T) {
	now := time.Now()
	w := ageWindow{tooNewAfter: now.AddDate(0, 0, -14), minDays: 14, tooOldBefore: now.AddDate(0, 0, -3650)}
	fresh := now.Add(-time.Hour)
	for _, tc := range []struct {
		name string
		rm   npmRefusal
	}{
		{"an advisory does not clear by waiting", npmRefusal{Version: "1.0.1", Cause: causeMalware, Published: fresh, HasTime: true}},
		{"an operator deny does not clear by waiting", npmRefusal{Version: "1.0.2", Cause: causeOperator, Published: fresh, HasTime: true}},
		{"an undated release has no clear date", npmRefusal{Version: "1.0.3", Cause: causeWindow}},
		{"the age floor only gets further away", npmRefusal{Version: "0.0.1", Cause: causeWindow, Published: now.AddDate(-20, 0, 0), HasTime: true}},
	} {
		if n := npmCooldownNotice("pkg", []npmRefusal{tc.rm}, w); n != "" {
			t.Errorf("%s: notice %q, want none", tc.name, n)
		}
	}
	// Control: the same shape, held by the cooldown, does speak.
	if n := npmCooldownNotice("pkg", []npmRefusal{{Version: "1.0.4", Cause: causeWindow, Published: fresh, HasTime: true}}, w); !strings.Contains(n, "pkg@1.0.4 until") {
		t.Errorf("control: a cooldown-held release produced notice %q", n)
	}
}

func TestTheNoticeNamesTheNewestAndCountsTheRest(t *testing.T) {
	now := time.Now()
	w := ageWindow{tooNewAfter: now.AddDate(0, 0, -14), minDays: 14}
	var removed []npmRefusal
	for i, v := range []string{"1.0.0", "1.1.0", "1.10.0", "1.2.0", "1.9.0"} {
		removed = append(removed, npmRefusal{Version: v, Cause: causeWindow, Published: now.Add(-time.Duration(i+1) * time.Hour), HasTime: true})
	}
	n := npmCooldownNotice("pkg", removed, w)
	i10, i9, i2 := strings.Index(n, "pkg@1.10.0 "), strings.Index(n, "pkg@1.9.0 "), strings.Index(n, "pkg@1.2.0 ")
	if i10 < 0 || i9 < 0 || i2 < 0 || !(i10 < i9 && i9 < i2) {
		t.Errorf("notice %q: want 1.10.0, 1.9.0, 1.2.0 in semver order, newest first", n)
	}
	if strings.Contains(n, "pkg@1.1.0 ") || !strings.Contains(n, "(and 2 more)") {
		t.Errorf("notice %q: want three named and the other two counted", n)
	}
}

func TestTheNoticeCannotBreakItsHeaderLine(t *testing.T) {
	now := time.Now()
	w := ageWindow{tooNewAfter: now.AddDate(0, 0, -14), minDays: 14}
	n := npmCooldownNotice("pkg", []npmRefusal{{Version: "1.0.0\r\nSet-Cookie: x=1", Cause: causeWindow, Published: now, HasTime: true}}, w)
	if strings.ContainsAny(n, "\r\n") {
		t.Errorf("a version string from upstream put a line break in the header: %q", n)
	}
}
