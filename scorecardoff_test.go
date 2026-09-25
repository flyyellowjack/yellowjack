package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// D273 + D280: `FW_SCORECARD_MODE=off` — scoring disabled, the gate running on the
// malware feed, the operator lists and the release-age window alone.
//
// WHY IT EXISTS. The project made OSSF scanning explicitly optional for the 1 November
// open-source launch — *"the ossf add on is infra complexity and should be an
// optional feature for the open source launch"*, and *"many customers will find
// value in simply the ability to blacklist/whitelist and package cooldown"*. That
// configuration was **not expressible**: the enum was stub|api|local, and the
// DEFAULT (`stub`) is not "no scanner" — it fabricates a flat 7.5 for every
// repository. So the shipped default was a scorer asserting a pass it never
// measured, and "ship without the scanner" had no setting.

// TestScorecardOffServesWithoutScoringAnything is the core of the mode.
func TestScorecardOffServesWithoutScoringAnything(t *testing.T) {
	var upstreamHits int32
	// Any scoring source reaching the network fails this outright. `off` means no
	// evaluation, so the short-circuit has to sit ABOVE repo resolution and deps.dev,
	// not inside the scorer — otherwise we make network calls to produce a number
	// nobody reads, and the mode is unusable in an air-gap.
	spy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer spy.Close()

	f := &Firewall{cfg: Config{
		Ecosystem:      "npm",
		ScorecardMode:  scorecardModeOff,
		ScoreThreshold: 5.0,
		// Deliberately the FAIL-CLOSED default. If `off` ever routed through the
		// unscorable path, this is what would turn it into "block everything".
		UnscorablePolicy: "block",
		DepsDevBase:      spy.URL,
		ScannerURL:       spy.URL,
	}, client: spy.Client(), scannerClient: spy.Client()}

	d := f.Evaluate("lodash")
	if !d.Allowed {
		t.Fatalf("with scoring off and nothing else refusing it, %q must be served; got: %s", "lodash", d.Reason)
	}
	if d.HasScore {
		t.Error("a decision made without scoring must not claim to carry a score")
	}
	if !strings.Contains(d.Reason, "scoring is disabled") {
		t.Errorf("the reason must say WHY it was served, so an operator reading the audit log can tell "+
			"'we did not ask' from 'we asked and it passed'; got %q", d.Reason)
	}
	if n := atomic.LoadInt32(&upstreamHits); n != 0 {
		t.Errorf("scoring off made %d network call(s); the short-circuit is below the repo lookup or the "+
			"scorer, so the mode still costs a round trip and still breaks in an air-gap", n)
	}
}

// TestScorecardOffStillEnforcesEverythingAboveIt is the discriminator, and without
// it the test above is satisfied by a gate that simply allows everything.
//
// `off` disables SCORING. It must not disable the layers the project named as the product:
// the operator lists, and the known-malware feed which outranks them.
func TestScorecardOffStillEnforcesEverythingAboveIt(t *testing.T) {
	f := &Firewall{cfg: Config{Ecosystem: "npm", ScorecardMode: scorecardModeOff, UnscorablePolicy: "block"}}
	f.denyList = staticList(mustParseOperatorList(t, "deny", "npm", "left-pad"))
	f.allowList = staticList(mustParseOperatorList(t, "allow", "npm", "lodash"))

	if d := f.Evaluate("left-pad"); d.Allowed {
		t.Error("the operator DENY list must still refuse with scoring off — it is one of the two features " +
			"the launch is built around, and it needs no network")
	} else if d.Deny != denyOperator {
		t.Errorf("deny kind = %q, want %q", d.Deny, denyOperator)
	}

	if d := f.Evaluate("lodash"); !d.Allowed {
		t.Errorf("the operator ALLOW list must still serve with scoring off; got %s", d.Reason)
	} else if !strings.Contains(d.Reason, "allow list") {
		t.Errorf("an allow-listed package should be served FOR THAT REASON, not by the scoring-off "+
			"fallthrough — the two are different facts and the audit log must distinguish them; got %q", d.Reason)
	}
}

// TestStubIsNotReadyAndOffIs pins the readiness split D273 settled (#141).
//
// `stub` does not decline to score — it ASSERTS a passing score it never measured,
// which is worse than not scoring, because the verdict looks like a measurement.
// Once `off` exists there is no legitimate reason to run `stub` in production.
//
// `off` is deliberately READY: it is a supported configuration and the launch
// posture (D280). Failing readiness on it would be exactly the "nagging the user
// with a big missing asset" the project ruled against.
func TestStubIsNotReadyAndOffIs(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		wantBusy bool
	}{
		{"stub", true},
		{scorecardModeOff, false},
		{"api", false},
		{"local", false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			f := &Firewall{cfg: Config{ScorecardMode: tc.mode}}
			reasons := f.notReady()
			if got := len(reasons) > 0; got != tc.wantBusy {
				t.Fatalf("mode %q: notReady=%v (%v), want notReady=%v", tc.mode, got, reasons, tc.wantBusy)
			}
			if tc.wantBusy && !strings.Contains(strings.Join(reasons, " "), "development fixture") {
				t.Errorf("the refusal must tell the operator WHAT is wrong and how to fix it, not just "+
					"report unready; got %v", reasons)
			}
		})
	}
}

// TestOffIsAnAcceptedConfigValue guards the enum itself. Without this the mode can
// be removed from the accepted set while every test above still passes, because
// they construct Config directly and never parse an environment variable — the
// shape where a helper's own test passes while its call site is unwired.
func TestOffIsAnAcceptedConfigValue(t *testing.T) {
	t.Setenv("FW_SCORECARD_MODE", "off")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("FW_SCORECARD_MODE=off must be accepted by config parsing: %v", err)
	}
	if cfg.ScorecardMode != scorecardModeOff {
		t.Fatalf("parsed mode = %q, want %q", cfg.ScorecardMode, scorecardModeOff)
	}

	// Control: a genuinely invalid value must still be rejected, or the assertion
	// above passes for a parser that accepts anything.
	t.Setenv("FW_SCORECARD_MODE", "offf")
	if cfg, err := loadConfig(); err == nil && cfg.ScorecardMode == "offf" {
		t.Error("config parsing accepted an unknown scorecard mode verbatim; the enum is not being enforced")
	}
}
