package main

import (
	"strings"
	"testing"
)

// mustLoadConfig is loadConfig for tests that expect a VALID environment. It fails
// the test on a config error rather than returning a zero Config, so a test that
// accidentally sets a bad value reports that — not a confusing downstream failure.
func mustLoadConfig(t *testing.T) Config {
	t.Helper()
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: unexpected error: %v", err)
	}
	return cfg
}

// TestConfigRejectsMalformedValues is the table the issue asks for: per knob,
// unset / malformed / out-of-range (issue #19).
//
// The behaviour under test is the CHANGE: these knobs used to fall back silently.
// An operator who typed FW_VERIFY_REPO=ture got repo verification switched OFF and
// was never told — a security posture altered by a typo, in silence. Startup now
// refuses, naming the knob.
//
// Each case asserts the error MENTIONS THE OFFENDING KNOB, not merely that some
// error occurred: "invalid configuration" with no name is the cascade this issue
// exists to prevent, and would pass a weaker assertion.
func TestConfigRejectsMalformedValues(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value string
		valid bool
	}{
		// Unset is never an error — it selects the documented default.
		{"threshold unset", "FW_SCORE_THRESHOLD", "", true},
		{"threshold valid", "FW_SCORE_THRESHOLD", "7.5", true},
		{"threshold at floor", "FW_SCORE_THRESHOLD", "0", true},
		{"threshold at ceiling", "FW_SCORE_THRESHOLD", "10", true},
		{"threshold not a number", "FW_SCORE_THRESHOLD", "high", false},
		{"threshold above the scale", "FW_SCORE_THRESHOLD", "50", false},
		{"threshold negative", "FW_SCORE_THRESHOLD", "-1", false},

		{"verify-repo valid", "FW_VERIFY_REPO", "false", true},
		{"verify-repo typo", "FW_VERIFY_REPO", "ture", false},
		{"verify-repo yes-no", "FW_VERIFY_REPO", "yes", false},

		{"duration valid", "FW_SCORE_CACHE_TTL", "30m", true},
		{"duration zero", "FW_SCORE_CACHE_TTL", "0", true},
		{"duration day-suffix", "FW_SCORE_CACHE_TTL", "14d", false},
		{"duration bare number", "FW_SCORE_CACHE_TTL", "3600", false},
		{"duration negative", "FW_SCORE_CACHE_TTL", "-5m", false},

		{"int valid", "FW_MAX_CONNS_PER_HOST", "64", true},
		{"int not a number", "FW_MAX_CONNS_PER_HOST", "many", false},
		{"int negative", "FW_MAX_CONNS_PER_HOST", "-1", false},

		{"retry-after valid", "FW_PENDING_RETRY_AFTER", "30", true},
		{"retry-after negative", "FW_PENDING_RETRY_AFTER", "-30", false},

		{"cache entries valid", "FW_SCORE_CACHE_MAX_ENTRIES", "500", true},
		{"cache entries malformed", "FW_SCORE_CACHE_MAX_ENTRIES", "1_000", false},

		{"release age valid", "FW_MAX_RELEASE_AGE_DAYS", "7", true},
		{"release age negative", "FW_MAX_RELEASE_AGE_DAYS", "-7", false},
		{"cooldown valid", "FW_MIN_RELEASE_AGE_DAYS", "7", true},
		{"cooldown negative", "FW_MIN_RELEASE_AGE_DAYS", "-1", false},

		{"flow interval valid", "FW_FLOW_FLUSH_INTERVAL", "5s", true},
		{"flow interval malformed", "FW_FLOW_FLUSH_INTERVAL", "5 seconds", false},

		{"l2 ttl malformed", "FW_SCORE_L2_TTL", "forever", false},
		{"backoff ttl malformed", "FW_RATELIMIT_BACKOFF_TTL", "10sec", false},

		// Enums. These previously selected a MODE on a typo — the two that warned
		// still ran in a posture the operator never chose, which a warning does not
		// fix. "open-with-visiblity" is the real misspelling main.go called out.
		{"byte gate valid", "FW_BYTE_GATE", "enforce", true},
		{"byte gate typo", "FW_BYTE_GATE", "enforcce", false},
		{"byte gate plausible-but-wrong", "FW_BYTE_GATE", "log-only", false},
		{"unverified valid", "FW_UNVERIFIED_POLICY", "open-with-visibility", true},
		{"unverified misspelled", "FW_UNVERIFIED_POLICY", "open-with-visiblity", false},
		{"ecosystem valid", "FW_ECOSYSTEM", "maven", true},
		{"ecosystem unknown", "FW_ECOSYSTEM", "cargo", false},
		{"scorecard mode valid", "FW_SCORECARD_MODE", "local", true},
		{"scorecard mode unknown", "FW_SCORECARD_MODE", "real", false},
		{"unscorable valid", "FW_UNSCORABLE_POLICY", "allow", true},
		{"unscorable unknown", "FW_UNSCORABLE_POLICY", "deny", false},
		{"unknown-path valid", "FW_UNKNOWN_PATH_POLICY", "allow-but-log", true},
		{"unknown-path unknown", "FW_UNKNOWN_PATH_POLICY", "warn", false},
		{"write policy valid", "FW_WRITE_POLICY", "allow", true},
		{"write policy unknown", "FW_WRITE_POLICY", "readonly", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			_, err := loadConfig()
			switch {
			case tc.valid && err != nil:
				t.Fatalf("%s=%q should be accepted, got error: %v", tc.key, tc.value, err)
			case !tc.valid && err == nil:
				t.Fatalf("%s=%q should be REJECTED at startup, but loadConfig accepted it "+
					"(this is the silent-fallback defect issue #19 is about)", tc.key, tc.value)
			case !tc.valid && !strings.Contains(err.Error(), tc.key):
				t.Errorf("error must name the offending knob %s so the operator knows what to fix; got: %v", tc.key, err)
			}
		})
	}
}

// TestConfigReportsEveryBadKnobAtOnce pins the accumulate-don't-bail behaviour.
//
// Returning on the first problem would be correct-but-hostile: the operator fixes
// one knob, restarts, and learns about the next. That fix-restart-fix loop is the
// same failure this issue is about, spread over time rather than down the log.
func TestConfigReportsEveryBadKnobAtOnce(t *testing.T) {
	t.Setenv("FW_SCORE_THRESHOLD", "high")
	t.Setenv("FW_VERIFY_REPO", "ture")
	t.Setenv("FW_SCORE_CACHE_TTL", "14d")

	_, err := loadConfig()
	if err == nil {
		t.Fatal("three malformed knobs should not start")
	}
	for _, key := range []string{"FW_SCORE_THRESHOLD", "FW_VERIFY_REPO", "FW_SCORE_CACHE_TTL"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error omits %s; an operator would fix one knob, restart, and meet the next.\nGot: %v", key, err)
		}
	}
	// One line, however many knobs are wrong: the requirement is a single actionable
	// statement at startup, not a stack of them.
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("config error must be one line, got:\n%v", err)
	}
}

// TestConfigDefaultsAreUnchanged guards the other direction. Making bad values fatal
// is only safe if GOOD ones still resolve exactly as before — a validator that also
// shifted a default would change the shipped security posture while claiming to be a
// diagnostics change.
func TestConfigDefaultsAreUnchanged(t *testing.T) {
	for _, k := range []string{
		"FW_SCORE_THRESHOLD", "FW_VERIFY_REPO", "FW_SCORE_CACHE_TTL", "FW_MAX_CONNS_PER_HOST",
		"FW_PENDING_RETRY_AFTER", "FW_SCORE_CACHE_MAX_ENTRIES", "FW_MAX_RELEASE_AGE_DAYS",
		"FW_MIN_RELEASE_AGE_DAYS",
		"FW_FLOW_FLUSH_INTERVAL", "FW_SCORE_L2_TTL", "FW_RATELIMIT_BACKOFF_TTL", "FW_BYTE_GATE",
		"FW_UNSCORABLE_POLICY", "FW_UNVERIFIED_POLICY", "FW_ECOSYSTEM",
	} {
		t.Setenv(k, "")
	}
	cfg := mustLoadConfig(t)

	if cfg.ScoreThreshold != 5.0 {
		t.Errorf("default ScoreThreshold = %v, want 5.0", cfg.ScoreThreshold)
	}
	if !cfg.VerifyRepo {
		t.Error("default VerifyRepo = false, want true (repo cross-check on by default)")
	}
	if cfg.UnscorablePolicy != "block" {
		t.Errorf("default UnscorablePolicy = %q, want \"block\" (fail-closed)", cfg.UnscorablePolicy)
	}
	if cfg.UnverifiedPolicy != unverifiedPolicyClosed {
		t.Errorf("default UnverifiedPolicy = %q, want %q (D36 Ruling A)", cfg.UnverifiedPolicy, unverifiedPolicyClosed)
	}
	if cfg.ByteGate != byteGateAllowButLog {
		t.Errorf("default ByteGate = %q, want %q (D49 visibility-first)", cfg.ByteGate, byteGateAllowButLog)
	}
	if cfg.Ecosystem != "npm" {
		t.Errorf("default Ecosystem = %q, want \"npm\"", cfg.Ecosystem)
	}
}
