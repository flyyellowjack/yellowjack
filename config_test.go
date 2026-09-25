package main

import "testing"

// TestDepsDevBaseFromEnv pins the FW_DEPSDEV_BASE wiring in BOTH directions.
//
// Worth a test despite being three lines of config, because the failure mode is
// silent rather than loud: f.depsDevBase is only ever used as the prefix of an
// fmt.Sprintf, so a wrong-but-non-empty value produces a well-formed URL pointing
// somewhere else, and an EMPTY one produces a relative URL ("/v3/projects/…") that
// http.NewRequest rejects — surfacing as "score source unavailable", i.e. a
// retryable 503 on every package, with nothing naming the real cause.
//
// The empty-means-default case is the one that actually protects something: most
// tests in this package build a Config literal without naming every field, so if
// NewFirewall ever propagated "" verbatim, api-mode scoring would break for all of
// them at once and look like a network problem.
func TestDepsDevBaseFromEnv(t *testing.T) {
	t.Run("env override is used", func(t *testing.T) {
		t.Setenv("FW_DEPSDEV_BASE", "http://127.0.0.1:9999")
		if got := mustLoadConfig(t).DepsDevBase; got != "http://127.0.0.1:9999" {
			t.Errorf("DepsDevBase = %q, want the FW_DEPSDEV_BASE value", got)
		}
	})

	t.Run("unset falls back to the public API", func(t *testing.T) {
		t.Setenv("FW_DEPSDEV_BASE", "")
		if got := mustLoadConfig(t).DepsDevBase; got != depsDevBaseURL {
			t.Errorf("DepsDevBase = %q, want the public default %q", got, depsDevBaseURL)
		}
	})

	t.Run("NewFirewall reads it through to the field", func(t *testing.T) {
		fw, err := NewFirewall(Config{Ecosystem: "npm", UpstreamRegistry: "https://registry.npmjs.org", DepsDevBase: "http://example.invalid"})
		if err != nil {
			t.Fatal(err)
		}
		if fw.depsDevBase != "http://example.invalid" {
			t.Errorf("depsDevBase = %q, want the configured base", fw.depsDevBase)
		}
	})

	t.Run("NewFirewall turns an empty base into the default, not an empty URL", func(t *testing.T) {
		fw, err := NewFirewall(Config{Ecosystem: "npm", UpstreamRegistry: "https://registry.npmjs.org"})
		if err != nil {
			t.Fatal(err)
		}
		if fw.depsDevBase != depsDevBaseURL {
			t.Errorf("depsDevBase = %q, want the public default %q", fw.depsDevBase, depsDevBaseURL)
		}
	})
}
