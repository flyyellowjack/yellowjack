package main

import (
	"strings"
	"testing"
)

// ecoFor mirrors the classification policyagewindow_test.go pins against config.go's enum.
func ecoFor(ecosystem string) Ecosystem {
	switch ecosystem {
	case "maven":
		return mavenEcosystem{}
	case "oci":
		return ociEcosystem{}
	}
	return nil // npm and pypi filter the index in proxy.go and carry no Ecosystem value
}

func inertWarningsFor(t *testing.T, ecosystem string, minDays, maxDays int) []string {
	t.Helper()
	return gateFor(ecosystem, ecoFor(ecosystem), minDays, maxDays).inertSettingWarnings()
}

// A configured control the gate cannot enforce must be named at startup (D299, #150's
// other half). The assertions are on the TEXT an operator reads, not on a count: a warning
// that fires but does not say which knob, or on which gate, sends them to the wrong place.
func TestInertReleaseWindowIsNamedAtStartup(t *testing.T) {
	got := inertWarningsFor(t, "oci", 7, 0)
	if len(got) != 1 {
		t.Fatalf("an OCI gate with FW_MIN_RELEASE_AGE_DAYS=7 produced %d warnings, want exactly 1: %q", len(got), got)
	}
	for _, want := range []string{"FW_MIN_RELEASE_AGE_DAYS=7", "NOT ENFORCED", "oci"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("the warning does not contain %q, so it does not tell the operator what to fix:\n%s", want, got[0])
		}
	}
	if both := inertWarningsFor(t, "oci", 7, 365); len(both) != 2 {
		t.Errorf("both window knobs set on an OCI gate produced %d warnings, want one per knob: %q", len(both), both)
	}
}

// THE CONTROLS. A warning that fires everywhere is noise, and noise on a gate where the
// window DOES apply would teach operators to ignore the one that matters. Each case here
// is a configuration that must stay silent.
func TestInertWarningStaysSilentWhereItWouldBeWrong(t *testing.T) {
	for name, tc := range map[string]struct {
		eco      string
		min, max int
	}{
		"npm enforces the window":              {"npm", 7, 365},
		"pypi enforces the window":             {"pypi", 7, 365},
		"maven enforces the window":            {"maven", 7, 365},
		"oci with nothing asked for (default)": {"oci", 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if got := inertWarningsFor(t, tc.eco, tc.min, tc.max); len(got) != 0 {
				t.Errorf("want no warning, got %q", got)
			}
		})
	}
}

// The banner and /policy must not disagree about whether the window applies: one says it
// at startup, the other on the page an operator checks later, and they are read by the
// same person. Both derive from releaseWindowEnforced; this pins that they still do.
func TestInertWarningAgreesWithThePolicyPage(t *testing.T) {
	for _, eco := range []string{"npm", "pypi", "maven", "oci"} {
		fw := gateFor(eco, ecoFor(eco), 7, 0)
		warned := len(fw.inertSettingWarnings()) > 0
		pageSaysInert := strings.Contains(fw.describePolicy().Values["min_release_age_days"], "NOT ENFORCED")
		if warned != pageSaysInert {
			t.Errorf("%s: startup warned=%v but /policy says inert=%v -- the two surfaces disagree", eco, warned, pageSaysInert)
		}
	}
}

// The shipped cooldown default (D335) must be ON exactly where the window is enforced
// and OFF where it is not. Derived from releaseWindowEnforced rather than restated, so a
// fifth ecosystem, or OCI gaining a trustworthy date (#127), fails here until the default
// is decided for it. Driven through loadConfig, because the default lives there.
func TestDefaultCooldownFollowsEnforcement(t *testing.T) {
	for _, eco := range []string{"npm", "pypi", "maven", "oci"} {
		t.Run(eco, func(t *testing.T) {
			t.Setenv("FW_ECOSYSTEM", eco)
			cfg, err := loadConfig()
			if err != nil {
				t.Fatal(err)
			}
			fw := gateFor(eco, ecoFor(eco), cfg.MinReleaseAgeDays, cfg.MaxReleaseAgeDays)
			if enforced := fw.releaseWindowEnforced(); enforced != (cfg.MinReleaseAgeDays > 0) {
				t.Errorf("default FW_MIN_RELEASE_AGE_DAYS=%d on %s, but the window enforced=%v there",
					cfg.MinReleaseAgeDays, eco, enforced)
			}
			if enforced := fw.releaseWindowEnforced(); enforced && cfg.MinReleaseAgeDays != cooldownDefaultDays {
				t.Errorf("default on %s is %d days, want the ruled %d (D335)", eco, cfg.MinReleaseAgeDays, cooldownDefaultDays)
			}
			// An operator who wrote nothing must not be told to remove something.
			if got := fw.inertSettingWarnings(); len(got) != 0 {
				t.Errorf("%s gate at DEFAULTS warns about a setting nobody wrote: %q", eco, got)
			}
		})
	}
}
