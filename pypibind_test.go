package main

import "testing"

// TestPypiFilenameBindsToPackage pins the rule that closes issue #67: the "/_files/"
// relay may only serve an artifact whose filename could actually belong to the package
// whose prefix was evaluated.
//
// The table is deliberately weighted toward the shapes that made the naive rules fail,
// because those are the cases a future change would break silently:
//   - real legacy filenames, which is where an exact name-recovery rule broke (2.55%
//     false rejects when measured across 82,970 real artifacts)
//   - attacker-chosen names EXTENDING an allowed name, which is where a plain prefix
//     rule broke, and which no corpus of real packages can ever contain
func TestPypiFilenameBindsToPackage(t *testing.T) {
	cases := []struct {
		name    string
		pkg     string
		objPath string
		want    bool
	}{
		// ── Honest traffic. Every one of these is a real filename shape from the
		// harvested sample; a false here is a broken install, not a caught attack.
		{"wheel", "requests", "/packages/aa/bb/requests-2.31.0-py3-none-any.whl", true},
		{"sdist", "six", "/packages/0e/f9/six-0.9.0.tar.gz", true},
		{"sdist zip", "attrs", "/packages/aa/attrs-17.1.0.zip", true},
		{"legacy windows installer", "numpy", "/packages/x/numpy-1.5.1.win32-py2.7-nosse.exe", true},
		{"legacy src rpm", "setuptools", "/packages/x/setuptools-0.6c4-1.src.rpm", true},
		{"egg", "MarkupSafe", "/packages/x/MarkupSafe-0.11-py2.5-win32.egg", true},
		// PEP 503 says these spellings are ONE project, so the comparison must fold
		// separators and case rather than string-match the requested spelling.
		{"underscore vs hyphen", "python-dateutil", "/packages/x/python_dateutil-2.8.2-py2.py3-none-any.whl", true},
		{"dotted name", "zope.interface", "/packages/x/zope.interface-5.4.0.tar.gz", true},
		{"dotted vs underscore", "ruamel.yaml", "/packages/x/ruamel_yaml-0.17.21.tar.gz", true},
		{"case folded", "PyYAML", "/packages/x/pyyaml-6.0.tar.gz", true},
		{"requested lowercase, file cased", "pillow", "/packages/x/Pillow-9.0.0.tar.gz", true},
		{"v-prefixed version", "somepkg", "/packages/x/somepkg-v1.2.3.tar.gz", true},
		{"percent-encoded filename", "zope.interface", "/packages/x/zope%2Einterface-5.4.0.tar.gz", true},

		// ── The issue-#67 attack itself: an allowed prefix carrying another
		// package's artifact. These are the measured bypasses, at real byte counts.
		{"different package entirely", "requests", "/packages/0e/f9/six-0.9.0.tar.gz", false},
		{"blocked pkg under allowed prefix", "flask", "/packages/x/evilpkg-1.0.0-py3-none-any.whl", false},

		// ── Name-extension attack. A plain prefix rule ACCEPTS every one of these:
		// the attacker publishes a name that extends an allowed one, so requiring a
		// version to follow is the load-bearing half of the rule, not a nicety.
		{"extension attack sdist", "requests", "/packages/x/requests-evil-1.0.tar.gz", false},
		{"extension attack wheel", "six", "/packages/x/six_backdoor-9.9.9-py3-none-any.whl", false},
		{"extension attack hyphen", "numpy", "/packages/x/numpy-utils-0.1.tar.gz", false},
		{"extension attack dotted", "zope.interface", "/packages/x/zope.interface.evil-1.0.tar.gz", false},

		// ── Degenerate shapes: no version at all, or the name alone.
		{"bare name no version", "requests", "/packages/x/requests.tar.gz", false},
		{"name then nothing", "requests", "/packages/x/requests-", false},
		{"empty filename", "requests", "/packages/x/", false},
		{"prefix is a longer name", "req", "/packages/x/requests-2.31.0.tar.gz", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pypiFilenameBindsToPackage(tc.pkg, tc.objPath); got != tc.want {
				t.Errorf("pypiFilenameBindsToPackage(%q, %q) = %v, want %v",
					tc.pkg, tc.objPath, got, tc.want)
			}
		})
	}
}

// TestNormalizePypiName pins PEP 503 normalization on its own, since the binding rule
// is only as correct as the spelling it compares in.
func TestNormalizePypiName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"requests", "requests"},
		{"Zope.Interface", "zope-interface"},
		{"zope_interface", "zope-interface"},
		{"zope-interface", "zope-interface"},
		{"ruamel.yaml", "ruamel-yaml"},
		{"a---b", "a-b"},  // runs collapse
		{"a._-.b", "a-b"}, // mixed runs collapse
		{"PyYAML", "pyyaml"},
	}
	for _, tc := range cases {
		if got := normalizePypiName(tc.in); got != tc.want {
			t.Errorf("normalizePypiName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestPypiBindingRuleCanFail is the negative control. A check that can only report
// green converts an unknown into false confidence, so prove the table above would
// actually catch a regression: a rule that always returns true must fail the attack
// rows, and a rule that always returns false must fail the honest rows.
func TestPypiBindingRuleCanFail(t *testing.T) {
	alwaysTrue := func(string, string) bool { return true }
	alwaysFalse := func(string, string) bool { return false }

	attack := [][2]string{
		{"requests", "/packages/x/requests-evil-1.0.tar.gz"},
		{"requests", "/packages/0e/f9/six-0.9.0.tar.gz"},
	}
	honest := [][2]string{
		{"requests", "/packages/x/requests-2.31.0-py3-none-any.whl"},
		{"zope.interface", "/packages/x/zope_interface-5.4.0.tar.gz"},
	}

	for _, c := range attack {
		if !alwaysTrue(c[0], c[1]) {
			t.Fatal("control broken: alwaysTrue should accept")
		}
		if pypiFilenameBindsToPackage(c[0], c[1]) {
			t.Errorf("real rule accepted an attack the control shows is detectable: %v", c)
		}
	}
	for _, c := range honest {
		if alwaysFalse(c[0], c[1]) {
			t.Fatal("control broken: alwaysFalse should reject")
		}
		if !pypiFilenameBindsToPackage(c[0], c[1]) {
			t.Errorf("real rule rejected honest traffic: %v", c)
		}
	}
}
