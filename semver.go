package main

import (
	"strconv"
	"strings"
)

// A minimal semver 2.0.0 precedence comparator, for one job: when a version is
// removed from an npm packument, a dist-tag that pointed at it has to be repointed at
// the newest COMPLIANT version, and "newest" is a semver question, not a string one
// ("1.10.0" is newer than "1.9.0"; "2.0.0-beta.1" is older than "2.0.0").
//
// Written rather than imported on purpose (few deps, every line understood): npm
// validates versions on publish, so what arrives here is strict semver and the whole
// grammar is a page. Build metadata is ignored, as the spec says. A version that does
// not parse sorts below every version that does, and among themselves such versions
// compare as strings — a deterministic answer for a registry that serves something
// odd, never a panic.

type semver struct {
	nums [3]int64
	pre  []string // empty for a release
	ok   bool
}

func parseSemver(s string) semver {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i] // build metadata never affects precedence
	}
	var v semver
	core := s
	if i := strings.IndexByte(s, '-'); i >= 0 {
		core, v.pre = s[:i], strings.Split(s[i+1:], ".")
		for _, id := range v.pre {
			if id == "" {
				return semver{}
			}
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semver{}
	}
	for i, p := range parts {
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil || n < 0 || (len(p) > 1 && p[0] == '0') {
			return semver{}
		}
		v.nums[i] = n
	}
	v.ok = true
	return v
}

// semverCompare reports -1, 0 or 1 as a is older than, the same as, or newer than b.
func semverCompare(a, b string) int {
	va, vb := parseSemver(a), parseSemver(b)
	switch {
	case !va.ok && !vb.ok:
		return strings.Compare(strings.TrimSpace(a), strings.TrimSpace(b))
	case !va.ok:
		return -1
	case !vb.ok:
		return 1
	}
	for i := 0; i < 3; i++ {
		if va.nums[i] != vb.nums[i] {
			if va.nums[i] < vb.nums[i] {
				return -1
			}
			return 1
		}
	}
	// Same core. A release outranks any prerelease of it (spec §11.3).
	switch {
	case len(va.pre) == 0 && len(vb.pre) == 0:
		return 0
	case len(va.pre) == 0:
		return 1
	case len(vb.pre) == 0:
		return -1
	}
	// Prerelease identifiers, left to right: numeric < alphanumeric, numerics
	// compare as numbers, alphanumerics lexically, and a longer list wins a tie
	// (spec §11.4).
	for i := 0; i < len(va.pre) && i < len(vb.pre); i++ {
		if c := comparePrereleaseID(va.pre[i], vb.pre[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(va.pre) < len(vb.pre):
		return -1
	case len(va.pre) > len(vb.pre):
		return 1
	}
	return 0
}

func comparePrereleaseID(a, b string) int {
	na, aNum := strconv.ParseInt(a, 10, 64)
	nb, bNum := strconv.ParseInt(b, 10, 64)
	switch {
	case aNum == nil && bNum == nil:
		if na < nb {
			return -1
		} else if na > nb {
			return 1
		}
		return 0
	case aNum == nil:
		return -1 // numeric identifiers always have lower precedence
	case bNum == nil:
		return 1
	}
	return strings.Compare(a, b)
}

// semverIsPrerelease reports whether v carries a prerelease part ("2.0.0-beta.1").
// An unparsable version counts as a prerelease: it is not something a `latest` tag
// should be steered onto.
func semverIsPrerelease(v string) bool {
	p := parseSemver(v)
	return !p.ok || len(p.pre) > 0
}
