package main

import (
	"regexp"
	"strconv"
	"strings"
)

// PEP 440 version comparison, for matching a version-pinned malware advisory against
// the version a client is actually resolving (issue #103).
//
// WHY THIS IS NOT string ==. The feed and the registry will not agree on spelling.
// `1.0`, `1.0.0` and `1` are the SAME release under PEP 440 — the spec zero-pads the
// release segments before comparing — and so are `1.0.0RC1`, `1.0.0-rc1` and
// `1.0.0rc1`. An advisory naming one spelling and an index carrying another is not a
// hypothetical: OSV advisories are written by many different sources.
//
// AND THE MISS IS SILENT. A version-pinned advisory that fails to match does not error;
// the file is simply served, and it looks exactly like a clean package. That is the same
// shape as the name-normalisation bypasses closed for #57/#59, which is why this has its
// own negative control rather than only a passing case.
//
// NAMED "comparison key", NOT "canonical form", DELIBERATELY. PEP 440's *canonical form*
// preserves trailing zeros (`1.0` and `1.0.0` normalise to themselves, distinctly). What
// we need is the *comparison* rule, under which they are equal. Calling this canonical
// would invite someone to use it where the canonical form is required.

// pep440Re mirrors the public version regex from PEP 440. RE2 has no backreferences or
// lookaround and needs none here.
var pep440Re = regexp.MustCompile(`^v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_\.]?(?P<preL>alpha|a|beta|b|preview|pre|c|rc)[-_\.]?(?P<preN>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<postN1>[0-9]+))|(?:[-_\.]?(?P<postL>post|rev|r)[-_\.]?(?P<postN2>[0-9]+)?))?` +
	`(?P<dev>[-_\.]?dev[-_\.]?(?P<devN>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?$`)

// preAlias folds the spellings PEP 440 treats as the same pre-release marker.
var preAlias = map[string]string{
	"alpha": "a", "a": "a",
	"beta": "b", "b": "b",
	"c": "rc", "pre": "rc", "preview": "rc", "rc": "rc",
}

// pep440Key returns a string that is equal for two versions exactly when PEP 440 says
// they are the same release, and ok=false when the input is not a PEP 440 version at all.
//
// A false `ok` is NOT an error to swallow. The caller must decide what an unparseable
// version means, and for a malware advisory the safe answer is not "no match" — see
// malwareList.pinnedFor.
func pep440Key(v string) (string, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	m := pep440Re.FindStringSubmatch(v)
	if m == nil {
		return "", false
	}
	g := func(name string) string { return m[pep440Re.SubexpIndex(name)] }

	var b strings.Builder
	// Epoch: omitted when 0, so "1.0" and "0!1.0" agree.
	if e := g("epoch"); e != "" {
		if n, err := strconv.Atoi(e); err == nil && n != 0 {
			b.WriteString(strconv.Itoa(n) + "!")
		}
	}
	// Release: trailing zero segments dropped, which is what makes 1 == 1.0 == 1.0.0.
	// Leading zeros within a segment are dropped too ("1.01" == "1.1").
	parts := strings.Split(g("release"), ".")
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return "", false
		}
		nums = append(nums, n)
	}
	for len(nums) > 1 && nums[len(nums)-1] == 0 {
		nums = nums[:len(nums)-1]
	}
	strs := make([]string, len(nums))
	for i, n := range nums {
		strs[i] = strconv.Itoa(n)
	}
	b.WriteString(strings.Join(strs, "."))

	// Pre-release. An absent number means 0 ("1.0a" == "1.0a0").
	if l := g("preL"); l != "" {
		b.WriteString(preAlias[l] + numOrZero(g("preN")))
	}
	// Post-release. PEP 440's implicit form "1.0-1" means post1.
	if n1 := g("postN1"); n1 != "" {
		b.WriteString(".post" + trimZeros(n1))
	} else if g("postL") != "" {
		b.WriteString(".post" + numOrZero(g("postN2")))
	}
	if g("dev") != "" {
		b.WriteString(".dev" + numOrZero(g("devN")))
	}
	// Local version: separators normalise to "." ("1.0+ubuntu-1" == "1.0+ubuntu.1").
	if loc := g("local"); loc != "" {
		b.WriteString("+" + strings.NewReplacer("-", ".", "_", ".").Replace(loc))
	}
	return b.String(), true
}

func numOrZero(s string) string {
	if s == "" {
		return "0"
	}
	return trimZeros(s)
}

func trimZeros(s string) string {
	if n, err := strconv.Atoi(s); err == nil {
		return strconv.Itoa(n)
	}
	return s
}

// pep440Same reports whether two version strings denote the same release.
//
// FALLBACK, AND WHY IT IS EQUALITY RATHER THAN "no match": when either side is not a
// parseable PEP 440 version we compare the trimmed, lower-cased strings. That still
// catches the exact-spelling case, which is the common one, instead of discarding the
// advisory entirely — an unparseable version must not become a silent allow.
func pep440Same(a, b string) bool {
	ka, oka := pep440Key(a)
	kb, okb := pep440Key(b)
	if oka && okb {
		return ka == kb
	}
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
