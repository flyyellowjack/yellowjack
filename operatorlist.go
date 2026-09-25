package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// The OPERATOR's own allow/deny lists (D193, issue #58).
//
// D192 trimmed the open-source launch to "time gating on package version age with a
// whitelist/blacklist", and D193 answered the question that left open: keep the
// published-malware feed AND let an operator add to the list. So there are now TWO
// denial sources, and this file owns the second one — the local, hand-authored list —
// while malware.go owns the feed.
//
// ⚠️ THE TWO MUST NOT BE MERGED, and that is the main design constraint here rather
// than an implementation detail. "This package is publicly reported as malicious" and
// "your own organisation blocked this package" are different facts about the world,
// they are actioned by different people, and a developer staring at a failed install
// needs to tell them apart in the first sentence. Folding them into one list would
// save a few lines and cost the operator the ability to answer "who decided this?" —
// which is the same legibility argument D137 made about block reasons generally.
//
// FORMAT: one package name per line; blank lines and "#" comments ignored.
//
// Deliberately NOT the feed's JSON-lines shape. The feed is machine-generated from OSV
// and is diffed by tooling; this file is written by a person and, per D193, edited
// through the console. A format a human can get right without documentation is worth
// more here than one that can carry structured advisory metadata we do not have.
//
// The ECOSYSTEM is not in the file because one process gates one ecosystem
// (FW_ECOSYSTEM), so within a given instance a bare name is unambiguous. An operator
// running npm and PyPI gates writes two files, which is also how they will want to
// review them.
//
// VERSIONS, on the DENY side, are supported as of #155/D312. A bare name still means
// every version of the package; a line that names a release denies exactly that release
// and leaves its siblings installable — the hijack case this file recorded as "a real
// want", and the case D312 turned into a prerequisite (an administrator allow that
// silently covers a release they never saw attributes to them a decision they did not
// make). It rides the per-version control points version-pinned advisories already use,
// so there is one place per ecosystem where "which release is this request for?" is
// answered.
//
// The SPELLING is each ecosystem's own, because the operator is copying it from their
// own build files: "lodash@4.17.20" (npm, including "@scope/name@1.2.3"),
// "requests==2.31.0" (PyPI), "group:artifact:1.2.3" (Maven).
//
// ⚠️ MAVEN COULD NOT USE THIS FILE AT ALL until #161: every Maven identity contains a
// colon ("group:artifact"), and the version-pin guard refused every line carrying one,
// which made a bad list — i.e. any real Maven list — a startup failure. Telling an
// identity from a version pin per ecosystem is what fixes that, so the two land together.
//
// ALLOW entries may name a release too, as of #155/D312, and that is what makes the
// ruling *"if the administrator allows it, it is allowed"* literally true: the
// administrator looked at ONE release and judged it, and a name-scoped entry would extend
// that judgement to an artifact that did not exist when they decided.
//
// ⚠️ A version-scoped allow is applied where the RELEASE IS KNOWN — the per-version
// control points (ocirevalidate/identity, the npm packument and tarball, the PyPI index
// and file, the Maven path). It does NOT rescue a package refused at the package level
// (an advisory naming every version, a low score, an unscorable repo), because at that
// control point no version has been named yet. That case is refused with a reason that
// SAYS an allow entry exists and could not be applied, rather than silently ignoring it.

// operatorList is a loaded allow- or deny-list: an immutable set built once at startup
// and only read afterwards, so it needs no lock. Same lifecycle as malwareList, and for
// the same D103 reason — we read an injected file, we never mutate durable state.
//
// A nil *operatorList is the "not configured" case and answers false to every lookup.
// That is what makes the zero value safe: an operator who sets neither variable gets
// exactly today's behaviour, and every call site can skip its nil check.
type operatorList struct {
	// names holds normalized "<ecosystem>\x00<name>" keys, produced by malwareKey.
	//
	// REUSING malwareKey IS THE POINT, not a convenience. It applies PEP 503
	// normalization for PyPI, case-folding for npm, and reference-stripping for OCI.
	// A second normalizer here would drift from it, and the drift would be silent and
	// exactly one way: an operator writes "Requests" in their denylist, our key does
	// not match the "requests" the feed would have caught, and the block they asked
	// for does not happen. A denylist that misses is worse than no denylist, because
	// they believe it is working.
	names map[string]bool

	// versions holds VERSION-SCOPED deny entries: the same normalized key, mapped to the
	// releases named. Kept SEPARATE from names rather than folded in, because the two say
	// different things and a lookup that could not tell them apart would silently widen
	// the narrow one: "deny lodash" must refuse every release, "deny lodash@4.17.20" must
	// refuse one and leave the rest installable.
	versions map[string][]string

	// kind is "allow" or "deny", carried only so log and error text can name which
	// list a problem is in. An operator with both configured needs to be told which
	// file to edit.
	kind string

	// path is where it was loaded from, for the same reason.
	path string

	// entries is the NORMALIZED package names, sorted -- what the gate actually matches,
	// which is not always what the operator typed ("LoDash" is enforced as "lodash").
	// Shown on the console's enforced-policy page, so the page describes the policy in
	// force rather than the file's spelling of it.
	entries []string

	// contentDigest fingerprints the normalized entry SET, not the file's bytes.
	//
	// Deliberately different from malwareList's raw-byte digest, and the difference is the
	// point: this file is hand-edited, so a reworded comment or a reordered line is not a
	// policy change and must not read as one. Two replicas whose lists differ only in
	// comments agree here; two whose enforced names differ do not -- which is exactly the
	// divergence the console's policy page already surfaces, and the failure mode D193
	// flagged for an editable list across replicas.
	contentDigest string

	// warnings are lines that PARSED and are enforced, but not with the scope they
	// appear to name. Today that is exactly one case: an OCI entry carrying a tag or
	// digest, which is silently widened to the whole repository (see
	// ociReferenceWarning).
	//
	// Separate from an error on purpose. These entries DO work -- refusing them would
	// break a legitimate deny -- so the operator must be told what they got, not
	// stopped. Carried on the list rather than logged at parse time because
	// parseOperatorList is pure and is called on a 5-second reload timer; the caller
	// that owns a logger decides when saying it again is useful.
	warnings []string
}

// has reports whether the list names this package. Safe on a nil receiver.
//
// PURE — no I/O, no mutation. That matters beyond good manners: policy.Rule requires
// pure conditions, and this is what a rule will call when the console view lands.
func (l *operatorList) has(ecosystem, name string) bool {
	if l == nil {
		return false
	}
	return l.names[malwareKey(ecosystem, name)]
}

// hasVersion reports whether this list names THIS RELEASE of the package (#155).
//
// Version comparison is sameVersion's, the ecosystem-aware one the feed uses, and reusing
// it is the point: PEP 440 folding is required for PyPI (1.0, 1.0.0 and 1 are one release)
// and WRONG for Maven and OCI, where a version is a literal path segment or an arbitrary
// tag. A second comparison here would drift from the feed's, and the drift would be
// invisible — an operator's deny would simply not fire.
func (l *operatorList) hasVersion(ecosystem, name, version string) bool {
	if l == nil || version == "" {
		return false
	}
	for _, v := range l.versions[malwareKey(ecosystem, name)] {
		if sameVersion(ecosystem, v, version) {
			return true
		}
	}
	return false
}

// anyVersionScoped reports whether this list carries version-scoped entries AT ALL.
//
// It exists for one reason, and it is the #103 lesson arriving a second time: the npm
// packument filter and the PyPI index filter are only INVOKED when a feed or a release
// window is configured. A version-scoped deny entry with neither of those set would be
// parsed, reported, digested -- and never consulted, which is the "correct filter that is
// never invoked" failure, indistinguishable at runtime from having no entry. Measured by
// this file's own tests before the predicate existed.
func (l *operatorList) anyVersionScoped() bool {
	return l != nil && len(l.versions) > 0
}

// hasAnyVersion reports whether ANY version-scoped entry names this package.
//
// This is what makes an unknown version dangerous rather than merely unknown, exactly as
// malwareList.hasPinned does for advisories: if we cannot tell which release a request is
// for and no entry names the package, there is nothing to miss; if one does, the caller
// must fail closed or the operator's deny is bypassed by whatever broke the join.
func (l *operatorList) hasAnyVersion(ecosystem, name string) bool {
	if l == nil {
		return false
	}
	return len(l.versions[malwareKey(ecosystem, name)]) > 0
}

// count reports how many entries were loaded. Used by the startup log and by the
// policy view, so an operator can confirm the file they edited is the file we read.
func (l *operatorList) count() int {
	if l == nil {
		return 0
	}
	// Version-scoped entries count too: the number is what an operator compares against
	// the file they just edited, and a file of ten version-scoped denies reporting "0
	// entries" reads as "my list did not load".
	n := len(l.names)
	for _, vs := range l.versions {
		n += len(vs)
	}
	return n
}

// describe renders the list for the policy view, mirroring malwareList.describe.
//
// Reported from the LOADED list rather than from cfg, for the reason describePolicy's
// comment already gives about the feed: naming the configured path says which file was
// asked for, while this says what was actually installed. Two replicas pointing at the
// same path with different contents behind it must diverge in the digest instead of
// agreeing falsely -- and for an operator-editable list that is not a corner case, it is
// the expected steady state during a rollout.
func (l *operatorList) describe() string {
	if l == nil {
		return "off"
	}
	if len(l.entries) == 0 {
		// A configured-but-empty list is NOT the same as no list, and saying "0 entries"
		// rather than "off" is what lets an operator tell "my file did not load" from "I
		// have not configured one".
		return "configured, 0 entries"
	}
	return fmt.Sprintf("%d entries, sha256:%s", len(l.entries), l.contentDigest[:12])
}

// listEntries returns up to max normalized names plus how many were omitted.
//
// Capped because this travels in every heartbeat to the control plane, and an operator
// who pastes a 50,000-line blocklist should not silently turn the health report into a
// bulk transfer. The omitted COUNT is returned rather than dropped: a truncated list that
// did not say it was truncated would read as the whole policy.
func (l *operatorList) listEntries(max int) ([]string, int) {
	if l == nil || len(l.entries) == 0 {
		return nil, 0
	}
	if len(l.entries) <= max {
		return append([]string(nil), l.entries...), 0
	}
	return append([]string(nil), l.entries[:max]...), len(l.entries) - max
}

// loadOperatorList reads a list file from an ABSOLUTE path.
//
// The absolute-path requirement is copied from loadMalwareList deliberately rather
// than relaxed: a relative path resolves against the working directory, so it is
// chosen by wherever the process happened to be launched rather than by the operator
// (#38 / CVE-2025-64726). That reasoning applies with MORE force here, because this
// file can ALLOW packages — a relative path an attacker can influence would let them
// pick which allowlist we honour.
func loadOperatorList(kind, ecosystem, path string) (*operatorList, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("operator %s-list %q must be an absolute path: a relative path "+
			"resolves against the working directory, so it is chosen by wherever the process "+
			"was launched rather than by the operator (issue #38 / CVE-2025-64726)", kind, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("operator %s-list: %w", kind, err)
	}
	defer f.Close()

	l, err := parseOperatorList(kind, ecosystem, f)
	if err != nil {
		return nil, err
	}
	l.path = path
	return l, nil
}

// parseOperatorList reads the list body. Split from loadOperatorList so tests drive
// the parser without touching the filesystem.
//
// FAILS on a malformed line rather than skipping it. That is the opposite of the
// malware feed, which counts and skips unusable records, and the asymmetry is
// deliberate: the feed has hundreds of thousands of machine-generated records where
// one bad row must not stop the service from booting, while this file has a handful
// of hand-written lines where a typo means the operator's intent is not being carried
// out. Refusing to start names the problem at the moment someone can still fix it,
// which is what #19 asks of config errors generally.
func parseOperatorList(kind, ecosystem string, r io.Reader) (*operatorList, error) {
	l := &operatorList{names: map[string]bool{}, versions: map[string][]string{}, kind: kind}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(text, '#'); i >= 0 {
			text = strings.TrimSpace(text[:i])
		}
		if text == "" {
			continue
		}
		if strings.ContainsAny(text, " \t") {
			return nil, fmt.Errorf("operator %s-list line %d: %q contains whitespace — one package "+
				"name per line, and no version or comment syntax beyond '#'", kind, line, text)
		}
		name, version, pinned := splitOperatorEntryFor(kind, ecosystem, text)
		if err := checkOperatorName(ecosystem, name); err != nil {
			return nil, fmt.Errorf("operator %s-list line %d: %q %v", kind, line, text, err)
		}
		// A separator with nothing after it is a TYPO, and reading it as the bare name
		// would widen the entry from one release to every release — silently, which is
		// the failure mode this file refuses lines to avoid.
		if pinned && strings.TrimSpace(version) == "" {
			return nil, fmt.Errorf("operator %s-list line %d: %q names an empty version. Write the "+
				"release, or write the bare name if you meant every version", kind, line, text)
		}
		if w := ociReferenceWarning(kind, ecosystem, line, text); w != "" {
			l.warnings = append(l.warnings, w)
		}
		if version == "" {
			l.names[malwareKey(ecosystem, text)] = true
			continue
		}
		key := malwareKey(ecosystem, name)
		l.versions[key] = append(l.versions[key], version)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("operator %s-list: %w", kind, err)
	}

	// Build the display list and the digest from the normalized KEY SET, sorted, so both
	// are stable regardless of the order the operator wrote the file in. Go randomizes map
	// iteration, so without the sort a replica would appear to diverge from itself -- the
	// same trap PolicyView.digest documents for its Values map.
	for key := range l.names {
		if i := strings.IndexByte(key, 0); i >= 0 {
			l.entries = append(l.entries, key[i+1:])
		}
	}
	// Version-scoped entries appear in the display list and therefore in the DIGEST, in
	// the ecosystem's own spelling. Leaving them out would let two replicas enforcing
	// different releases of the same package report an identical policy — the exact blind
	// spot contentDigest exists to close.
	for key, vs := range l.versions {
		i := strings.IndexByte(key, 0)
		if i < 0 {
			continue
		}
		for _, v := range vs {
			l.entries = append(l.entries, joinOperatorEntry(ecosystem, key[i+1:], v))
		}
	}
	sort.Strings(l.entries)
	h := sha256.New()
	for _, e := range l.entries {
		fmt.Fprintf(h, "%s\n", e)
	}
	l.contentDigest = hex.EncodeToString(h.Sum(nil))

	return l, nil
}

// splitOperatorEntry tells an IDENTITY from a VERSION-SCOPED entry, in each ecosystem's
// own spelling, and returns the package name and the version ("" when the line names no
// version).
//
// ⚠️ THE MAVEN CASE IS WHY THIS FUNCTION EXISTS RATHER THAN A SHARED SEPARATOR SCAN.
// The previous guard refused any non-OCI line containing ":", "@" or "==" as a version
// pin. Every Maven identity contains a colon, so a Maven operator list could not name a
// single coordinate, and because a bad list is fatal at startup a Maven gate configured
// with one would not boot (#161, measured). A separator is not a version marker; where
// it sits in the ecosystem's grammar is.
//
//   - npm: the LAST "@" that is not the scope's leading one. "@scope/name" is a name;
//     "@scope/name@1.2.3" and "lodash@4.17.20" name releases.
//   - PyPI: "==", pip's own exact-pin spelling. "===" (PEP 440 arbitrary equality) is
//     accepted as the same thing with the extra "=" trimmed; sameVersion folds PEP 440
//     spellings anyway, so the two cannot disagree about which release is meant.
//   - Maven: TWO colons name a release ("group:artifact:1.2.3"); one is the identity.
//   - OCI, DENY: never version-scoped. The reference is already part of the identity
//     (D164) and an entry carrying one widens to the repository with a warning (#128,
//     ociReferenceWarning). Narrowing that now would silently weaken every deny list
//     already written against the documented behaviour.
//   - OCI, ALLOW naming a DIGEST: version-scoped (#155). A digest names immutable
//     content, so an allow of one is exactly the artifact the administrator judged;
//     narrowing an allow is the fail-CLOSED direction, so no existing deployment is
//     served anything it was not served before. An allow naming a TAG stays widened with
//     its warning, because a tag is mutable (#93) and "allow whatever this tag points at
//     next" is precisely the decision D312 says nobody made.
func splitOperatorEntry(ecosystem, text string) (name, version string, pinned bool) {
	return splitOperatorEntryFor("deny", ecosystem, text)
}

// splitOperatorEntryFor is splitOperatorEntry with the list KIND, which only OCI needs.
func splitOperatorEntryFor(kind, ecosystem, text string) (name, version string, pinned bool) {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "oci":
		if kind == "allow" {
			if i := strings.LastIndex(text, "@sha256:"); i > 0 {
				return text[:i], text[i+1:], true
			}
		}
		return text, "", false
	case "pypi":
		if i := strings.Index(text, "=="); i > 0 {
			return text[:i], strings.TrimPrefix(text[i+2:], "="), true
		}
	case "maven":
		if strings.Count(text, ":") == 2 {
			i := strings.LastIndexByte(text, ':')
			return text[:i], text[i+1:], true
		}
	default: // npm
		if i := strings.LastIndexByte(text, '@'); i > 0 {
			return text[:i], text[i+1:], true
		}
	}
	return text, "", false
}

// joinOperatorEntry renders name+version back in the ecosystem's own spelling, for the
// display list, the digest and the operator-facing reason. Derived from the same grammar
// splitOperatorEntry reads, so what we print is what an operator can paste back.
func joinOperatorEntry(ecosystem, name, version string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "pypi":
		return name + "==" + version
	case "maven":
		return name + ":" + version
	default:
		return name + "@" + version
	}
}

// ociReferenceWarning returns the line an operator needs to see when an OCI entry
// names a tag or digest, or "" when there is nothing to say.
//
// ── THE DEFECT THIS CLOSES ───────────────────────────────────────────────────
//
// Measured: a deny list containing "library/alpine:3.19" refuses library/alpine:3.19
// AND library/alpine:latest AND every other tag, because malwareKey routes OCI names
// through ociRepoOnly. That widening is CORRECT for its original caller — a
// package-wide advisory condemns the repository whichever tag was asked for — and it
// is silently wrong for an operator who wrote one tag on purpose.
//
// The nastiest shape is the accidental one: someone blocks the single bad tag of a
// base image their builds depend on, and takes out every build using any tag of it.
// The refusal names the repository, so the log reads exactly as though they had
// written the repository, and nothing anywhere says the entry was widened.
//
// ── WHY A WARNING AND NOT AN ERROR ───────────────────────────────────────────
//
// Refusing the line would be worse. The entry is well formed (D164 puts the reference
// in the identity), it IS enforced, and refusing it would break an operator whose
// intent really was repository-wide. The failure here is a mismatch between what the
// line says and what it does, so the fix is to say what it does.
//
// ── WHY NOT JUST LOOK FOR ":" ────────────────────────────────────────────────
//
// Because a registry host legitimately carries a port: "registry.internal:5000/team/app"
// has a colon and names no tag. The reference always begins after the LAST "/", so
// that is where to look — anything earlier belongs to the host.
func ociReferenceWarning(kind, ecosystem string, line int, text string) string {
	if ecosystem != "oci" {
		return ""
	}
	// A digest-scoped ALLOW is exact, not widened (#155), so there is nothing to warn
	// about. Every other OCI entry still applies to the whole repository.
	if _, _, pinned := splitOperatorEntryFor(kind, ecosystem, text); pinned {
		return ""
	}
	last := text
	if i := strings.LastIndexByte(text, '/'); i >= 0 {
		last = text[i+1:]
	}
	if !strings.ContainsAny(last, ":@") {
		return ""
	}
	repo := malwareKeyName(ecosystem, text)
	// The last sentence differs by list, because since #155 the two lists no longer have
	// the same grammar. A DENY entry still cannot name less than a repository, so "not
	// supported" is true there -- and docs/REFERENCE_DEPLOYMENT.md quotes that line
	// verbatim, so it stays byte-for-byte. An ALLOW entry CAN name exactly one image, by
	// digest; telling an operator "per-tag entries are not supported" on the allow list
	// would send them away from the one spelling that does what they are trying to do.
	// (That sentence was true when written, and !370 made it false for this list without
	// touching it -- a new rule silently contradicting a standing message.)
	tail := "and note that per-tag entries are not supported."
	if kind == "allow" {
		tail = fmt.Sprintf("or, to allow exactly ONE image, name it by digest (%q) -- a tag is "+
			"mutable, so no tag can name one image.", repo+"@sha256:<digest>")
	}
	return fmt.Sprintf("operator %s-list line %d: %q names a tag or digest, but an entry here "+
		"applies to the WHOLE repository %q — every tag of it, not just the one written. "+
		"It is enforced that way, and this is not an error. Write %q if that is what you meant, "+
		"%s",
		kind, line, text, repo, repo, tail)
}

// malwareKeyName is malwareKey's normalized NAME without the ecosystem prefix, so a
// message can quote the repository the entry actually enforces. Derived from the same
// function rather than re-implemented, because a second normalizer here would let the
// message drift from the behaviour it describes — which is the defect it exists to
// report.
func malwareKeyName(ecosystem, name string) string {
	key := malwareKey(ecosystem, name)
	if i := strings.IndexByte(key, 0); i >= 0 {
		return key[i+1:]
	}
	return key
}

// ---------------------------------------------------------------------------
// RELOADING (D195, issue #58 increment 3a)
//
// D193 ruled that the console will EDIT these lists. Until now the firewall read
// them once in NewFirewall and never again, so an edit would not reach a running
// replica at all -- it would take a restart, and a whitelist that needs a deploy is
// not the feature that was asked for. This is the re-read.
//
// It does not weaken D103: we still never MUTATE durable state. We read an injected
// file, exactly as FW_UPSTREAM_AUTH_FILE already does.
//
// The shape is lifted from upstreamcred.go's fileCredentialEvery rather than
// reinvented, because two of its properties are counter-intuitive and this file
// would have got both wrong:
//
//  1. TIME-BASED, NOT mtime-BASED. The obvious cache key is (mtime, size). Its
//     silent failure: mtime granularity is one second on several filesystems, so a
//     rewrite within the same second producing the same length is INVISIBLE. For a
//     list that means an operator swaps one entry for another of equal length and
//     the gate keeps enforcing the old set while the console shows the new one.
//
//  2. A FAILED OR EMPTY READ NEVER REPLACES THE LAST GOOD LIST. Writers are not all
//     atomic, so a read can land mid-rewrite; a deleted file, a permission change
//     and a full disk look identical.
//
// 🚩 PROPERTY 2 IS ASYMMETRIC HERE IN A WAY IT IS NOT FOR A CREDENTIAL, and that is
// the reason this is not four lines. A blanked credential degrades us to anonymous.
// A blanked DENY list means every package the operator blocked silently becomes
// SERVABLE -- it fails OPEN. (A blanked allow list only fails closed: builds break,
// visibly, and nobody is exposed.) So retaining the last good value here is a
// security property, not an availability nicety.

// listReloadTTL bounds how stale an edited list can be.
//
// A constant rather than a knob, following credFileTTL: the config surface is a
// budget we defend (#51), and nothing yet suggests a deployer needs to tune this.
// Five seconds rather than the credential's one: an operator unblocking a developer
// wants it to feel immediate, and re-parsing a hand-authored list of dozens of names
// at that cadence is free. If a deployer ever pastes a bulk list, this is the number
// to revisit -- with a measurement, not a guess. A package variable rather than a
// constant only so the readiness tests can shorten it; it is still not a knob.
var listReloadTTL = 5 * time.Second

// allow / deny read the operator lists through their sources, tolerating a nil source.
//
// THE NIL GUARD IS LOAD-BEARING, not defensive habit. Plenty of tests (and the
// borrowed-score path's fixtures) build a Firewall as a struct literal rather than
// through NewFirewall, so these fields are nil there. Before the guard existed,
// Evaluate panicked on the first such test -- the zero value of a Firewall has always
// been usable, and turning a field into a func must not quietly take that away.
func (f *Firewall) allow() *operatorList {
	if f.allowList == nil {
		return nil
	}
	return f.allowList()
}

func (f *Firewall) deny() *operatorList {
	if f.denyList == nil {
		return nil
	}
	return f.denyList()
}

// listSource yields the operator list in force RIGHT NOW. Mirrors credentialSource.
//
// A function rather than a field so the request path cannot accidentally hold a
// stale pointer: every lookup asks, and the source decides whether that means a
// re-read or the cached value.
type listSource func() *operatorList

// staticList is a source that never changes -- the unconfigured case (nil) and the
// one tests use when reload is not what they are exercising.
func staticList(l *operatorList) listSource {
	return func() *operatorList { return l }
}

// reloadingSource is the state behind reloadingList, a type rather than a closure so
// readiness (D165) can ask the one question a closure could not answer: is the list in
// force the file on the mount, or the last good list retained after a failed re-read?
type reloadingSource struct {
	kind, ecosystem, path string
	logf                  func(string, ...any)
	ttl                   time.Duration

	mu       sync.Mutex
	last     *operatorList
	checked  time.Time
	degraded bool
	lastErr  error
}

// newReloadingList builds a source seeded with the list startup already loaded, so the
// list in force never depends on WHO reads it first. Measured while building /readyz:
// the window between the startup load and the first re-read was already closed in
// practice, because NewFirewall's policy digest reads both lists through their sources
// at construction -- a sabotage that removed this seed reddened nothing. The seed makes
// that a property of the source rather than of a caller order nobody asserted. first may
// be nil (the tests that exercise the first read).
func newReloadingList(kind, ecosystem, path string, logf func(string, ...any), ttl time.Duration, first *operatorList) *reloadingSource {
	return &reloadingSource{kind: kind, ecosystem: ecosystem, path: path, logf: logf, ttl: ttl, last: first}
}

// reloadingList re-reads path every ttl, keeping the last good list on any failure.
func reloadingList(kind, ecosystem, path string, logf func(string, ...any), ttl time.Duration) listSource {
	return (&reloadingSource{kind: kind, ecosystem: ecosystem, path: path, logf: logf, ttl: ttl}).current
}

// current is the listSource: the list in force right now, re-read when the ttl has passed.
func (s *reloadingSource) current() *operatorList {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	return s.last
}

// stale reports why the list in force is NOT the file on the mount -- the last read
// failed, and the previous good list (or nothing) is being enforced -- or nil when it is.
// It performs the same ttl-bounded re-read as current, so a readiness probe drives the
// reload on a gate that is serving no requests, instead of reporting a state nobody has
// refreshed. A file read, never a dial (D163).
func (s *reloadingSource) stale() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	if !s.degraded {
		return nil
	}
	if s.last == nil {
		return fmt.Errorf("%q is unreadable (%v) and nothing was ever loaded from it", s.path, s.lastErr)
	}
	return fmt.Errorf("%q is unreadable (%v); still enforcing the last good list (%d entries)", s.path, s.lastErr, s.last.count())
}

func (s *reloadingSource) refreshLocked() {
	if !s.checked.IsZero() && time.Since(s.checked) < s.ttl {
		return
	}
	s.checked = time.Now()

	next, err := loadOperatorList(s.kind, s.ecosystem, s.path)
	if err != nil {
		s.lastErr = err
		if !s.degraded {
			s.degraded = true
			// Name what is still being enforced, because the two cases need
			// very different urgency from whoever reads the line.
			if s.last != nil {
				s.logf("operator %s-list %q became unreadable (%v) -- STILL ENFORCING the last good list (%d entries). Fix the file; nothing has been dropped.",
					s.kind, s.path, err, s.last.count())
			} else {
				s.logf("operator %s-list %q is unreadable (%v) and nothing was ever loaded from it -- this list is enforcing NOTHING.",
					s.kind, s.path, err)
			}
		}
		return
	}
	if s.degraded {
		s.degraded = false
		s.lastErr = nil
		s.logf("operator %s-list %q is readable again (%d entries)", s.kind, s.path, next.count())
	}

	// 🚩 The suspicious transition, logged rather than trusted. A list that
	// PARSED CLEANLY but is now empty when it was not is the shape of a
	// truncated write or a wrong file mounted, and for the deny list it is the
	// fail-open direction. We honour it -- an operator is allowed to empty a
	// list -- but never silently, because "my blocks stopped applying" is
	// otherwise indistinguishable from "my blocks were removed on purpose".
	if s.last != nil && s.last.count() > 0 && next.count() == 0 {
		s.logf("operator %s-list %q went from %d entries to ZERO. Honouring it, but if that was not deliberate the file is truncated or the wrong one is mounted.",
			s.kind, s.path, s.last.count())
	}
	if s.last == nil || s.last.contentDigest != next.contentDigest {
		s.logf("operator %s-list %q reloaded: %d entries, sha256:%s",
			s.kind, s.path, next.count(), next.contentDigest[:12])
		// Entries that are enforced more broadly than they read (#128). Emitted
		// HERE, behind the same digest guard as the line above, for two reasons:
		// this runs every 5 seconds and repeating an unchanged warning forever
		// would train an operator to ignore it, and a warning that reappears is
		// then real news — the file changed and the entry is still widened.
		for _, w := range next.warnings {
			s.logf("%s", w)
		}
	}
	s.last = next
}

// checkOperatorName refuses a NAME that cannot be a package name in this ecosystem.
//
// Splitting a line into name and version is not enough on its own, and leaving this out
// would reopen the hole #128 closed from the other side. "requests:2.31.0" carries no
// "==", so the PyPI split yields the whole string as a NAME — a name PyPI cannot have,
// which normalises to a key nothing will ever match. The operator's deny would then load
// cleanly and silently enforce nothing, which is worse than refusing the line.
//
// So: a separator is legal exactly where the ecosystem's own grammar puts one.
//
//   - npm: "@" only as a scope's leading character, "/" only to close the scope; a name
//     never carries ":" or "=".
//   - PyPI: PEP 503 names are letters, digits, ".", "-" and "_" (normalisation collapses
//     the last three); ":", "@" and "=" cannot appear.
//   - Maven: exactly one ":" (group:artifact); never "@" or "=".
//   - OCI: not checked here. The reference is part of the identity (D164) and
//     ociReferenceWarning already says what such an entry enforces (#128).
func checkOperatorName(ecosystem, name string) error {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	if eco == "oci" {
		return nil
	}
	if name == "" {
		return fmt.Errorf("names no package")
	}
	switch eco {
	case "pypi":
		if strings.ContainsAny(name, ":@=") {
			return fmt.Errorf("is not a PyPI project name (it carries %q); pin a version with \"name==version\"", firstOf(name, ":@="))
		}
	case "maven":
		if strings.ContainsAny(name, "@=") {
			return fmt.Errorf("is not a Maven coordinate (it carries %q); write \"group:artifact\" or \"group:artifact:version\"", firstOf(name, "@="))
		}
		if strings.Count(name, ":") != 1 {
			return fmt.Errorf("is not a Maven coordinate; write \"group:artifact\" or \"group:artifact:version\"")
		}
	default: // npm
		if strings.ContainsAny(name, ":=") {
			return fmt.Errorf("is not an npm package name (it carries %q); pin a version with \"name@version\"", firstOf(name, ":="))
		}
		if i := strings.IndexByte(name, '@'); i > 0 {
			return fmt.Errorf("carries an \"@\" that is neither a scope nor a version pin")
		}
	}
	return nil
}

// firstOf returns the first character of s that appears in set, for an error message that
// quotes what was actually wrong rather than listing everything that could be.
func firstOf(s, set string) string {
	if i := strings.IndexAny(s, set); i >= 0 {
		return string(s[i])
	}
	return ""
}
