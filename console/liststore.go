package main

import (
	"fmt"
	"sort"
	"strings"
)

// The console's WRITE path for the operator's own allow/deny lists (issue #58
// increment 3b, D193).
//
// D193 answered "can the UI edit the whitelist, or only display it?" with **the UI
// edits it**, overruling the read-only recommendation. That one line moved the
// console from a viewer to an author, and D192 had already named the price: "a
// whitelist that the UI can edit is a database". D103 forbids the ENFORCEMENT plane
// from mutating durable state, so the write cannot land in the firewall.
//
// The mechanism is D193's option (c): the console commits to GIT and the replicas go
// on reading the file. It is the only option that satisfies "the UI edits it" without
// making the gate stateful, and the audit trail -- who, what, when -- is the git log
// rather than something we build. gitstore.go is that half.
//
// NOT a plain local file. D193 rules that out by name: a console writing to its own
// disk diverges across replicas and breaks the HA claim #23 exists to prove, silently.
// The commit is the durable write; the working tree is a cache of it.
//
// This file is the part with no I/O in it: what a well-formed entry is, and how an
// edit is applied to a file without damaging it.

const (
	listAllow = "allow"
	listDeny  = "deny"
)

// maxEntryLen bounds one authored entry.
//
// Generous on purpose: Go module paths and registry-qualified OCI references are the
// longest real names and sit well inside this, so the cap never argues with a legitimate
// entry. It exists to catch the wrong paste, not to police naming.
const maxEntryLen = 256

// validateEntry reports whether the console may write this entry into a list file.
//
// THIS IS A SAFETY CHECK, NOT INPUT TIDYING, and the reason is easy to miss.
// parseOperatorList does not skip a malformed line -- it REFUSES TO PARSE THE FILE.
// A running replica survives that (reloadingList keeps the last good list, deliberately,
// because a blanked deny list fails OPEN), but a replica that RESTARTS reads the file at
// boot and does not come up. So a console that writes an unparseable line has used the
// gate's own safety check to brick the gate, at a moment of its choosing rather than ours.
//
// The rules are therefore not re-derived here from memory. They are pinned against the
// gate's parser by a shared corpus, testdata/operator_list_lines.tsv, which both this
// package's test and the firewall's read -- including the one-way property that makes
// the pair safe: whatever the CONSOLE accepts, the GATE accepts. Stricter is fine;
// looser is the bricking case.
//
// Where this IS deliberately stricter than the gate: '#' and emptiness. Both are legal
// in a FILE (a comment line, a blank line) and neither is an entry. "lodash # note"
// parses to "lodash" at the gate, so accepting it in the add box would store something
// other than what the operator typed -- and they would have no way to see the difference.
func validateEntry(ecosystem, kind, entry string) error {
	if entry == "" {
		return fmt.Errorf("empty: type a package name")
	}
	if strings.TrimSpace(entry) != entry {
		return fmt.Errorf("%q has leading or trailing whitespace", entry)
	}
	if strings.ContainsAny(entry, " \t") {
		return fmt.Errorf("%q contains whitespace - one package name per entry, and a version is "+
			"not part of the name", entry)
	}
	if strings.ContainsAny(entry, "\r\n") {
		// LINE INJECTION. The file format is one entry per line, so an entry carrying a
		// newline is not a malformed name -- it is two lines, and the second one is
		// whatever the submitter chose. On the ALLOW list that is an arbitrary extra
		// package served without scoring, added by someone who appeared to add one name.
		return fmt.Errorf("a package name cannot span lines: the list format is one name per " +
			"line, so an entry containing a line break would add a second entry nobody typed")
	}
	if strings.ContainsRune(entry, 0) {
		return fmt.Errorf("a package name cannot contain a NUL byte")
	}
	if len(entry) > maxEntryLen {
		// A cap the GATE does not have, which is allowed (the console may be stricter,
		// never looser). No ecosystem's names come close to this, so the only things it
		// refuses are a paste of the wrong buffer and a deliberate attempt to bloat the
		// file and the commit message.
		return fmt.Errorf("that is %d characters long; a package name is at most %d. This looks "+
			"like a paste rather than a name", len(entry), maxEntryLen)
	}
	if strings.Contains(entry, "#") {
		return fmt.Errorf("%q contains '#', which starts a comment in the list file - the gate would "+
			"store only the part before it, which is not what you typed", entry)
	}
	return rejectVersionPinEntry(ecosystem, kind, entry)
}

// splitEntryVersion mirrors the gate's splitOperatorEntry, and entryNameIsWellFormed
// mirrors its checkOperatorName. The two packages cannot import each other (each service
// is its own `package main`), so the rules are restated and pinned to one shared corpus,
// testdata/operator_list_lines.tsv, plus the one-way property that the console is never
// LOOSER than the gate.
//
// The reasoning belongs to the gate and is not repeated here beyond what a reader needs:
// a version-scoped DENY names one release (#155/D312), a version on an ALLOW line is
// refused because a version-scoped allow is not built yet, and a name carrying a
// separator its ecosystem's grammar does not allow is refused because it would load and
// match nothing.
func splitEntryVersion(ecosystem, entry string) (name, version string, pinned bool) {
	return splitEntryVersionFor("deny", ecosystem, entry)
}

// splitEntryVersionFor is splitEntryVersion with the list KIND, which only OCI needs: an
// ALLOW entry naming a digest is version-scoped (#155), everything else on OCI is not.
func splitEntryVersionFor(kind, ecosystem, entry string) (name, version string, pinned bool) {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "oci":
		if kind == "allow" {
			if i := strings.LastIndex(entry, "@sha256:"); i > 0 {
				return entry[:i], entry[i+1:], true
			}
		}
		return entry, "", false
	case "pypi":
		if i := strings.Index(entry, "=="); i > 0 {
			return entry[:i], strings.TrimPrefix(entry[i+2:], "="), true
		}
	case "maven":
		if strings.Count(entry, ":") == 2 {
			i := strings.LastIndexByte(entry, ':')
			return entry[:i], entry[i+1:], true
		}
	default: // npm
		if i := strings.LastIndexByte(entry, '@'); i > 0 {
			return entry[:i], entry[i+1:], true
		}
	}
	return entry, "", false
}

func entryNameIsWellFormed(ecosystem, name string) error {
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
			return fmt.Errorf("%q is not a PyPI project name; pin a version with \"name==version\"", name)
		}
	case "maven":
		if strings.ContainsAny(name, "@=") || strings.Count(name, ":") != 1 {
			return fmt.Errorf("%q is not a Maven coordinate; write \"group:artifact\" or \"group:artifact:version\"", name)
		}
	default: // npm
		if strings.ContainsAny(name, ":=") {
			return fmt.Errorf("%q is not an npm package name; pin a version with \"name@version\"", name)
		}
		if i := strings.IndexByte(name, '@'); i > 0 {
			return fmt.Errorf("%q carries an \"@\" that is neither a scope nor a version pin", name)
		}
	}
	return nil
}

// rejectVersionPinEntry is the kind-aware successor to the gate's old rejectVersionPin.
//
// ⚠️ WHAT `kind` DOES AND DOES NOT DO HERE, measured by sabotage rather than assumed.
// Passing "deny" where "allow" belongs reddens NOTHING today, and that is structural, not
// a missing test: since #155 both lists accept the same grammar, and the one place the
// kinds differ — an OCI entry naming a digest is version-scoped on an ALLOW list only —
// is ACCEPTED either way here, as an exact entry or as a repository-wide one. Validation
// cannot see the difference; only the gate's enforcement can.
//
// It is kept, rather than dropped as dead, because the one-way property this pair rests on
// is "console accepts => gate accepts", and the gate IS kind-aware. The day the two kinds
// diverge on what is well-formed, a kind-blind console starts authoring lines the gate
// refuses to start on, which is the exact failure the shared corpus exists to prevent.
//
// Kept as a separate function with the same shape as its counterpart so a reviewer can
// read them side by side, and so the corpus test can point at the divergence if one
// appears. The reasoning for refusing a pin belongs to the gate and is not repeated:
// a pinned entry normalises to a name nothing matches, so the operator's deny silently
// does nothing, or their scoped allow allows nothing.
//
// oci is exempt and it is not a special case -- for oci the reference IS part of the
// package identity (D164), so "library/nginx:1.25" is well formed and means the whole
// repository. Surprising, so the corpus pins it rather than leaving it to be rediscovered.
func rejectVersionPinEntry(ecosystem, kind, entry string) error {
	name, version, pinned := splitEntryVersionFor(kind, ecosystem, entry)
	if err := entryNameIsWellFormed(ecosystem, name); err != nil {
		return err
	}
	if pinned && strings.TrimSpace(version) == "" {
		return fmt.Errorf("%q names an empty version: write the release, or the bare name for every version", entry)
	}
	return nil
}

// listDoc is one authored list file, held LINE BY LINE rather than parsed into a set.
//
// That is the whole design of the edit, and it is simpler than the alternative as well as
// safer. Parsing to a set and re-rendering would silently destroy everything the format
// allows but the set does not carry: the operator's comments ("# blocked after the 2026-08
// incident"), their grouping, their ordering. Those are the only record of WHY an entry is
// there, on a file whose entire purpose is to record an organisation's decisions.
//
// So an add appends a line and a remove deletes lines. Every other byte in the file is
// returned exactly as it was read.
type listDoc struct {
	Kind      string // "allow" | "deny"
	Path      string // path within the repo, for display and for the commit message
	Ecosystem string

	lines []string // verbatim, without their line terminators

	// eols is each line's OWN terminator: "\r\n", "\n", or "" for a final line that
	// had none. Parallel to lines.
	//
	// PER LINE, not one for the file, and that is not fussiness -- it is the difference
	// between an edit and a rewrite. A list file acquires MIXED endings as soon as two
	// tools touch it, which is the normal case here: the file is authored on one host,
	// appended to by a script on another, and edited by a console in a Linux container.
	// Rendering a mixed file with a single terminator rewrites every line that had the
	// other one, so a one-entry add lands in git as "-1/+2" or worse. The e2e caught
	// exactly that (+2/-1 on a file whose fixture lines were CRLF and whose appended line
	// was LF); every unit test had missed it, because a hand-written fixture is uniform
	// and real files are not.
	eols []string

	// eol is the terminator given to NEWLY appended lines -- the last line's, so an
	// append matches the file it is joining rather than the platform we happen to run on.
	eol string
	// Rev is the commit the content came from, or "" when the file is not yet committed.
	// Carried for display: it is the handle an operator uses to find the change in git log.
	Rev string
}

// parseListDoc reads a list file body.
//
// It FAILS on a line the gate would reject, and that refusal is load-bearing rather than
// pedantic: this doc is about to be the basis of a read-modify-write, and the one thing
// worse than refusing to edit a file is editing a file we have misread. A file already
// containing a bad line is a file the gate is already refusing to boot on, so the honest
// move is to name the line and let a human fix it.
func parseListDoc(kind, path, ecosystem string, body []byte) (*listDoc, error) {
	text := string(body)
	d := &listDoc{
		Kind:      kind,
		Path:      path,
		Ecosystem: ecosystem,
		eol:       "\n",
	}
	if text == "" {
		return d, nil
	}

	// Split so that every line keeps its own terminator. A final fragment with no
	// terminator is a real line with eol "" -- and re-emitting it without one is what
	// keeps "\ No newline at end of file" from flipping in the diff.
	for rest := text; rest != ""; {
		i := strings.IndexByte(rest, '\n')
		if i < 0 {
			d.lines = append(d.lines, rest)
			d.eols = append(d.eols, "")
			break
		}
		line, term := rest[:i], "\n"
		if strings.HasSuffix(line, "\r") {
			line, term = line[:len(line)-1], "\r\n"
		}
		d.lines = append(d.lines, line)
		d.eols = append(d.eols, term)
		rest = rest[i+1:]
	}
	// New lines inherit the last line's terminator, so an append joins the file in the
	// file's own style. A last line with none (no trailing newline) still needs one once
	// something follows it, so fall back to the previous line's, then to "\n".
	for i := len(d.eols) - 1; i >= 0; i-- {
		if d.eols[i] != "" {
			d.eol = d.eols[i]
			break
		}
	}

	for i, raw := range d.lines {
		entry, ok := entryOnLine(raw)
		if !ok {
			continue
		}
		if strings.ContainsAny(entry, " \t") {
			return nil, fmt.Errorf("%s-list %s line %d: %q contains whitespace - the gate refuses to "+
				"start on this file, so the console will not edit it either. Fix the line by hand",
				kind, path, i+1, entry)
		}
		if err := rejectVersionPinEntry(ecosystem, kind, entry); err != nil {
			return nil, fmt.Errorf("%s-list %s line %d: %v - the gate refuses to start on this file, "+
				"so the console will not edit it either. Fix the line by hand", kind, path, i+1, err)
		}
	}
	return d, nil
}

// entryOnLine returns the package name a raw line contributes, if any.
//
// Comment-stripping and trimming are the gate's, verbatim in behaviour: strip from the
// first '#', trim, and a line that is left empty contributes nothing.
func entryOnLine(raw string) (string, bool) {
	text := strings.TrimSpace(raw)
	if i := strings.IndexByte(text, '#'); i >= 0 {
		text = strings.TrimSpace(text[:i])
	}
	if text == "" {
		return "", false
	}
	return text, true
}

// Entries returns the authored names, in file order, as the operator wrote them.
//
// AS AUTHORED, not as the gate matches them. The console's own page shows this next to
// what replicas report they are ENFORCING (which is normalised), and the difference
// between those two columns is information, not noise -- it is how an operator sees that
// their edit has or has not reached the fleet yet.
func (d *listDoc) Entries() []string {
	var out []string
	for _, raw := range d.lines {
		if e, ok := entryOnLine(raw); ok {
			out = append(out, e)
		}
	}
	return out
}

// Count is the number of entries, for the "0 entries is not the same as no list" display.
func (d *listDoc) Count() int { return len(d.Entries()) }

// find returns the indexes of every line whose entry matches, case-folded.
//
// EVERY line, not the first, and case-folded rather than exact -- because the operator is
// removing a POLICY EFFECT, not a line of text. Two lines spelling the same package
// differently ("LoDash", "lodash") are one entry to the gate, and removing only one would
// leave the block in force while the console showed it gone.
//
// Case folding is a SUBSET of what the gate does. malwareKey also applies PEP 503
// folding for PyPI ('_' and '.' both become '-'), so "python_dateutil" and
// "python-dateutil" are one package there and two here. The console does not reimplement
// that -- a second normaliser is exactly the drift this file exists to avoid -- so a
// removal in that shape can leave the gate still enforcing. That is not left to be
// discovered: the /lists page shows the ENFORCED entries beside the authored ones, so a
// removal that did not take effect is visible in the next heartbeat rather than believed.
func (d *listDoc) find(entry string) []int {
	want := strings.ToLower(entry)
	var out []int
	for i, raw := range d.lines {
		if e, ok := entryOnLine(raw); ok && strings.ToLower(e) == want {
			out = append(out, i)
		}
	}
	return out
}

// Has reports whether the entry is already authored (case-folded).
func (d *listDoc) Has(entry string) bool { return len(d.find(entry)) > 0 }

// add appends an entry. Returns false when it was already there.
//
// Refusing the duplicate rather than appending a second identical line keeps the file
// something a human can read, and it means the count on the page is the number of
// decisions rather than the number of times someone clicked.
func (d *listDoc) add(entry string) (bool, error) {
	if err := validateEntry(d.Ecosystem, d.Kind, entry); err != nil {
		return false, err
	}
	if d.Has(entry) {
		return false, nil
	}
	// If the file's last line had no terminator, give it one now -- otherwise the new
	// entry would be glued onto the end of it and two entries would become one.
	if n := len(d.eols); n > 0 && d.eols[n-1] == "" {
		d.eols[n-1] = d.eol
	}
	d.lines = append(d.lines, entry)
	d.eols = append(d.eols, d.eol)
	return true, nil
}

// remove deletes every line carrying the entry and returns how many went.
//
// The COUNT is returned rather than a bool so the caller can tell "removed" from "it was
// not there", which are different things to say to an operator: one is a change they made,
// the other is a change they think they made.
func (d *listDoc) remove(entry string) int {
	hits := d.find(entry)
	if len(hits) == 0 {
		return 0
	}
	drop := map[int]bool{}
	for _, i := range hits {
		drop[i] = true
	}
	kept := make([]string, 0, len(d.lines))
	keptEOL := make([]string, 0, len(d.eols))
	for i, raw := range d.lines {
		if !drop[i] {
			kept = append(kept, raw)
			keptEOL = append(keptEOL, d.eols[i])
		}
	}
	d.lines, d.eols = kept, keptEOL
	return len(hits)
}

// Render returns the file bytes.
//
// Line endings and the trailing newline round-trip from what was read, so editing one
// entry produces a one-line diff. A console that rewrote CRLF as LF would show every
// commit as a whole-file rewrite, which destroys the audit trail this mechanism was
// chosen FOR -- git log -p on the deny list has to be readable, or the free audit
// trail is not one.
func (d *listDoc) Render() []byte {
	if len(d.lines) == 0 {
		return nil
	}
	var b strings.Builder
	for i, line := range d.lines {
		b.WriteString(line)
		b.WriteString(d.eols[i])
	}
	return []byte(b.String())
}

// prependHeader puts a comment block at the top of the file, keeping lines and eols in
// step. Only ever used on a file the console is creating.
func (d *listDoc) prependHeader(header []string) {
	eols := make([]string, len(header))
	for i := range eols {
		eols[i] = d.eol
	}
	d.lines = append(append([]string(nil), header...), d.lines...)
	d.eols = append(eols, d.eols...)
}

// newListFileHeader is the comment block written when the console CREATES a list file
// that did not exist. It is not written to a file that already has content: an
// operator's own file is theirs.
func newListFileHeader(kind string) []string {
	return []string{
		fmt.Sprintf("# Yellow Jack operator %s-list.", kind),
		"#",
		"# One package name per line. Blank lines and '#' comments are ignored.",
		"# A line names a package and means EVERY version of it.",
		"#",
		"# This file is read by the firewall and may be edited through the console.",
		"# Its history is the audit trail: git log -p on this file is who changed",
		"# what, and when.",
		"",
	}
}

// sortedEntries is a display helper: the authored names in a stable order.
//
// Used only for comparison against the enforced set, never to rewrite the file -- the
// file's own order is the operator's and is preserved.
func sortedEntries(d *listDoc) []string {
	e := append([]string(nil), d.Entries()...)
	sort.Strings(e)
	return e
}
