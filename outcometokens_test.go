package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The bracketed outcome token — [verdict-blocked], [served-anyway], [known-malware] and
// the rest — is the one part of a decision log line a reader can trust. proxy.go says why
// at length (#68): everything after the " -> " is filled in from the decision, including
// a policy rule NAME an operator chose, so a classifier keying on the payload can be
// steered by naming a rule after the text it looks for. That is not hypothetical; it
// moved 38 cells of the committed mode matrix while the status, the bytes and the verdict
// were all identical.
//
// So the token vocabulary is an interface between two files that never reference each
// other: proxy.go WRITES the tokens, and classifyLog in modematrix_test.go READS them.
// Nothing connected the two. classifyLog's own comment states the rule it wants —
//
//	"a new outcome added without a token must show up as its own unfamiliar value in
//	 the golden diff, rather than quietly joining a bucket"
//
// — and that rule is enforced for the four allow-but-log outcomes only. A metadata-path
// token it does not recognise falls through to `strings.Contains(s, "allowed=false")` and
// is labelled "decision-denied", which is the quiet bucket the comment forbids.
//
// MEASURED 2026-09-12: production emits nine tokens, classifyLog knew seven.
// [known-malware] and [release-window] were unknown to it. Both are latent today —
// uncoveredCells deliberately keeps FW_MALWARE_LIST and FW_MIN_RELEASE_AGE_DAYS off the
// matrix's axes, so neither token is produced by any committed cell. But that exclusion
// is written to be VOIDABLE ("If that test ever fails, this exclusion is void and the
// axis belongs in the matrix"), and on the day it is voided a layer-1 malware block would
// be recorded as an ordinary score denial — the two things the matrix exists to tell
// apart.
//
// This guard derives the vocabulary from the source on both sides rather than restating
// it, the same way configreference_test.go derives FW_* from config.go.

// tokenRe matches a bracketed outcome token: lowercase words joined by hyphens.
var tokenRe = regexp.MustCompile(`\[[a-z]+(?:-[a-z]+)*\]`)

// emittedOutcomeTokens returns every outcome token that production code can write,
// gathered from two places it can come from: a literal inside a log.Printf format string,
// and a string constant returned by outcomeToken.
func emittedOutcomeTokens(t *testing.T) map[string]string {
	t.Helper()
	found := map[string]string{} // token -> where it came from
	fset := token.NewFileSet()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read repo root: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for _, tok := range tokenRe.FindAllString(s, -1) {
				if _, seen := found[tok]; !seen {
					found[tok] = name
				}
			}
			return true
		})
	}
	return found
}

// tokensClassifyLogKnows reads the classifier's own source for the tokens it matches on.
// Deriving it beats restating it: a token removed from classifyLog but left in this list
// would make the guard pass while the classifier had stopped handling it.
func tokensClassifyLogKnows(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile("modematrix_test.go")
	if err != nil {
		t.Fatalf("read modematrix_test.go: %v", err)
	}
	body := classifyLogBody(t, string(src))
	out := map[string]bool{}
	// Only tokens inside a `case strings.Contains(...)` count as HANDLED. Scanning the
	// whole function body instead reads tokens out of its comments, and classifyLog
	// discusses several by name while explaining the design — including, as it happens,
	// ones it does not match on. That reported 16 known tokens where 7 were handled, and
	// would have let a token that is merely mentioned pass as covered: a guard that
	// accepts prose as evidence of behaviour.
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "case strings.Contains(") {
			continue
		}
		for _, tok := range tokenRe.FindAllString(trimmed, -1) {
			out[tok] = true
		}
	}
	return out
}

// classifyLogBody slices out just the classifyLog function, so a token mentioned in some
// unrelated comment elsewhere in the file cannot be mistaken for one the switch handles.
func classifyLogBody(t *testing.T, src string) string {
	t.Helper()
	start := strings.Index(src, "func classifyLog(")
	if start < 0 {
		t.Fatalf("classifyLog not found in modematrix_test.go — this guard is aimed at a " +
			"function that no longer exists under that name, so it proves nothing")
	}
	rest := src[start:]
	// The function ends at the first line that is exactly a closing brace at column 0.
	if end := strings.Index(rest, "\n}\n"); end >= 0 {
		return rest[:end]
	}
	return rest
}

// tokensNotClassified are tokens production emits that classifyLog deliberately does not
// map to a label of their own, WITH the reason. Same discipline as uncoveredCells: an
// exclusion lives in code beside the coverage it qualifies, not in prose somewhere else.
//
// Empty on purpose as of 2026-09-12. Both previously-unknown tokens were given labels
// rather than excused, because giving them one costs two lines and cannot change a
// committed cell (no matrix axis produces them), whereas excusing them leaves the trap
// armed for whoever voids the FW_MALWARE_LIST exclusion.
var tokensNotClassified = map[string]string{}

func TestEveryOutcomeTokenIsKnownToTheMatrixClassifier(t *testing.T) {
	emitted := emittedOutcomeTokens(t)
	known := tokensClassifyLogKnows(t)

	// Anti-vacuity on BOTH sides. Either extraction silently returning nothing turns the
	// comparison below into a green light, which is worse than having no guard at all.
	if len(emitted) < 4 {
		t.Fatalf("only %d outcome tokens found in production source — the AST extraction is "+
			"broken, so this test proves nothing", len(emitted))
	}
	if len(known) < 4 {
		t.Fatalf("only %d tokens found in classifyLog — the function slice is broken, so every "+
			"token below would read as unhandled", len(known))
	}

	var missing []string
	for tok := range emitted {
		if known[tok] {
			continue
		}
		if _, excused := tokensNotClassified[tok]; excused {
			continue
		}
		missing = append(missing, tok)
	}
	sort.Strings(missing)

	for _, tok := range missing {
		t.Errorf("production emits %s (%s) but classifyLog does not recognise it.\n"+
			"  An unrecognised token on the metadata path falls through to the allowed=\n"+
			"  fallbacks and is labelled \"decision-denied\", so the layer that actually\n"+
			"  refused the package is erased — which is the distinction the mode matrix\n"+
			"  exists to make. Either give it a label in classifyLog, or add it to\n"+
			"  tokensNotClassified with the reason it needs none.",
			tok, emitted[tok])
	}
	t.Logf("outcome tokens: %d emitted, %d known to classifyLog, %d excused",
		len(emitted), len(known), len(tokensNotClassified))
}

// TestOutcomeTokenGuardCanFail is the negative control: a check that can only print green
// converts an unknown into confidence.
//
// It sabotages neither file. It feeds the same two extractors a token that production
// does not emit and classifyLog does not know, which is what a newly added outcome looks
// like on the day someone adds it.
func TestOutcomeTokenGuardCanFail(t *testing.T) {
	known := tokensClassifyLogKnows(t)

	novel := "[quarantine-held]"
	if known[novel] {
		t.Fatalf("%s is already handled by classifyLog, so it cannot stand in for an "+
			"unhandled token and this control proves nothing", novel)
	}
	if _, excused := tokensNotClassified[novel]; excused {
		t.Fatalf("%s is excused, so the guard would skip it", novel)
	}

	// The mirror image, so the check above cannot pass merely because the extractor is
	// broken and returns nothing: a token that IS handled must be seen as handled.
	if !known["[verdict-blocked]"] {
		t.Fatalf("classifyLog's own [verdict-blocked] was not extracted — the extractor is " +
			"broken, so the unhandled-token check above passed vacuously")
	}

	// And prove the token regexp actually reads tokens out of a real emitted line, rather
	// than matching nothing and letting every comparison succeed by emptiness.
	line := `GET [known-malware] evilpkg -> allowed=false (BLOCKED: known malware)`
	if got := tokenRe.FindAllString(line, -1); len(got) != 1 || got[0] != "[known-malware]" {
		t.Fatalf("tokenRe read %v from a real log line, want exactly [known-malware]", got)
	}

	// The arrow rule, exercised in both directions against literal formats so it is known
	// to be capable of failing without editing production source.
	for _, tc := range []struct {
		name   string
		format string
		want   []string
	}{
		{"token before the arrow is correct", `%s [verdict-blocked] %s -> allowed=%v (%s)`, nil},
		{"no token at all is allowed", `GET %s -> allowed=%v (%s)`, nil},
		{"token after the arrow is the defect", `GET %s -> [verdict-blocked] allowed=%v (%s)`, []string{"[verdict-blocked]"}},
		{"token on both sides is fine", `%s [hard-deny] %s -> [hard-deny] (%s)`, nil},
	} {
		got := tokensOnlyAfterArrow(tc.format)
		if len(got) != len(tc.want) {
			t.Errorf("%s: tokensOnlyAfterArrow(%q) = %v, want %v", tc.name, tc.format, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
			}
		}
	}
}

// TestOutcomeTokensAreWrittenBeforeTheArrow pins the property that makes a token
// trustworthy in the first place.
//
// classifyLog matches against logLineHeads(s) — the text BEFORE " -> " — precisely so an
// operator-chosen rule name in the payload cannot forge a marker. A token emitted AFTER
// the arrow would be invisible to the classifier no matter how correctly classifyLog
// handled it, and the failure would look like a classifier bug rather than a call-site
// one.
// tokensOnlyAfterArrow returns the outcome tokens a format string writes AFTER the
// " -> " and nowhere before it. Split out of the AST walk purely so the rule can be
// control-tested against literal strings: the walk itself can only be made to fail by
// editing production source, and a control that edits the thing under test is a control
// nobody runs twice.
//
// A token in the head as well is fine — that is the normal case. A format string with no
// token at all is also fine: plenty of lines predate the tokens, and outcomeToken supplies
// one through a %s at runtime.
func tokensOnlyAfterArrow(format string) []string {
	head, tail, found := strings.Cut(format, " -> ")
	if !found {
		return nil
	}
	var out []string
	for _, tok := range tokenRe.FindAllString(tail, -1) {
		if !strings.Contains(head, tok) {
			out = append(out, tok)
		}
	}
	return out
}

func TestOutcomeTokensAreWrittenBeforeTheArrow(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read repo root: %v", err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil || !strings.Contains(s, " -> ") {
				return true
			}
			for _, tok := range tokensOnlyAfterArrow(s) {
				t.Errorf("%s:%d writes %s AFTER the \" -> \", where classifyLog cannot see it "+
					"(it matches on logLineHeads). Move it before the arrow.\n  format: %s",
					name, fset.Position(lit.Pos()).Line, tok, s)
			}
			checked++
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no format string containing \" -> \" was found — the extraction is broken, so " +
			"this test asserts nothing")
	}
	t.Logf("arrow-bearing format strings checked: %d", checked)
}
