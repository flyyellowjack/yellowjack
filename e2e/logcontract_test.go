//go:build e2e

package e2e

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The decision log line stopped being debug output when D137 moved block-reason
// legibility OUT of the pull path: pip and mvn never surface our reason and we are not
// going to make them, so the chat (#87) and CLI (#88) channels read the LOG instead.
// That makes this line an interface, and issue #20's remaining half asks for two things
// it never had — a stable contract, and an inventory of who reads it.
//
// There were three independent readers and no list of them:
//
//	1. e2e/harness.go  decisionRe / byteGateRe  -> parseDecisions (structured)
//	2. e2e/harness.go  blockedCount/allowedCount (raw "allowed=" substring counts)
//	3. modematrix_test.go  classifyLog          (root package, substring)
//
// #76 added an outcome token to two emitters and updated reader 3 only. The matrix
// stayed green while every parse in reader 1 silently returned nothing, surfacing ten
// minutes downstream as "no verdict was rendered for express" — a message describing a
// firewall bug that was really a parser bug.
//
// harness_parse_test.go is the cheap regression test for THAT incident, and it is
// exactly as good as its corpus: three lines, written by hand, of the shapes the author
// already knew. It cannot notice a shape nobody thought to add to it. That is not
// hypothetical — measured 2026-09-12, three production emitters were counted by reader 2
// and invisible to reader 1, and the hand-written corpus was green throughout.
//
// So this guard does not hand-write anything. It reads the SOURCE, extracts every
// log.Printf whose format string carries "allowed=", renders it, and requires the
// harness parser to understand it. A new emitter is caught by construction.
//
// Same family as configreference_test.go, which derives the FW_* enum from config.go
// rather than restating it.

// productionSourceDirs are the package directories whose log output the e2e harness
// parses. Scoped to the repo root, which is the firewall binary the e2e suite runs:
// reference/firewall-mvp is a teaching copy that no test drives, and including it would
// hold a deliberately simplified illustration to the shipped parser's contract.
var productionSourceDirs = []string{".."}

// decisionEmitter is one production log.Printf that announces a verdict.
type decisionEmitter struct {
	file   string
	line   int
	format string   // the concatenated format string, Go-unquoted
	args   []string // source text of each argument, for verb-aware rendering
}

// collectDecisionEmitters parses every non-test .go file in the given dirs and returns
// each log.Printf call whose format string mentions "allowed=".
func collectDecisionEmitters(t *testing.T, dirs []string) []decisionEmitter {
	t.Helper()
	var out []decisionEmitter
	fset := token.NewFileSet()

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 || !isLogPrintf(call.Fun) {
					return true
				}
				format, ok := stringLit(call.Args[0])
				if !ok || !strings.Contains(format, "allowed=") {
					return true
				}
				var args []string
				for _, a := range call.Args[1:] {
					args = append(args, exprText(a))
				}
				out = append(out, decisionEmitter{
					file:   name,
					line:   fset.Position(call.Pos()).Line,
					format: format,
					args:   args,
				})
				return true
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].line < out[j].line
	})
	return out
}

func isLogPrintf(fun ast.Expr) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Printf" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "log"
}

// stringLit unquotes a string literal, following `"a" + "b"` concatenation — several of
// these format strings are split across lines to stay readable.
func stringLit(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		l, okl := stringLit(v.X)
		r, okr := stringLit(v.Y)
		if !okl || !okr {
			return "", false
		}
		return l + r, true
	}
	return "", false
}

// exprText renders an argument expression back to rough source text. Only enough
// fidelity to recognise which VALUE a verb will receive.
func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprText(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprText(v.Fun) + "(…)"
	case *ast.BasicLit:
		return v.Value
	case *ast.IndexExpr:
		return exprText(v.X) + "[…]"
	}
	return "?"
}

var verbRe = regexp.MustCompile(`%[-+ #0]*[0-9]*(?:\.[0-9]+)?[a-zA-Z]`)

// renderEmitter turns a format string into one concrete log line, substituting each
// verb with a value shaped like what the call site actually passes.
//
// Verb-aware substitution is the point. A naive "%s -> pkg" makes
// `GET _files %s %s -> allowed=%v (%s)` render without its `[verdict-blocked]` token,
// and the harness regexp then parses the line at a DIFFERENT offset and reports
// bytes=false — the guard would be testing a line production never emits, and would go
// green on a parser that mishandles the real one.
func renderEmitter(em decisionEmitter) string {
	i := 0
	return verbRe.ReplaceAllStringFunc(em.format, func(verb string) string {
		var arg string
		if i < len(em.args) {
			arg = em.args[i]
		}
		i++
		return renderVerb(verb, arg)
	})
}

func renderVerb(verb, arg string) string {
	switch {
	case strings.Contains(arg, "outcomeToken"):
		return "[verdict-blocked]"
	case strings.HasSuffix(arg, ".Method"):
		return "GET"
	case strings.HasSuffix(verb, "q"):
		return `"a-rule-name"`
	case strings.HasSuffix(verb, "f"):
		return "3.2"
	case strings.HasSuffix(verb, "d"):
		return "1"
	case strings.HasSuffix(verb, "v"):
		return "false"
	case strings.Contains(strings.ToLower(arg), "reason"):
		return "a human readable reason"
	case strings.Contains(strings.ToLower(arg), "rule"):
		return "a-rule-name"
	case strings.Contains(strings.ToLower(arg), "deny"):
		return "score"
	}
	return "somepkg"
}

// TestEveryDecisionEmitterIsParsedByTheHarness is the contract: if a production log line
// says allowed=, the harness parser must produce exactly one decision from it.
//
// "Exactly one" matters in both directions. Zero is the #76 failure — the line is
// counted by blockedCount() while decisionsFor() reports the package was never judged.
// Two means decisionRe and byteGateRe both claimed the line, which would double-count
// every verdict of that shape and make a coalescing or fan-out test read a doubled
// number as a real regression.
func TestEveryDecisionEmitterIsParsedByTheHarness(t *testing.T) {
	emitters := collectDecisionEmitters(t, productionSourceDirs)

	// Anti-vacuity. An extraction that silently returns nothing turns this whole guard
	// into a green light, which is worse than not having it. The floor is deliberately
	// well below the count observed (8 on 2026-09-12) so that REMOVING an emitter is not
	// a failure, while a broken parse — the realistic breakage — is.
	if len(emitters) < 4 {
		t.Fatalf("found only %d decision emitters in %v — the AST extraction is broken, so "+
			"every assertion below would pass for the wrong reason", len(emitters), productionSourceDirs)
	}
	t.Logf("decision-log emitters found: %d", len(emitters))

	for _, em := range emitters {
		line := renderEmitter(em)
		got := parseDecisions(line)
		t.Logf("%s:%d -> %s", em.file, em.line, line)

		if len(got) != 1 {
			t.Errorf("%s:%d emits a verdict the harness parser turns into %d decisions, want 1.\n"+
				"  rendered: %s\n"+
				"  This line IS counted by blockedCount()/allowedCount(), which count the raw\n"+
				"  \"allowed=\" substring, so the two readers now disagree on real logs: a test\n"+
				"  asserting on the count stays green while decisionsFor(pkg) reports the gate\n"+
				"  never judged the package. That is the #76 failure, and it is what issue #20's\n"+
				"  stable-log-contract half exists to prevent.\n"+
				"  Fix by teaching decisionRe/byteGateRe in e2e/harness.go this shape — not by\n"+
				"  relaxing this test.",
				em.file, em.line, len(got), line)
			continue
		}
		if got[0].pkg == "" {
			t.Errorf("%s:%d parsed, but with an empty package name — decisionsFor() can never "+
				"match it.\n  rendered: %s", em.file, em.line, line)
		}
	}
}

// TestDecisionEmittersOnTheBytePathAreMarkedAsBytes pins the WHERE half of the contract.
//
// pypi_test.go asks `d.bytes` to prove a pinned install failed AT THE BYTE FETCH rather
// than at the index — the D22 gap — and that assertion is only as good as the field. Two
// npm emitters live inside proxyArtifactBytes and the npm byte gate yet reported
// bytes=false until this guard went in, so the npm side of the same question could only
// be asked through blockedCount(), a substring count that also rises when the firewall
// blocks something else entirely.
func TestDecisionEmittersOnTheBytePathAreMarkedAsBytes(t *testing.T) {
	// Keyed on text the CALL SITE writes literally, never on the reason or a rule name:
	// everything after the arrow is filled in from the decision, including an operator's
	// chosen rule name, and keying a classifier on operator-supplied text is how 38 cells
	// of the committed mode matrix moved silently once already (see proxy.go's note on
	// the bracketed tokens, #68).
	bytePathMarkers := []string{"_files", "artifact ", "byte gate"}

	emitters := collectDecisionEmitters(t, productionSourceDirs)
	if len(emitters) < 4 {
		t.Fatalf("found only %d decision emitters — extraction broken", len(emitters))
	}

	checked := 0
	for _, em := range emitters {
		onBytePath := false
		for _, m := range bytePathMarkers {
			if strings.Contains(em.format, m) {
				onBytePath = true
			}
		}
		if !onBytePath {
			continue
		}
		checked++
		got := parseDecisions(renderEmitter(em))
		if len(got) != 1 {
			continue // already reported by the contract test above
		}
		if !got[0].bytes {
			t.Errorf("%s:%d is a BYTE-PATH verdict but parses as bytes=false, so it reads as a "+
				"metadata decision.\n  rendered: %s\n"+
				"  A test asking \"was this refused at the artifact fetch?\" gets the wrong answer,\n"+
				"  and the only remaining signal is blockedCount() — which rises for any package.",
				em.file, em.line, renderEmitter(em))
		}
	}
	if checked == 0 {
		t.Fatalf("no byte-path emitter matched %v — the markers are stale, so this test asserts "+
			"nothing", bytePathMarkers)
	}
	t.Logf("byte-path emitters checked: %d", checked)
}

// TestLogContractGuardCanFail is the negative control. Every guard in this repo carries
// one, because a check that can only print green converts an unknown into confidence.
//
// It does not sabotage the repo; it feeds the same parser a line in a shape nobody
// taught it, which is exactly what a new emitter looks like on the day it is added.
func TestLogContractGuardCanFail(t *testing.T) {
	// Shaped like a plausible future emitter: a mode prefix in front, as the byte-gate
	// lines already have, but a word the parsers do not know.
	novel := `2026/09/12 10:00:00 quarantine gate (enforce) somepkg -> allowed=false rule="x" (a reason)`
	if got := parseDecisions(novel); len(got) != 0 {
		t.Fatalf("the control line parsed into %d decisions, so it is NOT an unknown shape and "+
			"proves nothing about the guard's ability to fail: %s", len(got), novel)
	}

	// And prove the assertion the contract test makes would actually fire on it.
	emitters := []decisionEmitter{{
		file: "synthetic.go", line: 1,
		format: `quarantine gate (enforce) %s -> allowed=%v rule=%q (%s)`,
		args:   []string{"pkg", "decision.Allowed", "rule.Name", "decision.Reason"},
	}}
	if got := parseDecisions(renderEmitter(emitters[0])); len(got) != 0 {
		t.Fatalf("the synthetic emitter rendered to something the parser understands (%d "+
			"decisions), so the contract test could not have reddened on it", len(got))
	}

	// The mirror image: a KNOWN shape must still parse, or the control above would pass
	// simply because parseDecisions is broken for everything.
	known := `2026/09/12 10:00:00 GET [verdict-blocked] express -> allowed=false score=2.6 hasScore=true (below threshold)`
	if got := parseDecisions(known); len(got) != 1 {
		t.Fatalf("a known decision shape parsed into %d decisions, want 1 — parseDecisions is "+
			"broken, so the unknown-shape check above passed vacuously", len(got))
	}
}

// TestRenderedEmittersMatchRealLogText guards the guard's own weakest link.
//
// Everything above tests the parser against RENDERED lines, so a rendering that drifts
// from what the firewall really writes would quietly test a line that does not exist.
// These are real lines, copied from container logs on 2026-09-12, and each must parse
// the same way its rendered twin does.
func TestRenderedEmittersMatchRealLogText(t *testing.T) {
	real := []struct {
		name  string
		line  string
		bytes bool
	}{
		{"metadata verdict", `2026/09/12 10:00:00 GET [verdict-blocked] express -> allowed=false score=2.6 hasScore=true (BLOCKED: "express" scored 2.6, below required 5.0)`, false},
		{"known-malware metadata", `2026/09/12 10:00:00 GET [known-malware] evilpkg -> allowed=false (BLOCKED: known malware)`, false},
		{"pypi _files relay", `2026/09/12 10:00:00 GET _files [verdict-blocked] six -> allowed=false (BLOCKED: "six" scored 3.7, below required 9.9)`, true},
		{"npm artifact known-malware", `2026/09/12 10:00:00 artifact [known-malware] evilpkg -> allowed=false (BLOCKED: known malware)`, true},
		{"npm byte gate enforce", `2026/09/12 10:00:00 byte gate (enforce) six -> allowed=false rule="deny-list" (BLOCKED: operator deny list)`, true},
		{"npm byte gate allowed", `2026/09/12 10:00:00 byte gate (allow-but-log) [allowed] six -> allowed=true (allowed)`, true},
		{"npm byte gate served-anyway", `2026/09/12 10:00:00 byte gate (allow-but-log) [served-anyway] six -> allowed=false pending=false unavailable=false deny="" rule="catch-all" (unscorable) — SERVING BYTES ANYWAY; set FW_BYTE_GATE=enforce to block`, true},
	}
	for _, tc := range real {
		t.Run(tc.name, func(t *testing.T) {
			got := parseDecisions(tc.line)
			if len(got) != 1 {
				t.Fatalf("parsed %d decisions, want 1\n%s", len(got), tc.line)
			}
			if got[0].pkg == "" {
				t.Errorf("empty package name\n%s", tc.line)
			}
			if got[0].bytes != tc.bytes {
				t.Errorf("bytes = %v, want %v — a metadata verdict and an artifact-byte verdict "+
					"are different claims about WHERE the package was refused\n%s",
					got[0].bytes, tc.bytes, tc.line)
			}
		})
	}

	// The reason must survive intact, including the trailing prose the byte-gate lines
	// carry AFTER the parenthesised reason. A greedy capture that ran to the end of the
	// line would swallow "— SERVING BYTES ANYWAY…" into the reason and every assertion on
	// reason text would start matching things it should not.
	served := parseDecisions(real[6].line)
	if len(served) == 1 && served[0].reason != "unscorable" {
		t.Errorf("served-anyway reason = %q, want %q — the capture is picking up the trailing "+
			"advisory prose", served[0].reason, "unscorable")
	}
}
