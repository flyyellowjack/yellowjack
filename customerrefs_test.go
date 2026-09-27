package main

// No internal decision-log or tracker references in text a customer can read.
//
// The codebase cites its decision log ("D312") and tracker ("#157") in COMMENTS, which is
// where that provenance belongs. In a STRING it reaches a person who cannot look it up: a
// refusal reason in npm's error output, a console banner, an operator log line. A demo
// rehearsal for a DevOps team and their CISO (2026-09-25) found seven of them on the
// console and in refusal reasons, e.g. "outranks the advisory for that release only
// (D312)". This test reads every Go string literal (comments excluded, by parsing) and
// every console template (template comments excluded), so it fails on exactly the text a
// user or operator can see.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// internalRef matches a decision-log id (D19, D312) or a tracker reference written as
// "(#157)" / "issue #157". A bare "#1" inside a CSS colour or a format verb does not match.
var internalRef = regexp.MustCompile(`\bD[0-9]{2,3}\b|\(#[0-9]{2,4}\)|\bissue #[0-9]{2,4}\b`)

var templateComment = regexp.MustCompile(`(?s)\{\{-?\s*/\*.*?\*/\s*-?\}\}`)

func TestInternalRefDetector(t *testing.T) {
	for _, s := range []string{"outranks the advisory (D312).", "per D19)", "shipped in (#157)", "see issue #104 for"} {
		if !internalRef.MatchString(s) {
			t.Errorf("detector missed an internal reference in %q", s)
		}
	}
	// Negative controls: ordinary text a product legitimately prints.
	for _, s := range []string{"sha256:abc", "D-Bus", "#1E3D4C", "HTTP 403", "Ed25519", "DEMO-0003", "MAL-2024-1234", "%d rows"} {
		if internalRef.MatchString(s) {
			t.Errorf("detector flagged ordinary text %q", s)
		}
	}
	if templateComment.ReplaceAllString("a{{/* the registry (D158) */}}b", "") != "ab" {
		t.Error("template comments must be stripped before the scan")
	}
}

func TestNoInternalRefsInCustomerText(t *testing.T) {
	var offenders []string
	skipDir := map[string]bool{".git": true, ".gocache": true, "vendor": true, "node_modules": true,
		"scripts": true, "e2e": true, "testdata": true, ".demo": true}
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go"):
			f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return nil // a file that does not parse is the compiler's problem, not this test's
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if m := internalRef.FindString(lit.Value); m != "" {
						offenders = append(offenders, fset.Position(lit.Pos()).String()+"  "+m)
					}
				}
				return true
			})
		case strings.HasSuffix(path, ".html") && strings.Contains(filepath.ToSlash(path), "/templates/"):
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			for i, line := range strings.Split(templateComment.ReplaceAllString(string(b), ""), "\n") {
				if m := internalRef.FindString(line); m != "" {
					offenders = append(offenders, path+":"+itoa(i+1)+"  "+m)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range offenders {
		t.Errorf("internal reference in customer-visible text (move it to a comment): %s", o)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for ; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	return s
}
