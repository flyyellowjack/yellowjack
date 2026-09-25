package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Guarding the defect class behind #134: SELECTING a value by ranging over a map.
//
// `pypiEcosystem.LookupRepo` did this:
//
//	for _, u := range m.Info.ProjectURLs {
//	    if repo := normalizeGitHub(u); repo != "" {
//	        return repo, nil
//	    }
//	}
//
// project_urls is a map, and Go randomises map iteration, so the repo the gate
// SCORED was chosen at random per process. Measured cost: 8.1% of popular PyPI
// packages declare two or more candidates, and for `attrs` the wrong one disagrees
// with deps.dev, trips the borrow-a-score tripwire and REFUSES the package — about
// half of every `pip install attrs`, with a security accusation in the log.
//
// ── WHAT THIS CHECKS, AND WHY IT IS NARROWER THAN "DO NOT RANGE A MAP" ──────────
//
// Ranging a map is fine and common. Two shapes make it a defect:
//
//	1. the loop exits early (return/break), AND
//	2. what it yields is DERIVED FROM the loop variable.
//
// Both together mean "the map's order picked the answer". Either alone is fine:
//
//	for k := range m { if k == want { return true } }      // returns a CONSTANT —
//	                                                        // any order, same answer
//	for _, v := range m { total += v.n }                    // no early exit —
//	                                                        // aggregation is order-free
//
// So the rule is: an early exit whose value mentions the range's key or value
// variable. That is exactly the old PyPI loop and exactly not the two above.
//
// ── THIS GUARD IS AST-DERIVED, NOT A HAND-WRITTEN LIST ─────────────────────────
//
// A hand-written corpus of "places to check" is bounded by whoever wrote it and
// goes stale the moment someone adds a file. This walks the tree instead. The
// map-ness test is source-derived too: a name counts as a map when this package
// declares it as one (a struct field, a var, a named type, or a function result
// spelled `map[`).
//
// ⚠️ THE LIMITATION, STATED: that table is syntactic, so a map reached through a
// type this package does not declare — an imported struct's field, say — is not
// recognised and this guard will not see it. It therefore catches REGRESSIONS of
// the shape we actually ship, and is not proof that no such loop exists anywhere.
// A guard that overstated its reach would be worse than one that names its edge.
//
// ── THE FIRST VERSION HAD A 100% FALSE-POSITIVE RATE, AND FIXING IT IS THE WORK ──
//
// Run against the tree it reported three findings and ALL THREE were wrong. Each
// bought a narrowing that is now part of the checker, and each is worth knowing
// because they are the shapes a naive version of this check always hits:
//
//  1. depsdevrepo.go — `p.Versions` is a []struct, but `approval/upstream.go`
//     declares a `Versions map[...]` field. A name-keyed table shared across the
//     whole tree conflated them. The table is now PER PACKAGE.
//  2. intercept.go — `hosts := s.hostList()` is a sorted []string, while the type
//     has a `hosts map[string]bool` field. A local SHADOWS a field of the same
//     name, so a local initialised from a non-map now wins.
//  3. console/gitstore.go — a loop over a real map that returns an ERROR on the
//     first invalid entry. It validates every entry, so any order yields an error
//     if any entry is bad; only WHICH message comes first varies, and that is not
//     a verdict. Returns whose tainted results are all errors are excluded.
//
// A checker that cried wolf three times out of three would have been ignored and
// then deleted, which is the fate of every gate that reports noise — so the
// narrowings matter more than the original idea did.
//
// PROVEN AGAINST THE REAL BUG, not just a fixture: reintroducing #134's exact loop
// in ecosystem.go turns this red, naming the file, the line and the map. On the
// clean tree it examines 35 map ranges across 80 files and reports none.

// mapOrderAllowlist holds ranges that LOOK order-dependent and are not, each with
// the reason. Empty on purpose: the tree is clean as of #134, and an entry here
// should be rare enough to argue for in review.
var mapOrderAllowlist = map[string]string{}

func TestNoVerdictIsPickedByMapOrder(t *testing.T) {
	files := productionGoFiles(t)
	if len(files) < 20 {
		t.Fatalf("walked only %d production .go files; the walk is broken and this guard "+
			"would pass vacuously", len(files))
	}

	// PER PACKAGE, not per tree. A name-keyed table shared across packages conflated
	// depsdevrepo's `Versions []struct{...}` with approval's `Versions map[...]` and
	// reported a slice range as a map range. Measured: that collision produced 2 of
	// the first 3 findings, both false.
	byPkg := map[string][]string{}
	for _, f := range files {
		byPkg[filepath.Dir(f)] = append(byPkg[filepath.Dir(f)], f)
	}
	maps := map[string]map[string]bool{}
	total := 0
	for dir, fs := range byPkg {
		maps[dir] = mapNamesDeclaredIn(t, fs)
		total += len(maps[dir])
	}
	if total < 10 {
		t.Fatalf("recognised only %d map-typed names in the tree; the type table is broken "+
			"and nothing would ever be flagged", total)
	}

	var findings []string
	mapRangesSeen := 0
	for _, path := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			rs, ok := n.(*ast.RangeStmt)
			if !ok {
				return true
			}
			if !maps[filepath.Dir(path)][rangedName(rs.X)] {
				return true
			}
			// A LOCAL of the same name shadows the field. `hosts := s.hostList()`
			// returns a sorted []string while the type has a `hosts map[string]bool`
			// field; without this the local range was reported as a map range.
			if shadowedByNonMapLocal(f, rs) {
				return true
			}
			mapRangesSeen++
			vars := loopVars(rs)
			if len(vars) == 0 {
				return true // `for range m {}` selects nothing
			}
			if !exitsEarlyUsingLoopVar(rs.Body, vars) {
				return true
			}
			pos := fset.Position(rs.Pos())
			key := fmt.Sprintf("%s:%d", filepath.ToSlash(relPath(path)), pos.Line)
			if _, allowed := mapOrderAllowlist[key]; allowed {
				return true
			}
			findings = append(findings, fmt.Sprintf(
				"%s  ranges the map %q and exits early with a value derived from the loop variable",
				key, rangedName(rs.X)))
			return true
		})
	}

	// ANTI-VACUITY, and it is not theoretical. Every check above can pass while this
	// guard examines NOTHING: rangedName could stop resolving selectors, or the
	// shadowing test could over-fire, and the result would be a serene "no findings"
	// that is indistinguishable from a healthy tree. The tree does range maps -- so
	// if this is zero, the checker is broken, not the code.
	if mapRangesSeen < 5 {
		t.Fatalf("examined only %d map range(s) across %d files; this tree definitely "+
			"ranges more maps than that, so the checker is not looking at anything and "+
			"its clean result means nothing", mapRangesSeen, len(files))
	}
	t.Logf("examined %d map range(s) across %d production files", mapRangesSeen, len(files))

	if len(findings) > 0 {
		sort.Strings(findings)
		t.Errorf("%d place(s) let Go's RANDOMISED map order choose a value:\n  %s\n\n"+
			"Go randomises map iteration, so each of these can return a different answer on "+
			"different processes. That is how #134 blocked `pip install attrs` about half the "+
			"time and accused a top-100 package of borrowing a score.\n\n"+
			"Fix it by collecting the candidates, ordering them by something meaningful (in "+
			"#134's case the project_urls LABEL) and breaking ties with a sort — not by hoping "+
			"the map only ever holds one. If a case really is order-independent, add it to "+
			"mapOrderAllowlist with the reason.",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// TestTheMapOrderGuardCanFail is the negative control. A checker that can only
// report zero is indistinguishable from one that is switched off, and this file's
// allowlist is empty, so "no findings" is the expected result on a healthy tree —
// precisely the state in which a broken checker looks correct.
func TestTheMapOrderGuardCanFail(t *testing.T) {
	const src = `package p

type t struct{ urls map[string]string }

func good(x map[string]bool, want string) bool {
	for k := range x {
		if k == want {
			return true // a CONSTANT: order cannot change the answer
		}
	}
	return false
}

func aggregate(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v // no early exit
	}
	return n
}

func bad(s t) string {
	for _, u := range s.urls {
		if u != "" {
			return u // DERIVED from the loop variable: order picks the answer
		}
	}
	return ""
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
	maps := map[string]bool{"urls": true, "x": true, "m": true}

	// Record the FUNCTION each finding sits in, not its line. An assertion on line
	// numbers is brittle against editing the fixture and says nothing about whether
	// the checker picked the right loop -- the first version of this control failed
	// for that reason alone while the checker was behaving correctly.
	var flagged []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			rs, ok := n.(*ast.RangeStmt)
			if !ok || !maps[rangedName(rs.X)] {
				return true
			}
			vars := loopVars(rs)
			if len(vars) > 0 && exitsEarlyUsingLoopVar(rs.Body, vars) {
				flagged = append(flagged, fn.Name.Name)
			}
			return true
		})
	}

	want := []string{"bad"}
	if len(flagged) != len(want) || flagged[0] != want[0] {
		t.Fatalf("flagged %v, want exactly %v -- `good` returns a constant so order cannot "+
			"change its answer, and `aggregate` never exits early; a checker that fires on "+
			"either is unusable and would be deleted", flagged, want)
	}
}

// ───────────────────────────── the checker ─────────────────────────────

// rangedName reduces the ranged expression to the name the type table is keyed on:
// `m.Info.ProjectURLs` -> "ProjectURLs", `l.names` -> "names", `x` -> "x".
func rangedName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	case *ast.IndexExpr:
		// `l.pinnedVersions[key]` ranges the ELEMENT, not the map. Its element type
		// here is a slice, so deliberately not treated as a map range.
		return ""
	}
	return ""
}

func loopVars(rs *ast.RangeStmt) []string {
	var out []string
	for _, e := range []ast.Expr{rs.Key, rs.Value} {
		if id, ok := e.(*ast.Ident); ok && id.Name != "_" && id.Name != "" {
			out = append(out, id.Name)
		}
	}
	return out
}

// exitsEarlyUsingLoopVar reports whether the body can leave the loop carrying a
// value that mentions one of the loop variables — directly, or through a local
// assigned from one.
func exitsEarlyUsingLoopVar(body *ast.BlockStmt, vars []string) bool {
	tainted := map[string]bool{}
	for _, v := range vars {
		tainted[v] = true
	}
	// A local assigned from a loop variable carries the same order-dependence, which
	// is exactly the shape #134 had (`repo := normalizeGitHub(u)`).
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		if !mentionsAny(as.Rhs, tainted) {
			return true
		}
		for _, lhs := range as.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
				tainted[id.Name] = true
			}
		}
		return true
	})

	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch s := n.(type) {
		case *ast.FuncLit:
			return false // a closure's returns leave the closure, not the loop
		case *ast.ReturnStmt:
			// A loop that returns an ERROR is reporting a problem, not selecting a
			// value: it validates every entry and any order produces an error if any
			// entry is bad. Only WHICH message comes first varies, which is not a
			// verdict. console/gitstore.go's list-path validation is exactly this,
			// and was the third of the three false positives.
			if mentionsAny(s.Results, tainted) && !onlyErrorResults(s.Results, tainted) {
				found = true
			}
		case *ast.BranchStmt:
			// `break` after assigning a tainted local is the same selection, just
			// spelled with the result read after the loop.
			if s.Tok == token.BREAK {
				for name := range tainted {
					if !containsVar(vars, name) {
						found = true // a local was carried out
						break
					}
				}
			}
		}
		return true
	})
	return found
}

func containsVar(vars []string, name string) bool {
	for _, v := range vars {
		if v == name {
			return true
		}
	}
	return false
}

func mentionsAny(exprs []ast.Expr, names map[string]bool) bool {
	hit := false
	for _, e := range exprs {
		if e == nil {
			continue
		}
		ast.Inspect(e, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && names[id.Name] {
				hit = true
			}
			return !hit
		})
	}
	return hit
}

// mapNamesDeclaredIn builds the set of identifiers this tree declares with a map
// type. Source-derived rather than hand-listed, so adding a map does not require
// editing this guard.
func mapNamesDeclaredIn(t *testing.T, files []string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, path := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.Field: // struct fields and function results
				if _, ok := v.Type.(*ast.MapType); ok {
					for _, name := range v.Names {
						out[name.Name] = true
					}
				}
			case *ast.ValueSpec: // var / const declarations
				if _, ok := v.Type.(*ast.MapType); ok {
					for _, name := range v.Names {
						out[name.Name] = true
					}
				}
			case *ast.AssignStmt: // x := map[...]{...} / make(map[...])
				if v.Tok != token.DEFINE {
					return true
				}
				for i, rhs := range v.Rhs {
					if i >= len(v.Lhs) {
						break
					}
					if !isMapExpr(rhs) {
						continue
					}
					if id, ok := v.Lhs[i].(*ast.Ident); ok && id.Name != "_" {
						out[id.Name] = true
					}
				}
			}
			return true
		})
	}
	delete(out, "_")
	return out
}

func isMapExpr(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.CompositeLit:
		_, ok := v.Type.(*ast.MapType)
		return ok
	case *ast.CallExpr:
		if id, ok := v.Fun.(*ast.Ident); ok && id.Name == "make" && len(v.Args) > 0 {
			_, isMap := v.Args[0].(*ast.MapType)
			return isMap
		}
	}
	return false
}

// productionGoFiles walks the repo for non-test .go files, skipping dot-dirs, the
// CI module cache and anything with its own go.mod — the exact skips a tree-walking
// check needs to survive CI, where GOMODCACHE lives inside the checkout.
func productionGoFiles(t *testing.T) []string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	var out []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if path != root {
				if strings.HasPrefix(name, ".") || name == "builds" || name == "node_modules" ||
					name == "testdata" || name == "vendor" || name == "reference" {
					return filepath.SkipDir
				}
				if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
					return filepath.SkipDir // a nested module is not this tree
				}
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	sort.Strings(out)
	return out
}

func relPath(p string) string {
	if wd, err := os.Getwd(); err == nil {
		if r, err := filepath.Rel(wd, p); err == nil {
			return r
		}
	}
	return p
}

// shadowedByNonMapLocal reports whether the function enclosing this range declares
// the ranged name as a LOCAL whose initialiser is not a map. Go scoping means such
// a local wins over a struct field of the same name, and the type table is keyed on
// bare names, so without this a sorted []string local reads as its type's map field.
func shadowedByNonMapLocal(file *ast.File, rs *ast.RangeStmt) bool {
	name := rangedName(rs.X)
	if _, isIdent := rs.X.(*ast.Ident); !isIdent {
		return false // `s.files` names the field explicitly; a local cannot shadow it
	}
	shadowed := false
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		if rs.Pos() < fn.Pos() || rs.End() > fn.End() {
			return true // the range is not in this function
		}
		ast.Inspect(fn.Body, func(m ast.Node) bool {
			as, ok := m.(*ast.AssignStmt)
			if !ok || as.Tok != token.DEFINE || as.Pos() > rs.Pos() {
				return true
			}
			for i, lhs := range as.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || id.Name != name || i >= len(as.Rhs) {
					continue
				}
				if !isMapExpr(as.Rhs[i]) {
					shadowed = true
				}
			}
			return true
		})
		return true
	})
	return shadowed
}

// onlyErrorResults reports whether every tainted result is an error value.
func onlyErrorResults(results []ast.Expr, tainted map[string]bool) bool {
	sawTainted := false
	for _, r := range results {
		if !mentionsAny([]ast.Expr{r}, tainted) {
			continue
		}
		sawTainted = true
		if !looksLikeError(r) {
			return false
		}
	}
	return sawTainted
}

func looksLikeError(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name == "err"
	case *ast.CallExpr:
		if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
			pkg, _ := sel.X.(*ast.Ident)
			if pkg != nil && (pkg.Name == "fmt" && sel.Sel.Name == "Errorf" ||
				pkg.Name == "errors" && sel.Sel.Name == "New") {
				return true
			}
		}
	}
	return false
}
