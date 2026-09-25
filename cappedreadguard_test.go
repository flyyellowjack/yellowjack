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

// #139's audit box, as an assertion: no body read may be able to hide an overrun.
//
// TestEveryUpstreamBodyDecodeIsBounded (#135) proves every read HAS a cap. It says nothing
// about what happens when the cap is hit, and the two bare idioms both get that wrong:
//
//	json.NewDecoder(io.LimitReader(body, cap)).Decode(&v)   -> "unexpected EOF": an
//	    oversized document is indistinguishable from a corrupt one
//	io.ReadAll(io.LimitReader(body, cap))                   -> the first `cap` bytes and a
//	    NIL error: the document is silently TRUNCATED
//
// !304 introduced decodeCapped/readCapped and converted the registry-metadata reads. The
// audit it left open found eleven more sites on the bare idiom, one of which
// (approval/upstream.go, Maven) was the silent truncation, and three of which were the
// reason the developer lookup reported popular npm packages as "registry unreachable".
//
// A fix applied to the sites someone happened to look at is the #135 story again, so the
// rule is asserted over BOTH binaries that read third-party documents. Each exception
// carries its reason, keyed by file and FUNCTION rather than by line so that an unrelated
// edit above it does not invalidate the entry.
var bareCappedReadAllowlist = map[string]string{
	"proxy.go:relayRewritten": "reads cap+1 and compares len(body) against the cap itself, refusing " +
		"with 'upstream metadata too large to relay'; it predates readCapped and does the same job",
	"pypiwheelversion.go:relayMetadataRecordingVersion": "a deliberate PREFIX, not a capped document: it holds " +
		"the first bytes to read the declared version, then streams the held prefix plus the rest, so nothing " +
		"the client receives is truncated",
}

// bareCappedReads returns "file:func" for every json/xml decoder or io.ReadAll whose
// argument is an io.LimitReader over a `.Body`, in the given directories.
func bareCappedReads(t *testing.T, dirs ...string) (sites []string, examined int) {
	t.Helper()
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("readdir %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", path, err)
			}
			examined++
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if call, ok := n.(*ast.CallExpr); ok && isBareCappedRead(call) {
						sites = append(sites, fmt.Sprintf("%s:%s", filepath.ToSlash(filepath.Clean(path)), fn.Name.Name))
					}
					return true
				})
			}
		}
	}
	sort.Strings(sites)
	return sites, examined
}

func isBareCappedRead(call *ast.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}
	switch calleeName(call.Fun) {
	case "json.NewDecoder", "xml.NewDecoder", "io.ReadAll", "ioutil.ReadAll":
	default:
		return false
	}
	return readsAResponseBody(call.Args[0]) && isLimited(call.Args[0])
}

func TestNoCappedReadCanHideAnOverrun(t *testing.T) {
	sites, examined := bareCappedReads(t, ".", "approval")
	if examined < 20 {
		t.Fatalf("examined only %d source files across both binaries; the walk is broken and a clean "+
			"result would mean nothing", examined)
	}

	seen := map[string]bool{}
	for _, s := range sites {
		seen[s] = true
		if _, ok := bareCappedReadAllowlist[s]; !ok {
			t.Errorf("%s reads a body through a bare io.LimitReader, so an overrun is either reported as "+
				"\"unexpected EOF\" (a decoder) or silently TRUNCATED with a nil error (io.ReadAll). "+
				"Use decodeCapped / readCapped, which report errUpstreamTooLarge. If the bare form is "+
				"deliberate, add it to bareCappedReadAllowlist WITH the reason.", s)
		}
	}
	// A stale exception is a hole with a comment on it: if the site was fixed or renamed,
	// the entry would silently cover whatever is written there next.
	for s := range bareCappedReadAllowlist {
		if !seen[s] {
			t.Errorf("bareCappedReadAllowlist names %s, which no longer reads a body through a bare "+
				"io.LimitReader. Remove the entry.", s)
		}
	}
}

// TestTheBareCappedReadGuardCanFail is the negative control. The allow-list covers every
// current site, so "no findings" is the healthy state -- exactly when a checker that
// resolves nothing looks identical to one that works.
func TestTheBareCappedReadGuardCanFail(t *testing.T) {
	const src = `package p

func bareDecode(resp *http.Response) { _ = json.NewDecoder(io.LimitReader(resp.Body, 100)).Decode(nil) }
func bareReadAll(resp *http.Response) { _, _ = io.ReadAll(io.LimitReader(resp.Body, 100)) }
func helper(resp *http.Response)      { _ = decodeCapped(resp.Body, 100, nil) }
func rawHelper(resp *http.Response)   { _, _ = readCapped(resp.Body, 100) }
func notABody(r io.Reader)            { _ = json.NewDecoder(io.LimitReader(r, 100)).Decode(nil) }
`
	f, err := parser.ParseFile(token.NewFileSet(), "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
	var flagged []string
	for _, decl := range f.Decls {
		fn := decl.(*ast.FuncDecl)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && isBareCappedRead(call) {
				flagged = append(flagged, fn.Name.Name)
			}
			return true
		})
	}
	sort.Strings(flagged)
	if got, want := strings.Join(flagged, ","), "bareDecode,bareReadAll"; got != want {
		t.Fatalf("flagged %q, want exactly %q: the two helpers are the FIX and must not be flagged, "+
			"and a plain io.Reader is not a response body", got, want)
	}
}
