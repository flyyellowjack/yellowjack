package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
)

// Guarding #135: every upstream body this package decodes must be bounded.
//
// The firewall reads metadata from registries and from deps.dev, and two of those
// documents are written by the attacker — a PyPI project JSON and, worse, an OCI
// config blob uploaded by whoever published the image. Four of nine such reads were
// capped and five were not, and the omissions were the ones that mattered: the OCI
// manifest was capped at 4 MB while the config blob it POINTS AT had no cap at all.
//
// The cost was measured rather than argued. Decoding a well-formed config blob with
// a large Labels map through the real ociImageConfig type grows the heap by about
// 5.6x the body:
//
//	 1.7 MB body ->   +7.2 MB heap
//	18.4 MB body -> +109.9 MB heap
//	76.1 MB body -> +429.3 MB heap
//
// against the 60.8 MiB idle footprint #21 measures for the whole firewall. The 10s
// client timeout bounds DURATION, not bytes.
//
// ── WHY A GUARD AND NOT JUST THE FIX ───────────────────────────────────────────
//
// The convention already existed — approval/upstream.go states it outright — and was
// still applied to four sites out of nine. A rule that is written down and followed
// half the time is the same as no rule; the next read added would have been the sixth
// unbounded one. So this asserts it instead.
//
// ── SCOPE, STATED ──────────────────────────────────────────────────────────────
//
// This package only — the firewall, which is what stands in the pull path reading
// attacker-controlled documents. Deliberately NOT the console/approval clients,
// which read our own control plane over a trusted hop, and deliberately NOT
// cache/main.go, which reads whole ARTIFACTS on purpose (a cap there would break
// large-artifact relay, and its in-memory buffering is a documented MVP limitation
// with its own separate ceiling in CACHE_MAX_BYTES).

// boundedReadAllowlist holds body reads that are deliberately unbounded, with the
// reason. Empty: every read in this package is capped as of #135.
var boundedReadAllowlist = map[string]string{}

func TestEveryUpstreamBodyDecodeIsBounded(t *testing.T) {
	files := firewallPackageFiles(t)
	if len(files) < 10 {
		t.Fatalf("found only %d .go files in the firewall package; the walk is broken and "+
			"this guard would pass vacuously", len(files))
	}

	var findings []string
	reads := 0
	for _, path := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			fn := calleeName(call.Fun)
			switch fn {
			case "json.NewDecoder", "xml.NewDecoder", "io.ReadAll", "ioutil.ReadAll":
			// decodeCapped and readCapped (#139) take the body AND its cap, and report the
			// overrun rather than truncating silently. They are bounded BY SIGNATURE, so
			// they count toward `reads` but can never be a finding.
			//
			// Teaching this guard about them is not optional bookkeeping. Converting six
			// sites to the safer helpers dropped the reads it examined from 14 to 8 —
			// every converted call became INVISIBLE to the check that exists to watch it,
			// and the suite stayed green. A guard that stops seeing a call the moment you
			// improve it is worse than one that never saw it, because the number that
			// would tell you goes down quietly.
			case "decodeCapped", "readCapped":
				if readsAResponseBody(call.Args[0]) {
					reads++
				}
				return true
			default:
				return true
			}
			if !readsAResponseBody(call.Args[0]) {
				return true
			}
			reads++
			if isLimited(call.Args[0]) {
				return true
			}
			line := fset.Position(call.Pos()).Line
			key := fmt.Sprintf("%s:%d", filepath.ToSlash(filepath.Base(path)), line)
			if _, allowed := boundedReadAllowlist[key]; allowed {
				return true
			}
			findings = append(findings, fmt.Sprintf("%s  %s reads a response body with no io.LimitReader", key, fn))
			return true
		})
	}

	// ANTI-VACUITY. Every assertion above can pass while this guard matches nothing —
	// if calleeName stopped resolving selectors, the result would be a serene "no
	// findings" indistinguishable from a compliant package.
	// The floor was 5, and 5 was too low to do its job: converting six sites to the bounded
	// helpers dropped this from 14 to 8 and the guard said nothing (#139). A floor that only
	// catches "the checker resolves NOTHING" misses the case that actually happens, which is
	// the checker quietly losing sight of half the package.
	//
	// So it is a COVERAGE FLOOR, one below the current count, and it is meant to be edited
	// deliberately: if you removed a read, lower it and say why in the commit. The same
	// bargain as the committed mode-matrix table — a number a human has to look at.
	const minReadsExamined = 13
	if reads < minReadsExamined {
		t.Fatalf("examined only %d body read(s) across %d files, below the floor of %d. Either a "+
			"read was removed — lower the floor deliberately — or the checker has stopped "+
			"RESOLVING a call shape it used to see, in which case those reads are now unguarded "+
			"and this guard's clean result means nothing.", reads, len(files), minReadsExamined)
	}
	t.Logf("examined %d upstream body read(s) across %d firewall files", reads, len(files))

	if len(findings) > 0 {
		sort.Strings(findings)
		t.Errorf("%d upstream body read(s) are unbounded:\n  %s\n\n"+
			"This package reads documents written by whoever published the package or "+
			"image. Decoding one grows the heap by roughly 5.6x the body, so a 76 MB "+
			"response becomes ~429 MB against a 60.8 MiB idle footprint (#135), and the "+
			"client timeout bounds DURATION not bytes.\n\n"+
			"Wrap the body: json.NewDecoder(io.LimitReader(resp.Body, someMaxBytes)). Pick "+
			"the cap from a MEASUREMENT of real documents, not intuition — a cap that "+
			"refuses a real package is a worse bug than the one it fixes. If a read is "+
			"deliberately unbounded, add it to boundedReadAllowlist with the reason.",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// TestTheBoundedReadGuardCanFail is the negative control: the allowlist is empty and
// the package is compliant, so "no findings" is the healthy state — exactly when a
// broken checker looks correct.
func TestTheBoundedReadGuardCanFail(t *testing.T) {
	const src = `package p

func bounded(resp *http.Response) {
	_ = json.NewDecoder(io.LimitReader(resp.Body, 100)).Decode(nil)
}

func unbounded(resp *http.Response) {
	_ = json.NewDecoder(resp.Body).Decode(nil)
}

func alsoUnbounded(resp *http.Response) {
	_, _ = io.ReadAll(resp.Body)
}

func notABody(r io.Reader) {
	_ = json.NewDecoder(r).Decode(nil)
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}

	var flagged []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			switch calleeName(call.Fun) {
			case "json.NewDecoder", "xml.NewDecoder", "io.ReadAll":
			default:
				return true
			}
			if readsAResponseBody(call.Args[0]) && !isLimited(call.Args[0]) {
				flagged = append(flagged, fn.Name.Name)
			}
			return true
		})
	}
	sort.Strings(flagged)
	want := []string{"alsoUnbounded", "unbounded"}
	if strings.Join(flagged, ",") != strings.Join(want, ",") {
		t.Fatalf("flagged %v, want exactly %v — `bounded` is already wrapped and `notABody` "+
			"is not a response body; a checker that fires on either is unusable", flagged, want)
	}
}

// ───────────────────────────── the checker ─────────────────────────────

// calleeName renders "pkg.Func" for a qualified call, or "" for anything else.
func calleeName(e ast.Expr) string {
	// A bare identifier is a function in THIS package — decodeCapped, readCapped (#139).
	// Returning "" for these is why converting six sites to the bounded helpers made them
	// invisible to this guard: it only ever resolved pkg.Func selectors.
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return pkg.Name + "." + sel.Sel.Name
}

// readsAResponseBody reports whether the expression reaches a `.Body` field —
// directly, or through a wrapper like io.LimitReader(resp.Body, n).
func readsAResponseBody(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Body" {
			found = true
		}
		return !found
	})
	return found
}

// isLimited reports whether the body is already wrapped in a limiting reader.
func isLimited(e ast.Expr) bool {
	limited := false
	ast.Inspect(e, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch calleeName(call.Fun) {
		case "io.LimitReader", "http.MaxBytesReader":
			limited = true
		}
		return !limited
	})
	return limited
}

// firewallPackageFiles lists this package's own non-test .go files — the top-level
// directory only, since the threat model this guard encodes is the firewall's.
func firewallPackageFiles(t *testing.T) []string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	entries, err := os.ReadDir(wd)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		out = append(out, filepath.Join(wd, e.Name()))
	}
	sort.Strings(out)
	return out
}

// ─────────── the caps have to WORK, not merely appear in the source ───────────

// countingBodyTransport counts the bytes a client actually READS from a response.
//
// "How many bytes did the peer send" and "how many did we read" are different
// numbers, and only the second is what a read cap bounds. Asserting on the first is
// what made the approval-side twin flaky (#111) — a peer can push megabytes into
// socket and transport buffers before our reader stops.
type countingBodyTransport struct {
	base http.RoundTripper
	n    *int64
}

func (t countingBodyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if err != nil || resp == nil || resp.Body == nil {
		return resp, err
	}
	resp.Body = countingReadCloser{ReadCloser: resp.Body, n: t.n}
	return resp, nil
}

type countingReadCloser struct {
	io.ReadCloser
	n *int64
}

func (c countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	atomic.AddInt64(c.n, int64(n))
	return n, err
}

// floodServer streams a well-formed-looking JSON prologue and then filler, far past
// any cap, so the read is ended by the cap rather than by the document running out.
func floodServer(t *testing.T, prologue string, offered int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(prologue))
		chunk := make([]byte, 64<<10)
		for i := range chunk {
			chunk[i] = 'A'
		}
		for written := int64(0); written < offered; written += int64(len(chunk)) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestAHostilePypiIndexCannotExhaustTheGate drives the REAL pypiEcosystem.LookupRepo.
// The syntactic guard above proves the source says io.LimitReader; this proves the
// bytes stop.
func TestAHostilePypiIndexCannotExhaustTheGate(t *testing.T) {
	const offered = int64(pypiMetaMaxBytes) * 2
	srv := floodServer(t, `{"info":{"home_page":"https://example.com","junk":"`, offered)

	var consumed int64
	client := srv.Client()
	client.Transport = countingBodyTransport{base: client.Transport, n: &consumed}

	eco := pypiEcosystem{base: srv.URL}
	_, _ = eco.LookupRepo(client, "huge") // a truncated document fails to parse; that is fine

	// The ceiling is the decode cap PLUS drainedBodyMax, and both halves are
	// deliberate. closeDrained reads up to 64 KiB of whatever is left so the
	// connection can be reused, and that limit exists for the same reason this one
	// does — transport.go calls it "small enough that a hostile upstream cannot hold a
	// probe on a streaming body". The first version of this assertion forgot it and
	// failed by exactly 65,536 bytes, which is how the drain was identified rather
	// than a broken cap.
	const ceiling = int64(pypiMetaMaxBytes) + drainedBodyMax
	got := atomic.LoadInt64(&consumed)
	if got > ceiling {
		t.Errorf("read %d bytes of the %d offered; the %d-byte cap (+%d drain) is not in "+
			"the read path", got, offered, pypiMetaMaxBytes, drainedBodyMax)
	}
	// ANTI-VACUITY: "consumed <= cap" is also satisfied by reading NOTHING, which a
	// connection that failed for an unrelated reason would do.
	if got < pypiMetaMaxBytes/2 {
		t.Errorf("read only %d bytes, far below the %d-byte cap: the read stopped for some "+
			"reason OTHER than the cap, so this proves nothing", got, pypiMetaMaxBytes)
	}
}

// TestAHostileImageConfigCannotExhaustTheGate is the same assertion for the read that
// mattered most — the config blob is uploaded by whoever published the image, and the
// manifest pointing at it was already capped while this was not.
func TestAHostileImageConfigCannotExhaustTheGate(t *testing.T) {
	const offered = int64(ociConfigMaxBytes) * 3
	srv := floodServer(t, `{"config":{"Labels":{"a":"`, offered)

	var consumed int64
	client := srv.Client()
	client.Transport = countingBodyTransport{base: client.Transport, n: &consumed}

	eco := ociEcosystem{base: srv.URL}
	_, _ = eco.ociFetchConfig(client, "library/evil", "sha256:"+strings.Repeat("a", 64), "")

	const ceiling = int64(ociConfigMaxBytes) + drainedBodyMax // see the PyPI twin above
	got := atomic.LoadInt64(&consumed)
	if got > ceiling {
		t.Errorf("read %d bytes of the %d offered; the %d-byte cap (+%d drain) is not in the "+
			"read path — a hostile image can still grow the heap by ~5.6x whatever it "+
			"sends (#135)", got, offered, ociConfigMaxBytes, drainedBodyMax)
	}
	if got < ociConfigMaxBytes/2 {
		t.Errorf("read only %d bytes, far below the %d-byte cap: the read stopped for some "+
			"reason OTHER than the cap", got, ociConfigMaxBytes)
	}
}

// TestRealDocumentsStillDecode is the other half, and the one that stops this fix
// from being worse than the bug. A cap that refuses a real package would break
// installs, so the caps were chosen from MEASUREMENTS: the largest PyPI project JSON
// among twelve popular packages is awscli at 3.60 MB, and real OCI image configs
// measure in the hundreds of bytes.
func TestRealDocumentsStillDecode(t *testing.T) {
	// A PyPI document an order of magnitude past the largest real one, still under cap.
	var b strings.Builder
	b.WriteString(`{"info":{"home_page":"https://github.com/owner/name","project_urls":{`)
	for i := 0; i < 60_000; i++ { // ~7 MB, about 2x awscli
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"Doc %d":"https://example.com/page/%d"`, i, i)
	}
	b.WriteString(`}}}`)
	if int64(b.Len()) >= pypiMetaMaxBytes {
		t.Fatalf("fixture is %d bytes, at or over the %d cap; it cannot show that a real "+
			"document survives", b.Len(), pypiMetaMaxBytes)
	}
	eco := pypiEcosystem{base: stubJSON(t, b.String())}
	repo, err := eco.LookupRepo(&http.Client{}, "big")
	if err != nil {
		t.Fatalf("a %0.1f MB project JSON -- roughly 2x the largest real one -- failed to "+
			"decode: %v", float64(b.Len())/(1<<20), err)
	}
	if repo != "github.com/owner/name" {
		t.Errorf("repo = %q, want github.com/owner/name", repo)
	}
}

func stubJSON(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
