package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode"
)

// D168's invariant, as an executable check (#94).
//
// ── THE INVARIANT, IN ITS CORRECTED FORM ─────────────────────────────────────
//
// > The self-hosted ENFORCEMENT PLANE must never meter. No component cap, no request
// > cap, no consumption meter, no scale cliff on the gate, the quarantine, the proxy
// > path, or locally-cached verdicts.
//
// The invariant is about hardware the operator already owns: nothing that runs on it may
// meter it. The check carries an allowlist for code that is NOT the self-hosted plane,
// and the allowlist is EMPTY for a reason worth stating: every package in this
// repository is the self-hosted plane.
//
// ── WHY A TEST AND NOT A SENTENCE ────────────────────────────────────────────
//
// #94: "the way this invariant dies is not a decision anyone announces, it is a
// plausible-looking bound added for a good local reason years from now." A doc does not
// survive that. Two checks, because the two ways it can arrive are different:
//
//   1. NAMED — someone adds `licenseKey`, `requestQuota`, `seatCount`. Caught by reading
//      the declared identifiers of every enforcement-plane package (below).
//   2. UNNAMED — someone writes `if served > 10000 { deny }` with no telltale word.
//      Caught by driving volume through the real decision path and requiring the verdict
//      not to change with it.
//
// ⚠️ WHAT NEITHER CATCHES, stated so nobody reads a green here as more than it is: a cap
// that is BOTH named innocuously AND set above the volumes driven below. That is the
// residual, and it is smaller than it sounds -- the usage meters self-hosted registries
// have adopted count requests and PEAK COMPONENTS, and a component cap in the low
// thousands is exactly the shape the component test drives past.

// entitlementStems are the word stems that have no business naming anything in a plane the
// customer runs on their own hardware.
//
// DERIVED, NOT GUESSED (the standing rule: a hand-written corpus is bounded by its author).
// A candidate list including `cap`, `limit`, `max`, `plan` and `tier` was run over the real
// packages first: `cap` matched PathEscape and capacityHTML, `limit` matched LimitReader and
// RateLimitBackoffTTL, `max` matched MaxIdleConns and interceptMaxConns, `plan` matched
// ControlPlanePath. Those are resource-safety bounds and unrelated words, and a guard that
// fights them would be turned off within a week. Every stem kept below matched NOTHING, so
// the guard starts from a clean plane and any hit is news.
//
// Matching is on WORDS, not substrings: an identifier is split on camelCase and underscores
// and each word must START WITH a stem. That is what keeps `parameters` from reading as
// `meter` while `metered` and `metering` still do.
var entitlementStems = []string{
	"license", "licence", "quota", "entitle", "seat", "billing", "billable",
	"invoice", "meter", "subscription", "subscriber", "freemium", "paywall",
	"trial", "tier",
}

// enforcementPlanePackages is every directory of this repository that ships to the
// customer's own hardware. All of them, today — see the header.
var enforcementPlanePackages = []string{".", "cache", "approval", "console", "scheduler", "scanner"}

// meteringAllowlist is the hosted intelligence service's paths, which D168 puts out of
// scope. EMPTY: nothing hosted lives in this repository. An entry here must carry the
// reason it is not the enforcement plane.
var meteringAllowlist = map[string]string{}

// splitIdentWords splits a Go identifier into lowercase words on camelCase boundaries and
// underscores, so matching can be on words rather than on substrings.
func splitIdentWords(name string) []string {
	var words []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			words = append(words, strings.ToLower(cur.String()))
			cur.Reset()
		}
	}
	for _, r := range name {
		switch {
		case r == '_':
			flush()
		case unicode.IsUpper(r):
			flush()
			cur.WriteRune(r)
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return words
}

// entitlementOffenders reports every declared identifier in files whose words name an
// entitlement concept. Factored out so the negative control can run the IDENTICAL
// procedure over source that is known to offend.
func entitlementOffenders(files map[string]*ast.File) []string {
	var out []string
	for path, file := range files {
		if reason, ok := meteringAllowlist[strings.ReplaceAll(path, "\\", "/")]; ok {
			_ = reason
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			for _, w := range splitIdentWords(id.Name) {
				for _, stem := range entitlementStems {
					if strings.HasPrefix(w, stem) {
						out = append(out, fmt.Sprintf("%s: %s (word %q matches %q)", path, id.Name, w, stem))
						return true
					}
				}
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

// parseEnforcementPlane parses every shipped package, reporting the files and how many
// identifiers were seen — the count is the anti-vacuity handle.
func parseEnforcementPlane(t *testing.T) (map[string]*ast.File, int) {
	t.Helper()
	files := map[string]*ast.File{}
	for _, dir := range enforcementPlanePackages {
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", dir, err)
		}
		for _, pkg := range pkgs {
			for path, file := range pkg.Files {
				files[path] = file
			}
		}
	}
	idents := 0
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if _, ok := n.(*ast.Ident); ok {
				idents++
			}
			return true
		})
	}
	return files, idents
}

// TestEnforcementPlaneNamesNoEntitlementConcept is the NAMED half: nothing the customer
// runs on their own hardware may so much as have a word for a licence, a quota, a seat or
// a meter.
func TestEnforcementPlaneNamesNoEntitlementConcept(t *testing.T) {
	files, idents := parseEnforcementPlane(t)

	// Anti-vacuity FIRST: a parse that silently found nothing would report a clean plane.
	if len(files) < 60 || idents < 25000 {
		t.Fatalf("the scan covered %d files and %d identifiers across %v — far less than the 71 files and 31,332 "+
			"identifiers measured when this was written, so a clean result would mean the walk broke rather than "+
			"that the plane is clean",
			len(files), idents, enforcementPlanePackages)
	}

	if hits := entitlementOffenders(files); len(hits) > 0 {
		t.Errorf("the self-hosted enforcement plane now names %d entitlement concept(s) — D168's invariant is that it "+
			"never meters hardware the customer already owns (#94). If this belongs to the HOSTED intelligence "+
			"service, which D168 puts out of scope, add its path to meteringAllowlist with the reason:\n  %s",
			len(hits), strings.Join(hits, "\n  "))
	}
	t.Logf("clean: %d files, %d identifiers, %d stems, allowlist %d entries", len(files), idents, len(entitlementStems), len(meteringAllowlist))
}

// TestEntitlementScanCanFail proves the scan above can report something, and that the
// allowlist works — a check that can only print green converts an unknown into false
// confidence, and an allowlist that never excuses anything is not an allowlist.
func TestEntitlementScanCanFail(t *testing.T) {
	const offending = `package main

type licenseKey struct{ requestQuota int }

func seatCount() int { return 0 }

var meteredRequests, subscriptionTier int
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "planted.go", offending, 0)
	if err != nil {
		t.Fatal(err)
	}
	hits := entitlementOffenders(map[string]*ast.File{"planted.go": f})
	for _, want := range []string{"licenseKey", "requestQuota", "seatCount", "meteredRequests", "subscriptionTier"} {
		found := false
		for _, h := range hits {
			if strings.Contains(h, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("the scan did not catch %q; the real scan above is passing for the wrong reason", want)
		}
	}

	// And the allowlist excuses the SAME source at a hosted path, so the D168 boundary is
	// a mechanism rather than a sentence.
	meteringAllowlist["intelligence/billing.go"] = "test: the hosted service, out of scope per D168"
	defer delete(meteringAllowlist, "intelligence/billing.go")
	if h := entitlementOffenders(map[string]*ast.File{"intelligence/billing.go": f}); len(h) != 0 {
		t.Errorf("an allowlisted hosted path was still flagged (%d hits) — the D168 out-of-scope boundary does not work", len(h))
	}

	// Words that merely CONTAIN a stem must not fire, or the guard gets switched off.
	const innocent = `package main

func parameters(capacity int) int { return capacity }

var PathControlPlane, MaxIdleConns, LimitReader, RateLimitBackoffTTL int
`
	f2, err := parser.ParseFile(fset, "innocent.go", innocent, 0)
	if err != nil {
		t.Fatal(err)
	}
	if h := entitlementOffenders(map[string]*ast.File{"innocent.go": f2}); len(h) != 0 {
		t.Errorf("the scan fired on innocent identifiers, which is how a guard gets deleted: %v", h)
	}
}

// meteringProbe drives volume through an evaluator and reports the first verdict that
// differs from the first one — the shape a cap, a meter or a scale cliff produces.
// Factored out so the negative control below runs the IDENTICAL procedure against an
// evaluator that is known to cap.
func meteringProbe(eval func(pkg string) Decision, pkgs []string) (firstAllowed bool, brokeAt int, reason string) {
	for i, p := range pkgs {
		d := eval(p)
		if i == 0 {
			firstAllowed = d.Allowed
			continue
		}
		if d.Allowed != firstAllowed {
			return firstAllowed, i, d.Reason
		}
	}
	return firstAllowed, -1, ""
}

// meteringFirewall is a gate wired to a LOCAL registry that answers for any package, so
// Evaluate runs its real path — repo resolution, scoring, policy — at in-process speed.
//
// ⚠️ THE UPSTREAM IS REAL (if local) RATHER THAN A PRE-WARMED CACHE, and that is the point
// rather than convenience. The first version seeded f.repos for all 25,000 packages and hung:
// the repo cache is bounded (FW_SCORE_CACHE_MAX_ENTRIES, 10,000 by default), so the early
// entries were evicted and every one of those packages fell through to a real lookup. That
// bound is a RESOURCE-SAFETY bound, not an entitlement cap — which is the exact distinction
// this whole file is about — and driving past it is therefore something to do deliberately,
// not to engineer around. What the component test now asserts is the stronger statement: past
// the cache's own bound the gate goes to the registry and still serves, rather than refusing.
func meteringFirewall(t *testing.T) *Firewall {
	t.Helper()
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/latest")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"name":%q,"version":"1.0.0","repository":{"type":"git","url":"https://github.com/org/%s"}}`, name, name)
	}))
	t.Cleanup(reg.Close)
	f, err := NewFirewall(Config{
		Ecosystem:        "npm",
		UpstreamRegistry: reg.URL,
		ScorecardMode:    "stub",
		ScoreThreshold:   5.0,
		UnscorablePolicy: "block",
		ScoreCacheTTL:    time.Minute,
	})
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	return f
}

// TestTheGateServesUnboundedComponents is the UNNAMED half, against the shape a usage
// meter takes: requests and PEAK COMPONENTS. A component cap
// would be a number in the thousands, so the probe drives well past that — every distinct
// package must be decided the same way as the first.
func TestTheGateServesUnboundedComponents(t *testing.T) {
	const components = 25000
	f := meteringFirewall(t)
	pkgs := make([]string, components)
	for i := range pkgs {
		pkgs[i] = fmt.Sprintf("pkg-%d", i)
	}

	start := time.Now()
	allowed, brokeAt, reason := meteringProbe(f.Evaluate, pkgs)
	if !allowed {
		t.Fatalf("CONTROL BROKEN: the very first component was not allowed, so nothing below measures a cap")
	}
	if brokeAt >= 0 {
		t.Fatalf("the gate changed its answer at component %d of %d (%q) — a self-hosted plane must not have a component "+
			"cap or a scale cliff (D168, #94)", brokeAt+1, components, reason)
	}
	t.Logf("%d distinct components, every one allowed, in %s (past the repo cache's own %d-entry bound, which degrades to a lookup rather than a refusal)",
		components, time.Since(start).Round(time.Millisecond), 10000)
}

// TestTheGateServesUnboundedRequests is the same property on the other axis D144 names:
// requests. The same component pulled many times must be decided the same way every time.
func TestTheGateServesUnboundedRequests(t *testing.T) {
	const requests = 50000
	f := meteringFirewall(t)
	pkgs := make([]string, requests)
	for i := range pkgs {
		pkgs[i] = "one-package"
	}

	start := time.Now()
	allowed, brokeAt, reason := meteringProbe(f.Evaluate, pkgs)
	if !allowed {
		t.Fatalf("CONTROL BROKEN: the first request was not allowed, so nothing below measures a cap")
	}
	if brokeAt >= 0 {
		t.Fatalf("the gate changed its answer at request %d of %d (%q) — a self-hosted plane must not have a request "+
			"cap or a consumption meter (D168, #94)", brokeAt+1, requests, reason)
	}
	t.Logf("%d requests for one component, every one allowed, in %s", requests, time.Since(start).Round(time.Millisecond))
}

// TestVolumeProbeCanFail runs the identical procedure against an evaluator that meters at
// 10,000 — the plausible shape, and the one the two tests above would otherwise be unable
// to distinguish from a gate that simply works.
func TestVolumeProbeCanFail(t *testing.T) {
	const cap = 10000
	served := 0
	metered := func(pkg string) Decision {
		served++
		if served > cap {
			return Decision{Allowed: false, Reason: "component limit reached for this deployment"}
		}
		return Decision{Allowed: true, Reason: "within plan"}
	}
	pkgs := make([]string, 25000)
	for i := range pkgs {
		pkgs[i] = fmt.Sprintf("pkg-%d", i)
	}
	allowed, brokeAt, reason := meteringProbe(metered, pkgs)
	if !allowed || brokeAt < 0 {
		t.Fatalf("the probe did NOT detect an evaluator that caps at %d (allowed=%v, brokeAt=%d) — "+
			"TestTheGateServesUnbounded* are passing for the wrong reason", cap, allowed, brokeAt)
	}
	if brokeAt+1 != cap+1 {
		t.Errorf("the probe reported the cap at %d, want %d — it detects something, but not the cap", brokeAt+1, cap+1)
	}
	t.Logf("the probe catches a cap at %d and names it: %q", brokeAt+1, reason)
}
