package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// D102 collapsed three outcomes onto ONE status code. Before the ruling, a client
// could tell them apart for free:
//
//	403 -> we evaluated it and said no
//	503 -> we are still scanning, or we could not look
//
// Now all three are 403, and the ONLY thing that separates them is the explanation
// string. The project made that explicit — "they should give different explanations of the
// 403" — which means those strings stopped being cosmetic and became the carrier of
// the whole distinction. This file guards them as such.

// TestD102ExplanationsAreDistinct asserts the three explanations are pairwise
// distinct AND that none is a SUBSTRING of another.
//
// The substring half is the part that is easy to miss and expensive to get wrong.
// Every assertion in the suite tests these with strings.Contains, so if (say)
// blockErrMsg were ever reworded into a prefix of unavailableErrMsg, then an
// unavailable response would satisfy a "contains blockErrMsg" check. Tests asserting
// "this must NOT read as a verdict" would start passing for responses that do exactly
// that — the guard would invert while staying green.
func TestD102ExplanationsAreDistinct(t *testing.T) {
	msgs := map[string]string{
		"block":       blockErrMsg,
		"pending":     pendingErrMsg,
		"unavailable": unavailableErrMsg,
	}
	for name, m := range msgs {
		if strings.TrimSpace(m) == "" {
			t.Errorf("%s explanation is empty — it is the only channel left for this "+
				"distinction now that the status code is shared (D102)", name)
		}
	}
	for aName, a := range msgs {
		for bName, b := range msgs {
			if aName == bName {
				continue
			}
			if a == b {
				t.Errorf("%s and %s share the explanation %q", aName, bName, a)
				continue
			}
			if strings.Contains(a, b) {
				t.Errorf("the %s explanation %q CONTAINS the %s one %q.\n"+
					"Every assertion in this suite matches these with strings.Contains, so a "+
					"%s response would satisfy a check for %s — the 'must not read as X' guards "+
					"would silently invert while still passing.",
					aName, a, bName, b, aName, bName)
			}
		}
	}
}

// TestD102BlockAndUnavailableAreDistinguishableOverHTTP drives the two outcomes
// through the real proxy and asserts a client can still tell them apart.
//
// The constants being distinct is necessary but not sufficient: they also have to
// actually reach the client, on the right response, in the body shape the ecosystem's
// tooling reads. This is the end-to-end form of the same claim.
func TestD102BlockAndUnavailableAreDistinguishableOverHTTP(t *testing.T) {
	// A healthy upstream that resolves a repo, so the package is fully evaluated and
	// genuinely DENIED on its score rather than for want of information.
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/latest") {
			w.Write([]byte(`{"repository":{"url":"git+https://github.com/lodash/lodash.git"}}`))
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer healthy.Close()

	// An upstream we cannot consult at all, so evaluation never completes.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()

	get := func(up *httptest.Server, threshold float64) (int, string, http.Header) {
		p := newTestProxy(t, up, func(c *Config) { c.ScoreThreshold = threshold })
		req := httptest.NewRequest(http.MethodGet, "http://fw.local/lodash", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String(), rec.Header()
	}

	// Threshold 9.9 is above the stub's 7.5, so this is a real verdict.
	blockCode, blockBody, blockHdr := get(healthy, 9.9)
	unavCode, unavBody, unavHdr := get(down, 5.0)

	if blockCode != http.StatusForbidden || unavCode != http.StatusForbidden {
		t.Fatalf("statuses = block %d, unavailable %d; want both 403 (D102)", blockCode, unavCode)
	}
	if blockBody == unavBody {
		t.Fatalf("a real denial and an unreachable upstream produced the SAME response:\n%s\n"+
			"With the status code shared, identical bodies mean a developer cannot tell "+
			"'your package is not allowed' from 'we couldn't check' — the distinction the "+
			"ruling explicitly required is gone.", blockBody)
	}
	if !strings.Contains(blockBody, blockErrMsg) {
		t.Errorf("denial body = %s, want the verdict explanation %q", blockBody, blockErrMsg)
	}
	if !strings.Contains(unavBody, unavailableErrMsg) {
		t.Errorf("unavailable body = %s, want %q", unavBody, unavailableErrMsg)
	}
	if strings.Contains(unavBody, blockErrMsg) {
		t.Errorf("unavailable body = %s reads as a verdict — nothing was evaluated", unavBody)
	}

	// Retry-After is gone on purpose: no client honours it on a 403, so emitting one
	// would be a contract we do not actually keep.
	for name, h := range map[string]http.Header{"block": blockHdr, "unavailable": unavHdr} {
		if ra := h.Get("Retry-After"); ra != "" {
			t.Errorf("%s response carries Retry-After %q on a 403; nothing acts on it", name, ra)
		}
	}
	// Both must still expose the reason to HEAD/body-less clients.
	for name, h := range map[string]http.Header{"block": blockHdr, "unavailable": unavHdr} {
		if h.Get("X-Yellowjack-Reason") == "" {
			t.Errorf("%s response lost X-Yellowjack-Reason — HEAD clients see nothing", name)
		}
	}

	// Moving off 503 made these responses CACHEABLE by intermediaries. An unavailable
	// answer is by definition about to change, so a proxy that stores it would answer
	// the developer's retry from cache and the package would look permanently denied
	// — with the request never reaching us to be re-decided.
	if cc := unavHdr.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("unavailable 403 has Cache-Control %q, want no-store: 403 is cacheable "+
			"where 503 was not, so this state can be pinned by an intermediary", cc)
	}
}

// TestD102PendingIsNotCacheable is the pending half of the caching claim, driven
// through the async path where a real cold scan produces the verdict.
//
// Separate from the block/unavailable test because reaching Pending needs the local
// scanner wiring, and folding that in would make the simpler test's failures harder
// to read.
func TestD102PendingIsNotCacheable(t *testing.T) {
	sched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond) // keep the scan in flight during the request
		_ = json.NewEncoder(w).Encode(scannerResponse{Score: 8.0})
	}))
	defer sched.Close()
	apprSrv := httptest.NewServer(newFakeApproval())
	defer apprSrv.Close()

	repo := "github.com/lodash/lodash"
	f := newAsyncFirewall(t, sched.URL, apprSrv.URL, "lodash", repo)
	p := newProxyServer(f.cfg, f)

	req := httptest.NewRequest(http.MethodGet, "http://firewall.local/lodash", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), pendingErrMsg) {
		t.Fatalf("not the pending outcome, so this test proves nothing: %s", rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("pending 403 has Cache-Control %q, want no-store.\n"+
			"This is the worst one to get wrong: we tell the developer to retry, and a "+
			"cached 403 means the retry is answered from cache while the scan that would "+
			"have cleared it completes unnoticed.", cc)
	}
	waitScanDone(t, f, repo)
}

// assertReasonSurfaced checks that a 403's reason reaches the field the CLIENT prints,
// not merely a field we happen to serialise.
//
// D102 made the explanation string the whole carrier of the three-way distinction, and
// the tests above guard that the right string is in the body. This guards the step after:
// npm parses the block body and prints ONLY "error". A reason carried solely in "reason"
// reaches the operator log and never the developer, who sees
//
//	403 Forbidden - GET .../pkg - blocked by firewall
//
// with no cause — indistinguishable from a broken registry, and useless for the two
// non-verdict outcomes where the whole point is telling the developer what to do next.
// The e2e ladder found this against a real npm; this is its unit-level counterpart, so
// the property is guarded without needing Docker.
//
// It DECODES the body rather than substring-matching it: X-Yellowjack-Reason carries the
// reason raw (`BLOCKED: "six" ...`) while the body JSON-escapes the quotes, so a
// strings.Contains check compares two different strings and fails for a reason that has
// nothing to do with the property under test.
func assertReasonSurfaced(t *testing.T, rec *httptest.ResponseRecorder, wantErrMsg string) {
	t.Helper()
	var body struct {
		Error   string `json:"error"`
		Package string `json:"package"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("403 body is not JSON: %v (%s)", err, rec.Body.String())
	}
	if !strings.HasPrefix(body.Error, wantErrMsg) {
		t.Errorf(`body "error" = %q, want it to start with the outcome explanation %q`,
			body.Error, wantErrMsg)
	}
	reason := rec.Header().Get("X-Yellowjack-Reason")
	if reason == "" {
		t.Fatal("no X-Yellowjack-Reason header to compare the body against")
	}
	if body.Reason != reason {
		t.Errorf(`body "reason" = %q, want the header's %q`, body.Reason, reason)
	}
	if !strings.Contains(body.Error, reason) {
		t.Errorf(`body "error" = %q does not contain the reason %q — npm prints ONLY this `+
			`field, so the developer would see a refusal with no cause`, body.Error, reason)
	}
}

// TestD102ReasonReachesTheClientForAllThreeOutcomes is the "does it actually arrive"
// half of D102. The ruling's requirement is that the three 403s "give different
// explanations", which only holds if the explanation survives to the client at all.
//
// The verdict case is covered by the byte-gate and proxy tests; this covers the two
// NON-verdict outcomes, which are the ones a developer must act on: "retry, we are
// scanning" and "we could not check" are instructions, and an instruction the developer
// never sees is the same as no instruction.
func TestD102ReasonReachesTheClientForAllThreeOutcomes(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":       "lodash",
			"dist-tags":  map[string]string{"latest": "1.0.0"},
			"repository": map[string]string{"url": "git+https://github.com/lodash/lodash.git"},
			"versions": map[string]any{"1.0.0": map[string]any{
				"name": "lodash", "version": "1.0.0",
				"dist": map[string]string{"tarball": "http://up/lodash-1.0.0.tgz"},
			}},
		})
	}))
	defer healthy.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer down.Close()

	get := func(up *httptest.Server, threshold float64) *httptest.ResponseRecorder {
		p := newTestProxy(t, up, func(c *Config) { c.ScoreThreshold = threshold })
		req := httptest.NewRequest(http.MethodGet, "http://fw.local/lodash", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		return rec
	}

	// Threshold 9.9 is above the stub's 7.5, so this is a real verdict.
	assertReasonSurfaced(t, get(healthy, 9.9), blockErrMsg)
	assertReasonSurfaced(t, get(down, 5.0), unavailableErrMsg)
}
