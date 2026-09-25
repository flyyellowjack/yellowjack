package main

import (
	"net/http"
	"testing"
)

// THE MUTATING SURFACE, ENUMERATED AND PINNED (#13, D77).
//
// The scheduler's result sink is authenticated — a per-scan capability token (!52,
// D44), with four tests in scheduler/capability_test.go proving a forged or absent
// token is refused. This file is the same question asked of the OTHER control plane,
// and the answer is different: the approval service takes no credential at all.
//
// ── WHY A TEST THAT ASSERTS A WEAKNESS ──────────────────────────────────────
//
// Adding authentication here is not ours to decide, and as of D77 (2026-07-27) it is
// no longer anyone's to decide: the project ruled inter-service auth OUT of the application
// and onto the deployment's service mesh or network policy. Issue #13 closed with its
// forgery half shipped (the capability token above) and its mechanism half DECLINED.
// So this file does not add auth and does not argue for a mechanism — and now it also
// does not wait for one.
//
// This header used to say the decision was DEFERRED pending a review of the code
// and the Kubernetes move. That was true when written and stale from the day D77
// landed; it is corrected here rather than left, because a test that explains itself
// with a superseded reason teaches the next reader the wrong thing about the product.
//
// What the file does is stop the gap being invisible — which matters MORE under a
// delegated boundary, not less, since nothing in this process will ever enforce it.
// The failure mode is that everyone assumes the decision went the other way: a reader
// sees `PUT /v1/decisions`,
// assumes the service behind it is protected because the scheduler's sink is, and
// builds on that assumption. The table below is the ground truth, in code, next to
// the handlers — and it fails the moment reality moves in EITHER direction:
//
//   - auth is added and the table is not updated  -> the test fails, and whoever
//     added it is forced to record which endpoints it actually covers
//   - a NEW mutating endpoint is added            -> it is absent from the table,
//     and the completeness check below fails
//
// ── THE SHAPE THIS GUARDS AGAINST IS ANOTHER PRODUCT'S SHIPPED DEFAULT ─────────
//
// Varnish Artifact Firewall documents it plainly: "There is no authentication. The
// listen address is the access control, and the default binds loopback." Their API
// can POST /api/mode {"mode":"report"} and switch the whole firewall to report-only.
//
// We are in the same position on this service with ONE fewer mitigation: our default
// listen address is `:8090`, every interface — while the read-only CONSOLE
// deliberately defaults to `127.0.0.1:8085` precisely so an unauthenticated operator
// surface is not published by accident. The service that merely DISPLAYS the queue is
// bound more carefully than the one that can APPROVE things in it. That asymmetry is
// recorded in docs/CONFIGURATION.md; it is not silently fixed here, because a default
// bind address is a deployment posture, which is exactly the half D77 delegates.
//
// One knob makes that delegation escapable and is worth knowing about while reading
// this file: docker-compose.yml publishes both ports through YJ_CONTROL_PLANE_BIND,
// default 127.0.0.1. Set it to 0.0.0.0 — as two e2e rigs deliberately do, inside a
// throwaway network — and this unauthenticated surface is on every interface.

// mutatingRoute is one endpoint that CHANGES state, and what it currently demands.
type mutatingRoute struct {
	method string
	target string
	body   string
	// authenticated records whether an unauthenticated caller is refused. Every entry
	// is false today. That is the finding, not an oversight in this table.
	authenticated bool
	// effect is what an unauthenticated caller achieves, in plain words — so the row
	// carries its own consequence rather than making a reader infer it.
	effect string
	// setup seeds whatever the route needs to exist before it will act.
	//
	// DELETE /v1/scores answers 404 for a repo it has never cached — a HANDLER 404,
	// indistinguishable from a routing 404 by status alone. The first run of this file
	// hit exactly that and the anti-vacuity check below reported the route as missing.
	// Seeding removes the ambiguity at the source rather than teaching the check to
	// tolerate a 404, which would have blinded it to a genuinely absent route.
	setup func(*server)
}

var mutatingRoutes = []mutatingRoute{
	{http.MethodPut, "/v1/decisions", `{"package":"evil","ecosystem":"npm","verdict":"approved"}`, false,
		"APPROVE A QUARANTINED PACKAGE — the human review step, performed by anyone who can reach the port", nil},
	{http.MethodPut, "/v1/scores", `{"repo":"github.com/evil/pkg","score":10}`, false,
		"write a 10.0 into the L2 score cache for any repo, which the firewall then serves as a verdict", nil},
	{http.MethodDelete, "/v1/scores?repo=github.com/x/y", "", false,
		"evict a cached score, forcing a re-scan (compute) or an unscorable verdict",
		func(srv *server) { srv.store.PutScore(ScoreRecord{Repo: "github.com/x/y", Score: ptrTo(7.5)}) }},
	{http.MethodPost, "/v1/events", `{"package":"x","ecosystem":"npm","action":"allow"}`, false,
		"append a fabricated entry to the append-only audit log the #28 compliance export reads", nil},
}

// TestTheMutatingSurfaceIsWhatWeThinkItIs walks the table against the real handler.
func TestTheMutatingSurfaceIsWhatWeThinkItIs(t *testing.T) {
	for _, rt := range mutatingRoutes {
		t.Run(rt.method+" "+rt.target, func(t *testing.T) {
			srv := &server{store: newMemStore()}
			if rt.setup != nil {
				rt.setup(srv)
			}
			rec := do(t, srv, rt.method, rt.target, rt.body)

			// ANTI-VACUITY, and it is the assertion this file would be worthless
			// without. "Unauthenticated" is only meaningful if the request REACHED a
			// handler: a typo in the path gives 404 and a wrong verb gives 405, and
			// either would let this file report an unprotected endpoint as fine.
			if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
				t.Fatalf("%s %s returned %d — the route does not exist as written, so this "+
					"row is testing nothing. Fix the table, not the assertion.",
					rt.method, rt.target, rec.Code)
			}

			refused := rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden
			if refused != rt.authenticated {
				if refused {
					t.Errorf("%s %s now REFUSES an unauthenticated caller (%d), but the table "+
						"says it does not.\nAuthentication has been added — update this table, and "+
						"update docs/CONFIGURATION.md and issue #13, which both still describe this "+
						"surface as open.", rt.method, rt.target, rec.Code)
				} else {
					t.Errorf("%s %s accepted an unauthenticated caller (%d) but the table claims "+
						"it is protected.\nConsequence if this is real: %s",
						rt.method, rt.target, rec.Code, rt.effect)
				}
			}
		})
	}
}

// TestTheTableCoversEveryMutatingRoute is the completeness half.
//
// A table of known-unprotected endpoints is only useful if it is exhaustive. Without
// this, a new mutating handler is unprotected AND unlisted, which is strictly worse
// than the state this file exists to document: the gap would look smaller than it is.
func TestTheTableCoversEveryMutatingRoute(t *testing.T) {
	// Every path the router serves, paired with the verbs it accepts. Kept beside the
	// switch in main.go; a new route that changes state belongs in both.
	type probe struct{ method, target, body string }
	probes := []probe{
		{http.MethodPut, "/v1/decisions", `{"package":"p","ecosystem":"npm","verdict":"approved"}`},
		{http.MethodPut, "/v1/scores", `{"repo":"r","score":1}`},
		{http.MethodDelete, "/v1/scores?repo=seeded", ""},
		{http.MethodPost, "/v1/events", `{"package":"p","ecosystem":"npm","action":"allow"}`},
	}

	listed := map[string]bool{}
	for _, rt := range mutatingRoutes {
		listed[rt.method+" "+pathOnly(rt.target)] = true
	}

	found := 0
	for _, p := range probes {
		srv := &server{store: newMemStore()}
		srv.store.PutScore(ScoreRecord{Repo: "seeded", Score: ptrTo(1.0)}) // see mutatingRoute.setup
		rec := do(t, srv, p.method, p.target, p.body)
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed {
			continue // not a live mutating route
		}
		found++
		if !listed[p.method+" "+pathOnly(p.target)] {
			t.Errorf("%s %s changes state and is NOT in mutatingRoutes. An unlisted "+
				"unprotected endpoint makes the recorded gap look smaller than it is.",
				p.method, pathOnly(p.target))
		}
	}
	if found != len(mutatingRoutes) {
		t.Errorf("probed %d live mutating routes but the table lists %d — the two have "+
			"drifted apart", found, len(mutatingRoutes))
	}
}

func pathOnly(target string) string {
	for i := 0; i < len(target); i++ {
		if target[i] == '?' {
			return target[:i]
		}
	}
	return target
}

// TestReadsAreNotMistakenForWrites — the negative control for the whole file.
//
// Every assertion above is satisfied by a table that simply says "nothing is
// protected", which is also what you would get from a check that cannot tell a
// refusal from an acceptance. A GET must come back 200: if reads were failing too,
// the "accepted an unauthenticated caller" result above would be meaningless because
// nothing would be succeeding.
func TestReadsAreNotMistakenForWrites(t *testing.T) {
	srv := &server{store: newMemStore()}
	if rec := do(t, srv, http.MethodGet, "/v1/decisions", ""); rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/decisions = %d, want 200 — if plain reads do not work, the "+
			"acceptance results above prove nothing about authentication", rec.Code)
	}
	// And the router really does refuse something, so a 401/403 is a value this suite
	// could actually observe rather than one it never produces.
	if rec := do(t, srv, http.MethodPatch, "/v1/decisions", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PATCH /v1/decisions = %d, want 405 — the router accepts anything, so "+
			"'the route exists' cannot be distinguished from 'the route is a catch-all'", rec.Code)
	}
}

func ptrTo(f float64) *float64 { return &f }
