package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// D163 Ruling 2, as an assertion rather than a comment.
//
// `/healthz` reflects only conditions LOCAL to this process. It must never go unhealthy
// because something external — the registry, deps.dev, the approval service — is
// unreachable. The reason is a SECURITY one, not an availability one: an orchestrator
// that pulls a replica out of service on an upstream outage turns that outage into a
// route AROUND the firewall, and every replica fails at once because they all depend on
// the same upstream. A developer whose proxy vanished goes straight to the public
// registry. "The well-meaning engineer bypassing the guardrails" is squarely in scope
// per D162.
//
// The handler already complies — proxy.go answers 200 unconditionally. Nothing here is
// fixing a defect. What is missing is protection against a future well-intentioned
// change, and CLAUDE.md is explicit that "watch out, X silently passes for the wrong
// reason" must become an assertion that FAILS, never a comment hoping someone reads it.
// This is that assertion.

// healthzProbe is everything about a /healthz response an orchestrator could act on.
// Status is what a Kubernetes probe reads; the body is what a human reads in a log.
type healthzProbe struct {
	status int
	body   string
}

func (p healthzProbe) String() string { return fmt.Sprintf("%d %q", p.status, p.body) }

func probeHealthz(t *testing.T, h http.Handler) healthzProbe { return probePath(t, h, "/healthz") }

// probePath is probeHealthz for any local endpoint: /readyz shares every property
// asserted in this file (D165 reconciles readiness with D163), see readyz_test.go.
func probePath(t *testing.T, h http.Handler, path string) healthzProbe {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://fw.local"+path, nil))
	return healthzProbe{status: rec.Code, body: rec.Body.String()}
}

// upstreamStates drives one upstream server through the three conditions an operator
// actually sees, without moving its address:
//
//	healthy  -> 200 on everything
//	erroring -> 500 on everything (the registry is up but broken — the COMMON outage)
//	closed   -> connection refused (the registry is gone — the obvious one)
//
// Keeping the address fixed matters: it means the handler under test is the same object
// throughout, so a difference in its answers is a difference in BEHAVIOUR rather than in
// construction.
type upstreamStates struct {
	srv     *httptest.Server
	failing atomic.Bool
	hits    atomic.Int64
}

func newUpstreamStates(t *testing.T) *upstreamStates {
	t.Helper()
	u := &upstreamStates{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		if u.failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

// healthzVarianceAcrossUpstreamStates is THE MEASUREMENT, and it is deliberately
// factored out so the negative control below can run the identical procedure against a
// handler known to be wrong. A test whose measurement is only ever pointed at correct
// code cannot report anything but success.
//
// Returns the probes in the order taken, plus whether any of them disagreed.
func healthzVarianceAcrossUpstreamStates(t *testing.T, u *upstreamStates, h http.Handler) (probes []healthzProbe, varied bool) {
	return varianceAcrossUpstreamStates(t, u, h, "/healthz")
}

// varianceAcrossUpstreamStates is the measurement for any local endpoint (readiness
// reuses it, D165).
func varianceAcrossUpstreamStates(t *testing.T, u *upstreamStates, h http.Handler, path string) (probes []healthzProbe, varied bool) {
	t.Helper()

	probes = append(probes, probePath(t, h, path)) // upstream healthy

	u.failing.Store(true)
	probes = append(probes, probePath(t, h, path)) // upstream up but returning 500

	u.srv.Close()
	probes = append(probes, probePath(t, h, path)) // upstream gone: connection refused

	for _, p := range probes[1:] {
		if p != probes[0] {
			varied = true
		}
	}
	return probes, varied
}

// TestHealthzDoesNotVaryWithUpstreamReachability is the assertion D163 asks for.
func TestHealthzDoesNotVaryWithUpstreamReachability(t *testing.T) {
	u := newUpstreamStates(t)
	p := newTestProxy(t, u.srv, nil)

	probes, varied := healthzVarianceAcrossUpstreamStates(t, u, p)
	if varied {
		t.Errorf("/healthz VARIED with upstream reachability: healthy=%s, erroring=%s, unreachable=%s.\n"+
			"Health must reflect only conditions local to this process (D163). A replica that reports "+
			"unhealthy on an upstream outage gets pulled from service — and since every replica shares "+
			"the same upstream, they all go at once, turning the outage into a route AROUND the "+
			"firewall rather than a failure of it.",
			probes[0], probes[1], probes[2])
	}
	if probes[0].status != http.StatusOK {
		t.Errorf("/healthz = %s with a healthy upstream, want 200 — anti-vacuity: if health were "+
			"broken in all three states this test would otherwise pass by consistency alone",
			probes[0])
	}
}

// TestHealthzNeverContactsUpstream is the stronger, cheaper half of the same property.
//
// The variance test above catches a dependency check that CHANGES the answer. It does not
// catch one that phones upstream and ignores the result — which is the shape a
// well-intentioned change actually arrives in ("just log it for now"), and which becomes
// the failing version one commit later. Asserting zero contact forbids the coupling
// rather than only its current consequence.
func TestHealthzNeverContactsUpstream(t *testing.T) {
	u := newUpstreamStates(t)
	p := newTestProxy(t, u.srv, nil)

	for i := 0; i < 5; i++ {
		if got := probeHealthz(t, p); got.status != http.StatusOK {
			t.Fatalf("/healthz = %s on probe %d, want 200", got, i+1)
		}
	}
	if n := u.hits.Load(); n != 0 {
		t.Errorf("/healthz reached upstream %d time(s) across 5 probes — liveness must not depend on "+
			"a network call, even one whose result is currently ignored", n)
	}
}

// dependencyCheckingHealthz is the NEGATIVE CONTROL's stand-in: a plausible, well-meaning
// implementation of exactly the change D163 forbids. Someone adds it to make the health
// endpoint "more informative", and every replica goes unhealthy the next time the
// registry has a bad ten minutes.
func dependencyCheckingHealthz(upstreamURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(upstreamURL + "/")
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, "upstream unreachable\n")
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, "upstream unhealthy\n")
			return
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok\n")
	})
}

// TestHealthzLocalityCheckCanFail proves the measurement above is capable of failing.
//
// Required by CLAUDE.md: a check that can only print green converts an unknown into false
// confidence. The real handler answers 200 unconditionally, so TestHealthzDoesNotVary...
// would pass even if its comparison were broken — nothing about a correct handler can
// distinguish "the property holds" from "the test cannot see". So the same procedure is
// run against a handler that violates the property on purpose, and is required to catch
// it. If this test ever goes green, the assertion above has stopped meaning anything.
func TestHealthzLocalityCheckCanFail(t *testing.T) {
	u := newUpstreamStates(t)

	probes, varied := healthzVarianceAcrossUpstreamStates(t, u, dependencyCheckingHealthz(u.srv.URL))
	if !varied {
		t.Errorf("the negative control did NOT detect a handler that fails on upstream state: "+
			"healthy=%s, erroring=%s, unreachable=%s. The measurement in "+
			"healthzVarianceAcrossUpstreamStates is broken, which means "+
			"TestHealthzDoesNotVaryWithUpstreamReachability is passing for the wrong reason.",
			probes[0], probes[1], probes[2])
	}
	// Pin the shape too, so a control that "detects variance" for some unrelated reason
	// (a panic, an empty body) does not count as detecting THIS.
	if probes[0].status != http.StatusOK || probes[2].status != http.StatusServiceUnavailable {
		t.Errorf("control stand-in did not behave as designed: healthy=%s, unreachable=%s — "+
			"want 200 then 503", probes[0], probes[2])
	}
}
