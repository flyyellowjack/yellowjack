package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// D342: a deps.dev OUTAGE must cost one probe, not one per cold package. Measured by
// counting what reaches a fake deps.dev that answers every call with `status`.
func depsDevOutageProbe(t *testing.T, status int, ttl time.Duration, pkgs int) (hits int64, errs []error) {
	t.Helper()
	var n atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(status)
	}))
	defer ts.Close()
	f := &Firewall{
		client:        &http.Client{Timeout: 5 * time.Second},
		depsDevBase:   ts.URL,
		depsDevOutage: newBackoffCache(ttl),
	}
	for i := 0; i < pkgs; i++ {
		_, _, err := f.depsDevSourceRepos("npm", fmt.Sprintf("cold-%d", i))
		errs = append(errs, err)
	}
	return n.Load(), errs
}

func TestDepsDevOutageCostsOneProbeNotOnePerPackage(t *testing.T) {
	hits, errs := depsDevOutageProbe(t, http.StatusServiceUnavailable, time.Minute, 5)
	if hits != 1 {
		t.Errorf("5 cold packages during a deps.dev outage made %d upstream calls, want 1", hits)
	}
	// Every one of them must still be the TRANSIENT answer, so both unverified policies
	// behave exactly as after a live failure: never a verdict in either direction.
	for i, err := range errs {
		if !errors.Is(err, errUpstreamUnavailable) {
			t.Errorf("package %d: got %v, want a transient errUpstreamUnavailable", i, err)
		}
	}

	// Control: with the breaker disabled (TTL 0) every package probes, which is what made
	// the outage cost one timeout per cold package before D342.
	if hits, _ := depsDevOutageProbe(t, http.StatusServiceUnavailable, 0, 5); hits != 5 {
		t.Errorf("with the breaker off, 5 packages made %d calls, want 5 (the control must see the old cost)", hits)
	}

	// A 429 is throttling, handled per package by D25: it must NOT trip the host breaker.
	if hits, _ := depsDevOutageProbe(t, http.StatusTooManyRequests, time.Minute, 5); hits != 5 {
		t.Errorf("a 429 tripped the host outage breaker (%d calls for 5 packages, want 5)", hits)
	}
}

// The breaker is a burst guard, never a verdict: once its TTL lapses the next package
// probes again and a recovered deps.dev is seen immediately.
func TestDepsDevOutageBreakerLapses(t *testing.T) {
	var down atomic.Bool
	down.Store(true)
	var n atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if down.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNotFound) // a real answer: deps.dev does not know it
	}))
	defer ts.Close()
	f := &Firewall{client: &http.Client{Timeout: 5 * time.Second}, depsDevBase: ts.URL,
		depsDevOutage: newBackoffCache(40 * time.Millisecond)}

	if _, _, err := f.depsDevSourceRepos("npm", "a"); !errors.Is(err, errUpstreamUnavailable) {
		t.Fatalf("outage not reported as transient: %v", err)
	}
	down.Store(false)
	time.Sleep(80 * time.Millisecond)
	before := n.Load()
	if _, found, err := f.depsDevSourceRepos("npm", "b"); err != nil || found {
		t.Fatalf("after the TTL lapsed, a recovered deps.dev was not asked: found=%v err=%v", found, err)
	}
	if n.Load() == before {
		t.Error("the lookup after the TTL lapsed made no upstream call")
	}
}
