package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Issue #118: a pooled connection is only reused if the body was read to EOF.
//
// !61 and !64 sized the pools; nothing made the firewall READ the answers it did not
// want. A 404, a 429, a 503, and the OCI auth probe's 200 were all closed unread, so
// Go discarded the connection each time and the next probe dialled and handshook
// again. These tests count dials through the zero-egress observer -- the same
// instrument that found #96 -- across repeated lookups against a registry that keeps
// answering the same non-200, and require ONE connection for all of them.

// drainLookups is how many sequential lookups each case makes. Before the fix each one
// dialled (twice, for OCI); after it the first dials and the rest reuse.
const drainLookups = 6

// countingClient is a pooled client whose every dial is counted. The pool is closed
// when the test ends so nothing lingers into the next one (#96).
func countingClient(t *testing.T) (*http.Client, *atomic.Int64) {
	t.Helper()
	tr := pooledTransport(0, nil)
	var dials atomic.Int64
	restore := setEgressObserver(func(_, _ string) { dials.Add(1) })
	t.Cleanup(func() {
		restore()
		tr.CloseIdleConnections()
	})
	return &http.Client{Timeout: 10 * time.Second, Transport: tr}, &dials
}

func TestNon200AnswersKeepTheConnection(t *testing.T) {
	pkgs := map[string]string{"npm": "somepkg", "pypi": "somepkg", "maven": "com.yj:somepkg"}
	for _, eco := range []string{"npm", "pypi", "maven"} {
		for _, status := range []int{404, 429, 500, 503} {
			t.Run(fmt.Sprintf("%s/%d", eco, status), func(t *testing.T) {
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "an error page of the usual size", status)
				}))
				defer up.Close()
				e, err := newEcosystem(eco, up.URL)
				if err != nil {
					t.Fatal(err)
				}
				c, dials := countingClient(t)
				for i := 0; i < drainLookups; i++ {
					e.LookupRepo(c, pkgs[eco]) // the error is the point; only the dial count is measured
				}
				if n := dials.Load(); n != 1 {
					t.Errorf("%d lookups against a %d-answering %s registry dialled %d times, want 1: "+
						"the answer's body is being closed unread, so the pooled connection is discarded "+
						"after every one and the next probe pays a fresh handshake (#118)", drainLookups, status, eco, n)
				}
			})
		}
	}

	// OCI is the case that leaked on the 200 path too: the unauthenticated probe closed
	// its body on every answer. Against a registry that needs no auth the probe IS a
	// full manifest fetch, so before the fix every lookup cost two dials.
	t.Run("oci/probe-200", func(t *testing.T) {
		up := newOciSpyUpstream()
		defer up.Close()
		e, err := newEcosystem("oci", up.URL)
		if err != nil {
			t.Fatal(err)
		}
		c, dials := countingClient(t)
		for i := 0; i < drainLookups; i++ {
			if _, err := e.LookupRepo(c, spyImage+":latest"); err != nil {
				t.Fatalf("lookup %d: %v", i, err)
			}
		}
		if n := dials.Load(); n != 1 {
			t.Errorf("%d OCI lookups dialled %d times, want 1: the auth probe is discarding its connection (#118)", drainLookups, n)
		}
		if !up.contacted("/manifests/") || !up.contacted("/blobs/") {
			t.Fatalf("the fixture was not walked (saw %v); a lookup that made no requests would pass vacuously", up.paths())
		}
	})
}

// TestDrainBoundDropsOversizedBodies is the negative control, and it pins the bound.
// A body larger than drainedBodyMax is not worth a connection, so it must be dropped
// -- which means the same counter that reads 1 above must read one per lookup here.
// If it did not, either the bound is not enforced (a hostile upstream could hold a
// probe on a streaming error page) or the observer is not seeing dials at all, and
// every green above would be meaningless.
func TestDrainBoundDropsOversizedBodies(t *testing.T) {
	big := strings.Repeat("x", drainedBodyMax+1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, big)
	}))
	defer up.Close()
	e, err := newEcosystem("npm", up.URL)
	if err != nil {
		t.Fatal(err)
	}
	c, dials := countingClient(t)
	for i := 0; i < drainLookups; i++ {
		e.LookupRepo(c, "somepkg")
	}
	if n := dials.Load(); n != drainLookups {
		t.Fatalf("NEGATIVE CONTROL FAILED: %d lookups with a %d-byte error body dialled %d times, want %d -- "+
			"either the drain is unbounded (it read the whole body) or the counter does not see dials, "+
			"and TestNon200AnswersKeepTheConnection proves nothing", drainLookups, len(big), n, drainLookups)
	}
}
