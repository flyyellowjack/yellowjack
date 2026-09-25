// credupstream is a recording npm-shaped upstream registry for the credential-rotation
// e2e leg (issue #53, D177, !148).
//
// It serves just enough metadata for the firewall to resolve a package's source repo,
// and it RECORDS the Authorization header each metadata probe carried. That recording is
// the whole point: the claim under test is "a rotated credential reaches upstream without
// a restart", and the only way to see which credential actually went out is to be the
// thing that received it.
//
// Deliberately NOT an auth ENFORCER. An upstream that 401s on the wrong token would make
// the leg assert on the firewall's error handling instead of on the credential, and — the
// sharper reason — a rejected probe cannot tell "sent the old token" from "sent no token
// at all". Those are different failures: the first is stale rotation, the second is the
// silent degrade-to-anonymous that !148's last-good retention exists to prevent. Recording
// keeps them distinguishable; enforcing collapses them into one 401.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

// observation is one metadata probe as this registry saw it.
type observation struct {
	Path string `json:"path"`
	// Auth is the Authorization header verbatim, or "" when the probe carried none.
	// Empty is a REAL observation here, not missing data — it is exactly the
	// degrade-to-anonymous case, so it is recorded rather than skipped.
	Auth string `json:"auth"`
}

type recorder struct {
	mu   sync.Mutex
	seen []observation
}

func (r *recorder) record(path, auth string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, observation{Path: path, Auth: auth})
}

func (r *recorder) snapshot() []observation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]observation(nil), r.seen...)
}

func main() {
	rec := &recorder{}
	addr := os.Getenv("CREDUPSTREAM_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	mux := http.NewServeMux()

	// The control endpoint. Deliberately NOT recorded: the test host polls it, without
	// a credential, and counting those would inject phantom anonymous observations into
	// the very signal the leg asserts on — a fixture that pollutes its own measurement.
	mux.HandleFunc("/_seen", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"seen": rec.snapshot()})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// npm metadata lookups are "<base>/<pkg>/latest" (ecosystem.go LookupRepo).
		// Anything else is not a probe and is not recorded.
		if !strings.HasSuffix(r.URL.Path, "/latest") {
			http.NotFound(w, r)
			return
		}
		pkg := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/latest")
		rec.record(r.URL.Path, r.Header.Get("Authorization"))

		// The minimum a packument needs for the gate to resolve a repo and reach a
		// verdict. A real repository URL, because an unresolvable one would route the
		// package down the unscorable path and change what the leg is measuring.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":        pkg,
			"version":     "1.0.0",
			"description": "credential-rotation e2e fixture",
			"repository":  map[string]string{"type": "git", "url": "git+https://github.com/stevemao/left-pad.git"},
			"dist":        map[string]string{"tarball": fmt.Sprintf("http://credupstream/%s/-/%s-1.0.0.tgz", pkg, pkg)},
		})
	})

	log.Printf("credupstream listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("credupstream: %v", err)
	}
}
