// tamperfront is a rig-only HTTP hop that relays to an upstream and corrupts ONE class of
// response, for e2e/registry_front.sh leg 11 (#147).
//
// It is the container form of tamperingFront in integritypreserved_test.go: the same seam
// (an HTTP front that rewrites one matched response and COUNTS that it fired), placed
// where the registry-in-front topology needs it -- between the customer's registry and the
// gate -- and a container because under dind everything a rig component dials must be one.
//
// WHAT IT CORRUPTS, AND WHAT IT LEAVES ALONE. For a matched GET that answered 200 with a
// body, the LAST byte is inverted. Every header is relayed untouched, including
// Content-Length and Docker-Content-Digest, so the response still CLAIMS the original
// digest while carrying bytes that no longer hash to it. That is the precise shape of the
// failure the leg is about: a hop that damages content without touching the integrity
// material beside it. Anything unmatched is relayed byte for byte, which is what lets the
// leg show the hop itself is sound.
//
// Redirects are NOT followed: they are handed back as they came. If the upstream ever
// redirected the matched class elsewhere, the tamper would silently never fire -- and the
// /_tamper counters are how the leg would find out, rather than passing on a pull that
// failed for some other reason.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
)

func main() {
	upstream := strings.TrimRight(os.Getenv("TAMPER_UPSTREAM"), "/")
	match := os.Getenv("TAMPER_MATCH")
	if upstream == "" || match == "" {
		log.Fatal("TAMPER_UPSTREAM and TAMPER_MATCH are required")
	}
	var seen, matched, fired atomic.Int64
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	http.HandleFunc("/_tamper", func(w http.ResponseWriter, _ *http.Request) {
		// Served here and never relayed, so reading the evidence cannot manufacture it.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int64{"seen": seen.Load(), "matched": matched.Load(), "fired": fired.Load()})
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		req, err := http.NewRequestWithContext(r.Context(), r.Method, upstream+r.URL.RequestURI(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		req.Header = r.Header.Clone()
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		hit := strings.Contains(r.URL.Path, match)
		if hit {
			matched.Add(1)
		}
		if !(hit && r.Method == http.MethodGet && resp.StatusCode == http.StatusOK) {
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
			return
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil || len(body) == 0 {
			// Relay what there is. NOT counted as fired: nothing was corrupted.
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(body)
			return
		}
		body[len(body)-1] ^= 0xFF
		fired.Add(1)
		log.Printf("TAMPER fired on %s %s (%d bytes, last byte inverted, headers untouched)", r.Method, r.URL.Path, len(body))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	})
	log.Printf("tamperfront relaying to %s, corrupting GET 200 bodies whose path contains %q", upstream, match)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
