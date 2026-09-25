package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestOCINameGrammar and TestOCIRefGrammar pin the distribution-spec grammar (#17).
//
// The valid cases matter as much as the invalid ones: a validator that rejects real
// image names would be found by an operator whose `docker pull` broke, which is a
// worse way to learn it than a test.
func TestOCINameGrammar(t *testing.T) {
	valid := []string{
		"library/nginx", "nginx", "library/nginx/sub", "my-org/my_app",
		"a", "org.example/app", "org__x/app", "a1/b2/c3",
	}
	for _, s := range valid {
		if !validOCIName(s) {
			t.Errorf("validOCIName(%q) = false, want true — this is a real image name", s)
		}
	}

	invalid := map[string]string{
		"":                       "empty",
		"library/":               "empty trailing component",
		"/nginx":                 "empty leading component",
		"library//nginx":         "empty middle component",
		"library/ng\x00inx":      "NUL byte — the one that panicked the handler",
		"library/ng\ninx":        "newline",
		"library/ng inx":         "space",
		"Library/Nginx":          "uppercase (not legal per spec)",
		"library/..":             "dot segment",
		"library/.hidden":        "leading dot",
		"library/nginx-":         "trailing dash",
		"-library/nginx":         "leading dash",
		"library/ng#inx":         "fragment character",
		"library/ng?inx":         "query character",
		"library/ng%2finx":       "still-encoded separator",
		"library/ng:inx":         "colon in a name",
		"http://evil/x":          "an absolute URL as a name",
		strings.Repeat("a", 256): "over the length cap",
	}
	for s, why := range invalid {
		if validOCIName(s) {
			t.Errorf("validOCIName(%q) = true, want false (%s)", s, why)
		}
	}
}

func TestOCIRefGrammar(t *testing.T) {
	valid := []string{
		"latest", "1.19", "v1.2.3-alpine", "_underscore", "3",
		"sha256:" + strings.Repeat("a", 64),
		"sha512:" + strings.Repeat("F", 128),
	}
	for _, s := range valid {
		if !validOCIRef(s) {
			t.Errorf("validOCIRef(%q) = false, want true — this is a real reference", s)
		}
	}

	invalid := map[string]string{
		"":                                  "empty",
		".dotfirst":                         "leading dot",
		"-dashfirst":                        "leading dash",
		"tag with space":                    "space",
		"tag\x00":                           "NUL byte",
		"sha256:":                           "digest with no hex",
		"sha256:abc":                        "digest hex too short",
		"sha256:" + strings.Repeat("z", 64): "digest hex not hexadecimal",
		":" + strings.Repeat("a", 64):       "digest with no algorithm",
		strings.Repeat("a", 129):            "tag over the length cap",
		"tag/../evil":                       "path traversal in a ref",
	}
	for s, why := range invalid {
		if validOCIRef(s) {
			t.Errorf("validOCIRef(%q) = true, want false (%s)", s, why)
		}
	}
}

// TestOCIMalformedNameIsRefusedNotPanicked is the regression test for the actual
// defect (#17).
//
// `GET /v2/library/ng%00inx/manifests/latest` PANICKED the handler: the name decodes
// to one containing a NUL, url.Parse rejects it, http.NewRequest returned (nil, err),
// the error was discarded with `req, _ :=`, and the next line dereferenced nil. One
// unauthenticated request was enough.
//
// Three things are asserted, because fixing only the crash would leave two of them:
// no panic, nothing forwarded upstream, and a fail-CLOSED verdict rather than a pass.
func TestOCIMalformedNameIsRefusedNotPanicked(t *testing.T) {
	var mu sync.Mutex
	var reached []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reached = append(reached, r.URL.EscapedPath())
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "oci"
		// Threshold 0 would allow anything that resolves — so if validation ever
		// stopped firing, this leg would go GREEN by allowing the hostile name
		// rather than red. The unscorable policy below is what makes the refusal
		// meaningful.
		c.ScoreThreshold = 0
		c.UnscorablePolicy = "block"
	})

	hostile := []string{
		"/v2/library/ng%00inx/manifests/latest",
		"/v2/library/ng%0ainx/manifests/latest",
		"/v2/library/ng%20inx/manifests/latest",
		"/v2/Library/Nginx/manifests/latest",
	}
	for _, path := range hostile {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://fw.local"+path, nil)
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req) // must not panic
			if rec.Code == http.StatusOK {
				t.Errorf("malformed image name was ALLOWED (200): %s", path)
			}
		})
	}

	mu.Lock()
	defer mu.Unlock()
	if len(reached) > 0 {
		t.Errorf("a malformed image name was forwarded UPSTREAM, which is what validating before "+
			"URL construction exists to prevent: %v", reached)
	}
}

// TestOCIUpstreamSuppliedDigestIsValidated covers the half a client cannot reach: the
// child-manifest and config digests come from the REGISTRY's response and are
// interpolated into the next URL. A gate whose job is distrusting what it fetches has
// to check those too.
func TestOCIUpstreamSuppliedDigestIsValidated(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.EscapedPath())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		// An index whose child digest is hostile rather than a digest.
		_, _ = w.Write([]byte(`{"manifests":[{"digest":"../../../etc/passwd"}]}`))
	}))
	defer upstream.Close()

	eco := ociEcosystem{base: upstream.URL}
	_, err := eco.LookupRepo(upstream.Client(), "library/nginx")
	if err == nil {
		t.Fatal("a hostile child-manifest digest from upstream was accepted")
	}
	if !errors.Is(err, errOCIMalformedRef) {
		t.Errorf("want errOCIMalformedRef so this routes to the unscorable policy rather than "+
			"passing through; got %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, p := range paths {
		if strings.Contains(p, "etc/passwd") || strings.Contains(p, "..") {
			t.Errorf("the hostile digest was used to build an upstream URL: %q", p)
		}
	}
}
