package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Tests for #64's PyPI half. Driven through a real server for the same reason as the OCI
// cases in relayintegrity_test.go: a mismatch aborts the handler, and only net/http turns
// that into the dropped connection a client actually sees.

const (
	pyIntWheelPath = "/packages/aa/bb/six-1.0-py3-none-any.whl"
	pyIntHonest    = "the-real-six-wheel-bytes"
	pyIntTampered  = "a-wheel-someone-swapped-in-on-the-way"
	pyIntMetadata  = "Metadata-Version: 2.1\nName: six\nVersion: 1.0\n"
)

func sha256Hex(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

// pyIntegrityRig is an upstream index host, a files host serving `served` under the path
// the index publishes the HONEST digest for, and a live gate in front of both. With
// served == pyIntHonest the registry is coherent; with pyIntTampered it is the attack.
func pyIntegrityRig(t *testing.T, served string, jsonIndex bool) (*httptest.Server, *proxyServer) {
	t.Helper()
	files := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case pyIntWheelPath:
			io.WriteString(w, served)
		case pyIntWheelPath + pep658MetadataSuffix:
			io.WriteString(w, pyIntMetadata)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(files.Close)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/simple/six/":
			if jsonIndex {
				w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
				fmt.Fprintf(w, `{"meta":{"api-version":"1.0"},"name":"six","files":[{"filename":"six-1.0-py3-none-any.whl","url":%q,"hashes":{"sha256":%q}}]}`,
					files.URL+pyIntWheelPath, sha256Hex(pyIntHonest))
				return
			}
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><body><a href="%s#sha256=%s">six-1.0-py3-none-any.whl</a></body></html>`,
				files.URL+pyIntWheelPath, sha256Hex(pyIntHonest))
		case "/pypi/six/json":
			io.WriteString(w, `{"info":{"project_urls":{"Source":"https://github.com/benjaminp/six"}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)
	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = files.URL // stub scores 7.5 >= default threshold -> ALLOW
	})
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return srv, p
}

func pyGet(t *testing.T, srv *httptest.Server, path string) (int, string, error) {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + path)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, readErr := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), readErr
}

func fetchIndex(t *testing.T, srv *httptest.Server) {
	t.Helper()
	if code, body, err := pyGet(t, srv, "/simple/six/"); err != nil || code != http.StatusOK {
		t.Fatalf("index fetch through the gate: status=%d err=%v body=%q", code, err, body)
	}
}

const pyIntFilesURL = "/_files/six" + pyIntWheelPath

// The positive control. A check that refused every wheel would pass the tampering
// case below while breaking every pip install, and this is what tells them apart.
func TestAPypiWheelMatchingItsIndexDigestIsServed(t *testing.T) {
	for _, jsonIndex := range []bool{false, true} {
		t.Run(map[bool]string{false: "html index", true: "json index"}[jsonIndex], func(t *testing.T) {
			srv, p := pyIntegrityRig(t, pyIntHonest, jsonIndex)
			fetchIndex(t, srv)
			code, got, err := pyGet(t, srv, pyIntFilesURL)
			if err != nil || code != http.StatusOK || got != pyIntHonest {
				t.Fatalf("honest wheel: status=%d body=%q err=%v", code, got, err)
			}
			if n := integrityMismatches(p); n != 0 {
				t.Errorf("an honest wheel counted %d mismatches", n)
			}
		})
	}
}

// The property: pip does not verify hashes unless the user asked it to, so this abort is
// the only thing between a swapped wheel and an install. Both index forms, because pip
// asks for PEP 691 JSON by default and an HTML-only reader would cover almost nothing.
func TestATamperedPypiWheelDoesNotCompleteAsASuccess(t *testing.T) {
	for _, jsonIndex := range []bool{false, true} {
		t.Run(map[bool]string{false: "html index", true: "json index"}[jsonIndex], func(t *testing.T) {
			srv, p := pyIntegrityRig(t, pyIntTampered, jsonIndex)
			fetchIndex(t, srv)
			_, got, readErr := pyGet(t, srv, pyIntFilesURL)
			if readErr == nil && got == pyIntTampered {
				t.Errorf("BYPASS: the swapped wheel was delivered complete with no transfer error")
			}
			// At least one, not exactly one. Measured: this wheel is smaller than the
			// server's write buffer, so the abort drops the connection before a single
			// byte -- headers included -- leaves it. The client had reused the keep-alive
			// connection from the index fetch, saw it close with nothing received, and
			// retried the idempotent GET, which aborted again: two transfers, two counts.
			// The counter is per transfer attempt and that is the honest unit. It also
			// means a small tampered artifact reaches the client as NO response at all,
			// which is closer to a refusal than the large-file case the source describes.
			if n := integrityMismatches(p); n < 1 {
				t.Errorf("integrity mismatches = %d, want at least 1", n)
			}
		})
	}
}

// The discriminator, and the stated coverage limit. Same tampered bytes, but no index
// passed through this gate first, so there is no digest to check against: the wheel is
// relayed exactly as before #64. It proves the abort above comes from the recorded
// digest and not from anything else in the relay -- and it pins the gap so nobody later
// describes this check as covering URLs replayed from a lockfile.
func TestAPypiWheelWithNoRelayedIndexIsNotVerified(t *testing.T) {
	srv, p := pyIntegrityRig(t, pyIntTampered, false)
	code, got, err := pyGet(t, srv, pyIntFilesURL)
	if err != nil || code != http.StatusOK || got != pyIntTampered {
		t.Fatalf("with no index relayed the wheel should pass as before: status=%d body=%q err=%v", code, got, err)
	}
	if n := integrityMismatches(p); n != 0 {
		t.Errorf("counted %d mismatches with no digest known", n)
	}
}

// The trap this design exists to avoid. The PEP 658 metadata document streams through
// the same function as the wheel, and its URL is the wheel's plus a suffix. A digest
// inferred from the URL would check the METADATA against the WHEEL's hash, fail, and
// abort the first request of every modern pip resolve. The digest is attached only by
// the wheel relay, so the document must come back whole and uncounted.
func TestAWheelsMetadataSiblingIsNotCheckedAgainstTheWheelDigest(t *testing.T) {
	srv, p := pyIntegrityRig(t, pyIntHonest, false)
	fetchIndex(t, srv)
	code, got, err := pyGet(t, srv, pyIntFilesURL+pep658MetadataSuffix)
	if err != nil || code != http.StatusOK || got != pyIntMetadata {
		t.Fatalf("metadata sibling: status=%d body=%q err=%v", code, got, err)
	}
	if n := integrityMismatches(p); n != 0 {
		t.Errorf("the metadata document was checked against its wheel's digest (%d mismatches)", n)
	}
}

func TestPypiIndexDigestsReadsBothIndexForms(t *testing.T) {
	const files = "https://files.example"
	h := sha256Hex("x")
	cases := []struct {
		name string
		body string
		want map[string]string
	}{
		{"html fragment", `<a href="` + files + `/packages/a/x.whl#sha256=` + h + `">x</a>`,
			map[string]string{"/packages/a/x.whl": h}},
		{"html query is not part of the path", `<a href="` + files + `/packages/a/x.whl?sig=1#sha256=` + h + `">x</a>`,
			map[string]string{"/packages/a/x.whl": h}},
		{"upper-case hex is the same bytes", `<a href="` + files + `/p/x.whl#sha256=` + strings.ToUpper(h) + `">x</a>`,
			map[string]string{"/p/x.whl": h}},
		{"another host is not bound", `<a href="https://elsewhere.example/p/x.whl#sha256=` + h + `">x</a>`,
			map[string]string{}},
		{"a relative link is not guessed at", `<a href="../../p/x.whl#sha256=` + h + `">x</a>`,
			map[string]string{}},
		{"no fragment, nothing recorded", `<a href="` + files + `/p/x.whl">x</a>`,
			map[string]string{}},
		{"json form", `{"files":[{"url":"` + files + `/p/x.whl","hashes":{"sha256":"` + h + `"}}]}`,
			map[string]string{"/p/x.whl": h}},
		{"json without sha256", `{"files":[{"url":"` + files + `/p/x.whl","hashes":{"md5":"abc"}}]}`,
			map[string]string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pypiIndexDigests([]byte(c.body), files)
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for k, v := range c.want {
				if got[k] != v {
					t.Errorf("%s -> %q, want %q", k, got[k], v)
				}
			}
		})
	}
}
