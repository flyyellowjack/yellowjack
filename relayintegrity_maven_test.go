package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Tests for #64's Maven half. Driven through a real server for the same reason as the OCI
// and PyPI cases: a mismatch aborts the handler, and only net/http turns that into the
// dropped connection a client actually sees.

const (
	mvnIntJarPath  = "/com/good/lib/1.0.0/lib-1.0.0.jar"
	mvnIntHonest   = "the-real-lib-jar-bytes"
	mvnIntTampered = "a-jar-someone-swapped-in-on-the-way"
)

func sha1Hex(s string) string { sum := sha1.Sum([]byte(s)); return hex.EncodeToString(sum[:]) }

// mvnIntegrityRig is a Maven repository serving `served` at the jar path while its
// X-Checksum-SHA1 header names the HONEST bytes -- a coherent repository when served is
// mvnIntHonest, the substitution case when it is not. sendChecksum=false is a repository
// that sends no checksum header at all. gzipIt serves the jar content-encoded, as Central
// does for a .pom when the client asks for gzip.
func mvnIntegrityRig(t *testing.T, served string, sendChecksum, gzipIt bool) (*httptest.Server, *proxyServer) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".pom"):
			fmt.Fprint(w, `<project><scm><url>https://github.com/good/lib</url></scm></project>`)
		case r.URL.Path == mvnIntJarPath:
			if sendChecksum {
				w.Header().Set("X-Checksum-SHA1", sha1Hex(mvnIntHonest))
			}
			if gzipIt {
				var buf bytes.Buffer
				zw := gzip.NewWriter(&buf)
				io.WriteString(zw, served)
				zw.Close()
				w.Header().Set("Content-Encoding", "gzip")
				w.Write(buf.Bytes())
				return
			}
			io.WriteString(w, served)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(upstream.Close)
	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "maven" // stub scores 7.5 >= default threshold -> ALLOW
	})
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return srv, p
}

func mvnGet(t *testing.T, srv *httptest.Server, path string) (int, string, error) {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + path)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, readErr := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), readErr
}

// The positive control: a check that aborted every jar would pass the tampering test
// while breaking every build, and this is the assertion that tells those apart.
func TestAMavenJarMatchingItsChecksumHeaderIsServed(t *testing.T) {
	srv, p := mvnIntegrityRig(t, mvnIntHonest, true, false)
	code, got, err := mvnGet(t, srv, mvnIntJarPath)
	if err != nil || code != http.StatusOK || got != mvnIntHonest {
		t.Fatalf("honest jar: status=%d body=%q err=%v — the check refused bytes that match their checksum", code, got, err)
	}
	if n := integrityMismatches(p); n != 0 {
		t.Errorf("honest jar counted %d mismatches, want 0", n)
	}
}

func TestATamperedMavenJarDoesNotCompleteAsASuccess(t *testing.T) {
	srv, p := mvnIntegrityRig(t, mvnIntTampered, true, false)
	_, got, readErr := mvnGet(t, srv, mvnIntJarPath)
	if readErr == nil && got == mvnIntTampered {
		t.Errorf("BYPASS: the swapped jar was delivered complete with no transfer error — under Maven's " +
			"default checksum policy (warn) it would be built into the classpath")
	}
	// At least one, not exactly one: a body this small aborts before a byte leaves the
	// server's buffer, the client sees no response and retries its idempotent GET, and
	// each attempt is a transfer of its own (the same measured behaviour as the PyPI case).
	if n := integrityMismatches(p); n < 1 {
		t.Errorf("integrity mismatches = %d, want >= 1 — the mismatch is invisible on the capacity view", n)
	}
}

// The discriminator and the stated coverage gap: same swapped bytes, no checksum header,
// and the jar flows. It proves the abort above comes from the header check and not from
// something else in the relay, and pins that a repository sending no checksum is
// unverified rather than refused, so nobody later describes this as covering it.
func TestAMavenJarWithNoChecksumHeaderIsNotVerified(t *testing.T) {
	srv, p := mvnIntegrityRig(t, mvnIntTampered, false, false)
	code, got, err := mvnGet(t, srv, mvnIntJarPath)
	if err != nil || code != http.StatusOK || got != mvnIntTampered {
		t.Fatalf("no-header jar: status=%d body=%q err=%v — want it relayed unverified", code, got, err)
	}
	if n := integrityMismatches(p); n != 0 {
		t.Errorf("no-header jar counted %d mismatches, want 0", n)
	}
}

// Central gzips a .pom when asked and still sends the checksum of the PLAIN file. The
// relay streams the encoded body through untouched, so without the Content-Encoding
// exclusion every pom of an ordinary resolve would be aborted. Go's client asks for gzip
// and decodes transparently, which is exactly the shape a real Maven client produces.
func TestAContentEncodedMavenFileIsNotVerified(t *testing.T) {
	srv, p := mvnIntegrityRig(t, mvnIntHonest, true, true)
	code, got, err := mvnGet(t, srv, mvnIntJarPath)
	if err != nil || code != http.StatusOK || got != mvnIntHonest {
		t.Fatalf("gzip-encoded honest file: status=%d body=%q err=%v — the encoded body was checked "+
			"against the decoded file's checksum", code, got, err)
	}
	if n := integrityMismatches(p); n != 0 {
		t.Errorf("gzip-encoded honest file counted %d mismatches, want 0", n)
	}
}

func TestMavenHeaderDigestReadsTheStrongestWellFormedChecksum(t *testing.T) {
	const s1 = "8ac9e16d933b6fb43bc7f576336b8f4d7eb5ba12"
	const s256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name string
		hdr  map[string]string
		algo string // "" means: not verifiable
		want string
		why  string
	}{
		{"central", map[string]string{"X-Checksum-SHA1": s1, "X-Checksum-MD5": "d98a9a02a99a9acd22d7653cbcc1f31f"},
			"sha1", s1, "the headers Maven Central actually sends"},
		{"both", map[string]string{"X-Checksum-Sha1": s1, "X-Checksum-Sha256": s256},
			"sha256", s256, "a repository sending both is checked against the stronger"},
		{"uppercase hex", map[string]string{"X-Checksum-SHA1": strings.ToUpper(s1)},
			"sha1", s1, "hex encodes bytes, case carries no meaning"},
		{"md5 only", map[string]string{"X-Checksum-MD5": "d98a9a02a99a9acd22d7653cbcc1f31f"},
			"", "", "md5 is never read"},
		{"none", map[string]string{}, "", "", "no header relays unverified"},
		{"short", map[string]string{"X-Checksum-SHA1": s1[:39]}, "", "",
			"a truncated value could never match, so the check would be manufactured by the parser"},
		{"bad sha256 falls back", map[string]string{"X-Checksum-Sha256": "zz", "X-Checksum-SHA1": s1},
			"sha1", s1, "one oddly spelled header does not cost the other"},
		{"not hex", map[string]string{"X-Checksum-SHA1": strings.Repeat("g", 40)}, "", "", "not a digest"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range c.hdr {
				h.Set(k, v)
			}
			algo, want, ok := mavenHeaderDigest(h)
			if c.algo == "" {
				if ok {
					t.Errorf("treated as verifiable (%s:%s) — %s", algo, want, c.why)
				}
				return
			}
			if !ok || algo != c.algo || want != c.want {
				t.Errorf("-> (%q, %q, %v), want (%q, %q) — %s", algo, want, ok, c.algo, c.want, c.why)
			}
		})
	}
}

// sha1 is accepted from a checksum header only. The OCI spec registers no sha1, so a blob
// URL naming one must stay unverifiable -- this pins that the Maven half did not widen
// the OCI parser on its way in.
func TestSha1IsNotAnOCIBlobDigest(t *testing.T) {
	if _, _, ok := expectedBlobDigest("/v2/lib/x/blobs/sha1:" + sha1Hex("x")); ok {
		t.Error("an OCI blob URL naming sha1 was treated as verifiable")
	}
}

func TestVerifiableTransferExcludesAContentEncodedBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://fw.local"+mvnIntJarPath, nil)
	for _, c := range []struct {
		ce   string
		want bool
	}{{"", true}, {"identity", true}, {"gzip", false}, {"br", false}} {
		resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}}
		if c.ce != "" {
			resp.Header.Set("Content-Encoding", c.ce)
		}
		if got := verifiableTransfer(r, resp); got != c.want {
			t.Errorf("Content-Encoding %q: verifiableTransfer = %v, want %v", c.ce, got, c.want)
		}
	}
}
