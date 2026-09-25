package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Tests for artifact integrity on relay (#64).
//
// The end-to-end cases run the proxy behind a REAL httptest.Server rather than through
// the recorder helper the other byte-gate tests use, and that is not a style choice. A
// mismatch aborts the handler with http.ErrAbortHandler, which net/http recovers as a
// dropped connection -- exactly what a client sees in production. Driven through a
// recorder there is no server to recover it, so the panic reaches the test runner and
// the case looks like a crash instead of the behaviour under test. That is how this
// change first announced itself in TestModeMatrix.

// integrityMismatches sums the counter across every flow row. Summed rather than read
// from one row because the key carries the package and kind, and a test that guessed
// which row the relay landed in would fail for the wrong reason when that changes.
func integrityMismatches(p *proxyServer) int64 {
	var n int64
	for _, r := range p.flow.Snapshot() {
		n += r.IntegrityMismatches
	}
	return n
}

const integrityImage = "library/goodimage"

// newIntegritySpy serves a coherent image: the manifest names the config and layer by
// their true digests, and the layer bytes are whatever `layer` says. Passing a `layer`
// that does not hash to the digest in the request path is how the tampering case is
// built -- a registry that cannot happen, which is the point.
func newIntegritySpy(t *testing.T, layerDigest, layerBody string) *httptest.Server {
	t.Helper()
	configBody := `{"config":{"Labels":{"org.opencontainers.image.source":"https://github.com/yj/goodimage"}}}`
	configDigest := ociDigest(configBody)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			fmt.Fprintf(w, `{"config":{"digest":%q},"layers":[{"digest":%q}]}`, configDigest, layerDigest)
		case strings.HasSuffix(r.URL.Path, "/blobs/"+configDigest):
			fmt.Fprint(w, configBody)
		case strings.HasSuffix(r.URL.Path, "/blobs/"+layerDigest):
			fmt.Fprint(w, layerBody)
		default:
			fmt.Fprint(w, "{}")
		}
	}))
}

// newServedProxy returns a live server in front of an allow-everything OCI gate, so the
// only thing that can stop a blob is the integrity check.
func newServedProxy(t *testing.T, upstream *httptest.Server) (*httptest.Server, *proxyServer) {
	t.Helper()
	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "oci"
		c.ScoreThreshold = 1.0 // stub scores 7.5, so every image is ALLOWED
		c.ByteGate = byteGateEnforce
	})
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return srv, p
}

func fetchBlob(t *testing.T, srv *httptest.Server, digest string, hdr map[string]string) (int, string, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v2/"+integrityImage+"/blobs/"+digest, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, readErr := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), readErr
}

// TestAMatchingBlobIsServedWhole is the positive control, and it is load-bearing: a
// check that refused everything would pass the tampering test below while making the
// product useless, and this is the assertion that tells those apart.
func TestAMatchingBlobIsServedWhole(t *testing.T) {
	const body = "this-is-a-real-layer-payload"
	digest := ociDigest(body)
	up := newIntegritySpy(t, digest, body)
	defer up.Close()
	srv, p := newServedProxy(t, up)

	code, got, err := fetchBlob(t, srv, digest, nil)
	if err != nil {
		t.Fatalf("an honest registry's blob failed to transfer: %v", err)
	}
	if code != http.StatusOK || got != body {
		t.Errorf("honest blob: status=%d body=%q, want 200 and %q", code, got, body)
	}
	if n := integrityMismatches(p); n != 0 {
		t.Errorf("a matching blob counted %d integrity mismatches, want 0 — the check is firing on good bytes", n)
	}
}

// TestATamperedBlobDoesNotCompleteAsASuccess is the property #64 buys. The registry
// serves a DIFFERENT payload under the digest the client asked for -- the tampered
// mirror / poisoned CDN slice -- and the client must not end up holding it alongside a
// clean end-of-response.
func TestATamperedBlobDoesNotCompleteAsASuccess(t *testing.T) {
	const honest = "this-is-a-real-layer-payload"
	const tampered = "this-is-NOT-the-payload-you-asked-for"
	digest := ociDigest(honest) // the client asks for the honest digest...
	up := newIntegritySpy(t, digest, tampered)
	defer up.Close()
	srv, p := newServedProxy(t, up)

	_, got, readErr := fetchBlob(t, srv, digest, nil)

	// The transfer must not be a clean, complete delivery of the wrong bytes. Asserted
	// as "not a clean success", not as a specific error: the status line is already
	// committed by the time the hash is known (see relayintegrity.go), so what the
	// client observes is a broken connection, and whether that surfaces as an
	// unexpected EOF or a short read is the transport's business, not ours.
	if readErr == nil && got == tampered {
		t.Errorf("BYPASS: the tampered payload was delivered complete with no transfer error — "+
			"a client would accept %q as the contents of %s", got, digest)
	}
	if n := integrityMismatches(p); n != 1 {
		t.Errorf("integrity mismatches = %d, want 1 — the mismatch was not counted, so it is "+
			"invisible on the capacity view and in the alert", n)
	}
}

// TestARangeRequestIsNotVerified is BOTH an exclusion test and the discriminator for the
// test above. Container clients resume interrupted layers with Range, and a range of a
// blob cannot hash to the whole blob's digest -- verifying it would break exactly the
// pulls already having a bad day. It also proves the abort above comes from the
// integrity check and not from something else in the relay: same upstream, same
// tampered bytes, one header different, and the bytes flow.
func TestARangeRequestIsNotVerified(t *testing.T) {
	const honest = "this-is-a-real-layer-payload"
	const tampered = "this-is-NOT-the-payload-you-asked-for"
	digest := ociDigest(honest)
	up := newIntegritySpy(t, digest, tampered)
	defer up.Close()
	srv, p := newServedProxy(t, up)

	code, got, err := fetchBlob(t, srv, digest, map[string]string{"Range": "bytes=0-"})
	if err != nil {
		t.Fatalf("a ranged fetch was broken by the integrity check: %v", err)
	}
	if code != http.StatusOK || got != tampered {
		t.Errorf("ranged fetch: status=%d body=%q — the exclusion did not apply", code, got)
	}
	if n := integrityMismatches(p); n != 0 {
		t.Errorf("a ranged fetch counted %d mismatches, want 0", n)
	}
}

func TestExpectedBlobDigestReadsOnlyWellFormedDigests(t *testing.T) {
	const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name string
		path string
		want string // "" means: not verifiable
		why  string
	}{
		{"sha256", "/v2/lib/x/blobs/sha256:" + hex64, hex64, "the ordinary case"},
		{"sha512", "/v2/lib/x/blobs/sha512:" + hex64 + hex64, hex64 + hex64, "registries may serve either"},
		{"upload path", "/v2/lib/x/blobs/uploads/9f1c-4b", "",
			"a push lands in the byte gate by design and names no digest"},
		{"short hex", "/v2/lib/x/blobs/sha256:abc", "",
			"a truncated digest would hash the body and compare against something that can never match"},
		{"uppercase", "/v2/lib/x/blobs/sha256:" + strings.ToUpper(hex64), "",
			"deciding two spellings name one blob is the registry's call, not ours"},
		{"not hex", "/v2/lib/x/blobs/sha256:" + strings.Repeat("z", 64), "", "not a digest"},
		{"unknown algorithm", "/v2/lib/x/blobs/sha3-256:" + hex64, "",
			"a future algorithm must be unverifiable rather than wrongly verified"},
		{"no colon", "/v2/lib/x/blobs/" + hex64, "", "not a digest"},
		{"not a blob path", "/v2/lib/x/manifests/latest", "", "manifests are not content we check here"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, got, ok := expectedBlobDigest(c.path)
			if c.want == "" {
				if ok {
					t.Errorf("%s was treated as verifiable (%q) — %s", c.path, got, c.why)
				}
				return
			}
			if !ok || got != c.want {
				t.Errorf("%s -> (%q, %v), want %q — %s", c.path, got, ok, c.want, c.why)
			}
		})
	}
}

func TestVerifiableTransferExcludesWhatCannotMatch(t *testing.T) {
	req := func(method, rangeHdr string) *http.Request {
		r := httptest.NewRequest(method, "http://fw.local/v2/lib/x/blobs/sha256:abc", nil)
		if rangeHdr != "" {
			r.Header.Set("Range", rangeHdr)
		}
		return r
	}
	cases := []struct {
		name   string
		r      *http.Request
		status int
		want   bool
		why    string
	}{
		{"whole GET", req(http.MethodGet, ""), 200, true, "the case the check exists for"},
		{"HEAD", req(http.MethodHead, ""), 200, false, "no body at all, so it hashes to the digest of nothing (#108's shape)"},
		{"partial content", req(http.MethodGet, "bytes=0-99"), 206, false, "a range cannot hash to the whole blob"},
		{"range header, 200 answer", req(http.MethodGet, "bytes=0-"), 200, false,
			"excluded on the REQUEST shape, so the check does not depend on the upstream's mood"},
		{"not found", req(http.MethodGet, ""), 404, false, "an error document is not an artifact"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := verifiableTransfer(c.r, &http.Response{StatusCode: c.status}); got != c.want {
				t.Errorf("verifiableTransfer = %v, want %v — %s", got, c.want, c.why)
			}
		})
	}
}
