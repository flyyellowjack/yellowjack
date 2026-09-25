package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// #147: "we never modify artifact bytes or integrity metadata" was asserted for npm
// (dist.integrity, with a forging control) and PyPI (#sha256= fragment), and for neither
// Maven nor OCI. A guarantee that says "artifacts" covers everything we proxy, so
// publishing it would have been true-but-untested on half the surface.
//
// WHAT "PRESERVED" MEANS HERE, in two independent halves, because either alone is weak:
//
//	IDENTITY   every byte the client receives equals the byte the upstream sent
//	COHERENCE  the integrity material still authenticates the artifact it sits beside
//	           (sha1(relayed jar) == relayed .sha1; sha256(relayed blob) == its digest)
//
// Identity alone would pass for a relay that mangled the artifact and its checksum the
// same way against a fixture that mangled them too. Coherence alone would pass for a
// relay that swapped in a DIFFERENT artifact with its own matching checksum. A real
// client only ever checks coherence; we can check both, so we do.
//
// THE CHECKERS RETURN ERRORS INSTEAD OF CALLING t.Fatal, and that is the design, not a
// style choice: the negative controls run the SAME checker against a relay that has
// been tampered with and REQUIRE an error naming the tampered thing. A checker that can
// only fail the test cannot be shown able to fail.
//
// These drive a real server and a real client (not a ResponseRecorder), with transport
// compression off, so what is compared is what crosses the wire.

// hostileBytes is a payload chosen to be damaged by anything that treats an artifact as
// text: NUL, 0xFF (invalid UTF-8), a bare CR, CRLF, a UTF-8 BOM, leading and trailing
// whitespace, and a final newline. A relay that trims, re-encodes or normalises line
// endings changes its hash.
func hostileBytes(tag string) []byte {
	b := []byte("  \t" + tag + " ")
	b = append(b, 0x00, 0xFF, 0xFE, '\r', 'x', '\r', '\n', 0xEF, 0xBB, 0xBF)
	for i := 0; i < 4096; i++ {
		b = append(b, byte(i*31+7))
	}
	return append(b, ' ', '\n')
}

func hexOf(h hash.Hash, b []byte) string {
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// rawWireClient never transparently decompresses, so a body is compared as sent.
var rawWireClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: &http.Transport{DisableCompression: true},
}

type wireResponse struct {
	status int
	header http.Header
	body   []byte
}

func wireDo(method, url string) (wireResponse, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return wireResponse{}, err
	}
	resp, err := rawWireClient.Do(req)
	if err != nil {
		return wireResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return wireResponse{}, fmt.Errorf("%s %s: reading body: %w", method, url, err)
	}
	return wireResponse{resp.StatusCode, resp.Header, body}, nil
}

// integrityGate stands a permissive gate in front of upstream: everything is allowed, so
// the only thing under test is what the relay does to the bytes it is allowed to carry.
func integrityGate(t *testing.T, ecosystem string, upstream *httptest.Server) *httptest.Server {
	t.Helper()
	cfg := Config{
		Ecosystem:        ecosystem,
		UpstreamRegistry: upstream.URL,
		FilesUpstream:    upstream.URL,
		UnscorablePolicy: "allow",
		UnverifiedPolicy: "open-with-visibility",
		ScoreThreshold:   0,
		ScorecardMode:    "stub",
		ScoreCacheTTL:    time.Minute,
		ByteGate:         byteGateEnforce,
	}
	fw, err := NewFirewall(cfg)
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	srv := httptest.NewServer(newProxyServer(cfg, fw))
	t.Cleanup(srv.Close)
	return srv
}

// tamperingFront sits between the client and the gate and rewrites one response. It is
// the negative control's stand-in for "the relay modified something": the checker sees
// exactly what it would see if the gate itself had done it.
func tamperingFront(t *testing.T, gate *httptest.Server, match func(*http.Request) bool, edit func(http.Header, []byte) []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := wireDo(r.Method, gate.URL+r.URL.RequestURI())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		body := got.body
		hdr := got.header.Clone()
		if match(r) {
			body = edit(hdr, body)
		}
		for k, vs := range hdr {
			if k == "Content-Length" {
				continue
			}
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(got.status)
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ───────────────────────────────────── Maven ─────────────────────────────────────

const (
	intGroupPath = "org/example/goodlib"
	intArtifact  = "goodlib"
	intVersion   = "2.1.0"
)

// mavenFixture is a fake repository: one artifact, its POM, and a checksum sidecar of
// every algorithm the gate exempts from scoring (mavenUngatedSuffixes), in the three
// textual shapes real repositories publish -- bare hex, hex + newline, and the
// coreutils "hex  filename" form. A relay that normalised any of them would still
// "contain the right hash" and would no longer be byte-identical.
type mavenFixture struct {
	*httptest.Server
	files map[string][]byte // path -> exact bytes served
}

func newMavenFixture(t *testing.T) *mavenFixture {
	t.Helper()
	base := "/" + intGroupPath + "/" + intVersion + "/" + intArtifact + "-" + intVersion
	jar := hostileBytes("JAR")
	pom := []byte(`<project><scm><url>https://github.com/example/goodlib</url></scm></project>`)
	f := &mavenFixture{files: map[string][]byte{
		base + ".jar":        jar,
		base + ".pom":        pom,
		base + ".jar.sha1":   []byte(hexOf(sha1.New(), jar)),
		base + ".jar.md5":    []byte(hexOf(md5.New(), jar) + "\n"),
		base + ".jar.sha256": []byte(hexOf(sha256.New(), jar) + "  " + intArtifact + "-" + intVersion + ".jar\n"),
		base + ".jar.sha512": []byte(strings.ToUpper(hexOf(sha512.New(), jar))),
		base + ".pom.sha1":   []byte(hexOf(sha1.New(), pom)),
	}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := f.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(b)
	}))
	t.Cleanup(f.Close)
	return f
}

// checkMavenIntegrity fetches every fixture file from front and returns the first
// violation of IDENTITY or COHERENCE, or nil. `checked` reports how many comparisons
// actually ran, so a caller can refuse a vacuous pass.
func checkMavenIntegrity(front string, f *mavenFixture) (checked int, err error) {
	relayed := map[string][]byte{}
	for path, want := range f.files {
		got, err := wireDo(http.MethodGet, front+path)
		if err != nil {
			return checked, err
		}
		if got.status != http.StatusOK {
			return checked, fmt.Errorf("%s: status %d, so nothing was compared", path, got.status)
		}
		if !bytes.Equal(got.body, want) {
			return checked, fmt.Errorf("IDENTITY: %s differs from upstream (%d bytes relayed, %d sent)", path, len(got.body), len(want))
		}
		relayed[path] = got.body
		checked++
	}
	algos := map[string]func() hash.Hash{".sha1": sha1.New, ".md5": md5.New, ".sha256": sha256.New, ".sha512": sha512.New}
	for path, side := range relayed {
		for suffix, mk := range algos {
			if !strings.HasSuffix(path, suffix) {
				continue
			}
			target, ok := relayed[strings.TrimSuffix(path, suffix)]
			if !ok {
				return checked, fmt.Errorf("COHERENCE: %s has no relayed artifact beside it", path)
			}
			fields := strings.Fields(string(side))
			if len(fields) == 0 {
				return checked, fmt.Errorf("COHERENCE: %s is empty", path)
			}
			if !strings.EqualFold(fields[0], hexOf(mk(), target)) {
				return checked, fmt.Errorf("COHERENCE: %s no longer authenticates the artifact relayed beside it", path)
			}
			checked++
		}
	}
	return checked, nil
}

func TestMavenRelayPreservesArtifactsAndTheirChecksums(t *testing.T) {
	f := newMavenFixture(t)
	gate := integrityGate(t, "maven", f.Server)

	checked, err := checkMavenIntegrity(gate.URL, f)
	if err != nil {
		t.Fatalf("the Maven relay does not preserve integrity material: %v", err)
	}
	// 7 identity comparisons + 5 coherence comparisons. A smaller number means the
	// fixture shrank or a loop stopped matching, and the pass above proved less than
	// its name.
	if checked != 12 {
		t.Fatalf("expected 12 comparisons, ran %d; this test is asserting less than it claims", checked)
	}

	// ── negative controls: the SAME checker must catch each kind of modification ──
	for _, c := range []struct {
		name, suffix, wantIn string
		edit                 func(http.Header, []byte) []byte
	}{
		{"an altered checksum sidecar", ".jar.sha1", ".jar.sha1 differs",
			func(_ http.Header, b []byte) []byte { return append([]byte("0"), b[1:]...) }},
		{"a sidecar merely NORMALISED (trailing newline trimmed)", ".jar.md5", ".jar.md5 differs",
			func(_ http.Header, b []byte) []byte { return bytes.TrimSpace(b) }},
		{"one flipped byte in the artifact", ".jar", ".jar differs",
			func(_ http.Header, b []byte) []byte { c := bytes.Clone(b); c[len(c)/2] ^= 0x01; return c }},
		{"an artifact re-encoded as text (invalid UTF-8 replaced)", ".jar", ".jar differs",
			func(_ http.Header, b []byte) []byte { return []byte(strings.ToValidUTF8(string(b), "?")) }},
	} {
		t.Run("control: "+c.name, func(t *testing.T) {
			hits := 0
			front := tamperingFront(t, gate,
				func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, c.suffix) },
				func(h http.Header, b []byte) []byte { hits++; return c.edit(h, b) })
			_, err := checkMavenIntegrity(front.URL, f)
			if hits == 0 {
				t.Fatal("CONTROL DID NOT FIRE: the tampering front edited nothing")
			}
			if err == nil {
				t.Fatalf("CONTROL FAILED TO FAIL: %s went undetected, so the green result above proves nothing", c.name)
			}
			if !strings.Contains(err.Error(), c.wantIn) {
				t.Fatalf("the checker failed for the wrong reason: %v (expected it to name %s)", err, c.wantIn)
			}
		})
	}
}

// ────────────────────────────────────── OCI ──────────────────────────────────────

const intImage = "example/goodimage"

// ociFixture is a fake registry serving one image the way a real one does: the manifest
// under a tag AND under its digest, with Docker-Content-Digest and the manifest media
// type on both GET and HEAD, and each blob under its sha256.
//
// The manifest is served as EXACT BYTES with deliberately non-canonical JSON (odd
// spacing, a trailing newline). A manifest's digest is the hash of its bytes, not of its
// meaning: a relay that parsed and re-serialised it -- as the npm packument path does by
// design -- would keep the meaning and break every pull by digest.
type ociFixture struct {
	*httptest.Server
	manifest       []byte
	manifestDigest string
	mediaType      string
	blobs          map[string][]byte // digest -> bytes
}

func newOciFixture(t *testing.T) *ociFixture {
	t.Helper()
	config := []byte(`{"config":{"Labels":{"org.opencontainers.image.source":"https://github.com/example/goodimage"}}}`)
	layerA, layerB := hostileBytes("LAYER-A"), hostileBytes("LAYER-B")
	dg := func(b []byte) string { return "sha256:" + hexOf(sha256.New(), b) }

	f := &ociFixture{
		mediaType: "application/vnd.oci.image.manifest.v1+json",
		blobs:     map[string][]byte{dg(config): config, dg(layerA): layerA, dg(layerB): layerB},
	}
	f.manifest = []byte(fmt.Sprintf("{ \"schemaVersion\":2,\n\t\"mediaType\": %q,\n  \"config\":{\"digest\":%q , \"size\":%d},\n  \"layers\":[ {\"digest\":%q,\"size\":%d},{\"digest\":%q,\"size\":%d} ]  }\n",
		f.mediaType, dg(config), len(config), dg(layerA), len(layerA), dg(layerB), len(layerB)))
	f.manifestDigest = dg(f.manifest)

	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/"+intImage+"/manifests/1.0", r.URL.Path == "/v2/"+intImage+"/manifests/"+f.manifestDigest:
			w.Header().Set("Content-Type", f.mediaType)
			w.Header().Set("Docker-Content-Digest", f.manifestDigest)
			w.Header().Set("Content-Length", fmt.Sprint(len(f.manifest)))
			if r.Method != http.MethodHead {
				_, _ = w.Write(f.manifest)
			}
		case strings.HasPrefix(r.URL.Path, "/v2/"+intImage+"/blobs/"):
			d := strings.TrimPrefix(r.URL.Path, "/v2/"+intImage+"/blobs/")
			b, ok := f.blobs[d]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Docker-Content-Digest", d)
			_, _ = w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

// checkOciIntegrity pulls the image the way a client does -- resolve the tag, fetch the
// manifest by tag and by digest, then every blob the RELAYED manifest names -- and
// returns the first violation. The blob list comes from the relayed manifest rather than
// from the fixture, so a relay that rewrote a layer digest would be followed to wherever
// it pointed and caught there.
func checkOciIntegrity(front string, f *ociFixture) (checked int, err error) {
	base := front + "/v2/" + intImage

	head, err := wireDo(http.MethodHead, base+"/manifests/1.0")
	if err != nil {
		return checked, err
	}
	if head.status != http.StatusOK {
		return checked, fmt.Errorf("HEAD manifest: status %d, so nothing was compared", head.status)
	}
	if got := head.header.Get("Docker-Content-Digest"); got != f.manifestDigest {
		return checked, fmt.Errorf("IDENTITY: HEAD manifest Docker-Content-Digest is %q, upstream sent %q (a client resolves the tag from this header)", got, f.manifestDigest)
	}
	checked++

	var relayedManifest []byte
	for _, ref := range []string{"1.0", f.manifestDigest} {
		got, err := wireDo(http.MethodGet, base+"/manifests/"+ref)
		if err != nil {
			return checked, err
		}
		if got.status != http.StatusOK {
			return checked, fmt.Errorf("GET manifest %s: status %d, so nothing was compared", ref, got.status)
		}
		if !bytes.Equal(got.body, f.manifest) {
			return checked, fmt.Errorf("IDENTITY: manifest (by %s) differs from upstream's bytes", ref)
		}
		if d := "sha256:" + hexOf(sha256.New(), got.body); d != f.manifestDigest {
			return checked, fmt.Errorf("COHERENCE: manifest (by %s) hashes to %s, not the digest it is addressed by", ref, d)
		}
		if got.header.Get("Docker-Content-Digest") != f.manifestDigest {
			return checked, fmt.Errorf("IDENTITY: manifest (by %s) Docker-Content-Digest header is %q", ref, got.header.Get("Docker-Content-Digest"))
		}
		// The media type is integrity material too: it selects how a client parses the
		// bytes it just verified, and a registry-in-front re-serves it verbatim.
		if got.header.Get("Content-Type") != f.mediaType {
			return checked, fmt.Errorf("IDENTITY: manifest (by %s) Content-Type is %q, upstream sent %q", ref, got.header.Get("Content-Type"), f.mediaType)
		}
		relayedManifest = got.body
		checked += 4
	}

	var m struct {
		Config struct{ Digest string }   `json:"config"`
		Layers []struct{ Digest string } `json:"layers"`
	}
	if err := json.Unmarshal(relayedManifest, &m); err != nil {
		return checked, fmt.Errorf("relayed manifest does not parse: %w", err)
	}
	digests := []string{m.Config.Digest}
	for _, l := range m.Layers {
		digests = append(digests, l.Digest)
	}
	for _, d := range digests {
		got, err := wireDo(http.MethodGet, base+"/blobs/"+d)
		if err != nil {
			return checked, err
		}
		if got.status != http.StatusOK {
			return checked, fmt.Errorf("GET blob %s: status %d, so nothing was compared", d, got.status)
		}
		if !bytes.Equal(got.body, f.blobs[d]) {
			return checked, fmt.Errorf("IDENTITY: blob %s differs from upstream's bytes", d)
		}
		if sum := "sha256:" + hexOf(sha256.New(), got.body); sum != d {
			return checked, fmt.Errorf("COHERENCE: blob %s hashes to %s", d, sum)
		}
		checked += 2
	}
	return checked, nil
}

func TestOciRelayPreservesManifestAndLayerDigests(t *testing.T) {
	f := newOciFixture(t)
	gate := integrityGate(t, "oci", f.Server)

	checked, err := checkOciIntegrity(gate.URL, f)
	if err != nil {
		t.Fatalf("the OCI relay does not preserve integrity material: %v", err)
	}
	// 1 (HEAD) + 2 manifests x 4 + 3 blobs x 2.
	if checked != 15 {
		t.Fatalf("expected 15 comparisons, ran %d; this test is asserting less than it claims", checked)
	}

	isManifest := func(r *http.Request) bool { return strings.Contains(r.URL.Path, "/manifests/") }
	for _, c := range []struct {
		name, wantIn string
		match        func(*http.Request) bool
		edit         func(http.Header, []byte) []byte
	}{
		{"a forged layer (one flipped byte)", "blob",
			func(r *http.Request) bool { return strings.Contains(r.URL.Path, "/blobs/") },
			func(_ http.Header, b []byte) []byte { c := bytes.Clone(b); c[len(c)/2] ^= 0x01; return c }},
		{"a manifest re-serialised with the SAME meaning", "manifest",
			func(r *http.Request) bool { return isManifest(r) && r.Method == http.MethodGet },
			func(_ http.Header, b []byte) []byte {
				var v any
				_ = json.Unmarshal(b, &v)
				out, _ := json.Marshal(v)
				return out
			}},
		{"a forged Docker-Content-Digest on the tag HEAD", "HEAD manifest",
			func(r *http.Request) bool { return isManifest(r) && r.Method == http.MethodHead },
			func(h http.Header, b []byte) []byte {
				h.Set("Docker-Content-Digest", "sha256:"+strings.Repeat("0", 64))
				return b
			}},
		{"a dropped Docker-Content-Digest header", "Docker-Content-Digest",
			func(r *http.Request) bool { return isManifest(r) && r.Method == http.MethodGet },
			func(h http.Header, b []byte) []byte { h.Del("Docker-Content-Digest"); return b }},
		{"a rewritten manifest media type", "Content-Type",
			func(r *http.Request) bool { return isManifest(r) && r.Method == http.MethodGet },
			func(h http.Header, b []byte) []byte { h.Set("Content-Type", "application/json"); return b }},
	} {
		t.Run("control: "+c.name, func(t *testing.T) {
			hits := 0
			front := tamperingFront(t, gate, c.match,
				func(h http.Header, b []byte) []byte { hits++; return c.edit(h, b) })
			_, err := checkOciIntegrity(front.URL, f)
			if hits == 0 {
				t.Fatal("CONTROL DID NOT FIRE: the tampering front edited nothing")
			}
			if err == nil {
				t.Fatalf("CONTROL FAILED TO FAIL: %s went undetected, so the green result above proves nothing", c.name)
			}
			if !strings.Contains(err.Error(), c.wantIn) {
				t.Fatalf("the checker failed for the wrong reason: %v (expected it to mention %q)", err, c.wantIn)
			}
		})
	}
}
