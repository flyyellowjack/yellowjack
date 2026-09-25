package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// Signed artifact URLs end to end through the proxy (issue #72 / #67-npm).
//
// urlsign_test.go covers the primitive. This file covers the two things wiring it up
// has to get right: that we MINT a signature real clients can carry, and that the byte
// route REFUSES a package prefix paired with an object path we never signed with it.

// signedProxy builds a test proxy with URL signing turned on.
func signedProxy(t *testing.T, upstream *httptest.Server, extra func(*Config)) *proxyServer {
	t.Helper()
	return newTestProxy(t, upstream, func(c *Config) {
		c.URLSigningKey = testKey
		if extra != nil {
			extra(c)
		}
	})
}

// packumentUpstream serves a packument whose one release points at a tarball, plus the
// tarball bytes for any "/-/" path. onTarball fires when bytes are actually fetched —
// how these tests detect a BYPASS rather than only reading the status the client saw.
func packumentUpstream(t *testing.T, pkg string, onTarball func(*http.Request)) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := url.PathUnescape(r.URL.EscapedPath())
		switch {
		case strings.Contains(p, "/-/"):
			if onTarball != nil {
				onTarball(r)
			}
			w.Write([]byte("raw-tarball-bytes"))
		case p == "/"+pkg:
			w.Write([]byte(`{"versions":{"1.0.0":{"dist":{"tarball":"` +
				srv.URL + `/` + pkg + `/-/` + pkg + `-1.0.0.tgz"}}}}`))
		case p == "/"+pkg+"/latest":
			w.Write([]byte(`{"repository":"github.com/acme/` + pkg + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	return srv
}

var sigRe = regexp.MustCompile(`_yjsig=([A-Za-z0-9_-]+)`)

// A minted tarball URL must carry a signature that this deployment can verify for the
// exact (ecosystem, package, object path) it was minted for.
func TestSignedMintAddsVerifiableSignature(t *testing.T) {
	upstream := packumentUpstream(t, "lodash", nil)
	defer upstream.Close()

	p := signedProxy(t, upstream, nil)
	req := httptest.NewRequest(http.MethodGet, "http://firewall.local:8080/lodash", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "/_tarball/lodash/lodash/-/lodash-1.0.0.tgz") {
		t.Fatalf("tarball URL not rewritten through /_tarball/<pkg>/: %s", body)
	}
	m := sigRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("minted tarball URL carries no %s: %s", sigParam, body)
	}
	if !p.signer.Verify("npm", "lodash", "/lodash/-/lodash-1.0.0.tgz", m[1]) {
		t.Errorf("the signature we minted does not verify for the object path we minted it for")
	}
}

// With signing off — the default — the rewrite must be exactly what it was before this
// feature existed. This is the regression guard on the opt-in half of D103.
func TestSignedMintUnchangedWhenSigningOff(t *testing.T) {
	upstream := packumentUpstream(t, "lodash", nil)
	defer upstream.Close()

	p := newTestProxy(t, upstream, nil) // no key
	req := httptest.NewRequest(http.MethodGet, "http://firewall.local:8080/lodash", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, sigParam) {
		t.Errorf("a signature was minted with no signing key configured: %s", body)
	}
	if !strings.Contains(body, "http://firewall.local:8080/_tarball/lodash/lodash/-/lodash-1.0.0.tgz") {
		t.Errorf("the unsigned rewrite changed shape: %s", body)
	}
}

// The #67 confused deputy itself, end to end.
//
// An ALLOWED package's prefix is paired with a DIFFERENT package's object path: the
// firewall evaluates the prefix, then forwards the object path, handing over bytes it
// never rendered a verdict about.
//
// THE CONTROL HERE WAS INVERTED BY D159, deliberately. It used to assert that the bypass
// still reproduced with signing off — correct at the time, because the signature was the
// only thing that closed it, so "signing off still leaks" was the evidence that the
// signed subtest below was testing the signature rather than some unrelated refusal.
// D159 closed the hole in the DEFAULT deployment with an exact prefix/object-path
// binding, so that control now asserts the opposite: no key, still refused.
//
// That leaves the signed subtest needing a different guarantee, because a cross-package
// attack is now refused by the binding before the signature is ever consulted — its 403
// would prove nothing about signing. So it uses an attack the binding CANNOT catch: the
// prefix and the object path name the SAME package and differ only in version. Only the
// signature can refuse that, which is the point of having it.
func TestSignedTarballConfusedDeputyRefused(t *testing.T) {
	t.Run("control: the default deployment, with no signing key, already refuses it", func(t *testing.T) {
		const crossPackage = "http://fw.local/_tarball/lodash/evil-pkg/-/evil-pkg-1.0.0.tgz"

		var fetched string
		upstream := packumentUpstream(t, "lodash", func(r *http.Request) { fetched = r.URL.EscapedPath() })
		defer upstream.Close()

		p := newTestProxy(t, upstream, nil) // signing OFF — the out-of-the-box posture
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, crossPackage, nil))

		if rec.Code == http.StatusOK {
			t.Errorf("status = %d — the #67 bypass reproduces in the DEFAULT deployment, which is "+
				"exactly the claim D159 makes it must not (body: %s)", rec.Code, rec.Body.String())
		}
		if fetched != "" {
			t.Errorf("BYPASS: upstream was fetched (%q) with no signing key configured", fetched)
		}
	})

	t.Run("signed deployment refuses a signature minted for a different object path", func(t *testing.T) {
		// Same package on both halves, so the binding is satisfied and cannot be what
		// refuses. A real attack: an attacker with a lockfile URL for one version tries
		// to pull a different one.
		const sameNameOtherVersion = "http://fw.local/_tarball/lodash/lodash/-/lodash-9.9.9.tgz"

		var fetched string
		upstream := packumentUpstream(t, "lodash", func(r *http.Request) { fetched = r.URL.EscapedPath() })
		defer upstream.Close()

		p := signedProxy(t, upstream, nil)
		// Anti-vacuity: prove the binding really does pass this path, so a 403 below is
		// attributable to the signature and not to the check that runs before it.
		if !npmObjectPathBindsToPackage("lodash", "/lodash/-/lodash-9.9.9.tgz") {
			t.Fatal("control: the binding rejects this path, so the signature is not what " +
				"this subtest would be measuring")
		}
		// A signature that is perfectly valid — for the object path it was minted with.
		sig := p.signer.Sign("npm", "lodash", "/lodash/-/lodash-1.0.0.tgz")
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, sameNameOtherVersion+"?"+sigParam+"="+sig, nil))

		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 — a signature minted for one object path must not "+
				"authorise another (body: %s)", rec.Code, rec.Body.String())
		}
		if fetched != "" {
			t.Errorf("BYPASS: upstream was fetched (%q) despite the signature not covering this path", fetched)
		}
	})
}

// With signing on, a "/_tarball/" URL carrying no signature is refused. This is the case
// an attacker gets for free by simply omitting the parameter, and it is also what an
// operator sees for lockfiles minted before they enabled the feature.
func TestSignedTarballUnsignedMintedShapeRefused(t *testing.T) {
	var fetched bool
	upstream := packumentUpstream(t, "lodash", func(*http.Request) { fetched = true })
	defer upstream.Close()

	p := signedProxy(t, upstream, nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"http://fw.local/_tarball/lodash/lodash/-/lodash-1.0.0.tgz", nil))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for an unsigned /_tarball/ URL (body: %s)", rec.Code, rec.Body.String())
	}
	if fetched {
		t.Error("BYPASS: upstream was fetched for an unsigned /_tarball/ URL")
	}
}

// A correctly signed URL still installs. Signing must not break the ordinary path.
func TestSignedTarballValidSignatureAllowed(t *testing.T) {
	upstream := packumentUpstream(t, "lodash", nil)
	defer upstream.Close()

	p := signedProxy(t, upstream, nil)
	sig := p.signer.Sign("npm", "lodash", "/lodash/-/lodash-1.0.0.tgz")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"http://fw.local/_tarball/lodash/lodash/-/lodash-1.0.0.tgz?"+sigParam+"="+sig, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a correctly signed URL (body: %s)", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "raw-tarball-bytes" {
		t.Errorf("tarball bytes altered: %q", rec.Body.String())
	}
}

// npm's OWN "/<pkg>/-/<file>.tgz" shape must keep working with signing on. We never
// minted it, every lockfile in the wild records it, and modern npm/pnpm construct it by
// swapping only the origin — so requiring a signature there would break installs
// wholesale. It is safe unsigned because its identity comes from the same path it
// forwards, leaving nothing to confuse.
func TestSignedTarballNativeShapeStillAllowed(t *testing.T) {
	upstream := packumentUpstream(t, "lodash", nil)
	defer upstream.Close()

	p := signedProxy(t, upstream, nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://fw.local/lodash/-/lodash-1.0.0.tgz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — npm's native lockfile URL shape must not require a "+
			"signature we never minted (body: %s)", rec.Code, rec.Body.String())
	}
}

// Our signature parameter is ours: the upstream registry must never receive it, and any
// other query the URL carried must survive untouched.
func TestSignedTarballSignatureStrippedBeforeUpstream(t *testing.T) {
	var gotQuery string
	upstream := packumentUpstream(t, "lodash", func(r *http.Request) { gotQuery = r.URL.RawQuery })
	defer upstream.Close()

	p := signedProxy(t, upstream, nil)
	sig := p.signer.Sign("npm", "lodash", "/lodash/-/lodash-1.0.0.tgz")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"http://fw.local/_tarball/lodash/lodash/-/lodash-1.0.0.tgz?keep=1&"+sigParam+"="+sig, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(gotQuery, sigParam) {
		t.Errorf("upstream received our signature parameter: %q", gotQuery)
	}
	if gotQuery != "keep=1" {
		t.Errorf("upstream query = %q, want %q — unrelated parameters must pass through", gotQuery, "keep=1")
	}
}

// --- PyPI ---------------------------------------------------------------------
//
// PyPI's /_files/ relay is the other route with the confusable shape. Its filename
// grammar check (pypiFilenameBindsToPackage) already closed #67 there and STAYS; the
// signature is exact where that check is a heuristic, so the two run together.

const pypiFilesHost = "https://files.example.test"

func pypiIndexUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/six/json":
			w.Write([]byte(`{"info":{"project_urls":{"Source":"https://github.com/benjaminp/six"}}}`))
		case "/simple/six/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<a href="` + pypiFilesHost + `/packages/aa/six-1.0-py3-none-any.whl#sha256=deadbeef">six-1.0</a>`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func signedPypiProxy(t *testing.T, upstream *httptest.Server) *proxyServer {
	t.Helper()
	return newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = pypiFilesHost
		c.PublicURL = "http://fw.local:8080"
		c.URLSigningKey = testKey
	})
}

// The minted index link must carry a verifiable signature — and the "#sha256=" integrity
// fragment must survive it. Order matters: a fragment is never sent to a server, so a
// signature appended AFTER it would silently never arrive.
func TestSignedPypiIndexMintsVerifiableSignature(t *testing.T) {
	upstream := pypiIndexUpstream(t)
	defer upstream.Close()

	p := signedPypiProxy(t, upstream)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://fw.local:8080/simple/six/", nil))

	body := rec.Body.String()
	if strings.Contains(body, pypiFilesHost) {
		t.Errorf("index still references the file host: %s", body)
	}
	m := sigRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("minted wheel URL carries no %s: %s", sigParam, body)
	}
	if !p.signer.Verify("pypi", "six", "/packages/aa/six-1.0-py3-none-any.whl", m[1]) {
		t.Error("the signature minted into the index does not verify for that object path")
	}
	if !strings.Contains(body, "#sha256=deadbeef") {
		t.Errorf("the integrity fragment did not survive signing: %s", body)
	}
	if strings.Index(body, sigParam) > strings.Index(body, "#sha256=") {
		t.Errorf("signature was appended AFTER the fragment, so it would never be sent: %s", body)
	}
}

// An unsigned /_files/ request is refused once signing is on. Every /_files/ URL is one
// we minted, so there is no legitimate unsigned caller.
func TestSignedPypiUnsignedFilesRefused(t *testing.T) {
	upstream := pypiIndexUpstream(t)
	defer upstream.Close()

	p := signedPypiProxy(t, upstream)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"http://fw.local:8080/_files/six/packages/aa/six-1.0-py3-none-any.whl", nil))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for an unsigned /_files/ URL (body: %s)", rec.Code, rec.Body.String())
	}
}

// A signature minted for one object path must not carry another — the same confused
// deputy as the npm leg, on the route where the filename check is the existing defence.
func TestSignedPypiConfusedDeputyRefused(t *testing.T) {
	upstream := pypiIndexUpstream(t)
	defer upstream.Close()

	p := signedPypiProxy(t, upstream)
	sig := p.signer.Sign("pypi", "six", "/packages/aa/six-1.0-py3-none-any.whl")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"http://fw.local:8080/_files/six/packages/zz/requests-2.31.0-py3-none-any.whl?"+sigParam+"="+sig, nil))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 — six's signature must not authorise requests' object path (body: %s)",
			rec.Code, rec.Body.String())
	}
}

// PEP 658: pip fetches a wheel's METADATA without the wheel by appending ".metadata" to
// the distribution URL — to the WHOLE URL, query included, so on a signed link the
// suffix lands on the signature instead of the path. Found by running real pip, which is
// the only thing that could have found it: every unit test until now built the URL the
// way we imagined pip would.
func TestSignedPypiMetadataDerivativeAllowed(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/pypi/six/json":
			w.Write([]byte(`{"info":{"project_urls":{"Source":"https://github.com/benjaminp/six"}}}`))
		default:
			gotPath = r.URL.Path
			w.Write([]byte("METADATA-BYTES"))
		}
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = upstream.URL
		c.PublicURL = "http://fw.local:8080"
		c.URLSigningKey = testKey
	})
	// The signature covers the WHEEL; pip mangles it exactly as below.
	sig := p.signer.Sign("pypi", "six", "/packages/aa/six-1.0-py3-none-any.whl")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"http://fw.local:8080/_files/six/packages/aa/six-1.0-py3-none-any.whl?"+
			sigParam+"="+sig+pep658MetadataSuffix, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — pip's PEP 658 metadata fetch must work against a signed "+
			"link (body: %s)", rec.Code, rec.Body.String())
	}
	if want := "/packages/aa/six-1.0-py3-none-any.whl" + pep658MetadataSuffix; gotPath != want {
		t.Errorf("upstream path = %q, want %q — the suffix must be put back on the OBJECT, not left "+
			"on the query", gotPath, want)
	}
}

// The attacker half of the same allowance: permitting the ".metadata" derivative must not
// become a way to reach an object we never signed. Verification still happens against the
// base path, so a valid signature for one wheel cannot carry another wheel's metadata.
func TestSignedPypiMetadataDerivativeCannotBeConfused(t *testing.T) {
	fetched := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pypi/six/json" {
			w.Write([]byte(`{"info":{"project_urls":{"Source":"https://github.com/benjaminp/six"}}}`))
			return
		}
		fetched = true
		w.Write([]byte("METADATA-BYTES"))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream, func(c *Config) {
		c.Ecosystem = "pypi"
		c.FilesUpstream = upstream.URL
		c.PublicURL = "http://fw.local:8080"
		c.URLSigningKey = testKey
	})
	sig := p.signer.Sign("pypi", "six", "/packages/aa/six-1.0-py3-none-any.whl")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"http://fw.local:8080/_files/six/packages/zz/requests-2.31.0-py3-none-any.whl?"+
			sigParam+"="+sig+pep658MetadataSuffix, nil))

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 — six's signature must not carry another package's metadata "+
			"object (body: %s)", rec.Code, rec.Body.String())
	}
	if fetched {
		t.Error("BYPASS: upstream was fetched for an object the signature does not cover")
	}
}
