package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Issue #117: a registry that does not ANSWER is not a registry that says "no repo".
//
// !93 taught the OCI lookup to file a 429/5xx as transient. It left the four places
// where there is no status at all -- the connection refused, reset, or timed out on
// the manifest probe, the token fetch, the manifest, or the config blob -- returning
// the raw transport error, which Evaluate's catch-all files as UNSCORABLE: a verdict
// about the image. Under the shipped defaults (FW_BYTE_GATE=allow-but-log,
// FW_UNSCORABLE_POLICY=block) that serves the LAYER BLOB with only a log line, because
// the byte gate treats unscorable as an absence of trust (D72, visibility-first) and a
// dead socket was being filed as exactly that; the manifest route answers a 403 that
// reads as a verdict, which D102 forbids. Under unscorable=allow everything is served.
// The #60 shape, reachable by a third route.
//
// Measured before it was reasoned: the #96 reproduction exhausted the host's ephemeral
// ports so a random subset of the mode matrix's dials failed, and every cell that
// changed VERDICT was an OCI cell -- `lowscore/unscorable=allow` recorded as 200
// allowed. npm, PyPI and Maven cells in the same runs diverged only as "unavailable",
// because they already wrap the same failure.

// ociDropAt names which step of the OCI lookup the fixture kills the connection on.
// An empty value drops nothing, which is the control that proves the auth dance
// completes -- without it, a fixture whose token leg was simply broken would make
// every case Unavailable and this file would pass while measuring nothing.
const (
	ociDropNothing  = ""
	ociDropProbe    = "probe"    // the unauthenticated manifest GET that draws the challenge
	ociDropToken    = "token"    // the realm's token endpoint
	ociDropManifest = "manifest" // the authenticated manifest GET
	ociDropConfig   = "config"   // the config blob the source label is read from
)

var ociDropSteps = []string{ociDropProbe, ociDropToken, ociDropManifest, ociDropConfig}

// newOciDroppingUpstream is a registry with a real Bearer dance -- 401 + challenge,
// token, authenticated manifest, config blob, layer -- that kills the TCP connection
// at exactly one step. Killing rather than answering is the point: ociTransient never
// sees a status, so this exercises the path !93 did not.
//
// The layer blob is always served, for the same reason newOciSpyUpstreamOpts serves
// it under failMeta: the bytes must be one relay away while evaluation is impossible,
// or "nothing was delivered" could not tell the gate holding from the registry being
// down.
func newOciDroppingUpstream(dropAt string) *ociSpyUpstream {
	u := &ociSpyUpstream{}
	configBody := `{"config":{"Labels":{"org.opencontainers.image.source":"https://github.com/evil/badimage"}}}`
	configDigest := ociDigest(configBody)
	layerDigest := ociDigest(spyLayerBody)

	drop := func(w http.ResponseWriter) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			panic("fixture cannot hijack: " + err.Error())
		}
		conn.Close()
	}

	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hit = append(u.hit, r.URL.Path)
		u.mu.Unlock()

		p := r.URL.Path
		switch {
		case p == "/token":
			if dropAt == ociDropToken {
				drop(w)
				return
			}
			fmt.Fprint(w, `{"token":"pull-token"}`)
		case strings.Contains(p, "/manifests/"):
			if r.Header.Get("Authorization") == "" {
				// The probe. A real registry challenges here.
				if dropAt == ociDropProbe {
					drop(w)
					return
				}
				w.Header().Set("WWW-Authenticate",
					fmt.Sprintf(`Bearer realm="%s/token",service="registry",scope="repository:%s:pull"`, u.Server.URL, spyImage))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if dropAt == ociDropManifest {
				drop(w)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			fmt.Fprintf(w, `{"config":{"digest":%q},"layers":[{"digest":%q}]}`, configDigest, layerDigest)
		case strings.HasSuffix(p, "/blobs/"+configDigest):
			if dropAt == ociDropConfig {
				drop(w)
				return
			}
			fmt.Fprint(w, configBody)
		case strings.HasSuffix(p, "/blobs/"+layerDigest):
			fmt.Fprint(w, spyLayerBody)
		default:
			fmt.Fprint(w, "{}")
		}
	}))
	return u
}

// TestOciFailedConnectionIsUnavailableNotUnscorable pins the classification at the
// Decision level, one drop point at a time, so a future edit that fixes three sites
// and misses the fourth fails by name.
func TestOciFailedConnectionIsUnavailableNotUnscorable(t *testing.T) {
	for _, step := range ociDropSteps {
		t.Run("drop-"+step, func(t *testing.T) {
			up := newOciDroppingUpstream(step)
			defer up.Close()
			p := newTestProxy(t, up.Server, func(cfg *Config) {
				cfg.Ecosystem = "oci"
				cfg.ScoreThreshold = 1.0 // healthy, this image is ALLOWED: nothing here is a disguised deny
			})
			d := p.firewall.Evaluate(spyImage + ":latest")
			if !d.Unavailable {
				t.Fatalf("connection dropped at %q: decision = %+v\n  want Unavailable -- the registry never answered, "+
					"so there is no verdict; anything else is a claim about the image made without looking", step, d)
			}
			if d.Allowed {
				t.Fatalf("connection dropped at %q: Allowed=true alongside Unavailable -- an outage must never allow", step)
			}
		})
	}

	// CONTROL: with nothing dropped the same dance completes and the image is judged
	// on its merits. This is what makes the loop above evidence rather than a fixture
	// that fails for its own reasons.
	t.Run("control-healthy", func(t *testing.T) {
		up := newOciDroppingUpstream(ociDropNothing)
		defer up.Close()
		p := newTestProxy(t, up.Server, func(cfg *Config) {
			cfg.Ecosystem = "oci"
			cfg.ScoreThreshold = 1.0
		})
		d := p.firewall.Evaluate(spyImage + ":latest")
		if d.Unavailable || !d.Allowed || !d.HasScore {
			t.Fatalf("healthy registry: decision = %+v; want a scored ALLOW -- the fixture's auth dance is broken, "+
				"so the drop cases above prove nothing", d)
		}
		for _, must := range []string{"/token", "/manifests/", "/blobs/"} {
			if !up.contacted(must) {
				t.Errorf("healthy registry was never asked for %s -- the fixture does not exercise that step, "+
					"so dropping it could not have been tested (saw %v)", must, up.paths())
			}
		}
	})
}

// TestOciDeadSocketDoesNotServeAHardDeniedImage is the #60-shaped consequence over
// HTTP, under the SHIPPED default byte gate and both unscorable policies. Measured
// on the unfixed code: the layer was DELIVERED (a 200 with the payload) at every drop
// point under BOTH policies, because on the blob route the byte gate serves an
// unscorable image visibility-first (D72) -- the default is not the safe side here.
// The explanation is asserted as well as the delivery, so a withheld-with-the-wrong-
// reason outcome (a verdict about an image nobody looked at) cannot pass either.
func TestOciDeadSocketDoesNotServeAHardDeniedImage(t *testing.T) {
	blobPath := "/v2/" + spyImage + "/blobs/" + ociDigest(spyLayerBody)

	for _, policy := range []string{"allow", "block"} {
		for _, step := range ociDropSteps {
			t.Run("unscorable="+policy+"/drop-"+step, func(t *testing.T) {
				up := newOciDroppingUpstream(step)
				defer up.Close()
				p := newTestProxy(t, up.Server, func(cfg *Config) {
					cfg.Ecosystem = "oci"
					cfg.ScoreThreshold = 1.0 // allowed on a healthy registry -- see the control below
					cfg.UnscorablePolicy = policy
					cfg.ByteGate = byteGateAllowButLog // the shipped default
				})
				code, body := get(t, p, blobPath)
				if code == http.StatusOK || strings.Contains(body, spyLayerBody) {
					t.Fatalf("connection dropped at %q, unscorable=%s: layer DELIVERED (status %d) -- "+
						"a dead socket to the registry became a policy bypass (#117 / the #60 shape)", step, policy, code)
				}
				if code != http.StatusForbidden || !strings.Contains(body, unavailableErrMsg) {
					t.Errorf("connection dropped at %q, unscorable=%s: status %d, body %q\n  want 403 with the UNAVAILABLE "+
						"explanation (D102): withheld because we could not look, not because of anything about the image",
						step, policy, code, body)
				}
				if strings.Contains(body, blockErrMsg) {
					t.Errorf("connection dropped at %q, unscorable=%s: body reads as a VERDICT (%q) when nothing was evaluated",
						step, policy, body)
				}
				if up.contacted(ociDigest(spyLayerBody)) {
					t.Errorf("connection dropped at %q, unscorable=%s: the layer was fetched from upstream -- bytes moved "+
						"even if they were not relayed", step, policy)
				}
			})
		}
	}

	// CONTROL: the same image, same config, healthy registry -> the layer IS delivered.
	// Without this, a proxy that refused every OCI blob would pass everything above.
	t.Run("control-healthy-delivers", func(t *testing.T) {
		up := newOciDroppingUpstream(ociDropNothing)
		defer up.Close()
		p := newTestProxy(t, up.Server, func(cfg *Config) {
			cfg.Ecosystem = "oci"
			cfg.ScoreThreshold = 1.0
			cfg.ByteGate = byteGateAllowButLog
		})
		code, body := get(t, p, blobPath)
		if code != http.StatusOK || !strings.Contains(body, spyLayerBody) {
			t.Fatalf("healthy registry: status %d, body %q -- the layer must be delivered for an allowed image, "+
				"or the withheld cases above are vacuous", code, body)
		}
	})
}
