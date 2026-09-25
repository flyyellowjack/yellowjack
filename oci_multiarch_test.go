package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// MULTI-ARCH IS THE NORMAL CASE, AND THE BLOB BINDING ONLY COVERED ONE ARCHITECTURE (#126).
//
// !135/D164 made an approved manifest vouch for its layers, so a blocked version's blobs
// cannot be fetched directly under an allowed version's name;
// TestBlobVerdictFollowsTheVersionThatEnumeratedIt pins that for a single-architecture
// image. resolveRepo followed `man.Manifests[0]` only, so for an INDEX just the first
// platform's blobs ever reached bindBlobs. The first child is conventionally linux/amd64,
// so the protection covered amd64 and left every ARM client exposed.
//
// Measured before the fix, with the rig below:
//
//	amd64 = child[0]  status=403  servedBlockedBytes=false   <- bound, verdict applied
//	arm64 = child[1]  status=200  servedBlockedBytes=true    <- unbound, bytes delivered
//
// Nothing had ever constructed a multi-arch index in a unit test, and no test referenced
// bindBlobs or boundPackage at all, so `Manifests[0]` was always the whole story.

const maImage = "library/ma"

// maUpstream serves ONE image at two multi-arch tags. Every child is a distinct manifest
// with its own config and layer, so a digest identifies (version, architecture) exactly.
//
//	"ok"  -> children declare a source repo  => stub scores 7.5 => allowed at 5.0
//	"bad" -> children declare none           => unscorable      => blocked
type maUpstream struct {
	*httptest.Server
	layOKAmd, layOKArm   string
	layBadAmd, layBadArm string
	cfgBadArm            string

	// attestChildren are the digests of the buildx ATTESTATION manifests in the index,
	// and attestLayers the layers they enumerate. Both are real and fetchable, so
	// "never requested" and "left unbound" are properties of the resolver rather than
	// of a registry that could not have served them anyway.
	attestChildren []string
	attestLayers   []string

	mu      sync.Mutex
	fetched []string // every manifest reference asked for, in order
	// failChild, when set, is a child digest the registry refuses to serve.
	failChild string
}

func newMAUpstream(extraChildren, attestations int) *maUpstream {
	u := &maUpstream{
		layOKAmd: "MA-OK-AMD64", layOKArm: "MA-OK-ARM64",
		layBadAmd: "MA-BAD-AMD64", layBadArm: "MA-BAD-ARM64",
	}
	cfgOKAmd := `{"config":{"Labels":{"org.opencontainers.image.source":"https://github.com/acme/ma","p":"amd64"}}}`
	cfgOKArm := `{"config":{"Labels":{"org.opencontainers.image.source":"https://github.com/acme/ma","p":"arm64"}}}`
	cfgBadAmd := `{"config":{"Labels":{"p":"amd64"}}}`
	u.cfgBadArm = `{"config":{"Labels":{"p":"arm64"}}}`

	child := func(cfg, layer string) string {
		return fmt.Sprintf(`{"config":{"digest":%q},"layers":[{"digest":%q}]}`, ociDigest(cfg), ociDigest(layer))
	}
	okAmd, okArm := child(cfgOKAmd, u.layOKAmd), child(cfgOKArm, u.layOKArm)
	badAmd, badArm := child(cfgBadAmd, u.layBadAmd), child(u.cfgBadArm, u.layBadArm)

	manifests := map[string]string{
		ociDigest(okAmd): okAmd, ociDigest(okArm): okArm,
		ociDigest(badAmd): badAmd, ociDigest(badArm): badArm,
	}
	blobs := map[string]string{
		ociDigest(cfgOKAmd): cfgOKAmd, ociDigest(cfgOKArm): cfgOKArm,
		ociDigest(cfgBadAmd): cfgBadAmd, ociDigest(u.cfgBadArm): u.cfgBadArm,
		ociDigest(u.layOKAmd): u.layOKAmd, ociDigest(u.layOKArm): u.layOKArm,
		ociDigest(u.layBadAmd): u.layBadAmd, ociDigest(u.layBadArm): u.layBadArm,
	}

	entry := func(m string, arch string) string {
		return fmt.Sprintf(`{"digest":%q,"platform":{"architecture":%q,"os":"linux"}}`, ociDigest(m), arch)
	}
	// extraChildren pads the index so the cap can be exercised. Each pad is a real,
	// fetchable manifest, so a test can count how many the resolver actually read.
	pad := make([]string, 0, extraChildren)
	for i := 0; i < extraChildren; i++ {
		cfg := fmt.Sprintf(`{"config":{"Labels":{"pad":"%d"}}}`, i)
		lay := fmt.Sprintf("MA-PAD-LAYER-%d", i)
		m := child(cfg, lay)
		manifests[ociDigest(m)] = m
		blobs[ociDigest(cfg)] = cfg
		blobs[ociDigest(lay)] = lay
		pad = append(pad, entry(m, fmt.Sprintf("pad%d", i)))
	}

	// Attestation children, declared with the buildx placeholder platform unknown/unknown.
	// MEASURED on Docker Hub: exactly half of every real index is these (alpine:3.20,
	// nginx:stable and python:3.12-slim are 8 platforms + 8 attestations each).
	att := make([]string, 0, attestations)
	for i := 0; i < attestations; i++ {
		cfg := fmt.Sprintf(`{"config":{"Labels":{"att":"%d"}}}`, i)
		lay := fmt.Sprintf("MA-ATTESTATION-LAYER-%d", i)
		m := child(cfg, lay)
		manifests[ociDigest(m)] = m
		blobs[ociDigest(cfg)] = cfg
		blobs[ociDigest(lay)] = lay
		u.attestChildren = append(u.attestChildren, ociDigest(m))
		u.attestLayers = append(u.attestLayers, lay)
		att = append(att, fmt.Sprintf(`{"digest":%q,"platform":{"architecture":"unknown","os":"unknown"}}`, ociDigest(m)))
	}

	index := func(a, b string) string {
		parts := append([]string{entry(a, "amd64"), entry(b, "arm64")}, pad...)
		parts = append(parts, att...)
		return `{"manifests":[` + strings.Join(parts, ",") + `]}`
	}
	okIndex, badIndex := index(okAmd, okArm), index(badAmd, badArm)

	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if i := strings.LastIndex(p, "/manifests/"); i >= 0 {
			ref := p[i+len("/manifests/"):]
			u.mu.Lock()
			u.fetched = append(u.fetched, ref)
			fail := u.failChild
			u.mu.Unlock()

			if ref != "" && ref == fail {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if m, ok := manifests[ref]; ok {
				fmt.Fprint(w, m)
				return
			}
			if ref == "bad" {
				fmt.Fprint(w, badIndex)
				return
			}
			fmt.Fprint(w, okIndex) // "ok" and "latest"
			return
		}
		if i := strings.LastIndex(p, "/blobs/"); i >= 0 {
			if b, ok := blobs[p[i+len("/blobs/"):]]; ok {
				fmt.Fprint(w, b)
				return
			}
		}
		fmt.Fprint(w, "{}")
	}))
	return u
}

func (u *maUpstream) manifestFetches() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.fetched...)
}

// TestBlockedMultiArchLayerIsRefusedOnEveryArchitecture is the bypass regression.
//
// The amd64 leg is the CONTROL and it is the reason the arm64 leg means anything: the
// binding demonstrably works for child[0], so an arm64 result that differs isolates the
// defect to index-following rather than to a broken rig.
func TestBlockedMultiArchLayerIsRefusedOnEveryArchitecture(t *testing.T) {
	up := newMAUpstream(0, 0)
	defer up.Close()

	p := newTestProxy(t, up.Server, func(c *Config) {
		c.Ecosystem = "oci"
		c.ScoreThreshold = 5.0
		c.UnscorablePolicy = "block"
		c.ByteGate = byteGateEnforce
	})

	// Anti-vacuity: the ALLOWED multi-arch tag must really be allowed, or a blanket
	// refusal would make every assertion below pass for the wrong reason.
	if code := ociGet(t, p, "/v2/"+maImage+"/manifests/ok"); code != http.StatusOK {
		t.Fatalf("the allowed multi-arch tag = %d, want 200 — a gate refusing everything "+
			"cannot demonstrate anything about the blocked one", code)
	}
	if code := ociGet(t, p, "/v2/"+maImage+"/manifests/bad"); code != http.StatusForbidden {
		t.Fatalf("the blocked multi-arch tag = %d, want 403 (unscorable + policy=block)", code)
	}

	for _, tc := range []struct{ name, layer string }{
		{"amd64, the first child (control: binding already worked here)", up.layBadAmd},
		{"arm64, a later child (#126: was served byte-for-byte)", up.layBadArm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, code := ociGetBody(t, p, "/v2/"+maImage+"/blobs/"+ociDigest(tc.layer))
			if strings.Contains(body, tc.layer) {
				t.Errorf("BYPASS: the BLOCKED version's layer was delivered byte-for-byte (status %d).\n"+
					"  A multi-arch index must vouch for EVERY child's layers, not just Manifests[0]'s —\n"+
					"  otherwise the version verdict covers one architecture and every other client\n"+
					"  falls back to the bare image name, which resolves as the allowed 'latest'.", code)
			}
			if code == http.StatusOK {
				t.Errorf("layer returned 200; want a refusal (body %q)", body)
			}
		})
	}
}

// TestMultiArchIndexBindsEveryChildsBlobs asserts the mechanism directly, because the
// bypass test above could in principle pass for an unrelated reason (a blanket refusal
// of unknown digests, say). This one names what must be in the binding table.
func TestMultiArchIndexBindsEveryChildsBlobs(t *testing.T) {
	up := newMAUpstream(0, 0)
	defer up.Close()

	eco := ociEcosystem{base: up.URL, bindings: newOCIBlobBindings()}
	if _, err := eco.LookupRepo(up.Client(), maImage+":bad"); err != nil {
		t.Fatalf("LookupRepo: %v", err)
	}

	for _, tc := range []struct{ name, layer string }{
		{"child[0] amd64 layer", up.layBadAmd},
		{"child[1] arm64 layer", up.layBadArm},
	} {
		if _, found := eco.boundPackage(maImage, ociDigest(tc.layer)); !found {
			t.Errorf("%s is NOT bound — its bytes are judged on the bare image name, so a "+
				"blocked version's layer is served whenever another version of the same "+
				"image is allowed", tc.name)
		}
	}

	// A digest belonging to NO child must stay unbound: the fallback in proxy.go is
	// deliberate (TestUnknownBlobDigestFallsBackToTheImageName), and a binding table
	// that answered for everything would make the assertions above vacuous.
	if _, found := eco.boundPackage(maImage, ociDigest("NOT-A-LAYER-OF-THIS-IMAGE")); found {
		t.Error("an unrelated digest resolved to a bound identity — the table is answering " +
			"for blobs it never saw, so 'bound' no longer means anything")
	}
}

// TestALaterChildFailingDoesNotBreakAWorkingResolve pins the property that makes this
// change safe to ship: it is ADDITIVE.
//
// Fetching every child means fetching manifests we never used to touch — an attestation
// manifest, a platform the registry has garbage-collected. If any of those failing broke
// the resolve, this fix would turn working pulls into outages. The FIRST child keeps its
// old error behaviour exactly, because it is the one the source label is read from.
func TestALaterChildFailingDoesNotBreakAWorkingResolve(t *testing.T) {
	up := newMAUpstream(0, 0)
	defer up.Close()

	// The arm64 child (child[1]) 500s. Its layer therefore cannot be bound, but the
	// resolve must still succeed on the strength of child[0].
	badArmChild := ""
	for _, ref := range []string{ociDigest(fmt.Sprintf(`{"config":{"digest":%q},"layers":[{"digest":%q}]}`,
		ociDigest(up.cfgBadArm), ociDigest(up.layBadArm)))} {
		badArmChild = ref
	}
	up.mu.Lock()
	up.failChild = badArmChild
	up.mu.Unlock()

	eco := ociEcosystem{base: up.URL, bindings: newOCIBlobBindings()}
	if _, err := eco.LookupRepo(up.Client(), maImage+":bad"); err != nil {
		t.Fatalf("a later child returning 500 broke the whole resolve: %v\n"+
			"  Before #126 that child was never fetched, so this would be a new outage "+
			"on images that work today", err)
	}
	if _, found := eco.boundPackage(maImage, ociDigest(up.layBadAmd)); !found {
		t.Error("child[0]'s layer is unbound even though child[0] was readable — one bad " +
			"child must not cost the others their binding")
	}
	// And the unreadable child's layer is simply unbound, which is the documented
	// pre-#126 fallback rather than a refusal.
	if _, found := eco.boundPackage(maImage, ociDigest(up.layBadArm)); found {
		t.Error("the unreadable child's layer is bound, so the test is not exercising the " +
			"failure path it claims to")
	}
}

// TestIndexChildrenAreBounded stops a hostile or broken registry turning one resolve into
// thousands of upstream fetches.
func TestIndexChildrenAreBounded(t *testing.T) {
	const extra = 12
	up := newMAUpstream(ociMaxIndexChildren+extra, 0)
	defer up.Close()

	eco := ociEcosystem{base: up.URL, bindings: newOCIBlobBindings()}
	if _, err := eco.LookupRepo(up.Client(), maImage+":bad"); err != nil {
		t.Fatalf("LookupRepo: %v", err)
	}

	// Fetches = the index itself (possibly re-read) plus at most the capped children.
	children := 0
	for _, ref := range up.manifestFetches() {
		if strings.HasPrefix(ref, "sha256:") {
			children++
		}
	}
	if children > ociMaxIndexChildren {
		t.Errorf("followed %d children, cap is %d — an index with thousands of entries would "+
			"turn one cold resolve into thousands of upstream requests", children, ociMaxIndexChildren)
	}
	if children == 0 {
		t.Fatal("no child manifest was fetched at all, so the cap assertion proves nothing")
	}
}

// TestAttestationChildrenAreNotFetched pins the HALF of the index we deliberately do not
// bind, and why that is safe.
//
// Binding every child (#126) costs one manifest fetch each on a cold resolve. Measured on
// Docker Hub, exactly half of every real index is buildx ATTESTATION manifests --
// alpine:3.20, nginx:stable and python:3.12-slim are 8 platforms + 8 attestations, golang
// 9 + 7, node 5 + 5 -- so skipping them halves the registry requests. That matters against
// the anonymous pull budget, which is the documented way this suite has been taken down
// before (scripts/dev.sh, the 2026-08-31 incident behind #106).
//
// It is safe because an attestation manifest's blobs are in-toto SBOM and provenance
// DOCUMENTS ABOUT the image, never the image's own layers: the fallback can serve
// metadata, never the software a blocked version would deliver.
//
// The rig makes the attestation manifests REAL and fetchable, so "never requested" is a
// property of the resolver and not of a registry that would have 404'd anyway -- remove
// the skip and this test goes red rather than passing for free.
func TestAttestationChildrenAreNotFetched(t *testing.T) {
	up := newMAUpstream(0, 2)
	defer up.Close()

	eco := ociEcosystem{base: up.URL, bindings: newOCIBlobBindings()}
	if _, err := eco.LookupRepo(up.Client(), maImage+":bad"); err != nil {
		t.Fatalf("LookupRepo: %v", err)
	}

	// ANTI-VACUITY, and it is the assertion that stops this becoming "skip everything":
	// both PLATFORM children must still be bound. Without this, deleting the whole child
	// loop would satisfy every check below.
	for _, tc := range []struct{ name, layer string }{
		{"child[0] amd64", up.layBadAmd},
		{"child[1] arm64", up.layBadArm},
	} {
		if _, found := eco.boundPackage(maImage, ociDigest(tc.layer)); !found {
			t.Errorf("%s layer is NOT bound — skipping attestations must not cost a PLATFORM "+
				"child its binding, which is the whole point of #126", tc.name)
		}
	}

	fetched := map[string]bool{}
	for _, ref := range up.manifestFetches() {
		fetched[ref] = true
	}
	for _, d := range up.attestChildren {
		if fetched[d] {
			t.Errorf("attestation manifest %s was fetched — half of every real index is "+
				"attestations, so fetching them doubles the registry requests a cold resolve "+
				"spends against the anonymous pull budget", d)
		}
	}
	// ...and their layers are therefore unbound, which is the documented pre-#126 fallback
	// to the bare image name, not a refusal.
	for _, lay := range up.attestLayers {
		if _, found := eco.boundPackage(maImage, ociDigest(lay)); found {
			t.Errorf("attestation layer %q is bound, so the skip did not happen and this test "+
				"is not exercising what it names", lay)
		}
	}
}
