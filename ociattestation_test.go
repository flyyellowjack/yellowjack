package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// A REAL `docker pull` OF AN ALLOWED IMAGE FAILED, AND EVERY OCI LEG WAS GREEN (#129).
//
// The Docker daemon does not stop at the platform manifest. It GETs the buildx
// ATTESTATION manifests the index lists -- children with the placeholder platform
// unknown/unknown -- and those declare no org.opencontainers.image.source, because they
// are in-toto documents ABOUT the image rather than an image. So LookupRepo resolved
// nothing, Evaluate returned unscorable, and the default FW_UNSCORABLE_POLICY=block
// refused the pull AFTER every real layer had already been served:
//
//	GET [verdict-allowed] library/memcached@sha256:fb019eac -> allowed  (linux/amd64)
//	GET [verdict-BLOCKED] library/memcached@sha256:fe04e0ef -> unscorable ... policy=block
//	=> error from registry: blocked by firewall: unscorable ...
//
// Reproduced against Docker Hub directly and behind a registry:2 pull-through, and
// isolated by a paired control -- same gate, same image, FW_UNSCORABLE_POLICY=block
// fails and =allow succeeds, nothing else differing. 16 of 16 sampled Docker Hub
// official images carry attestations, this tree's own registry:2 and verdaccio included.
//
// WHY NO TEST SAW IT: the OCI e2e drives `crane`, which resolves one platform and never
// asks for an attestation. A rig that names an ecosystem is testing one CLIENT of it.
//
// THE FIX IS NOT "FETCH THEM". #126 deliberately does not fetch attestation children,
// because half of every real index is attestations and the anonymous pull budget has
// taken this suite down before. Binding needs no fetch: the digest is already in the
// index bytes the resolver parsed. So these tests pin the two halves APART -- bound
// (here) and not fetched (TestAttestationChildrenAreNotFetched, which must stay green).

// attestationRepoLabel is what the rig's "ok" children put in
// org.opencontainers.image.source; attestationRepo is what LookupRepo returns for it,
// after normalizeGitHub drops the scheme. Two constants rather than one because
// conflating them is how a test asserts the wrong value and calls the rig broken.
const (
	attestationRepoLabel = "https://github.com/acme/ma"
	attestationRepo      = "github.com/acme/ma"
)

func newAttestationEcosystem(up *maUpstream) ociEcosystem {
	return ociEcosystem{
		base:         up.URL,
		bindings:     newOCIBlobBindings(),
		repoByDigest: newTTLLRU[string](ociDigestRepoTTL, 0),
	}
}

// TestAttestationManifestInheritsTheAllowedImagesVerdict is #129 itself, at the layer
// the developer meets it: a request the Docker daemon makes on every pull.
//
// The tag leg is not decoration. It is what makes the digest leg mean something: if the
// allowed image were refused too, a 403 on its attestation would say nothing about
// attestations.
func TestAttestationManifestInheritsTheAllowedImagesVerdict(t *testing.T) {
	up := newMAUpstream(0, 2)
	defer up.Close()
	if len(up.attestChildren) == 0 {
		t.Fatal("the rig built no attestation children, so this test cannot fail")
	}

	p := newTestProxy(t, up.Server, func(c *Config) {
		c.Ecosystem = "oci"
		c.ScoreThreshold = 5.0
		c.UnscorablePolicy = "block"
	})

	if code := ociGet(t, p, "/v2/"+maImage+"/manifests/ok"); code != http.StatusOK {
		t.Fatalf("the allowed tag itself = %d, want 200 — a gate refusing the image cannot "+
			"demonstrate anything about the image's attestations", code)
	}

	for i, dig := range up.attestChildren {
		code := ociGet(t, p, "/v2/"+maImage+"/manifests/"+dig)
		if code != http.StatusOK {
			t.Errorf("attestation manifest %d (%s) = %d, want 200.\n"+
				"  This is the request a real `docker pull` makes after the platform manifest,\n"+
				"  and refusing it kills the pull of an image we just ALLOWED — with every\n"+
				"  layer already delivered. The attestation declares no source repo because it\n"+
				"  is not an image; it must inherit the verdict of the index that enumerated\n"+
				"  it, exactly as that index's layers do (D164).", i, dig, code)
		}
	}
}

// TestAttestationManifestOfABlockedImageIsAlsoBlocked is the direction that must not
// regress, and it is the reason the fix is a BINDING rather than an exemption.
//
// Exempting attestations from judgement would have fixed the pull just as well and would
// have opened a hole: an attacker controls what their index calls an attestation, so
// "unknown/unknown means do not judge it" hands them a manifest we never look at. The
// verdict is inherited instead, so a blocked image's attestations are blocked with it.
//
// IT ASSERTS THE REASON, NOT THE STATUS, AND THE FIRST VERSION OF THIS TEST DID NOT.
// Written against the "bad" tag it passed with the whole fix removed, because an
// unbound attestation resolves no repo and is refused as UNSCORABLE -- the same 403,
// for a reason that has nothing to do with the image. A status code shared with an
// impostor proves nothing (the sabotage leg caught this, not review).
//
// So the blocking here is done by the SCORE instead: threshold above the stub's fixed
// 7.5 refuses the image on its merits, and the two hypotheses then say different things.
//
//	bound   -> inherits the image's repo -> "score 7.5 < threshold 9"
//	unbound -> resolves no repo          -> "does not declare a usable source repository"
func TestAttestationManifestOfABlockedImageIsAlsoBlocked(t *testing.T) {
	up := newMAUpstream(0, 2)
	defer up.Close()

	p := newTestProxy(t, up.Server, func(c *Config) {
		c.Ecosystem = "oci"
		c.ScoreThreshold = 9.0 // above the stub's fixed 7.5: refused ON ITS SCORE
		c.UnscorablePolicy = "block"
	})

	body, code := ociGetBody(t, p, "/v2/"+maImage+"/manifests/ok")
	if code != http.StatusForbidden {
		t.Fatalf("the image itself = %d, want 403 — at threshold 9 the stub's 7.5 must "+
			"refuse it, or there is no blocked verdict for anything to inherit", code)
	}
	if strings.Contains(body, "does not declare a usable source repository") {
		t.Fatalf("the image was refused as UNSCORABLE, not on its score. This test needs a "+
			"score refusal, because unscorable is exactly the answer an UNBOUND attestation "+
			"gives and the two would be indistinguishable.\n  body: %s", body)
	}

	for i, dig := range up.attestChildren {
		body, code := ociGetBody(t, p, "/v2/"+maImage+"/manifests/"+dig)
		if code != http.StatusForbidden {
			t.Errorf("attestation manifest %d (%s) of a BLOCKED image = %d, want 403.\n"+
				"  Inheriting the index's verdict has to work in both directions. If this is\n"+
				"  200, the fix exempted attestations from judgement instead of binding them,\n"+
				"  and an index can then declare any child unknown/unknown to skip the gate.",
				i, dig, code)
			continue
		}
		if strings.Contains(body, "does not declare a usable source repository") {
			t.Errorf("attestation manifest %d (%s) was refused as UNSCORABLE, not by the "+
				"image's own verdict.\n"+
				"  The 403 is right and the REASON is wrong, which means the digest was never\n"+
				"  bound: it was judged alone, found to declare no source repo (it is a\n"+
				"  document, not an image) and refused on that. Under an ALLOWED image the\n"+
				"  same path returns 403 for a pull that should succeed — #129.\n  body: %s",
				i, dig, body)
		}
	}
}

// TestAttestationDigestsAreBoundWithoutBeingFetched is the guard on the fix itself.
//
// The cheap wrong fix is to drop the skip and fetch every child, which would work and
// would double the registry requests a cold resolve spends -- the exact cost #126 priced
// and refused. This asserts both properties at once: bound, and still never requested.
func TestAttestationDigestsAreBoundWithoutBeingFetched(t *testing.T) {
	up := newMAUpstream(0, 3)
	defer up.Close()

	eco := newAttestationEcosystem(up)
	repo, err := eco.LookupRepo(up.Client(), maImage+":ok")
	if err != nil {
		t.Fatalf("LookupRepo: %v", err)
	}
	if repo != attestationRepo {
		t.Fatalf("the image resolved to %q, want %q — the rig changed and every expectation "+
			"below is about the wrong value", repo, attestationRepo)
	}

	fetched := map[string]bool{}
	for _, ref := range up.manifestFetches() {
		fetched[ref] = true
	}

	for i, dig := range up.attestChildren {
		got, ok := eco.repoByDigest.get(ociBindingKey(maImage, dig))
		if !ok {
			t.Errorf("attestation %d (%s) is NOT bound: a GET by this digest resolves no repo, "+
				"reads as unscorable and refuses the pull (#129)", i, dig)
		} else if got != repo {
			t.Errorf("attestation %d (%s) bound to %q, want the image's own %q — an attestation "+
				"inherits the verdict of the index that listed it, so it must inherit the repo "+
				"that verdict was computed from", i, dig, got, repo)
		}
		if fetched[dig] {
			t.Errorf("attestation %d (%s) was FETCHED. Binding it must cost no request: the "+
				"digest is already in the index we parsed, and half of every real index is "+
				"attestations, so fetching them doubles a cold resolve against the anonymous "+
				"pull budget (#126)", i, dig)
		}
	}
}

// attestUpstream serves one index with a single amd64 child and a single attestation
// child whose digest the "registry" has mangled. Separate from maUpstream on purpose:
// that rig's job is to be well formed, and #17's rule is that a gate distrusts what it
// FETCHES, not only what a client sends.
type attestUpstream struct {
	*httptest.Server
	layer string

	mu      sync.Mutex
	fetched []string
}

func newAttestUpstream(attestDigest string) *attestUpstream {
	u := &attestUpstream{layer: "ATT-AMD64-LAYER"}
	cfg := `{"config":{"Labels":{"org.opencontainers.image.source":"` + attestationRepoLabel + `"}}}`
	amd := fmt.Sprintf(`{"config":{"digest":%q},"layers":[{"digest":%q}]}`, ociDigest(cfg), ociDigest(u.layer))
	index := fmt.Sprintf(
		`{"manifests":[{"digest":%q,"platform":{"architecture":"amd64","os":"linux"}},`+
			`{"digest":%q,"platform":{"architecture":"unknown","os":"unknown"}}]}`,
		ociDigest(amd), attestDigest)

	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if i := strings.LastIndex(p, "/manifests/"); i >= 0 {
			ref := p[i+len("/manifests/"):]
			u.mu.Lock()
			u.fetched = append(u.fetched, ref)
			u.mu.Unlock()
			if ref == ociDigest(amd) {
				fmt.Fprint(w, amd)
				return
			}
			fmt.Fprint(w, index)
			return
		}
		if i := strings.LastIndex(p, "/blobs/"); i >= 0 && p[i+len("/blobs/"):] == ociDigest(cfg) {
			fmt.Fprint(w, cfg)
			return
		}
		fmt.Fprint(w, "{}")
	}))
	return u
}

// TestAMalformedAttestationDigestIsNotBound pins the grammar check on the binding path.
//
// The digest recorded is upstream-supplied and goes straight into a map key, so it gets
// the same check the fetched path gets (#17). The resolve must still SUCCEED: a corrupt
// attestation entry is not a reason to fail an image whose platform child is fine.
func TestAMalformedAttestationDigestIsNotBound(t *testing.T) {
	const junk = "sha256:../../etc/passwd"
	up := newAttestUpstream(junk)
	defer up.Close()

	eco := ociEcosystem{
		base:         up.URL,
		bindings:     newOCIBlobBindings(),
		repoByDigest: newTTLLRU[string](ociDigestRepoTTL, 0),
	}
	repo, err := eco.LookupRepo(up.Client(), "library/att:ok")
	if err != nil {
		t.Fatalf("a malformed ATTESTATION entry broke a resolve whose platform child is "+
			"perfectly good: %v", err)
	}
	if repo != attestationRepo {
		t.Fatalf("resolved %q, want %q", repo, attestationRepo)
	}
	if _, ok := eco.repoByDigest.get(ociBindingKey("library/att", junk)); ok {
		t.Errorf("the malformed digest %q was bound. It arrives from an upstream response "+
			"and becomes a map key, so it gets the same grammar check as a client-supplied "+
			"ref (#17)", junk)
	}
}

// TestAttestationBindingAssertionsCanFail is the negative control.
//
// Every assertion above is "this digest is present/absent in a map", the kind that goes
// quietly vacuous when a rig stops producing the thing being counted. These check the
// instrument rather than the subject.
func TestAttestationBindingAssertionsCanFail(t *testing.T) {
	up := newMAUpstream(0, 2)
	defer up.Close()

	if len(up.attestChildren) != 2 {
		t.Fatalf("the rig produced %d attestation children, want 2 — the tests above would "+
			"iterate over nothing and pass", len(up.attestChildren))
	}

	eco := newAttestationEcosystem(up)
	if _, err := eco.LookupRepo(up.Client(), maImage+":ok"); err != nil {
		t.Fatalf("LookupRepo: %v", err)
	}

	// A digest that was never in any index must NOT be bound, or the lookup is
	// answering yes to everything and the "is bound" assertions prove nothing.
	absent := ociDigest("A-MANIFEST-THAT-WAS-NEVER-IN-AN-INDEX")
	if _, ok := eco.repoByDigest.get(ociBindingKey(maImage, absent)); ok {
		t.Error("an unlisted digest reads as bound, so repoByDigest answers yes to anything " +
			"and none of the binding assertions above discriminate")
	}

	// And the index's own digest IS bound, so a miss above means "not recorded" rather
	// than "this ecosystem never recorded anything".
	if eco.repoByDigest.len() == 0 {
		t.Error("nothing at all was bound, so every 'not bound' assertion would pass for free")
	}
}
