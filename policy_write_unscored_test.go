package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRelayedWritesAreNotScored is the D134 regression assertion.
//
// D134 (2026-08-14): "uploads shouldn't be subjected to ossf scans, for sure,
// because, well, the fact that you are an employee gives you some implicit trust, and
// many of the elements of the scorecard are not applicable to in-house developed
// containers."
//
// So a Scorecard verdict on a push is the WRONG QUESTION, not a stricter answer to the
// right one — it describes the source repo of an image being consumed and says nothing
// about whether someone may publish one.
//
// WHY THIS TEST DID NOT EXIST BEFORE, which is the interesting part. #66 landed the
// write policy and its tests pass, but every one of them sets ScoreThreshold = 0 —
// "nothing is blocked on score, so only the write policy is in play". That isolates the
// policy beautifully and, in doing so, makes the scoring question unobservable. The
// defect survived a green suite: with FW_WRITE_POLICY=allow a push to a low-scoring
// image was refused with `BLOCKED: "library/badimage" scored 7.5, below required 9.9`.
// The default block SHADOWED it, so the only way to see it was to set the escape hatch
// the policy exists to provide.
//
// The threshold below is therefore load-bearing and must stay hostile: at 9.9 against a
// stub score of 7.5, the image WOULD be blocked as a pull. If a future edit drops it to
// 0 "to isolate the policy", this test stops testing anything.
func TestRelayedWritesAreNotScored(t *testing.T) {
	for _, policy := range []string{writePolicyAllow, writePolicyAllowButLog} {
		t.Run(policy, func(t *testing.T) {
			up := newOciSpyUpstream() // config blob declares a repo -> stub 7.5
			defer up.Close()

			p := newTestProxy(t, up.Server, func(c *Config) {
				c.Ecosystem = "oci"
				c.ScoreThreshold = 9.9 // 7.5 < 9.9: as a PULL this image is blocked
				c.WritePolicy = policy
				c.ByteGate = byteGateEnforce
			})

			req := httptest.NewRequest(http.MethodPut,
				"http://fw.local/v2/"+spyImage+"/blobs/uploads/abc-123",
				strings.NewReader("payload"))
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)

			if rec.Code == http.StatusForbidden {
				t.Errorf("the push was refused by a SCORE verdict (%q).\n"+
					"  D134: a push must not be Scorecard-scored — employee trust, and most\n"+
					"  Scorecard checks do not apply to an in-house container. The policy said\n"+
					"  relay this write; the gate answered a question about consuming the image.",
					rec.Header().Get("X-Yellowjack-Reason"))
			}
			if rec.Code == http.StatusMethodNotAllowed {
				t.Errorf("FW_WRITE_POLICY=%s still refused the write with 405 — the escape hatch is broken", policy)
			}

			// ANTI-VACUITY: a proxy that silently dropped the request would also avoid a
			// 403. The write must actually reach the registry.
			if !up.contacted("/blobs/uploads/") {
				t.Errorf("the upstream never saw the push, so a 'not blocked' result proves nothing.\n"+
					"  paths seen: %v", up.paths())
			}
		})
	}
}

// TestScoringStillGatesPullsOfTheSameImage is the discriminator for the test above.
//
// Without it, "the push was not blocked" is equally consistent with a firewall that has
// stopped scoring OCI entirely — which would be a far worse regression than the one
// being fixed. Same image, same threshold, same proxy: the PULL must still be refused.
func TestScoringStillGatesPullsOfTheSameImage(t *testing.T) {
	up := newOciSpyUpstream()
	defer up.Close()

	p := newTestProxy(t, up.Server, func(c *Config) {
		c.Ecosystem = "oci"
		c.ScoreThreshold = 9.9
		c.WritePolicy = writePolicyAllow // the permissive setting, to prove it leaks nothing
		c.ByteGate = byteGateEnforce
	})

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"http://fw.local/v2/"+spyImage+"/manifests/latest", nil))

	if rec.Code != http.StatusForbidden {
		t.Errorf("PULL of the low-scoring image = %d, want 403.\n"+
			"  Exempting writes from scoring must not exempt reads. If this fails, the\n"+
			"  'writes are not scored' test above is passing for the wrong reason.", rec.Code)
	}
}
