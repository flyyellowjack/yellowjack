package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TIER 1 for #139: a document that exceeds its cap must be DISTINGUISHABLE from a malformed
// one.
//
// The property is not "we stop reading" — #135 already ensured that, and
// TestEveryUpstreamBodyDecodeIsBounded guards it. The property here is that the two failures
// can be told apart at all. Before this, both arrived as "unexpected EOF": the operator saw
// "could not determine source repository" for a perfectly well-formed 32 MB document, and
// nothing counted the event.

func TestACappedDecodeSeparatesTooLargeFromMalformed(t *testing.T) {
	const cap = 1 << 10

	cases := []struct {
		name     string
		body     string
		wantErr  error // errUpstreamTooLarge, or nil for "some other error"
		wantCode bool  // true = expect an error at all
	}{
		{
			name:     "a valid document under the cap decodes",
			body:     `{"name":"ok"}`,
			wantCode: false,
		},
		{
			name:     "a valid document at exactly the cap decodes",
			body:     fmt.Sprintf(`{"name":%q}`, strings.Repeat("x", cap-12)),
			wantCode: false,
		},
		{
			name:     "a valid document OVER the cap is too large, not malformed",
			body:     fmt.Sprintf(`{"name":%q}`, strings.Repeat("x", cap*4)),
			wantErr:  errUpstreamTooLarge,
			wantCode: true,
		},
		{
			// The case the old code could not distinguish: this one really IS broken, and
			// must NOT be reported as an oversize.
			name:     "a malformed document under the cap is malformed, not too large",
			body:     `{"name":`,
			wantCode: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v struct {
				Name string `json:"name"`
			}
			err := decodeCapped(strings.NewReader(tc.body), cap, &v)
			switch {
			case !tc.wantCode && err != nil:
				t.Fatalf("a %d-byte body was refused: %v", len(tc.body), err)
			case !tc.wantCode:
				return
			case err == nil:
				t.Fatalf("a %d-byte body was accepted", len(tc.body))
			}
			isTooLarge := errors.Is(err, errUpstreamTooLarge)
			if want := tc.wantErr != nil; isTooLarge != want {
				t.Fatalf("errUpstreamTooLarge = %v, want %v (err: %v)\n"+
					"Telling these apart is the whole point: one means the publisher sent something "+
					"enormous, the other means the registry sent something broken, and they need "+
					"different responses from the operator.", isTooLarge, want, err)
			}
			if isTooLarge && !strings.Contains(err.Error(), "1 KB") {
				t.Errorf("the error does not name the cap that fired, so an operator cannot tell "+
					"WHICH limit to look at: %v", err)
			}
		})
	}
}

// TestACappedReadRefusesInsteadOfTruncating is the readCapped half, and it pins the failure
// that io.ReadAll(io.LimitReader(...)) has by construction: no error at all.
func TestACappedReadRefusesInsteadOfTruncating(t *testing.T) {
	const cap = 512
	big := strings.Repeat("A", cap*3)

	// What the old idiom does — this is a CONTROL, not an aspiration: it demonstrates the
	// silent truncation the helper exists to replace, so the assertion below is measured
	// against a real alternative rather than an imagined one.
	truncated, err := io.ReadAll(io.LimitReader(strings.NewReader(big), cap))
	if err != nil || len(truncated) != cap {
		t.Fatalf("control: io.ReadAll+LimitReader should silently return %d bytes and no error, "+
			"got %d bytes and err=%v — if this changed, the premise of #139 changed", cap, len(truncated), err)
	}

	got, err := readCapped(strings.NewReader(big), cap)
	if !errors.Is(err, errUpstreamTooLarge) {
		t.Fatalf("readCapped returned err=%v (%d bytes) for a %d-byte body; a silent truncation is "+
			"worse than an error because whatever parses it downstream sees a short, "+
			"well-formed-looking prefix", err, len(got), len(big))
	}
	if got != nil {
		t.Errorf("readCapped returned %d bytes alongside its error; a caller that ignores the error "+
			"would then parse a truncated document", len(got))
	}

	// And the negative control: a body under the cap comes back whole.
	small := strings.Repeat("B", cap-1)
	if b, err := readCapped(strings.NewReader(small), cap); err != nil || string(b) != small {
		t.Errorf("a body under the cap was not returned intact: %d bytes, err=%v", len(b), err)
	}
}

// TestAnOversizeUpstreamIsNotTreatedAsTransient pins the classification choice, because
// getting it wrong is a bug with a known shape: !94 refused to map the scheduler's 502 onto
// the transient sentinel precisely because a deterministic failure that retries forever is
// worse than one that stops.
func TestAnOversizeUpstreamIsNotTreatedAsTransient(t *testing.T) {
	err := fmt.Errorf("npm metadata: %w", errUpstreamTooLarge)

	if errors.Is(err, errUpstreamUnavailable) {
		t.Error("an oversize document is classified as TRANSIENT. Retrying yields the same bytes " +
			"forever, so the client would be told to come back and would fail identically every " +
			"time — the infinite-retry shape !94 exists to avoid.")
	}
	if errors.Is(err, errPkgNotFound) {
		t.Error("an oversize document is classified as 'package does not exist', which passes the " +
			"request through to the registry ungated")
	}
	if !errors.Is(err, errUpstreamTooLarge) {
		t.Error("wrapping lost the sentinel, so no caller can act on it")
	}
}

// TestTheRealFetchPathReportsAnOversizeDocument drives fetchMeta against a server that
// serves more than the cap, because a helper's own test never proves the call site is wired
// — that has cost two rounds of rework before (see the sabotage memory).
func TestTheRealFetchPathReportsAnOversizeDocument(t *testing.T) {
	// A well-formed packument that is simply enormous: the point is that nothing about it is
	// malformed, so any "unexpected EOF" is our cap and not the registry's fault.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"name":"huge","description":"`)
		chunk := strings.Repeat("x", 1<<16)
		for written := 0; written < npmMetaMaxBytes+(1<<20); written += len(chunk) {
			fmt.Fprint(w, chunk)
		}
		fmt.Fprint(w, `"}`)
	}))
	defer srv.Close()

	_, err := npmEcosystem{}.fetchMeta(srv.Client(), srv.URL+"/huge")
	if !errors.Is(err, errUpstreamTooLarge) {
		t.Fatalf("fetchMeta did not report an oversize document: %v\n"+
			"The helper's own tests pass either way; this one drives the real path, which is "+
			"where the previous idiom turned a 32 MB document into 'could not determine source "+
			"repository'.", err)
	}
	if !strings.Contains(err.Error(), "32 MB") {
		t.Errorf("the error does not name the cap: %v", err)
	}
}
