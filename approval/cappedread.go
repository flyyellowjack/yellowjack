package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Reading a registry document that is bigger than this service will buffer (#139).
//
// These are the approval service's copies of the firewall's decodeCapped / readCapped
// (../cappedread.go, which carries the full rationale). They are COPIES because the two
// are separate `package main` binaries and cannot share an import; the root guard
// TestNoCappedReadCanHideAnOverrun walks both directories, so the two cannot drift into
// one using the helper and the other the bare idiom.
//
// Why this service needs them at all: the harvest below reads PUBLIC registry documents
// -- publisher-controlled content -- and with the bare idiom a cap hit was
// indistinguishable from a broken registry. The developer lookup then rendered
// "we could not reach the registry" for a registry that had answered perfectly well.

// errBodyTooLarge means the peer sent a complete body and it exceeds our cap. It is an
// answer about OUR LIMIT, never about connectivity or syntax, and both users give it its
// own outcome for that reason: harvestUpstream its own availability marker, the ingest
// handlers a 413 instead of "invalid JSON body".
var errBodyTooLarge = errors.New("body exceeds this service's read cap")

// decodeCapped decodes JSON from r, reading at most limit bytes, and reports an overrun
// as errBodyTooLarge instead of the "unexpected EOF" a truncated document produces.
//
// It reads exactly `limit` bytes and not one more: TestAHostileRegistryResponseCannotExhaustUs
// bounds what a hostile registry gets to send, and a cap is not the place to be generous.
// The one ambiguous case -- a malformed document of exactly `limit` bytes -- is reported
// as too large; it is an error either way.
func decodeCapped(r io.Reader, limit int64, v any) error {
	lr := &io.LimitedReader{R: r, N: limit}
	if err := json.NewDecoder(lr).Decode(v); err != nil {
		if lr.N <= 0 {
			return fmt.Errorf("%w (cap %s)", errBodyTooLarge, capText(limit))
		}
		return err
	}
	return nil
}

// readCapped is decodeCapped for a caller that parses the bytes itself (Maven's XML).
//
// io.ReadAll(io.LimitReader(...)) cannot report an overrun: it returns the first `limit`
// bytes and a NIL error, so an oversized document is silently truncated and the parser
// sees a short prefix.
//
// ⚠️ It reads AT MOST `limit` bytes, never limit+1, and a body that FILLS the cap is
// reported as too large. The firewall's readCapped spends the extra byte; this one cannot,
// because TestAHostileMavenRepositoryCannotExhaustUs asserts the fetcher consumes not one
// byte past the cap, with no slack -- and loosening a memory-exhaustion guard to make a
// helper tidier is the wrong way round. The price is one ambiguous case (a document of
// exactly `limit` bytes is refused), the same one decodeCapped already accepts, against a
// cap that is ~140x the largest real Maven metadata document.
func readCapped(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) >= limit {
		return nil, fmt.Errorf("%w (cap %s)", errBodyTooLarge, capText(limit))
	}
	return b, nil
}

// capText renders a cap the way an operator would say it. KiB matters here: the
// heartbeat cap is 64 KiB, and "cap 0 MB" in a log line would be worse than no number.
func capText(limit int64) string {
	if limit >= 1<<20 {
		return fmt.Sprintf("%d MB", limit>>20)
	}
	return fmt.Sprintf("%d KiB", limit>>10)
}
