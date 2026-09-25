package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Reading an upstream document that is bigger than we are willing to buffer (#139).
//
// #135 bounded every upstream body this package decodes, which was the right fix and is
// guarded by TestEveryUpstreamBodyDecodeIsBounded. What it did not settle is what happens
// WHEN A BOUND IS HIT — and the answer today is that nobody can tell.
//
// `json.NewDecoder(io.LimitReader(body, cap)).Decode(&v)` hands the decoder a truncated
// document, so the error it returns is "unexpected EOF": indistinguishable from a corrupt
// body, a half-written response, or a registry bug. Two things follow, and both are bad:
//
//   - The operator sees "could not determine source repository for X" for a document that
//     was perfectly well-formed and merely enormous. Nothing names the cap, nothing counts
//     the event, so an operator cannot tell whether a cap is biting anything at all.
//   - Every caller classifies it as an ORDINARY decode failure, which for the firewall's
//     metadata path means `unscorable` -- a verdict about the PACKAGE. The input is
//     publisher-controlled content, so whether we hit the cap is chosen by the party the
//     gate exists to judge.
//
// ⚠️ WHAT THIS FILE DOES NOT DO, deliberately. It does not change any verdict. A cap hit
// is still `unscorable` and the shipped byte-gate default still serves unscorable artifacts
// (D49, visibility-first). Moving it to the HARD side of hardDenyKind would refuse the bytes
// -- and that is a false-refusal trade (a legitimately enormous package would stop
// installing) which the taxonomy in firewall.go explicitly requires be CHOSEN rather than
// inherited. #139 leaves that one bit open. This file makes the event legible and
// countable so the choice can be made against evidence instead of a guess.
//
// REACHABILITY, MEASURED 2026-09-17 so the next reader does not have to guess how urgent
// this is: the largest real documents on the paths that use these helpers are npm `/latest`
// at 66.8 KB (`npm`), PyPI `/simple/` at 2.31 MB (`numpy`) and PyPI's JSON API at 3.83 MB
// (`botocore`), against caps of 32 MB. No sampled package comes close. But an abbreviated
// npm packument already reaches 8.69 MB (`typescript`), packuments only grow, and a cap that
// bites is disproportionately likely to be biting malware: a sibling measurement of a 4 MB
// per-member cap excluded 0.0285% of benign package members and 0.6770% of labelled malware,
// 24x the benign rate, because malware bundles one enormous payload far more often. A
// threshold applied identically to every population does not affect them identically, which
// is why "no real package is near it" is not the same as "this does not matter".

// errUpstreamTooLarge is returned when an upstream document exceeds the bytes we are willing
// to buffer for it.
//
// It deliberately does NOT wrap errUpstreamUnavailable. That sentinel means "no answer at
// all, try again", and the firewall turns it into a retryable 503. This is the opposite: the
// answer arrived, it is simply bigger than the cap, and retrying produces the same result
// forever. Wrapping it would give us the infinite-retry bug !94 refused to introduce for the
// scheduler's 502.
var errUpstreamTooLarge = errors.New("upstream document exceeds the inspection cap")

// decodeCapped decodes JSON from r, reading at most limit bytes, and distinguishes "this
// document is too big" from "this document is malformed".
//
// The mechanism: decode through an io.LimitedReader and, if the decode FAILS, ask whether the
// reader was exhausted. Exhausted means the document filled the cap and the decoder ran out of
// input; not exhausted means the body really is malformed.
//
// ⚠️ It reads exactly `limit` bytes and NOT one more, which is not a detail: #135 ships two
// behavioural tests that offer a hostile upstream 64 MB and assert the gate reads no more than
// the cap plus its drain. A single extra byte of headroom -- the obvious way to write this --
// fails both, and widening those ceilings to fit would have been weakening a memory-exhaustion
// guard to accommodate an implementation choice with a cheaper alternative.
//
// The residual ambiguity is one case: a document of EXACTLY `limit` bytes that is also
// malformed is reported as too large. It is an error either way, and the alternative costs a
// byte the guard above is right to refuse.
func decodeCapped(r io.Reader, limit int64, v any) error {
	lr := &io.LimitedReader{R: r, N: limit}
	if err := json.NewDecoder(lr).Decode(v); err != nil {
		if lr.N <= 0 {
			return fmt.Errorf("%w (cap %s)", errUpstreamTooLarge, humanBytes(limit))
		}
		return err
	}
	return nil
}

// readCapped is decodeCapped for callers that want the raw bytes: XML, a PEM bundle, a
// manifest they parse themselves.
//
// io.ReadAll(io.LimitReader(...)) CANNOT report this, which is the reason this exists: it
// returns the first limit bytes and a nil error, so an oversized document is silently
// TRUNCATED and whatever parses it downstream sees a short, well-formed-looking prefix. That
// is a worse failure than an error, because nothing anywhere says it happened.
//
// Unlike decodeCapped this DOES read one byte past the cap, because "exactly the cap" and
// "more than the cap" are otherwise indistinguishable to a caller that wants the raw bytes.
// One byte is not a memory-exhaustion concern; it is called out because the sibling above
// deliberately does not, and the difference should look intentional rather than sloppy.
func readCapped(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w (cap %s)", errUpstreamTooLarge, humanBytes(limit))
	}
	return b, nil
}

// humanBytes renders a cap the way an operator would write it, so the log line reads
// "cap 32 MB" rather than "cap 33554432".
//
// The cap's VALUE appears in operator-facing logs only, never in a response body: what we
// refuse to read is policy detail, and D182's disclosure sweep keeps policy detail off the
// wire. An attacker can discover the boundary by bisection anyway, but they should have to.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MB", n/(1<<20))
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%d KB", n/(1<<10))
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}
