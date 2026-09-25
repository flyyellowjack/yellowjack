package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// VERIFY THE KNOWN-MALWARE SNAPSHOT BEFORE THE GATE USES IT (#157, D294 → D329).
//
// D294 ruled the intelligence reaches a customer as *"a cached object on a
// daily or hourly pull refresh"*. #157 says the quiet half of that is the one that
// matters: **the integrity question outranks the scheduling one.** A snapshot that
// arrives on time and is wrong is worse than one that arrives late, because layer 1's
// whole job is to answer a verdict from a local file, and nothing downstream of here
// re-examines what that file said.
//
// What an unverified feed lets an attacker do, in order of how cheap it is:
//
//	TAMPER  drop the advisory naming their package. The gate then serves malware and
//	        logs a clean verdict. Nothing looks wrong anywhere.
//	REPLAY  serve yesterday's snapshot forever. Every new advisory is invisible, and
//	        the gate reports a feed that loads, parses and enforces — because it does.
//	TRUNCATE
//	        serve the first few kilobytes. The parse succeeds (NDJSON has no end
//	        marker) and layer 1 silently shrinks to whatever fits.
//
// None of the three is detectable from the parsed content, which is why this is a
// SIGNATURE and not more parsing. The signer is the party that produced the snapshot;
// the public key is operator configuration (`FW_MALWARE_FEED_KEY`), so an operator who
// builds their own feed with scripts/build-malware-feed.py signs it with their own key
// and no trust in us is implied by the mechanism.
//
// ⚠️ SCOPE. This verifies a feed that is ALREADY ON DISK. It does not fetch, and the
// fetch is deliberately not in this increment: putting a dialler in the gate touches
// docs/EGRESS.md's enumerated destination list, which is a published claim, and the
// default destination is a project decision rather than a technique call (QN16).
// Verification composes with every mechanism that question can be answered with — a
// documented cron plus curl, a Helm CronJob, or an in-process fetcher — because all
// three end with bytes at the path FW_MALWARE_LIST names, which is where this runs.

// feedMaxBytes bounds the snapshot we will read into memory to check a signature.
//
// Ed25519 signs a whole message, so verification cannot stream (Ed25519ph could, but
// the prehash variant is not what `openssl pkeyutl -sign -rawin` produces, and an
// operator signing their own feed with standard tooling is the case that must work).
// 64 MB against a measured ~25 MB for the full public OSV corpus: room for the corpus
// to double twice, and a bound so a mount pointed at something enormous fails with a
// sentence instead of an OOM kill.
const feedMaxBytes = 64 << 20

// feedSigSuffix is where the detached signature lives: beside the feed, same name.
//
// Beside, rather than a second knob, because the two files are one artifact — a
// snapshot whose signature is configured separately can be half-updated, and the
// failure that produces (a valid signature over the PREVIOUS snapshot) is the replay
// case arriving by accident. ⚠️ Mount the DIRECTORY, not the file: an atomic swap
// replaces the inode, and a file bind-mount would show the container the old one for
// ever (the FW_ALLOW_LIST lesson from !185).
const feedSigSuffix = ".sig"

// feedHeader is the snapshot's self-description, carried in its first line and covered
// by the signature.
//
// It exists because a signature alone answers "did the party holding the key produce
// these bytes" and not "are these bytes the CURRENT snapshot" — the replay case. The
// serial and the timestamp are what make that question answerable, and they are only
// worth anything INSIDE the signed bytes, which is why they are a line of the feed
// rather than an HTTP header or a sidecar.
type feedHeader struct {
	Present   bool
	Version   int
	Serial    int64
	Generated time.Time
	Rows      int // declared row count, checked against what the parser actually read
}

const feedHeaderPrefix = "# yellowjack-feed "

// parseFeedHeader reads the header line, if this is one.
//
// A line that does not begin with the prefix is not a header and not an error: feeds
// are allowed to carry ordinary "#" comments, and every feed produced before this
// existed has no header at all. A line that DOES begin with the prefix and is then
// malformed IS an error — a half-recognised header is the one case where silence would
// let a snapshot claim less than it means to.
func parseFeedHeader(line string) (feedHeader, bool, error) {
	if !strings.HasPrefix(line, feedHeaderPrefix) {
		return feedHeader{}, false, nil
	}
	h := feedHeader{Present: true}
	for _, f := range strings.Fields(strings.TrimPrefix(line, feedHeaderPrefix)) {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			if !strings.HasPrefix(f, "v") {
				return feedHeader{}, true, fmt.Errorf("header field %q is neither a version nor key=value", f)
			}
			n, err := strconv.Atoi(strings.TrimPrefix(f, "v"))
			if err != nil {
				return feedHeader{}, true, fmt.Errorf("header version %q is not a number", f)
			}
			h.Version = n
			continue
		}
		var err error
		switch k {
		case "serial":
			h.Serial, err = strconv.ParseInt(v, 10, 64)
		case "generated":
			h.Generated, err = time.Parse(time.RFC3339, v)
		case "rows":
			h.Rows, err = strconv.Atoi(v)
		default:
			// Unknown fields are IGNORED on purpose, so a newer signer can add one
			// without every older gate refusing the snapshot it needs most.
			continue
		}
		if err != nil {
			return feedHeader{}, true, fmt.Errorf("header field %s=%q: %w", k, v, err)
		}
	}
	if h.Version != 1 {
		return feedHeader{}, true, fmt.Errorf("header declares version %d, and this gate understands 1", h.Version)
	}
	if h.Serial <= 0 {
		return feedHeader{}, true, fmt.Errorf("header carries no serial, so a replayed snapshot could not be told from the current one")
	}
	if h.Generated.IsZero() {
		return feedHeader{}, true, fmt.Errorf("header carries no generated timestamp, so staleness is unmeasurable")
	}
	return h, true, nil
}

// String renders the header for an operator's log line.
func (h feedHeader) String() string {
	if !h.Present {
		return "unversioned (no header)"
	}
	return fmt.Sprintf("serial %d, generated %s", h.Serial, h.Generated.UTC().Format(time.RFC3339))
}

// age is how old the snapshot says it is. Negative means it claims the future, which is
// reported rather than clamped: a signer with a wrong clock and an attacker buying time
// look identical here, and both are worth an operator's attention.
func (h feedHeader) age(now time.Time) time.Duration { return now.Sub(h.Generated) }

// feedMaxAge is when a snapshot stops being evidence.
//
// A constant, not a knob: the config surface is a budget (#51), and an operator who
// needs a different number needs a different refresh cadence, which is the thing to
// change. 72 h is three missed daily pulls — long enough that a weekend outage does not
// shout, short enough that it cannot quietly become a fortnight. Exceeding it is LOUD
// and changes no verdict: an old advisory is still an advisory, and refusing to enforce
// what we have because it is old would turn a stale feed into no feed.
const feedMaxAge = 72 * time.Hour

// parseFeedKey reads the operator's configured public key: standard base64 of the raw
// 32-byte Ed25519 key, which is what `scripts/feedsign -gen` prints.
func parseFeedKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("is not base64 (%v); use the value scripts/feedsign -gen prints", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("decodes to %d bytes, and an Ed25519 public key is %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// verifyFeedSignature checks the detached signature beside the feed.
//
// The error text names the file and what was wrong with it, because every one of these
// is an operator mistake before it is an attack, and a failure that reads as "invalid"
// with no subject sends someone to the wrong file.
func verifyFeedSignature(feedPath string, data []byte, key ed25519.PublicKey) error {
	sigPath := feedPath + feedSigSuffix
	raw, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("a feed-signing key is configured but its signature %q cannot be read (%v): "+
			"the snapshot and its signature are one artifact, so mount them together", sigPath, err)
	}
	return verifySignatureBytes(sigPath, data, raw, key)
}

// verifySignatureBytes checks a base64 detached signature held in memory. The fetcher
// calls it on bytes still in memory, so a snapshot that fails never touches the mount;
// the loader calls it (through verifyFeedSignature) on the file beside the feed. One
// implementation, so the two can never disagree about what verifies. label names the
// signature's source in the error.
func verifySignatureBytes(label string, data, raw []byte, key ed25519.PublicKey) error {
	sigPath := label
	// ed25519.Verify PANICS on a key of the wrong length. Startup refuses a pull with
	// no key, but a guard one layer up is not a reason to let this layer crash the gate:
	// found by a sabotage that removed the startup check and got a panic, not a refusal.
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("signature %q cannot be checked: the verification key is %d bytes, not %d",
			sigPath, len(key), ed25519.PublicKeySize)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("signature %q is not base64 (%v)", sigPath, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature %q decodes to %d bytes, and an Ed25519 signature is %d",
			sigPath, len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(key, data, sig) {
		return fmt.Errorf("signature %q does not verify against the configured key for these bytes: "+
			"the snapshot was modified, truncated, or signed by a different key — REFUSED, and the feed "+
			"already loaded (if any) stays in force", sigPath)
	}
	return nil
}
