// Command feedsign generates a key pair and signs a known-malware snapshot (#157).
//
// It is RELEASE tooling, not a service: whoever produces a snapshot runs it, and the
// gate verifies with the public half (FW_MALWARE_FEED_KEY). An operator who builds
// their own feed with scripts/build-malware-feed.py signs it with their own key, so
// the mechanism implies no trust in us.
//
// Why a Go program next to a Python generator: Ed25519 is in Go's standard library and
// is not in Python's. The alternative was a hand-rolled implementation in the
// generator, and hand-rolled signature code is exactly the thing not to write.
//
//	go run ./scripts/feedsign -gen
//	go run ./scripts/feedsign -key feed.key -in feed.jsonl -serial 42
//
// The second form REWRITES the feed's header line (serial + generated + rows) and then
// writes feed.jsonl.sig beside it. Header first, signature second, and never the other
// way round: the header is inside the signed bytes, which is the only thing that makes
// a replayed snapshot detectable.
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

const headerPrefix = "# yellowjack-feed "

func main() {
	gen := flag.Bool("gen", false, "generate a key pair and print it; the public half goes in FW_MALWARE_FEED_KEY")
	keyPath := flag.String("key", "", "file holding the base64 PRIVATE key (from -gen)")
	in := flag.String("in", "", "the snapshot to stamp and sign, in place")
	serial := flag.Int64("serial", 0, "the snapshot's serial; must increase with every release")
	flag.Parse()

	if *gen {
		if err := generate(); err != nil {
			fail(err)
		}
		return
	}
	if *keyPath == "" || *in == "" || *serial <= 0 {
		fail(fmt.Errorf("need -key, -in and a positive -serial (or -gen); see -h"))
	}
	if err := sign(*keyPath, *in, *serial); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "feedsign: %v\n", err)
	os.Exit(1)
}

func generate() error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	// The PRIVATE key goes to stdout deliberately, so it can be redirected to a file
	// the caller controls the mode of. Writing it ourselves would mean choosing where
	// a secret lives, which is not this tool's decision to make.
	fmt.Printf("# private key -- keep this out of the repo and off the gate\n%s\n",
		base64.StdEncoding.EncodeToString(priv.Seed()))
	fmt.Printf("# FW_MALWARE_FEED_KEY (public; safe to publish)\n%s\n",
		base64.StdEncoding.EncodeToString(pub))
	return nil
}

func sign(keyPath, feedPath string, serial int64) error {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("private key %q is not base64: %w", keyPath, err)
	}
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("private key %q decodes to %d bytes, and an Ed25519 seed is %d",
			keyPath, len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	feed, err := os.ReadFile(feedPath)
	if err != nil {
		return err
	}
	stamped, rows, err := stamp(feed, serial)
	if err != nil {
		return err
	}
	// The feed is rewritten BEFORE it is signed, and the signature is written last, so
	// an interrupted run leaves a feed with no signature (which the gate refuses) and
	// never a signature that does not match the feed (which it would also refuse, but
	// as a tamper alarm rather than a missing file).
	if err := os.WriteFile(feedPath, stamped, 0o644); err != nil {
		return err
	}
	sig := ed25519.Sign(priv, stamped)
	sigPath := feedPath + ".sig"
	if err := os.WriteFile(sigPath, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %s: serial %d, %d records\n%s\n", feedPath, serial, rows, sigPath)
	return nil
}

// stamp replaces (or inserts) the header line and counts the records it describes.
func stamp(feed []byte, serial int64) ([]byte, int, error) {
	var out bytes.Buffer
	fmt.Fprintf(&out, "%sv1 serial=%d generated=%s rows=%%ROWS%%\n",
		headerPrefix, serial, time.Now().UTC().Format(time.RFC3339))
	rows := 0
	sc := bufio.NewScanner(bytes.NewReader(feed))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		text := strings.TrimSpace(line)
		if strings.HasPrefix(text, headerPrefix) {
			continue // the previous release's header; there is exactly one
		}
		if text != "" && !strings.HasPrefix(text, "#") {
			rows++
		}
		out.WriteString(line)
		out.WriteString("\n")
	}
	if err := sc.Err(); err != nil {
		return nil, 0, err
	}
	if rows == 0 {
		// The generator already refuses to write fewer than 1,000 rows; this refuses
		// the degenerate case it cannot see, which is signing a file that emptied
		// between generation and release. A signed empty feed switches layer 1 off
		// while looking perfectly configured.
		return nil, 0, fmt.Errorf("%s holds no records: signing it would certify an EMPTY feed", "the snapshot")
	}
	return bytes.Replace(out.Bytes(), []byte("%ROWS%"), []byte(fmt.Sprint(rows)), 1), rows, nil
}
