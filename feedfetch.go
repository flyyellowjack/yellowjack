package main

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FETCHING THE KNOWN-MALWARE SNAPSHOT ON A SCHEDULE (#157, D294, D308, D329).
//
// D294 made the default delivery model "a cached object on a daily or hourly
// pull refresh" from a distribution endpoint we host, and D308 made the pull mechanism
// our build work. D329 shipped the verification half; this is the pull.
//
// The design is a composition, not a second loader. The fetcher's only output is two
// files at the path FW_MALWARE_LIST already names: the snapshot and its signature. The
// existing re-read (#160, malwarereload.go) notices the new file within a minute and
// installs it through the same verification as any other snapshot. So there is ONE
// path by which a feed becomes enforcing, and the fetcher cannot bypass it.
//
// What it guarantees, each pinned by a test in feedfetch_test.go:
//
//   - VERIFY BEFORE WRITE. The signature, the header and the row count are checked on
//     the bytes in memory. A snapshot that fails never reaches the mount, so the
//     re-read's last-good retention is the second line of defence, not the first.
//   - NEVER BACKWARDS. A served snapshot whose serial is older than the one in force
//     is refused. Compared against the feed in force, never a remembered maximum (D103:
//     no durable mutable state; and a deliberate rollback stays possible by restart).
//   - NO CHURN. A snapshot with the serial already in force is not re-written, so an
//     hourly pull of an unchanged feed does not force an hourly re-parse.
//   - NOT ON THE REQUEST PATH, NOT IN READINESS. A failed pull keeps the feed in force
//     and says so; it never makes a replica unready, because every replica shares one
//     endpoint and an outage there would take the whole fleet out of rotation at once.
//   - LOUD ONCE. A failure is logged when the outcome CHANGES, not every interval.
//   - NO BORROWED CREDENTIAL. The client carries the gate's user agent and nothing
//     else. The upstream registry credential is host-scoped to the registry, and the
//     fetcher is built without that wrapper at all, so it cannot reach the feed host.
//
// The endpoint is operator configuration with NO default (docs/EGRESS.md: every
// address the gate dials comes from config). Whether the shipped default should name
// our endpoint is QN16, a single default value, and it does not change this code.

// feedFetchInterval is how often the snapshot is pulled. A constant, not a knob (#51):
// D294 says "daily or hourly", and hourly is the shorter of the two a customer was
// promised. A variable only so tests can shorten it.
var feedFetchInterval = time.Hour

// feedSigMaxBytes caps the signature download. A base64 Ed25519 signature is 88 bytes;
// anything near this cap is not a signature.
const feedSigMaxBytes = 4 << 10

type feedFetcher struct {
	url, path string
	key       ed25519.PublicKey
	client    *http.Client
	logf      func(string, ...any)
	// inForce reports the feed currently enforcing, so a served snapshot can be
	// compared against it. The reloading source's current().
	inForce func() *malwareList

	mu          sync.Mutex
	lastOutcome string // the last outcome logged; a repeat is not logged again
	writes      int    // snapshots written to the mount; the churn test reads this
}

// fetchOnce pulls, verifies and (if newer) installs one snapshot. It returns what
// happened as a short outcome string and an error when the pull was refused or failed.
func (f *feedFetcher) fetchOnce() (string, error) {
	data, err := f.get(f.url, feedMaxBytes)
	if err != nil {
		return "", fmt.Errorf("snapshot %q: %w", f.url, err)
	}
	sig, err := f.get(f.url+feedSigSuffix, feedSigMaxBytes)
	if err != nil {
		return "", fmt.Errorf("signature %q: %w", f.url+feedSigSuffix, err)
	}
	if err := verifySignatureBytes(f.url+feedSigSuffix, data, sig, f.key); err != nil {
		return "", err
	}
	next, err := parseSignedFeed(f.url, data)
	if err != nil {
		return "", err
	}
	if cur := f.inForce(); cur != nil && cur.header.Present {
		switch {
		case next.header.Serial < cur.header.Serial:
			return "", fmt.Errorf("serial %d served by %q is OLDER than the %d in force: a snapshot "+
				"that goes backwards is a replay, whether or not it is signed", next.header.Serial, f.url,
				cur.header.Serial)
		case next.header.Serial == cur.header.Serial:
			return fmt.Sprintf("unchanged (serial %d)", cur.header.Serial), nil
		}
	}
	if err := f.install(data, sig); err != nil {
		return "", err
	}
	f.mu.Lock()
	f.writes++
	f.mu.Unlock()
	return fmt.Sprintf("installed serial %d (%s)", next.header.Serial, next.header), nil
}

// get downloads a URL with a size cap. Anything but 200 is an error: a registry-style
// 304 or 404 is not a snapshot, and treating a 404 body as one is how an empty feed
// would be installed.
func (f *feedFetcher) get(url string, limit int64) ([]byte, error) {
	resp, err := f.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return readCapped(resp.Body, limit)
}

// install writes the signature first and the snapshot second, each by temp file and
// rename in the SAME directory (a rename across filesystems is not atomic).
//
// Why the signature goes first: the re-read is triggered by the SNAPSHOT changing
// (a stat on its size and mtime). Written in this order, by the time the re-read sees a
// new snapshot, the signature beside it is already the matching one. The reverse order
// would let the re-read pair a new snapshot with the previous signature, refuse it, and
// log a SECURITY line about a perfectly good refresh.
func (f *feedFetcher) install(data, sig []byte) error {
	if err := writeReplace(f.path+feedSigSuffix, sig); err != nil {
		return fmt.Errorf("writing the signature beside %q: %w", f.path, err)
	}
	if err := writeReplace(f.path, data); err != nil {
		return fmt.Errorf("writing the snapshot to %q: %w", f.path, err)
	}
	return nil
}

// writeReplace writes b to a temp file beside path, syncs it, and renames it over path.
// A reader of path sees the old bytes or the new ones, never a half-written file.
func writeReplace(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // a no-op once the rename has succeeded
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// report logs an outcome when it differs from the last one logged. A refusal is a
// SECURITY line; an ordinary failure (the endpoint is down) is not, because it is not an
// attack and a fleet-wide outage should not look like one.
func (f *feedFetcher) report(outcome string, err error) {
	line := outcome
	if err != nil {
		line = "ERR " + err.Error()
	}
	f.mu.Lock()
	same := line == f.lastOutcome
	f.lastOutcome = line
	f.mu.Unlock()
	if same {
		return
	}
	if err != nil {
		f.logf("SECURITY known-malware snapshot pull from %q refused or failed: %v -- the feed in force "+
			"is unchanged and still enforcing", f.url, err)
		return
	}
	f.logf("known-malware snapshot pull from %q: %s", f.url, outcome)
}

// run pulls once immediately and then every interval, for the life of the process.
func (f *feedFetcher) run() {
	for {
		out, err := f.fetchOnce()
		f.report(out, err)
		time.Sleep(feedFetchInterval)
	}
}

// seedIfMissing handles a replica that starts with NO snapshot on its mount.
//
// A configured feed that cannot be read at startup is fatal, deliberately: the
// alternative is a gate that boots enforcing nothing while looking configured. With a
// pull configured there is one more option first -- pull once, now. If that works the
// replica starts normally. If it fails, startup still fails, with a message naming the
// fix: SEED the directory (bake a signed snapshot into the image, copy one in with an
// init container). A seeded replica never needs our endpoint to start, which is the
// property D294 was chosen for -- a customer keeps enforcing a local copy while we are
// down. An unseeded one would crash-loop through our outage, and that is the operator's
// choice to make knowingly, not a default to discover.
func (f *feedFetcher) seedIfMissing() error {
	if _, err := os.Stat(f.path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return nil // unreadable for another reason: let the loader report it as it always has
	}
	out, err := f.fetchOnce()
	if err != nil {
		return fmt.Errorf("known-malware feed %q does not exist and the first pull from %q failed (%v). "+
			"Seed that directory with a signed snapshot and its .sig (bake it into the image, or copy it in "+
			"with an init container) so a replica can start while the endpoint is unreachable", f.path, f.url, err)
	}
	f.logf("known-malware snapshot: no snapshot at %q, so pulled one before starting: %s", f.path, out)
	return nil
}

func (f *feedFetcher) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}
