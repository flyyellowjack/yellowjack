package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// VERIFYING THE KNOWN-MALWARE SNAPSHOT (#157, D329).
//
// Three attacks and one compatibility promise, each with the control that keeps it
// honest. The controls matter more than usual here, because every refusal in this file
// is indistinguishable from a broken loader: a verifier that refused EVERYTHING would
// pass all three attack tests and disarm layer 1 completely.

// feedKeys returns a signing pair and the base64 public half an operator would
// configure, so a test exercises the same encoding the config parser reads.
func feedKeys(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub, base64.StdEncoding.EncodeToString(pub)
}

// feedHeaderLine renders a header the signer would write.
func feedHeaderLine(serial int64, generated time.Time, rows int) string {
	return fmt.Sprintf("%sv1 serial=%d generated=%s rows=%d",
		feedHeaderPrefix, serial, generated.UTC().Format(time.RFC3339), rows)
}

// writeSignedFeed writes a feed and its detached signature, and returns the path.
// signBytes decides WHAT is signed, which is how the tamper cases are built: they sign
// one thing and install another.
func writeSignedFeed(t *testing.T, dir string, priv ed25519.PrivateKey, body string, signBytes []byte) string {
	t.Helper()
	path := filepath.Join(dir, "malware.ndjson")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if signBytes == nil {
		signBytes = []byte(body)
	}
	sig := ed25519.Sign(priv, signBytes)
	if err := os.WriteFile(path+feedSigSuffix, []byte(base64.StdEncoding.EncodeToString(sig)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// goodFeed is two advisories under a valid header: the shape every case below starts from.
func goodFeed(serial int64, generated time.Time) string {
	return feedHeaderLine(serial, generated, 2) + "\n" +
		`{"id":"MAL-1","ecosystem":"npm","name":"evil-a"}` + "\n" +
		`{"id":"MAL-2","ecosystem":"npm","name":"evil-b","versions":["1.0.0"]}` + "\n"
}

// ── THE CONTROL: a good snapshot must LOAD ───────────────────────────────────
//
// First, and deliberately: every refusal below is worthless if this one fails, because
// a verifier that refuses everything satisfies all of them at once.
func TestASignedSnapshotLoadsAndCarriesItsSerial(t *testing.T) {
	priv, pub, _ := feedKeys(t)
	gen := time.Now().Add(-time.Hour)
	path := writeSignedFeed(t, t.TempDir(), priv, goodFeed(7, gen), nil)

	l, err := loadMalwareList(path, pub)
	if err != nil {
		t.Fatalf("a correctly signed snapshot was REFUSED, so nothing else in this file proves anything: %v", err)
	}
	if !l.header.Present || l.header.Serial != 7 {
		t.Errorf("header not read back: %+v", l.header)
	}
	if l.records != 2 {
		t.Errorf("records = %d, want 2 (the header line must not be counted as one)", l.records)
	}
	if _, ok := l.lookupAll("npm", "evil-a"); !ok {
		t.Error("the advisories did not survive verification, so the feed verified and then did nothing")
	}
	// RFC3339 keeps whole seconds, so compare against the timestamp the header actually
	// carries rather than the sub-second one the fixture started from.
	if got := l.header.age(l.header.Generated.Add(90 * time.Minute)); got != 90*time.Minute {
		t.Errorf("age = %v, want 90m", got)
	}
}

// ── ATTACK 1: TAMPER ─────────────────────────────────────────────────────────
func TestATamperedSnapshotIsRefused(t *testing.T) {
	priv, pub, _ := feedKeys(t)
	body := goodFeed(7, time.Now())
	// The realistic edit, not a random byte: DROP the advisory naming the attacker's
	// package. The file still parses, still has a header, and the gate would serve it.
	tampered := strings.Replace(body, `{"id":"MAL-1","ecosystem":"npm","name":"evil-a"}`+"\n", "", 1)
	path := writeSignedFeed(t, t.TempDir(), priv, tampered, []byte(body))

	_, err := loadMalwareList(path, pub)
	if err == nil {
		t.Fatal("a snapshot with an advisory REMOVED was accepted; the signature is not being checked")
	}
	if !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("the refusal does not say the signature failed, so an operator cannot tell this from a "+
			"parse error: %v", err)
	}
}

// ── ATTACK 2: TRUNCATE, re-signed ────────────────────────────────────────────
//
// The interesting truncation is not the one that breaks the signature — that is attack
// 1 — but the one signed by a key the gate trusts: a release job that shipped a partial
// file, or an attacker who compromised the signer. NDJSON has no end marker, so the
// parse succeeds and layer 1 quietly shrinks. The declared row count is the only thing
// that notices.
func TestASignedButShortSnapshotIsRefused(t *testing.T) {
	priv, pub, _ := feedKeys(t)
	body := feedHeaderLine(9, time.Now(), 2) + "\n" +
		`{"id":"MAL-1","ecosystem":"npm","name":"evil-a"}` + "\n" // says 2, carries 1
	path := writeSignedFeed(t, t.TempDir(), priv, body, nil)

	_, err := loadMalwareList(path, pub)
	if err == nil {
		t.Fatal("a snapshot declaring more records than it holds was accepted: a truncated feed enforces " +
			"less while looking fully loaded")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("the refusal does not name the defect: %v", err)
	}
}

// ── ATTACK 3: REPLAY ─────────────────────────────────────────────────────────
//
// The signature cannot see this one at all: an older snapshot is genuinely ours and
// genuinely signed. Only the serial distinguishes it, and only while the newer one is
// in force -- which is why the comparison is against the loaded feed and not a
// persisted high-water mark.
func TestAnOlderSnapshotIsRefusedOnReload(t *testing.T) {
	shortFeedIntervals(t)
	priv, pub, _ := feedKeys(t)
	dir := t.TempDir()
	path := writeSignedFeed(t, dir, priv, goodFeed(12, time.Now()), nil)

	first, err := loadMalwareList(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	var logged []string
	src := newReloadingFeed(path, "npm", func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }, first, pub)

	// The rollback: an older, perfectly valid, perfectly signed snapshot.
	old := goodFeed(11, time.Now()) + `{"id":"MAL-3","ecosystem":"npm","name":"evil-c"}` + "\n"
	old = strings.Replace(old, "rows=2", "rows=3", 1)
	writeSignedFeed(t, dir, priv, old, nil)
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}

	now := src.current()
	if now.header.Serial != 12 {
		t.Errorf("serial %d is in force; the gate accepted a snapshot that goes BACKWARDS", now.header.Serial)
	}
	if _, ok := now.lookupAll("npm", "evil-c"); ok {
		t.Error("the replayed snapshot's contents reached the request path")
	}
	if !strings.Contains(strings.Join(logged, "\n"), "OLDER than") {
		t.Errorf("a replayed snapshot was refused SILENTLY; an operator has nothing to act on:\n%s",
			strings.Join(logged, "\n"))
	}
	// DISCRIMINATOR: the same mechanism must still accept a snapshot that moves FORWARD,
	// or this test is satisfied by a gate that stopped reloading altogether.
	writeSignedFeed(t, dir, priv, strings.Replace(goodFeed(13, time.Now()), "rows=2", "rows=3", 1)+
		`{"id":"MAL-4","ecosystem":"npm","name":"evil-d"}`+"\n", nil)
	later := time.Now().Add(4 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	// Force the next interval rather than rely on the wall clock. The stat throttle is
	// 1 ms under shortFeedIntervals, and on Linux the two current() calls land inside it
	// -- measured: 194 of 200 runs failed in golang:1.26, 0 of 200 on the Windows host,
	// which is slow enough to cross it by accident. The test was asserting the clock.
	src.checked = time.Time{}
	if got := src.current(); got.header.Serial != 13 {
		t.Errorf("serial %d in force after a FORWARD refresh: the refusal above is refusing everything (stale: %v)",
			got.header.Serial, src.stale())
	}
}

// ── The re-read is verified too, not only the first read ─────────────────────
func TestAReReadIsVerifiedAndABadOneKeepsTheLastGoodFeed(t *testing.T) {
	shortFeedIntervals(t)
	priv, pub, _ := feedKeys(t)
	other, _, _ := feedKeys(t)
	dir := t.TempDir()
	path := writeSignedFeed(t, dir, priv, goodFeed(3, time.Now()), nil)
	first, err := loadMalwareList(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	var logged []string
	src := newReloadingFeed(path, "npm", func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }, first, pub)

	// A newer snapshot signed by the WRONG key: the shape of a compromised mirror.
	writeSignedFeed(t, dir, other, strings.Replace(goodFeed(4, time.Now()), "rows=2", "rows=3", 1)+
		`{"id":"MAL-X","ecosystem":"npm","name":"attacker-choice"}`+"\n", nil)
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}

	got := src.current()
	if got.header.Serial != 3 {
		t.Errorf("a snapshot signed by another key reached the request path (serial %d)", got.header.Serial)
	}
	if _, ok := got.lookupAll("npm", "attacker-choice"); ok {
		t.Error("the unverified snapshot's contents are being enforced")
	}
	if _, ok := got.lookupAll("npm", "evil-a"); !ok {
		t.Error("the LAST GOOD feed was dropped; a failed verification must not fail open")
	}
	if err := src.stale(); err == nil {
		t.Error("readiness reports the feed as current while the mount holds something we refused")
	}
}

// ── The compatibility promise: no key, no change ─────────────────────────────
//
// Every feed in every deployment today is unsigned and unversioned. If configuring
// nothing changed anything, this feature would disarm layer 1 for everyone who has not
// re-generated a snapshot -- a strictly worse outcome than the attacks above.
func TestWithoutAKeyNothingChanges(t *testing.T) {
	path := writeFeed(t, `{"id":"MAL-1","ecosystem":"npm","name":"evil-a"}`)
	l, err := loadMalwareList(path, nil)
	if err != nil {
		t.Fatalf("an unsigned, unversioned feed must still load when no key is configured: %v", err)
	}
	if _, ok := l.lookupAll("npm", "evil-a"); !ok {
		t.Error("the advisory did not load")
	}
	if l.header.Present {
		t.Error("a feed with no header reported one")
	}
	// And a feed that HAS a header still loads without a key: the header is not a
	// second gate, it is what makes the signature meaningful.
	path2 := writeFeed(t, feedHeaderLine(5, time.Now(), 1), `{"id":"MAL-2","ecosystem":"npm","name":"evil-b"}`)
	l2, err := loadMalwareList(path2, nil)
	if err != nil {
		t.Fatalf("a headered but unsigned feed was refused with no key configured: %v", err)
	}
	if l2.header.Serial != 5 {
		t.Errorf("serial = %d, want 5", l2.header.Serial)
	}
}

// ── A key with no signature, and a signature with no header ──────────────────
func TestAConfiguredKeyRequiresBothASignatureAndAHeader(t *testing.T) {
	priv, pub, _ := feedKeys(t)

	// No .sig beside the feed at all.
	bare := writeFeed(t, feedHeaderLine(1, time.Now(), 1), `{"id":"MAL-1","ecosystem":"npm","name":"a"}`)
	_, err := loadMalwareList(bare, pub)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("a configured key with no signature file must refuse, naming the file: %v", err)
	}

	// Signed, but with no header: valid bytes, unknowable freshness.
	noHeader := writeSignedFeed(t, t.TempDir(), priv, `{"id":"MAL-1","ecosystem":"npm","name":"a"}`+"\n", nil)
	_, err = loadMalwareList(noHeader, pub)
	if err == nil || !strings.Contains(err.Error(), "header") {
		t.Errorf("a signed feed with no header must refuse, because a signature alone cannot tell the "+
			"current snapshot from a replayed one: %v", err)
	}
}

// ── Staleness is LOUD, never a refusal ───────────────────────────────────────
//
// An old advisory is still an advisory. Refusing to enforce what we have because it is
// old would turn a stale feed into NO feed, which is the one outcome worse than being
// stale -- and it would do it during exactly the incident that stopped the refresh.
func TestAStaleSnapshotIsEnforcedAndSaidOutLoud(t *testing.T) {
	priv, pub, _ := feedKeys(t)
	old := time.Now().Add(-feedMaxAge - time.Hour)
	path := writeSignedFeed(t, t.TempDir(), priv, goodFeed(2, old), nil)

	l, err := loadMalwareList(path, pub)
	if err != nil {
		t.Fatalf("a stale snapshot must still LOAD: %v", err)
	}
	if _, ok := l.lookupAll("npm", "evil-a"); !ok {
		t.Error("a stale snapshot stopped enforcing; that is worse than being stale")
	}
	if l.header.age(time.Now()) <= feedMaxAge {
		t.Error("the fixture is not actually stale, so this test proves nothing")
	}
}

// TestAFeedThatAgesWithoutChangingIsStillReported is the test that did not exist, and
// its absence hid a hole in the code rather than only in the coverage.
//
// A sabotage shrinking feedMaxAge to a nanosecond reddened NOTHING. The reason was not
// a missing assertion: the staleness check lived inside the branch that runs when the
// BYTES change, so a feed that simply aged in place could never reach it. That is the
// likeliest real failure of the whole feature -- the refresh job dies, the file stops
// changing, and the gate ages past the limit in silence while every log line it does
// print says the feed loaded fine.
func TestAFeedThatAgesWithoutChangingIsStillReported(t *testing.T) {
	shortFeedIntervals(t)
	priv, pub, _ := feedKeys(t)
	dir := t.TempDir()
	// Fresh when loaded, stale by the time the interval comes round: exactly the
	// crossing, with nothing on the mount touched in between.
	path := writeSignedFeed(t, dir, priv, goodFeed(4, time.Now().Add(-feedMaxAge+time.Second)), nil)
	first, err := loadMalwareList(path, pub)
	if err != nil {
		t.Fatal(err)
	}
	var logged []string
	src := newReloadingFeed(path, "npm", func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }, first, pub)
	if strings.Contains(strings.Join(logged, "\n"), "the refresh has stopped") {
		t.Fatal("reported stale while still fresh, so the line below would prove nothing")
	}

	time.Sleep(1100 * time.Millisecond) // crosses feedMaxAge without touching the file
	got := src.current()

	if _, ok := got.lookupAll("npm", "evil-a"); !ok {
		t.Error("a stale feed stopped enforcing; that is worse than being stale")
	}
	if err := src.stale(); err != nil {
		t.Errorf("staleness must not fail READINESS: every replica shares one source, so this would take "+
			"the fleet out of rotation at once and route developers around the gate: %v", err)
	}
	joined := strings.Join(logged, "\n")
	if !strings.Contains(joined, "the refresh has stopped") {
		t.Fatalf("a feed aged past the limit WITHOUT the file changing, and nothing was said:\n%s", joined)
	}
	// ONCE per crossing. A line repeated every interval for a week trains an operator to
	// filter it, and then the one that matters is filtered too.
	before := len(logged)
	src.checked = time.Time{} // force the next interval to run
	_ = src.current()
	if n := len(logged) - before; n != 0 {
		t.Errorf("the staleness line repeated %d more time(s) on the next interval", n)
	}
	// And a fresher snapshot clears it, so a recovery is reported rather than assumed.
	writeSignedFeed(t, dir, priv, goodFeed(5, time.Now()), nil)
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	src.checked = time.Time{}
	_ = src.current()
	if !strings.Contains(strings.Join(logged, "\n"), "current again") {
		t.Errorf("recovery was silent, so an operator watching for the all-clear never sees one:\n%s",
			strings.Join(logged, "\n"))
	}
}

// ── The header parser's own edges ────────────────────────────────────────────
func TestFeedHeaderParsing(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	cases := []struct {
		name, line string
		isHeader   bool
		wantErr    string
	}{
		{"a good header", feedHeaderPrefix + "v1 serial=4 generated=" + now + " rows=9", true, ""},
		{"an ordinary comment is not a header", "# built by hand", false, ""},
		{"a comment that merely mentions the feed", "# yellowjack feed notes", false, ""},
		{"an unknown field is ignored, so a newer signer is not refused",
			feedHeaderPrefix + "v1 serial=4 generated=" + now + " rows=9 channel=beta", true, ""},
		{"a version we do not understand", feedHeaderPrefix + "v2 serial=4 generated=" + now, true, "version 2"},
		{"no serial", feedHeaderPrefix + "v1 generated=" + now, true, "no serial"},
		{"no timestamp", feedHeaderPrefix + "v1 serial=4", true, "no generated"},
		{"a serial that is not a number", feedHeaderPrefix + "v1 serial=x generated=" + now, true, "serial"},
		{"a timestamp that is not RFC3339", feedHeaderPrefix + "v1 serial=4 generated=yesterday", true, "generated"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, isHeader, err := parseFeedHeader(c.line)
			if isHeader != c.isHeader {
				t.Fatalf("isHeader = %v, want %v", isHeader, c.isHeader)
			}
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error = %v, want one naming %q", err, c.wantErr)
			}
		})
	}
}

func TestASecondHeaderLineIsRefused(t *testing.T) {
	now := time.Now()
	path := writeFeed(t, feedHeaderLine(1, now, 1), feedHeaderLine(2, now, 1),
		`{"id":"MAL-1","ecosystem":"npm","name":"a"}`)
	if _, err := loadMalwareList(path, nil); err == nil || !strings.Contains(err.Error(), "second header") {
		t.Errorf("two headers in one file must be refused -- one snapshot, one serial: %v", err)
	}
}

// ── The key as an operator types it ──────────────────────────────────────────
func TestTheConfiguredKeyIsParsedWithAUsefulComplaint(t *testing.T) {
	_, pub, b64 := feedKeys(t)
	got, err := parseFeedKey("  " + b64 + "\n")
	if err != nil {
		t.Fatalf("surrounding whitespace must not defeat a pasted key: %v", err)
	}
	if !got.Equal(pub) {
		t.Error("the parsed key is not the one configured")
	}
	if got, err := parseFeedKey(""); err != nil || got != nil {
		t.Errorf("empty must mean off, not an error: %v %v", got, err)
	}
	if _, err := parseFeedKey("not base64!!"); err == nil || !strings.Contains(err.Error(), "base64") {
		t.Errorf("a mistyped key must say so: %v", err)
	}
	// A valid base64 string of the wrong length is the mistake that would otherwise
	// reach ed25519.Verify and fail there, naming the FEED instead of the KEY.
	short := base64.StdEncoding.EncodeToString([]byte("too short"))
	if _, err := parseFeedKey(short); err == nil || !strings.Contains(err.Error(), "32") {
		t.Errorf("a wrong-length key must be refused by length, naming the key: %v", err)
	}
}
