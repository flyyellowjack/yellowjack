package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// The served version must be the version inside the artifact (issue #52).
//
// A registry addresses a tarball as "/<name>/-/<base>-<version>.tgz", and the tarball
// carries its own package.json with its own "version". Nothing in npm compares the two:
// the lockfile records the version from the URL, node_modules gets the package.json from
// the bytes, and a registry, mirror or cache that pairs one version's URL with another
// version's bytes is invisible to the client. That is not hypothetical — a vendor whose
// product is trustworthy artifacts shipped a `:latest` advertising one major version and
// containing another, and could not reproduce the digest mismatch two users reported.
//
// ✅ THAT PREMISE IS NOW MEASURED RATHER THAN ASSERTED, and it was worth measuring.
// npm 10 on node 22, fixture registry, NO firewall in the path: a tarball served under a
// 1.0.0 URL whose package.json declares 9.9.9 installs with exit 0 and no complaint —
// node_modules gets 9.9.9 from the bytes while package-lock.json records 1.0.0 from the
// URL. The two disagree inside one install, which is the concrete form of "invisible to
// the client". Pinned by TestNpmItselfDoesNotCompareTheVersions, which fails LOUDLY if
// npm ever starts checking, because that is good news that invalidates this paragraph.
//
// ⚠️ It needed measuring because the same claim, made for PyPI, was FALSE. #136 shipped
// saying pip does not compare them; pip resolving from an index compares the filename
// version against the PEP 658 metadata itself and discards the file. The claim had been
// measured on `pip install ./local.whl` and generalised to a path that behaves
// differently — the same binary, the same flags, a different argument shape. So "the
// client does not check" is a PER-ECOSYSTEM fact and does not transfer; npm's happens to
// hold and PyPI's did not.
//
// We are the one party that holds both facts at once — the URL we were asked for and the
// bytes we are about to hand over — so the comparison is cheap here and, for npm,
// genuinely unavailable to the client. A mismatch is refused with its OWN reason: the
// package is not unknown (unscorable), it is misrepresenting itself, and the operator
// must be able to tell those apart.
//
// What this is and is not. It catches misrepresentation: a wrong file under a right
// name, from a buggy or stale or substituted upstream. It is not a defence against an
// attacker who controls the bytes — they write whatever package.json they like — and it
// does not pretend to be one; that attacker is the byte-integrity and advisory layers'
// problem. So when the version cannot be READ at all (not a gzip stream, no
// package.json within the inspection window) the tarball is served with the reason
// logged rather than refused: a tarball we cannot read is usually one npm cannot install
// either, and refusing here would break every fixture and registry quirk that serves
// unusual bytes on a .tgz path.
//
// "Usually" is doing real work in that sentence, and it is why this reader is written to
// match npm's extractor rather than to be merely reasonable (#47, issue #122). A reader
// that is lenient in different places from the installer does not just miss things — it
// makes CONFIDENT and WRONG statements. Measured against `npm install` on node 22, the
// first version of this check reported "version verified: 1.0.0" for a tarball npm
// installs as 9.9.9, and served three more it could not read at all but npm installs
// happily. Two rules close that gap, and both come from measurement, not from reading
// npm's source:
//
//   - ENTRY SELECTION. npm strips the first path component, whatever it is called, after
//     collapsing repeated slashes. So "package/package.json", "./package.json",
//     "/package.json" and "package//package.json" are all the manifest, while
//     "package.json", "./package/package.json" and "package/sub/package.json" are not.
//     npmTarballEntryIsPackageJSON agrees with npm on all eleven shapes tested.
//
//   - WHICH ONE WINS. An extractor writes entries in order, so when a tarball carries
//     more than one manifest the LAST is what lands in node_modules. Reading the first
//     is how "verified" got attached to bytes declaring something else. Nothing npm
//     packs produces a duplicate, but nothing stops an upstream serving one.
//
// The cost is that the decision now needs the whole archive rather than its first entry,
// so the client's first byte waits for the tarball to arrive instead of for its first
// tar entry — bounded, as before, by npmTarballInspectBytes. Past that bound the reader
// has seen a PREFIX of what the installer will see, and says so rather than claiming a
// verification it cannot support.

// npmTarballInspectBytes bounds how much of a tarball relayNpmTarball holds back before
// the first byte reaches the client. The check needs package.json; npm writes it as the
// FIRST entry of every tarball it packs, so in practice the decision lands after the
// first few KiB and the bound is never reached. It exists so the check can never turn
// into "buffer the whole artifact" on a large package.
const npmTarballInspectBytes = 4 << 20

// npmPackageJSONMax bounds the package.json entry itself; a real one is a few KiB.
const npmPackageJSONMax = 1 << 20

// npmTarballVersionFromPath recovers the version a tarball is SERVED AS from the
// registry's own object path: "/<name>/-/<base>-<version>.tgz", where <base> is the
// package name without its scope ("@babel/core" is served as "core-7.0.0.tgz").
//
// The same "/-/" boundary rule as npmObjectPathBindsToPackage, and for the same reason:
// a package name cannot contain "/-/", so the first occurrence is the real one. The
// filename is required to start with the package's own base name — a tarball the
// registry serves under some other filename has no version we can trust the URL for,
// and the check declines (ok=false) rather than guessing.
func npmTarballVersionFromPath(pkg, objectPath string) (string, bool) {
	idx := strings.Index(objectPath, "/-/")
	if idx <= 0 {
		return "", false
	}
	// The object path travels ESCAPED (it is forwarded verbatim); decode the filename
	// before reading it, so a "+" in a build-metadata version cannot become "%2B" on one
	// side of the comparison only.
	file, err := url.PathUnescape(objectPath[idx+len("/-/"):])
	if err != nil || strings.Contains(file, "/") {
		return "", false
	}
	base := pkg
	if i := strings.LastIndexByte(pkg, '/'); i >= 0 {
		base = pkg[i+1:]
	}
	rest := strings.TrimPrefix(file, base+"-")
	if rest == file {
		return "", false
	}
	version := strings.TrimSuffix(rest, ".tgz")
	if version == rest || version == "" {
		return "", false
	}
	return version, true
}

// npmTarballScan is everything the reader could learn about a tarball's own version.
// It is deliberately not a verdict: relayNpmTarball decides, and the distinction between
// "read nothing", "read a prefix" and "read the whole archive" is the reason this is a
// struct rather than a (string, error) pair.
type npmTarballScan struct {
	// Version is declared by the LAST top-level package.json in the stream — the entry
	// npm's extractor leaves in node_modules. Empty when none could be read.
	Version string
	// Entries counts the top-level package.json entries seen. More than one is never
	// produced by `npm pack`, and is exactly the case first-match reading gets wrong.
	Entries int
	// Final reports that the tar's end-of-archive marker was reached, so no later entry
	// can override Version. False means the stream ran out first and Version describes a
	// PREFIX of what the installer will see.
	Final bool
	// Err is why no usable version came out, phrased for the operator's log line. Every
	// value is a reason, never a verdict.
	Err error
}

// npmDeclaredVersion reads a tarball's own declared version the way npm's extractor
// would: the last top-level package.json wins, and the entry is matched by npm's path
// rule (see the file comment). It consumes the whole tar stream, because "which entry is
// last" is not knowable from a prefix; the caller bounds how much stream it is given.
//
// A stream that ends before the end-of-archive marker is not an error by itself — it
// leaves Final false and lets the caller say so — but a stream that ends before any
// manifest was read surfaces the underlying io.ErrUnexpectedEOF, wrapped, so the caller
// can still tell "cut short" from "not there".
func npmDeclaredVersion(r io.Reader) npmTarballScan {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return npmTarballScan{Err: fmt.Errorf("not a gzip stream (%w)", err)}
	}
	tr := tar.NewReader(zr)

	var scan npmTarballScan
	var lastErr error // why the LAST manifest was unusable, if it was
	for {
		h, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				scan.Final = true
				break
			}
			// Broke or ran out mid-archive. What was read stands as a prefix; only a
			// stream that yielded nothing at all is reported as unreadable.
			if scan.Entries == 0 {
				scan.Err = fmt.Errorf("tar stream unreadable (%w)", err)
			}
			break
		}
		if !npmTarballEntryIsPackageJSON(h.Name) {
			continue
		}
		// Only a REGULAR file can be the manifest, because npm's extractor skips symlink and
		// hardlink entries outright (measured 2026-09-23 with a real `npm install`, #47). A
		// link NAMED package/package.json after the real one used to be counted as the last
		// manifest. Reading it failed, and the tarball was served unchecked, so one appended
		// link entry turned a refused version mismatch into a served one.
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			continue
		}
		scan.Entries++
		// Last one wins, including when the last one is broken: npm reads the same bytes
		// and fails on them, so inheriting an earlier entry's version would be claiming
		// something about an artifact the developer cannot install.
		scan.Version, lastErr = npmPackageJSONVersion(tr, h.Size)
	}
	switch {
	case scan.Err != nil:
	case lastErr != nil:
		scan.Err = lastErr
	case scan.Entries == 0:
		scan.Err = errors.New("no package.json in the tarball")
	}
	return scan
}

// npmPackageJSONVersion reads one package.json entry's "version".
func npmPackageJSONVersion(tr *tar.Reader, size int64) (string, error) {
	if size > npmPackageJSONMax {
		return "", fmt.Errorf("package.json is %d bytes, larger than the %d-byte limit", size, npmPackageJSONMax)
	}
	body, err := io.ReadAll(tr)
	if err != nil {
		return "", fmt.Errorf("package.json cut short (%w)", err)
	}
	var manifest struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return "", fmt.Errorf("package.json is not JSON (%v)", err)
	}
	if manifest.Version == "" {
		return "", errors.New("package.json declares no version")
	}
	return manifest.Version, nil
}

// npmTarballEntryIsPackageJSON reports whether an entry is the tarball's OWN manifest —
// the one npm extracts — by npm's rule: collapse repeated slashes, drop the first path
// component whatever it is called, and what remains must be exactly "package.json".
//
// The first component is dropped literally, so "." and the empty component before a
// leading "/" are components like any other. That is not a guess: each shape below was
// installed with a real npm and the two agree on all of them (issue #122).
//
//	package/package.json    manifest        package.json             not
//	./package.json          manifest        ./package/package.json   not
//	/package.json           manifest        /package/package.json    not
//	package//package.json   manifest        package/sub/package.json not
//	anything/package.json   manifest
func npmTarballEntryIsPackageJSON(name string) bool {
	for strings.Contains(name, "//") {
		name = strings.ReplaceAll(name, "//", "/")
	}
	i := strings.IndexByte(name, '/')
	return i >= 0 && name[i+1:] == "package.json"
}

// errScanDone is how the scanner tells the feeder it has decided: a write into the pipe
// after this fails with it, and the feeder stops holding bytes back.
var errScanDone = errors.New("npm tarball scan finished")

// errReader hands a stored read error to whoever reads it, so a body that failed while
// its head was being inspected fails again, identically, when it is streamed.
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// relayNpmTarball is relay for an npm tarball fetch, with one check between the
// upstream's answer and the first byte to the client: the version inside the tarball
// must be the version it is served as. `served` is the version from the object path.
//
// The body is fed to the scanner AS IT ARRIVES, with a copy of everything fed held back,
// so the client's first byte waits only for the decision — the first tar entry, for a
// tarball npm packed — and never for more than npmTarballInspectBytes. Then the held
// bytes and the rest of the body go through the same streaming path as every other
// relay, so what the client receives is the upstream's bytes and dist.integrity still
// verifies. Nothing is written to the client before the decision: a refusal is a clean
// 403 with a reason, never a 200 that stops short. An upstream that fails mid-head is
// served as far as it got and then fails the way relay fails, so the short-transfer
// accounting is the same on this path as on every other.
//
// Report mode (FW_MODE=report) turns the refusal into a "WOULD HAVE REFUSED" line and
// serves the tarball, through p.refuse like every other refusal.
func (p *proxyServer) relayNpmTarball(w http.ResponseWriter, r *http.Request, target, pkg, served string, id flowID) {
	resp, srcIP, ok := p.openUpstream(w, r, target, false, id)
	if !ok {
		return
	}
	defer resp.Body.Close()

	// Only a 200 GET carries bytes to inspect. A HEAD has no body by definition, and a
	// non-200 answer (a 404 for a version that does not exist, a 429) is the upstream's
	// to explain — relayed as-is, exactly as relay would.
	if resp.StatusCode != http.StatusOK || r.Method == http.MethodHead {
		p.streamResponse(w, r, target, resp, resp.Body, id, srcIP)
		return
	}

	pr, pw := io.Pipe()
	scanned := make(chan npmTarballScan, 1)
	go func() {
		scan := npmDeclaredVersion(pr)
		pr.CloseWithError(errScanDone) // unblocks a feeder still writing; nothing more is needed
		scanned <- scan
	}()

	var held bytes.Buffer
	var readErr error
	chunk := make([]byte, 32<<10)
	for held.Len() < npmTarballInspectBytes {
		want := chunk
		if room := npmTarballInspectBytes - held.Len(); room < len(want) {
			want = want[:room]
		}
		n, err := resp.Body.Read(want)
		if n > 0 {
			held.Write(want[:n])
			if _, werr := pw.Write(want[:n]); werr != nil {
				break // the scanner has decided
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
			}
			break
		}
	}
	pw.Close() // a scanner still reading sees EOF and decides on what it has
	scan := <-scanned

	rest := io.Reader(resp.Body)
	if readErr != nil {
		rest = errReader{readErr}
	}
	body := io.MultiReader(bytes.NewReader(held.Bytes()), rest)
	serve := func() { p.streamResponse(w, r, target, resp, body, id, srcIP) }

	if scan.Err != nil && held.Len() >= npmTarballInspectBytes && errors.Is(scan.Err, io.ErrUnexpectedEOF) {
		// Not a broken tarball: one whose package.json sits past the window. The
		// documented limit of the check, named as such in the log.
		scan.Err = fmt.Errorf("no package.json in the first %d bytes", held.Len())
	}
	// A tarball carrying more than one manifest is worth saying out loud wherever it
	// appears, because `npm pack` does not produce one and because it is the shape that
	// makes a first-match reader disagree with the installer (#122).
	duplicates := ""
	if scan.Entries > 1 {
		duplicates = fmt.Sprintf("; the tarball carries %d package.json entries and npm installs the last", scan.Entries)
	}
	switch {
	case scan.Err != nil:
		// Visibility, not a hole: see the file comment. The line names the reason so an
		// operator can tell "npm's tarballs never trip this" from "my mirror serves
		// something odd on every .tgz path".
		log.Printf("artifact %s -> version unverified, serving as %s: %v%s", pkg, served, scan.Err, duplicates)
		serve()
	case scan.Version != served:
		reason := fmt.Sprintf("tarball declares version %s but was served as version %s%s", scan.Version, served, duplicates)
		log.Printf("artifact %s -> refused: %s (#52)", pkg, reason)
		p.refuse(w, pkg, blockErrMsg, reason, notAReviewItem,
			verdictMeta{Kind: "integrity", Rule: "tarball-version", Source: sourceIntegrity}, serve)
	case !scan.Final:
		// The versions agree across everything we were allowed to read, and the archive
		// runs on past the window. Saying "verified" here would be claiming a whole-file
		// property from a prefix — the exact conflation #47 exists to prevent.
		log.Printf("artifact %s -> version matches %s in the first %d bytes, but the tarball continues "+
			"past the inspection window and a later package.json would override it%s", pkg, served, held.Len(), duplicates)
		serve()
	default:
		log.Printf("artifact %s -> version verified: %s%s", pkg, served, duplicates)
		serve()
	}
}
