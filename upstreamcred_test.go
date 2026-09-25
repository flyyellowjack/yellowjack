package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A re-read interval short enough that a test can cross it without a visible pause.
const testCredTTL = 5 * time.Millisecond

func writeCred(t *testing.T, path, v string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(v), 0o600); err != nil {
		t.Fatal(err)
	}
}

// discard swallows the source's log lines. Tests that assert ON the logging use
// captureLog instead.
func discard(string, ...any) {}

func captureLog(t *testing.T) (func(string, ...any), func() string) {
	t.Helper()
	var mu sync.Mutex
	var sb strings.Builder
	return func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			sb.WriteString(format)
			for range args {
			}
			sb.WriteString("\n")
		}, func() string {
			mu.Lock()
			defer mu.Unlock()
			return sb.String()
		}
}

// TestFileCredentialPicksUpARotatedToken is the whole point of issue #53: a token
// that changes on disk must reach the wire WITHOUT restarting the process. Before
// this, FW_UPSTREAM_AUTH was read once at startup, so a CodeArtifact token expiring
// mid-day took the gate down with it.
func TestFileCredentialPicksUpARotatedToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeCred(t, path, "Bearer first")
	src := fileCredentialEvery(path, discard, testCredTTL)

	if got := src(); got != "Bearer first" {
		t.Fatalf("initial read = %q, want %q", got, "Bearer first")
	}
	writeCred(t, path, "Bearer second")
	time.Sleep(2 * testCredTTL)
	if got := src(); got != "Bearer second" {
		t.Fatalf("after rotation = %q, want %q — a rotated token did not reach the caller", got, "Bearer second")
	}
}

// TestFileCredentialKeepsTheLastGoodValueWhenTheFileBreaks is the SAFETY property,
// and it is the reason this source is not four lines.
//
// Refreshers do not all write atomically, so a read can land mid-rewrite on an empty
// or truncated file; a deleted file, a permissions change, or a full disk look the
// same. Returning "" there would drop the Authorization header and silently degrade
// us to ANONYMOUS — requests keep succeeding, at the lower anonymous rate ceiling,
// with nothing in the logs tied to the cause. That is a "passes for the wrong reason"
// failure, which this project treats as worse than an outright error.
func TestFileCredentialKeepsTheLastGoodValueWhenTheFileBreaks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeCred(t, path, "Bearer good")
	logf, logged := captureLog(t)
	src := fileCredentialEvery(path, logf, testCredTTL)

	if got := src(); got != "Bearer good" {
		t.Fatalf("initial read = %q", got)
	}

	// Case 1: mid-rewrite — the file exists but is empty.
	writeCred(t, path, "")
	time.Sleep(2 * testCredTTL)
	if got := src(); got != "Bearer good" {
		t.Fatalf("after an EMPTY read = %q, want the last good %q — an empty file blanked the credential",
			got, "Bearer good")
	}

	// Case 2: the file is gone entirely.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * testCredTTL)
	if got := src(); got != "Bearer good" {
		t.Fatalf("after a FAILED read = %q, want the last good %q — a missing file blanked the credential",
			got, "Bearer good")
	}

	// The degradation must be audible. A credential source that silently papers over
	// a broken file is how an operator finds out weeks later.
	if !strings.Contains(logged(), "still sending the last credential") &&
		!strings.Contains(logged(), "keeping the previous credential") {
		t.Errorf("degradation was not logged; got %q", logged())
	}
}

// TestFileCredentialWithNoGoodReadEverYieldsEmpty is the DISCRIMINATOR for the test
// above, and without it that test proves nothing.
//
// "Keeps the last good value" and "always returns something non-empty" are different
// properties that pass the previous test identically. This pins the difference: with
// no successful read EVER, there is no last-good value to keep, and the source must
// yield "" (which withUpstreamAuth treats as "send no header") rather than inventing
// one. It also asserts the log says so in the stronger wording, because "no
// credential has ever been read" and "still sending the previous one" need different
// urgency from whoever is reading.
func TestFileCredentialWithNoGoodReadEverYieldsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-created")
	logf, logged := captureLog(t)
	src := fileCredentialEvery(path, logf, testCredTTL)

	if got := src(); got != "" {
		t.Fatalf("with no readable file ever, source = %q, want empty", got)
	}
	if !strings.Contains(logged(), "NO credential has ever been read") {
		t.Errorf("the never-read case must be logged distinctly; got %q", logged())
	}
}

// TestFileCredentialTrimsSurroundingWhitespace covers the way these files are
// actually produced. `aws codeartifact get-authorization-token … > token` and every
// editor leave a trailing newline, and an Authorization header value containing one
// is invalid — net/http rejects the request outright, so an untrimmed value would
// fail EVERY upstream call rather than degrade quietly.
func TestFileCredentialTrimsSurroundingWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeCred(t, path, "  Bearer padded\n")
	if got := fileCredentialEvery(path, discard, testCredTTL)(); got != "Bearer padded" {
		t.Fatalf("= %q, want %q — a shell-written token would break every request", got, "Bearer padded")
	}
}

// TestFileCredentialRecoversWhenTheFileComesBack: a refresher that was briefly broken
// must not leave us pinned to a stale token forever. Pairs with the safety property —
// "keep the last good value" has to mean "until a better one arrives", not "forever".
func TestFileCredentialRecoversWhenTheFileComesBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeCred(t, path, "Bearer old")
	src := fileCredentialEvery(path, discard, testCredTTL)
	if got := src(); got != "Bearer old" {
		t.Fatalf("initial = %q", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * testCredTTL)
	_ = src() // degraded, serving the last good value
	writeCred(t, path, "Bearer new")
	time.Sleep(2 * testCredTTL)
	if got := src(); got != "Bearer new" {
		t.Fatalf("after recovery = %q, want %q — stuck on the stale credential", got, "Bearer new")
	}
}

// TestFileCredentialIsConcurrencySafe. The source is called from RoundTrip, which
// runs on every proxy goroutine at once. Meaningful only under -race, which CI runs.
func TestFileCredentialIsConcurrencySafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeCred(t, path, "Bearer concurrent")
	src := fileCredentialEvery(path, discard, testCredTTL)

	// PRIME with one successful read before anything starts truncating. Without this
	// the test is flaky, and the flake was real: it failed on CI on 2026-09-04 (#110)
	// while the same commit passed in the other pipeline 25 seconds later.
	//
	// The mechanism, confirmed deterministically rather than inferred: the writer
	// below uses os.WriteFile, which TRUNCATES before it writes, so the file is
	// genuinely empty for a moment. fileCredentialEvery handles that correctly — an
	// empty read keeps the last good value — but `last` is "" until the first good
	// read, so a reader whose FIRST call lands inside the truncation window has
	// nothing to fall back to and correctly returns "".
	//
	// So the product was right and the test was wrong: it demanded a fallback value
	// before establishing one. Priming makes the assertion below mean what it says —
	// "a truncating refresher must never blank an ALREADY-GOOD credential", which is
	// a real scenario (`echo "$TOKEN" > /run/creds/token` truncates too).
	//
	// The two behaviours this leans on are pinned deterministically elsewhere in this
	// file and are not left to timing: an empty read keeps the last good value, and
	// with no good read ever the result IS "" (TestFileCredentialWithNoGoodReadEverYieldsEmpty).
	if got := src(); got != "Bearer concurrent" {
		t.Fatalf("priming read = %q, want %q — the fixture is wrong before concurrency is involved", got, "Bearer concurrent")
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if got := src(); got != "Bearer concurrent" {
					t.Errorf("concurrent read = %q", got) // Errorf IS safe off-goroutine; Fatal is not
					return
				}
			}
		}()
	}
	// Rewrite underneath the readers: writers and readers must not race either.
	//
	// This writer is in the WaitGroup and does NOT use writeCred, deliberately. The
	// first version of this test spawned an unwaited goroutine calling writeCred,
	// which calls t.Fatal — and t.Fatal from a non-test goroutine is illegal, while
	// an unwaited goroutine can outlive the test and hit a t.TempDir() that cleanup
	// has already removed. That combination made the whole PACKAGE run unstable, not
	// just this test: it was caught by bisecting a TestModeMatrix flake down to this
	// file rather than to any production change.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := os.WriteFile(path, []byte("Bearer concurrent"), 0o600); err != nil {
			t.Errorf("concurrent write: %v", err)
		}
	}()
	wg.Wait()
}

// TestRotatingCredentialIsStillScopedToTheUpstreamHost re-proves the SECURITY
// property against the new source type.
//
// Host scoping is the hard requirement in upstreamauth.go: the same client also talks
// to deps.dev and the approval service, and leaking a registry credential to either
// would be the bug. Changing the credential from a string to a function is exactly
// the kind of refactor that quietly relocates a check, so the property is re-asserted
// here rather than assumed to have survived.
func TestRotatingCredentialIsStillScopedToTheUpstreamHost(t *testing.T) {
	var upstreamAuth, otherAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth = r.Header.Get("Authorization")
	}))
	defer upstream.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherAuth = r.Header.Get("Authorization")
	}))
	defer other.Close()

	path := filepath.Join(t.TempDir(), "token")
	writeCred(t, path, "Bearer rotating")
	client := &http.Client{Transport: withUpstreamAuth(
		nil, hostOf(t, upstream.URL), fileCredentialEvery(path, discard, testCredTTL))}

	if _, err := client.Get(upstream.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(other.URL); err != nil {
		t.Fatal(err)
	}
	if upstreamAuth != "Bearer rotating" {
		t.Errorf("upstream got %q, want the credential", upstreamAuth)
	}
	if otherAuth != "" {
		t.Errorf("LEAK: a non-upstream host received %q", otherAuth)
	}
}

// TestBothCredentialFormsAtOnceIsRefusedAtStartup. They are not composable — one is
// fixed, the other rotates — so an operator setting both has a belief about which
// wins, and silently picking one is wrong half the time. The wrong pick also fails
// INVISIBLY: the static value keeps working right up until it expires.
func TestBothCredentialFormsAtOnceIsRefusedAtStartup(t *testing.T) {
	t.Setenv("FW_UPSTREAM_AUTH", "Bearer static")
	// An ABSOLUTE path, so the refusal below can only be the mutual-exclusion rule.
	// A relative one would trip the absolute-path guard instead and the test would
	// still pass with the exclusion deleted — passing for the wrong reason.
	t.Setenv("FW_UPSTREAM_AUTH_FILE", filepath.Join(t.TempDir(), "token"))
	_, err := loadConfig()
	if err == nil {
		t.Fatal("setting BOTH credential forms was accepted; startup must refuse it")
	}
	if !strings.Contains(err.Error(), "FW_UPSTREAM_AUTH_FILE") {
		t.Errorf("the error must name the offending knob; got %q", err)
	}
}

// TestEitherCredentialFormAloneIsAccepted is the negative control for the check
// above: a refusal that fires on the legal configurations too would be worse than no
// check at all, because it would block both supported deployments.
func TestEitherCredentialFormAloneIsAccepted(t *testing.T) {
	t.Run("static only", func(t *testing.T) {
		t.Setenv("FW_UPSTREAM_AUTH", "Bearer static")
		if _, err := loadConfig(); err != nil {
			t.Fatalf("static-only config refused: %v", err)
		}
	})
	t.Run("file only", func(t *testing.T) {
		// t.TempDir() rather than a literal like "/run/secrets/token": that spelling is
		// absolute on Linux, where the container runs, but NOT on Windows, where
		// filepath.IsAbs wants a drive letter. A literal would make this test pass in CI
		// and fail on the dev host — which trains people to ignore local red.
		t.Setenv("FW_UPSTREAM_AUTH_FILE", filepath.Join(t.TempDir(), "token"))
		if _, err := loadConfig(); err != nil {
			t.Fatalf("file-only config refused: %v", err)
		}
	})
	t.Run("neither", func(t *testing.T) {
		if _, err := loadConfig(); err != nil {
			t.Fatalf("default config refused: %v", err)
		}
	})
}

// TestRelativeCredentialFileIsRefusedAtStartup. The allowlist entry in
// configsurface_test.go that permits upstreamcred.go to read a file at runtime is
// not a pardon — it is a CLAIM that the path can only come from the operator, and
// this is the test that makes the claim true.
//
// A relative path resolves against the working directory, so the credential we
// present upstream would be chosen by wherever the process was launched. That is
// #38 / CVE-2025-64726's mechanism, and it is worse here than for the malware feed
// because this file holds a secret rather than a blocklist.
func TestRelativeCredentialFileIsRefusedAtStartup(t *testing.T) {
	for _, rel := range []string{"token", "./token", "../secrets/token", "secrets/token"} {
		t.Run(rel, func(t *testing.T) {
			t.Setenv("FW_UPSTREAM_AUTH_FILE", rel)
			_, err := loadConfig()
			if err == nil {
				t.Fatalf("relative path %q was accepted; it must be refused", rel)
			}
			if !strings.Contains(err.Error(), "absolute path") {
				t.Errorf("error should explain the absolute-path requirement; got %q", err)
			}
		})
	}
}

// TestAbsoluteCredentialFileIsAccepted is the negative control for the guard above:
// a check that also rejected the legal form would block the only supported way to
// configure a rotating credential, while looking like a security win.
func TestAbsoluteCredentialFileIsAccepted(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "token") // TempDir is absolute on every platform
	t.Setenv("FW_UPSTREAM_AUTH_FILE", abs)
	if _, err := loadConfig(); err != nil {
		t.Fatalf("absolute path %q refused: %v", abs, err)
	}
}
