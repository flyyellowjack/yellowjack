package main

import (
	"os"
	"strings"
	"sync"
	"time"
)

// A credentialSource yields the Authorization header value to send upstream, re-read
// at call time rather than captured once at startup.
//
// WHY THIS EXISTS (issue #53, D177). FW_UPSTREAM_AUTH is a static string read once
// from the environment. That cannot front an upstream that mints SHORT-LIVED tokens:
// the credential expires part-way through the day and the gate goes down with it.
// AWS CodeArtifact — the first integration target under D177 — issues exactly that
// kind of token, so "in front of CodeArtifact" is unreachable without this.
//
// A func, not an interface: there is one method, and every caller wants "give me the
// current value".
type credentialSource func() string

// staticCredential is the pre-#53 behaviour, preserved exactly: one value, forever.
// It remains the default, so a deployment that sets FW_UPSTREAM_AUTH sees no change.
func staticCredential(v string) credentialSource {
	return func() string { return v }
}

// credFileTTL bounds how stale a rotated credential can be. One second: the file is a
// few hundred bytes, so a read per second is free next to the network calls it
// authenticates, and it keeps the window in which we would send an expired token to
// roughly one request.
const credFileTTL = time.Second

// fileCredential reads the Authorization value from a file, re-reading it as it
// changes so a rotated token is picked up WITHOUT a restart.
//
// A file is the interop point every refresh mechanism already has: Kubernetes
// projected service-account tokens ARE files rotated in place, Vault agent writes
// files, and a sidecar or cron running `aws codeartifact get-authorization-token`
// writes a file. So this supports all of them without us executing anything — which
// an exec-helper would have required, and executing a configured subprocess from
// inside a security product is attack surface we decided not to buy for a mechanism
// a file already covers.
//
// TIME-BASED, NOT mtime-BASED, AND THAT IS DELIBERATE. The obvious implementation
// caches on (mtime, size) and re-reads when either changes. It has a silent failure:
// tokens from a given issuer are typically a FIXED LENGTH, mtime granularity is one
// second on several filesystems, and a refresher that rewrites the token within the
// same second produces an identical (mtime, size) pair. The new credential would be
// invisible and the gate would keep presenting the old one until something else
// disturbed the file. Re-reading on a timer cannot have that bug.
//
// THE SAFETY PROPERTY, which is the whole reason this is not four lines: a failed or
// empty read NEVER blanks the credential. Refreshers do not all write atomically, so
// a read can land mid-rewrite and see an empty or truncated file; a deleted file, a
// permissions change, or a full disk produce the same thing. Returning "" there would
// silently drop the Authorization header and degrade us to anonymous — the gate would
// keep working, at the lower anonymous rate limit, giving no signal that anything
// broke. That is precisely the "passes for the wrong reason" failure this project
// treats as worse than an outright error. So the last good value is retained, and a
// read error is logged once per transition rather than every second.
func fileCredential(path string, logf func(string, ...any)) credentialSource {
	return fileCredentialEvery(path, logf, credFileTTL)
}

// fileCredentialEvery is fileCredential with the re-read interval exposed, so tests
// can exercise rotation without sleeping a real second per assertion.
func fileCredentialEvery(path string, logf func(string, ...any), ttl time.Duration) credentialSource {
	var (
		mu       sync.Mutex
		last     string    // last value successfully read; "" until the first good read
		checked  time.Time // when the file was last read
		degraded bool      // true while reads are failing, so the log fires on transitions only
	)
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		if !checked.IsZero() && time.Since(checked) < ttl {
			return last
		}
		checked = time.Now()

		b, err := os.ReadFile(path)
		if err != nil {
			if !degraded {
				degraded = true
				// Name whether a credential is still being served, because the two
				// cases need different urgency from whoever reads this line.
				if last != "" {
					logf("upstream-auth: cannot read %s (%v) — still sending the last credential read successfully", path, err)
				} else {
					logf("upstream-auth: cannot read %s (%v) — NO credential has ever been read; upstream requests are going out unauthenticated", path, err)
				}
			}
			return last
		}
		// Trim: a token written by a shell (`aws … > token`) or an editor carries a
		// trailing newline, and a header value containing one is invalid — net/http
		// rejects it, so this would fail every request rather than degrade quietly.
		v := strings.TrimSpace(string(b))
		if v == "" {
			if !degraded {
				degraded = true
				logf("upstream-auth: %s is empty — keeping the previous credential (a refresher may be mid-write)", path)
			}
			return last
		}
		if degraded {
			degraded = false
			logf("upstream-auth: %s is readable again", path)
		}
		last = v
		return last
	}
}
