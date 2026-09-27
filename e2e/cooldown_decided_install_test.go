//go:build e2e

package e2e

// What the release cooldown does to an install whose version is ALREADY DECIDED -- a
// lockfile, or a requirement that pins one exact release (pre-registered before any leg
// ran).
//
// The cooldown is applied to the metadata a resolver reads: npm's packument loses the
// held version, PyPI's index marks it yanked (PEP 592). That steers a fresh resolve. It
// says nothing about a client that does not resolve: `npm ci` fetches the tarball its
// lockfile recorded, and PEP 592 tells pip to ignore a yank when the requirement pins
// that exact version. CONFIGURATION.md said "a lockfile install is never held (E108)",
// which E108 argued from the design and nothing ever ran -- in a row that also covers
// PyPI, where an exact pin (the shape of every hash-pinned requirements file) is the
// case in question. These legs are what the doc now cites.

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// six's two newest releases, read from pypi.org's JSON API. The cooldown in the PyPI legs
// is sized from these dates so that 1.17.0 is held and 1.16.0 is not -- the shipped
// mechanism at a width that holds a real release, since no release of a stable real
// package is reliably under 14 days old.
const (
	decidedPkg      = "six"
	decidedSettled  = "1.16.0"
	decidedHeld     = "1.17.0"
	decidedHeldHash = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274" // six-1.17.0-py2.py3-none-any.whl
)

var (
	decidedHeldAt    = time.Date(2024, 12, 4, 17, 35, 26, 0, time.UTC)
	decidedSettledAt = time.Date(2021, 5, 5, 14, 18, 17, 0, time.UTC)
)

// decidedWindowDays holds 1.17.0 with 30 days to spare and still admits 1.16.0.
func decidedWindowDays(t *testing.T) int {
	t.Helper()
	days := int(time.Since(decidedHeldAt).Hours()/24) + 30
	if settledAge := int(time.Since(decidedSettledAt).Hours() / 24); days >= settledAge {
		t.Fatalf("a %d-day window would also hold %s (%d days old); pick a newer pair of releases", days, decidedSettled, settledAge)
	}
	return days
}

// pypiDecided runs a shell script in the client image with the gate as its only index and
// prints RESOLVED=<version of six that landed>.
func pypiDecided(t *testing.T, port int, image, script string) (int, string) {
	t.Helper()
	index := fmt.Sprintf("http://host.docker.internal:%d/simple/", port)
	full := script + ` && echo RESOLVED=$(python -c 'import sys; sys.path.insert(0, "/tmp/s"); import six; print(six.__version__)')`
	return runClient(t, "docker", "run", "--rm",
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "PIP_INDEX_URL="+index,
		"-e", "PIP_TRUSTED_HOST=host.docker.internal",
		"-e", "PIP_DISABLE_PIP_VERSION_CHECK=1",
		"-e", "UV_INDEX_URL="+index,
		"--entrypoint", "sh", image, "-c", full)
}

// segmentSince returns the gate's log written after `mark` bytes, so a leg's contact
// check cannot be satisfied by an earlier leg's request.
func segmentSince(fw *firewall, mark int) string {
	logs := fw.log.String()
	if mark > len(logs) {
		return ""
	}
	return logs[mark:]
}

func report(t *testing.T, id string, held bool, detail string) {
	t.Helper()
	verdict := "FALSIFIED"
	if held {
		verdict = "HELD"
	}
	t.Logf("E121 %s %s: %s", id, verdict, detail)
}

func TestCooldownAndDecidedInstallsNpm(t *testing.T) {
	bin := buildFirewall(t)
	now := time.Now()
	reg := startTwoVersionRegistry(t, map[string]time.Time{
		vfClean:    now.AddDate(0, 0, -400),
		vfPoisoned: now.Add(-2 * time.Hour),
	})
	port := freePort(t)
	vol := npmLockWorkspace(t, port)

	// The lockfile a machine OUTSIDE the cooldown writes: no window, so 2.0.0 (two hours
	// old, `latest`) is what npm records.
	open := vfEnv(reg, false) // FW_MIN_RELEASE_AGE_DAYS=0
	fw := startFirewallOnPort(t, bin, port, open)
	code, out := npmInWorkspace(t, vol, port, "npm init -y >/dev/null && npm install "+vfPkg+" >/dev/null && "+
		"node -p \"require('./package-lock.json').packages['node_modules/"+vfPkg+"'].version\"")
	if code != 0 || !strings.Contains(out, vfPoisoned) {
		t.Fatalf("VOID: could not write a lockfile naming %s through a gate with no window (exit %d)\n%s\n--- gate ---\n%s",
			vfPoisoned, code, tail(out, 20), tail(fw.log.String(), 20))
	}
	fw.stop()

	// The SHIPPED DEFAULT: FW_MIN_RELEASE_AGE_DAYS unset is a 14-day cooldown (D335).
	shipped := vfEnv(reg, false)
	delete(shipped, "FW_MIN_RELEASE_AGE_DAYS")
	fw = startFirewallOnPort(t, bin, port, shipped)
	defer fw.stop()

	// P3, the control, runs FIRST: if the explicit request is not refused, the window is
	// not active on this gate and every leg below is void.
	code, out = npmInstallResolving(t, port, vfPkg+"@"+vfPoisoned)
	refused := code != 0 && (strings.Contains(out, "No matching version") || strings.Contains(out, "ETARGET"))
	report(t, "P3", refused, fmt.Sprintf("explicit %s@%s exit %d", vfPkg, vfPoisoned, code))
	if !refused {
		t.Fatalf("VOID: the control was not refused, so the cooldown is not active on this gate\n%s\n--- gate ---\n%s",
			tail(out, 20), tail(fw.log.String(), 30))
	}

	for _, leg := range []struct{ id, cmd string }{
		{"P1", "npm ci"},
		{"P2", "npm install"},
	} {
		t.Run(leg.id+" "+leg.cmd, func(t *testing.T) {
			mark := len(fw.log.String())
			code, out := npmInWorkspace(t, vol, port, "rm -rf node_modules && "+leg.cmd+
				" && echo RESOLVED=$(node -p \"require('"+vfPkg+"/package.json').version\")")
			seg := segmentSince(fw, mark)
			if !strings.Contains(seg, vfPkg) {
				t.Fatalf("VOID: %s exited %d but the gate logged nothing for %s during this leg\n%s", leg.cmd, code, vfPkg, tail(out, 20))
			}
			installed := code == 0 && strings.Contains(out, "RESOLVED="+vfPoisoned)
			report(t, leg.id, installed, fmt.Sprintf("%s exit %d, held-by-window in log: %v\n%s\n--- gate (this leg) ---\n%s",
				leg.cmd, code, strings.Contains(seg, "release-window"), tail(out, 12), tail(seg, 12)))
			if !installed {
				t.Errorf("%s from a lockfile naming %s is now HELD by the cooldown. E121 measured it installing, and "+
					"docs/CONFIGURATION.md says a lockfile install is never held: change the doc (and the E121 result) "+
					"with the behaviour, or this is a regression", leg.cmd, vfPoisoned)
			}
		})
	}
}

func TestCooldownAndDecidedInstallsPypi(t *testing.T) {
	bin := buildFirewall(t)
	days := decidedWindowDays(t)
	fw := startFirewall(t, bin, permissiveEnv("pypi", map[string]string{
		"FW_MIN_RELEASE_AGE_DAYS": fmt.Sprint(days),
	}))
	defer fw.stop()
	t.Logf("window: %d days (holds %s, admits %s)", days, decidedHeld, decidedSettled)

	pipTarget := "pip install --no-cache-dir --target /tmp/s "

	// P7, the control: an unpinned resolve must land on the settled release, or the window
	// is not active and the pinned legs are void.
	code, out := pypiDecided(t, fw.port, "python:3.12-slim", pipTarget+decidedPkg)
	steered := code == 0 && strings.Contains(out, "RESOLVED="+decidedSettled)
	report(t, "P7", steered, fmt.Sprintf("unpinned pip exit %d", code))
	if !steered {
		t.Fatalf("VOID: an unpinned pip did not resolve to %s, so the window is not steering\n%s\n--- gate ---\n%s",
			decidedSettled, tail(out, 20), tail(fw.log.String(), 30))
	}
	// The operator's side of the same hold (E123b): the gate's log must name the release it
	// yanked, as npm's does. Before, pip printed the reason and the gate logged only a serve.
	if want := "[release-window] " + decidedPkg + " -> version " + decidedHeld + " yanked in the index"; !strings.Contains(fw.log.String(), want) {
		t.Errorf("the cooldown steered pip off %s but the gate's log does not say so (want %q)\n--- gate ---\n%s",
			decidedHeld, want, tail(fw.log.String(), 30))
	}

	reqs := fmt.Sprintf("printf '%%s\\n' '%s==%s --hash=sha256:%s' > /tmp/r.txt && ", decidedPkg, decidedHeld, decidedHeldHash)
	for _, leg := range []struct{ id, image, script string }{
		{"P4", "python:3.12-slim", pipTarget + decidedPkg + "==" + decidedHeld},
		{"P5", "python:3.12-slim", reqs + pipTarget + "--require-hashes -r /tmp/r.txt"},
		// --index-url as a flag, as runUvInstall does: an env name uv stopped reading would
		// let the leg resolve against pypi.org and look like a pass.
		{"P6", uvImage, "uv pip install --no-cache --index-url \"$UV_INDEX_URL\" --target /tmp/s " + decidedPkg + "==" + decidedHeld},
	} {
		t.Run(leg.id, func(t *testing.T) {
			mark := len(fw.log.String())
			code, out := pypiDecided(t, fw.port, leg.image, leg.script)
			seg := segmentSince(fw, mark)
			if !strings.Contains(seg, "_files") || !strings.Contains(seg, decidedPkg) {
				if code == 0 {
					t.Fatalf("VOID: exit 0 but the gate logged no file fetch for %s during this leg\n%s", decidedPkg, tail(out, 20))
				}
			}
			installed := code == 0 && strings.Contains(out, "RESOLVED="+decidedHeld)
			report(t, leg.id, installed, fmt.Sprintf("exit %d, client mentions yank: %v\n%s\n--- gate (this leg) ---\n%s",
				code, strings.Contains(strings.ToLower(out), "yank"), tail(out, 12), tail(seg, 12)))
			if !installed {
				t.Errorf("an exact pin of %s==%s is now HELD by the cooldown. E121 measured it installing (PEP 592 lets "+
					"an exact pin select a yanked file), and docs/CONFIGURATION.md says so: change the doc with the "+
					"behaviour, or this is a regression", decidedPkg, decidedHeld)
			}
		})
	}
}
