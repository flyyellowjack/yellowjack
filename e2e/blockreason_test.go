//go:build e2e

package e2e

import (
	"os/exec"
	"strings"
	"testing"
)

// A block must be LEGIBLE AT THE TERMINAL, in every real client (issue #20, increment 1).
//
// WHY THIS FILE EXISTS. The firewall already returns a structured refusal — a 403 carrying
// X-Yellowjack-Reason and an ecosystem-shaped body (writeForbidden in proxy.go), with the
// reason deliberately duplicated into npm's "error" field because npm prints only that one.
// All of that is asserted at the HTTP layer. **Nothing asserted what the developer actually
// sees**, and the gap between those two is the whole risk: a header we set faithfully and
// no client displays is, from the operator's chair, a silent failure.
//
// The bar comes from a survey of comparable tools. Another vendor built its gate partly to eliminate "CLI
// timeouts and silent failures", their docs setting the goal that "developers see a clear,
// immediate response rather than a timeout or unexplained error". That is the bar for
// anything sitting in the pull path and saying no: a developer who sees only
//
//	403 Forbidden - GET https://…/lodash
//
// cannot tell our refusal from a broken registry, and the support cost lands on whoever
// deployed us. A blocking product that cannot explain itself gets removed.
//
// SCOPE: this is increment 1 of #20 — reason legibility across the four real clients. The
// other two parts of that issue (lockfile `resolved` stability, and every block being
// self-serve clearable in one step) are separate legs and are NOT covered here.

// clientLeg is one real package manager driven against a blocking firewall.
type clientLeg struct {
	name      string
	ecosystem string
	// env is the strict posture for this ecosystem. Kept per-leg rather than shared
	// because the ecosystems genuinely differ: Maven's unverified default cannot be
	// "closed" or mvn cannot bootstrap its own plugin tree (D36/D42), which would make
	// this leg measure a broken rig instead of a block.
	env map[string]string
	// run drives the real client and returns (exit code, combined output).
	run func(t *testing.T, port int) (int, string)
	// reasonMarker overrides blockedMarker for a leg whose route does not carry it.
	//
	// Needed because PyPI's block is not a 403 body at all: it is a PEP 592 yank, and the
	// text that reaches the client is `decision.Reason` ("BLOCKED: %q scored …, below
	// required …"), which never contains blockErrMsg. A leg asserting the shared marker on
	// that route would be asserting a phrase the route cannot produce — it would fail for
	// the wrong reason and be "fixed" by deleting the assertion.
	reasonMarker string
	// illegible names the open issue for a client that does NOT surface our reason, or
	// "" when it does. Measured, not assumed — see the table in #79.
	//
	// The leg still runs: it keeps asserting that the pull FAILS and does not present as
	// an outage, so a regression to "the block silently succeeds" is still caught. Only
	// the legibility assertion is held back.
	//
	// WHY IT IS HELD BACK IS NOT WHAT THIS COMMENT USED TO SAY. It said the fix was "a
	// D22 design decision rather than a test change", i.e. that we might yet change how a
	// block is expressed on the wire. D137 (2026-08-14) ruled the opposite and
	// ruled it explicitly: legibility is solved OUT OF BAND — chat integrations (#87) and
	// a CLI wrapper with --dry-run (#88) — and "protocol-hacking is not endorsed". So
	// these legs are not waiting on a protocol decision that might land. They are pinning
	// a permanent property of the clients.
	illegible string

	// seesInstead is what the developer ACTUALLY reads when illegible != "".
	//
	// MEASURED 2026-09-05 by running these very legs and dumping the client's output —
	// not inferred from the protocol. Asserting it turns #79's severity argument from
	// prose into a check: if a client's rendering changes, we are told to re-measure
	// rather than continuing to justify #87/#88 with a stale quotation.
	seesInstead []string

	// misattributes is the distinction that decides how bad this is, and the two clients
	// differ — which #79's own table does not yet record.
	//
	// D137 names the danger precisely: "the developer concludes our proxy is broken,
	// points around it, and the firewall is silently off for them forever." That is an
	// ENFORCEMENT failure, not a UX one, and it needs the output to blame something other
	// than policy. pip qualifies: "No matching distribution found" reads as the package
	// not existing. mvn does NOT: it prints "status code: 403 ... Forbidden", which is
	// illegible (our reason is absent) but points at permission, not at absence.
	misattributes bool

	// alsoPrints is text the client prints AROUND our reason, for a leg whose reason
	// IS legible but arrives coloured. Asserted for every leg (empty pins nothing), so
	// a change in that framing is a re-measurement rather than a silent drift. The
	// legacy-store Docker daemon is the case: it prints our whole reason, prefixed
	// with "repository does not exist or may require 'docker login'".
	alsoPrints []string

	// precondition runs first and may t.Skip -- for a leg that measures one variant
	// of a client and must not run against the other. Kept out of `run` so a skip
	// happens before a firewall is launched for the control.
	precondition func(t *testing.T)
}

// strictEnv is the shipped-strictest posture: nothing passes on its merits, so whatever the
// client prints is a genuine policy refusal rather than a scoring accident.
func strictEnv(ecosystem string, extra map[string]string) map[string]string {
	env := map[string]string{
		"FW_ECOSYSTEM":         ecosystem,
		"FW_SCORECARD_MODE":    "stub", // flat 7.5 — no deps.dev drift
		"FW_SCORE_THRESHOLD":   "10.0", // above the stub score: everything is refused
		"FW_UNSCORABLE_POLICY": "block",
		"FW_BYTE_GATE":         "enforce",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

// permissiveEnv is the same ecosystem with the gate open. Used as the anti-vacuity control:
// if the client cannot install even when nothing is blocked, then its failure in the strict
// leg says nothing about our refusal.
func permissiveEnv(ecosystem string, extra map[string]string) map[string]string {
	env := map[string]string{
		"FW_ECOSYSTEM":         ecosystem,
		"FW_SCORECARD_MODE":    "stub",
		"FW_SCORE_THRESHOLD":   "0",
		"FW_UNSCORABLE_POLICY": "allow",
		"FW_UNVERIFIED_POLICY": "open-with-visibility",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

// syntheticRegistryDates turns the release cooldown OFF for a leg whose upstream is a
// stand-in registry we serve ourselves, and is the ONLY sanctioned way to do so.
//
// Since D335 the cooldown defaults to 14 days. A stand-in registry's packages carry a
// publish time of "now" or none at all, so the window holds back every version and the leg
// measures the window instead of the thing it was written for. These dates are an artefact
// of the fixture, not a fact about any package, so switching the window off here edits
// nothing the leg measures. Legs against a REAL registry must not call this: they are the
// ones that prove the default does not break a real install.
func syntheticRegistryDates(env map[string]string) map[string]string {
	env["FW_MIN_RELEASE_AGE_DAYS"] = "0"
	return env
}

func blockReasonLegs() []clientLeg {
	return []clientLeg{
		{
			name: "npm", ecosystem: "npm",
			env: strictEnv("npm", map[string]string{"FW_UNVERIFIED_POLICY": "closed"}),
			run: func(t *testing.T, port int) (int, string) { return runNpmInstall(t, port, "express") },
		},
		{
			name: "pip", ecosystem: "pypi",
			env: strictEnv("pypi", map[string]string{"FW_UNVERIFIED_POLICY": "closed"}),
			run: func(t *testing.T, port int) (int, string) { return runPipInstall(t, port, "requests") },
			seesInstead: []string{
				"No matching distribution found",
				"Could not find a version that satisfies the requirement",
			},
			misattributes: true,
			// #79: PyPI blocks are PEP 592 yanks (!16/D22); pip honours the yank but drops
			// the REASON, then reports "No matching distribution found" — the developer is
			// told the package does not exist.
			illegible: "#79",
		},
		{
			// THE SAME CLIENT, THE OTHER SHAPE. A rig that drives one route per client is
			// the gap !84 was written about, and here the two routes genuinely differ:
			// measured 2026-09-12, an UNPINNED install fails in the index and a PINNED one
			// fails at the artifact fetch, with different text and different severity.
			//
			// Unpinned, every version is yanked so nothing satisfies the requirement and
			// pip never SELECTS a candidate — it reports absence. Pinned, pip selects the
			// yanked candidate and the very next fetch (the PEP 658 .metadata file) is
			// refused by the byte gate, so the download error arrives before pip would
			// have printed "Reason for being yanked:". Our reason is dropped either way.
			//
			// It earns its place because the SEVERITY differs: this shape points at
			// permission, so it does not carry the misattribution risk D137 names, while
			// the unpinned one above does. #79's table records one number for pip; the
			// client has two behaviours and only one of them is the dangerous one.
			name: "pip (version pinned)", ecosystem: "pypi",
			env: strictEnv("pypi", map[string]string{"FW_UNVERIFIED_POLICY": "closed"}),
			run: func(t *testing.T, port int) (int, string) {
				return runPipInstall(t, port, "requests==2.31.0")
			},
			seesInstead: []string{"403", "Forbidden"},
			// Deliberately explicit rather than left as the zero value: this false IS the
			// finding, and a reader should not have to infer it from an absent field.
			misattributes: false,
			illegible:     "#79",
		},
		{
			// uv, THE SAME INDEX AS pip, AND IT PRINTS OUR REASON IN FULL.
			//
			// This leg exists because #79 concluded the opposite about the whole language.
			// It measured pip, found the reason discarded, and generalised to "the CLI is
			// structurally unable to explain". Measured 2026-09-18 against uv 0.12.10 on the
			// identical stub index and identical package, uv renders the yank reason:
			//
			//	Because yjblocked==1.0.0 was yanked (reason: blocked by Yellow Jack: …)
			//
			// so the generalisation was one client mistaken for an ecosystem. pip drops the
			// reason; uv is the counterexample, and it is a fast-growing pip replacement
			// rather than an exotic tool.
			//
			// WHAT THIS LEG IS ACTUALLY GUARDING is the block SHAPE, not uv. #79 offers a
			// ruling three ways, one of which is "return a 403 on /simple/ instead of
			// yanking". Measured, that option costs this: under a 403 uv prints "yjblocked
			// was not found in the package registry" — the misattribution #79 was filed
			// about. So the only in-band channel any Python client gives us is destroyed by
			// one of the options on the menu, and nothing would have gone red. Now it does,
			// and it names uv as the cost.
			//
			// It asserts the reason via reasonMarker, not blockedMarker: the PyPI route is a
			// yank carrying decision.Reason, which never contains blockErrMsg. See the field.
			name: "uv", ecosystem: "pypi",
			env: strictEnv("pypi", map[string]string{"FW_UNVERIFIED_POLICY": "closed"}),
			run: func(t *testing.T, port int) (int, string) {
				return runUvInstall(t, port, "requests")
			},
			reasonMarker: "below required",
		},
		{
			// crane, and ONLY crane. This row used to be called "docker/crane", and the
			// name claimed a measurement of two clients that had been taken on one: crane
			// issues a GET and prints the registry's error body, so our reason reaches
			// the terminal. A real `docker pull` is the two rows below, and they differ.
			name: "crane", ecosystem: "oci",
			env: strictEnv("oci", map[string]string{"FW_UNVERIFIED_POLICY": "open-with-visibility"}),
			run: func(t *testing.T, port int) (int, string) {
				return runCranePull(t, port, "library/alpine:3.20")
			},
		},
		{
			// THE DAEMON, NOT CRANE. #79's table had one ✅ row for "docker/crane", true of
			// crane and measured on crane; #129 found the same row-names-two-clients pattern
			// on the allow path. A real `docker pull` was measured on 2026-09-14 against the
			// same firewall image on two daemons, and they DISAGREE -- keyed by the daemon's
			// IMAGE STORE, not by its version or by anything the client did:
			//
			//   containerd image store (Docker Desktop 29.5.3, snapshotter "overlayfs"):
			//     Error response from daemon: unknown: failed to resolve reference
			//     "127.0.0.1:P/library/alpine:3.20": unexpected status from HEAD request to
			//     http://127.0.0.1:P/v2/library/alpine/manifests/3.20: 403 Forbidden
			//
			//   legacy graphdriver store (docker:27-dind, overlay2 -- what CI runs):
			//     Error response from daemon: pull access denied for
			//     127.0.0.1:P/library/alpine, repository does not exist or may require
			//     'docker login': denied: blocked by firewall: BLOCKED: "library/alpine:3.20"
			//     scored 7.5, below required 10.0. This package is now in the firewall's
			//     approval queue, waiting on a person. ...
			//
			// The containerd store resolves the tag with a HEAD, which has no body by
			// specification, and reports the status. Our reason rides that response as the
			// X-Yellowjack-* headers (D182); the daemon discards them. The legacy store
			// fetches the manifest with a GET and prints the error body -- our whole reason
			// -- but leads with a guess ("repository does not exist or may require 'docker
			// login'") that is wrong on both counts.
			//
			// So the daemon is TWO rows, one per store. Each skips on a daemon running the
			// other store, and the store check is an instrument that FAILS when it cannot
			// tell, so the two legs cannot both skip and leave the daemon unmeasured. CI's
			// 27-dind exercises the legacy row; a Docker Desktop laptop exercises the
			// containerd row. Docker is moving new installations to the containerd store,
			// so the illegible row is the one a developer is increasingly likely to see.
			name: "docker daemon (containerd image store)", ecosystem: "oci",
			env:          strictEnv("oci", map[string]string{"FW_UNVERIFIED_POLICY": "open-with-visibility"}),
			precondition: func(t *testing.T) { requireImageStore(t, storeContainerd) },
			run: func(t *testing.T, port int) (int, string) {
				return runDockerPull(t, port, "library/alpine:3.20")
			},
			seesInstead:   []string{"unexpected status from HEAD request", "403 Forbidden"},
			misattributes: false,
			illegible:     "#79",
		},
		{
			name: "docker daemon (legacy image store)", ecosystem: "oci",
			env:          strictEnv("oci", map[string]string{"FW_UNVERIFIED_POLICY": "open-with-visibility"}),
			precondition: func(t *testing.T) { requireImageStore(t, storeLegacy) },
			run: func(t *testing.T, port int) (int, string) {
				return runDockerPull(t, port, "library/alpine:3.20")
			},
			// LEGIBLE: blockedMarker is in the output, so the ordinary assertion applies.
			// But the daemon frames the refusal as a missing repository or a login problem
			// BEFORE our text, on the same line, and that framing is pinned here: it is the
			// misattribution D137 names, printed next to the explanation that corrects it.
			alsoPrints: []string{"repository does not exist or may require 'docker login'"},
		},
		{
			// open-with-visibility, not closed: under the fail-closed default mvn cannot
			// bootstrap (maven-dependency-plugin is durably unverified), so a "closed" leg
			// would measure a rig that never reached the gate. See maven_test.go.
			name: "mvn", ecosystem: "maven",
			env: strictEnv("maven", map[string]string{"FW_UNVERIFIED_POLICY": "open-with-visibility"}),
			run: func(t *testing.T, port int) (int, string) {
				return runMvnGet(t, port, "com.google.guava:guava:33.0.0-jre")
			},
			// #79 said mvn shows "a bare transfer failure" and grouped it with pip. MEASURED
			// 2026-09-05, that is wrong in the direction that matters: mvn prints
			//
			//   status code: 403, reason phrase: Forbidden (403)
			//
			// Our reason (the response body) is still absent, so the leg stays illegible.
			// But "Forbidden" points at PERMISSION, not at absence — so mvn does NOT carry
			// the misattribution risk D137 is about. The two clients are not equally bad and
			// #79's table has been corrected to say so.
			//
			// Note what the block actually lands on here: maven-dependency-plugin, not
			// guava. Under this posture mvn cannot bootstrap its own plugin tree, so this
			// measures a refused PLUGIN fetch. Still a real block reaching a real client,
			// but worth knowing when reading the output.
			seesInstead:   []string{"status code: 403", "Forbidden"},
			misattributes: false,
			illegible:     "#79",
		},
	}
}

// TestBlockReasonIsLegibleInEveryRealClient drives each package manager against a firewall
// that refuses everything, and reads what the developer would read.
func TestBlockReasonIsLegibleInEveryRealClient(t *testing.T) {
	bin := buildFirewall(t)

	for _, leg := range blockReasonLegs() {
		t.Run(leg.name, func(t *testing.T) {
			if leg.precondition != nil {
				leg.precondition(t)
			}
			// Anti-vacuity FIRST: the client must be able to install through a permissive
			// firewall. Without this, "the client failed" in the strict leg is equally
			// explained by a broken image, an unreachable upstream, or a rig mistake — and
			// every assertion below would be satisfied by a firewall that does nothing.
			func() {
				fw := startFirewall(t, bin, permissiveEnv(leg.ecosystem, nil))
				defer fw.stop()
				if code, out := leg.run(t, fw.port); code != 0 {
					t.Fatalf("control: %s could not install through a PERMISSIVE firewall (exit %d) — "+
						"the rig is broken, so a failure in the strict leg would prove nothing\n%s",
						leg.name, code, tail(out, 25))
				}
			}()

			fw := startFirewall(t, bin, leg.env)
			code, out := leg.run(t, fw.port)

			// 1. It must FAIL. A block the client treats as success is the worst outcome:
			//    the developer gets the package and believes the gate approved it.
			if code == 0 {
				t.Fatalf("%s SUCCEEDED against a firewall refusing everything — the block did not "+
					"reach the client at all\n%s\n--- firewall ---\n%s",
					leg.name, tail(out, 25), logAround(fw.log.String(), 30, "blocked", "allowed"))
			}

			// 2. It must fail with OUR reason, visible in the client's own output. This is
			//    the assertion #20 exists for: everything else is already covered at the
			//    HTTP layer, and the HTTP layer is not what the developer reads.
			switch {
			case leg.illegible != "" && strings.Contains(out, leg.marker()):
				// The filed defect is FIXED. Say so loudly rather than passing quietly: the
				// leg must be re-armed by clearing `illegible`, or the coverage silently
				// stops meaning anything the next time it regresses.
				t.Errorf("%s NOW SURFACES the reason, but this leg is still marked illegible (%s). "+
					"Clear the `illegible` field so the assertion is enforced again, and close %s.",
					leg.name, leg.illegible, leg.illegible)
			case leg.illegible != "":
				// PIN WHAT THE DEVELOPER SEES INSTEAD. Without this the leg records only that
				// our reason is absent, which is the weaker half: #79's severity argument, and
				// the case for the two out-of-band channels D137 chose (#87/#88), rest on the
				// SPECIFIC text these clients print. If that text changes, the argument must be
				// re-made rather than re-quoted.
				for _, phrase := range leg.seesInstead {
					if !strings.Contains(out, phrase) {
						t.Errorf("%s no longer prints %q. Its rendering has CHANGED, so the "+
							"measurement behind %s is stale — re-measure and update seesInstead "+
							"before anyone quotes that issue again.\n--- what the developer saw ---\n%s",
							leg.name, phrase, leg.illegible, tail(out, 30))
					}
				}
				if leg.misattributes {
					t.Logf("%s: reason NOT surfaced, and the output MISATTRIBUTES the failure "+
						"(filed as %s). This is the enforcement risk D137 names — the developer "+
						"concludes our proxy is broken and routes around it.", leg.name, leg.illegible)
				} else {
					t.Logf("%s: reason NOT surfaced, but the output points at permission rather "+
						"than absence (filed as %s), so it does not carry the misattribution risk.",
						leg.name, leg.illegible)
				}
			case !strings.Contains(out, leg.marker()):
				t.Errorf("BLOCK IS ILLEGIBLE: %s failed (exit %d) but its output never says why — "+
					"no %q anywhere. The developer sees a bare transport error and cannot tell our "+
					"refusal from a broken registry, which is exactly the 'unexplained error' bar "+
					"a survey of comparable tools sets (#20).\n--- what the developer saw ---\n%s\n"+
					"--- what the firewall logged ---\n%s",
					leg.name, code, leg.marker(), tail(out, 30),
					logAround(fw.log.String(), 30, "blocked", "refused"))
			}

			// 2b. What the client prints AROUND the reason, where that framing was measured
			//     to matter (the legacy-store daemon's "repository does not exist" preamble).
			for _, phrase := range leg.alsoPrints {
				if !strings.Contains(out, phrase) {
					t.Errorf("%s no longer prints %q alongside our reason. Its framing has CHANGED; "+
						"re-measure and update alsoPrints (and the row in #79) before anyone quotes it.\n"+
						"--- what the developer saw ---\n%s", leg.name, phrase, tail(out, 30))
				} else {
					t.Logf("%s: our reason is legible, but the client leads with %q -- a "+
						"misattributing preamble printed next to the text that corrects it", leg.name, phrase)
				}
			}

			// 3. It must not present as an outage. A timeout or a 5xx tells the developer to
			//    retry, which they will, forever — and it misattributes our policy decision
			//    to broken infrastructure.
			for _, bad := range []string{"500 Internal Server Error", "502 Bad Gateway", "timed out", "timeout"} {
				if strings.Contains(strings.ToLower(out), strings.ToLower(bad)) {
					t.Errorf("%s was refused but the output reads as an OUTAGE (%q) rather than a "+
						"policy decision — that teaches developers to retry through the gate\n%s",
						leg.name, bad, tail(out, 30))
				}
			}
			// Say what actually happened. This line used to claim "refused with a legible
			// reason" for EVERY leg, including the two that had just logged that the reason
			// was not surfaced at all -- so the suite's own summary contradicted its findings
			// two lines earlier. Noticed 2026-09-05 while reading a passing run: a green test
			// whose log misdescribes the outcome is how a known gap gets quoted as covered.
			// ...and the same defect had one layer left in it. The branch below described
			// the leg's INTENT, not its outcome, so a leg that had just FAILED the
			// legibility assertion still signed off with "refused with a legible reason".
			// Seen for real: sabotaging the PyPI block to a 403 reddened the uv leg, and
			// that success line printed directly underneath the failure. t.Failed() is the
			// only thing here that knows what actually happened.
			switch {
			case t.Failed():
				t.Logf("%s: assertions FAILED above — the lines below this point describe what "+
					"was expected, not what happened (exit %d)", leg.name, code)
			case leg.illegible == "":
				t.Logf("%s: refused with a legible reason (exit %d)", leg.name, code)
			default:
				t.Logf("%s: refused (exit %d), reason NOT legible -- see %s", leg.name, code, leg.illegible)
			}
		})
	}
}

// blockedMarker is the phrase every ecosystem's refusal body carries (blockErrMsg in
// proxy.go). Asserted as the shared minimum rather than per-client phrasing: the clients
// wrap it differently, and pinning each one's exact rendering would make this test fail on
// a harmless npm output change while missing the property that actually matters — that OUR
// words reach the terminal at all.
const blockedMarker = "blocked by firewall"

// marker is the phrase this leg's route actually carries — blockedMarker unless the leg
// names its own. Used by every legibility branch so that "our words reached the terminal"
// is asked about the text the route emits, not the text most routes emit.
func (l clientLeg) marker() string {
	if l.reasonMarker != "" {
		return l.reasonMarker
	}
	return blockedMarker
}

// The Docker daemon's two image stores, which render a refused pull differently (see the
// two daemon legs in blockReasonLegs).
const (
	storeContainerd = "containerd image store"
	storeLegacy     = "legacy graphdriver image store"
)

// dockerImageStore reports which image store the daemon behind `docker` is using. Under
// the containerd store `docker info` prints a single DriverStatus row, driver-type =
// io.containerd.snapshotter.v1; the legacy graphdriver store prints filesystem rows and
// no driver-type. A daemon that answers with no driver at all is a broken instrument and
// FAILS here, so the two daemon legs -- each of which skips on the other's store -- can
// never both skip and report the daemon as measured.
func dockerImageStore(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "info", "--format",
		"{{.Driver}}|{{range .DriverStatus}}{{index . 0}}={{index . 1}};{{end}}").CombinedOutput()
	if err != nil {
		t.Fatalf("docker info (is the daemon reachable?): %v\n%s", err, out)
	}
	driver, status, _ := strings.Cut(strings.TrimSpace(string(out)), "|")
	if driver == "" {
		t.Fatalf("`docker info` named no storage driver (%q): cannot tell which image store "+
			"the daemon uses, so neither daemon leg can be trusted to run", out)
	}
	if strings.Contains(status, "driver-type=io.containerd.snapshotter.v1") {
		return storeContainerd
	}
	return storeLegacy
}

// requireImageStore skips the calling leg unless the daemon uses the named store, naming
// the store it found so a skipped row in the output still says what was measured instead.
func requireImageStore(t *testing.T, want string) {
	t.Helper()
	if got := dockerImageStore(t); got != want {
		t.Skipf("this daemon uses the %s; this leg measures the %s (the other daemon leg "+
			"runs here instead)", got, want)
	}
}
