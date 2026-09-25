package main

import (
	"log"
)

// interception is a configured TLS-interception listener: the banner line that names
// it, and start, which binds it (fatally on failure). Built by setupInterception, which
// exists in two forms: intercept_main.go (with the mode) and intercept_off.go (without).
type interception struct {
	banner string
	start  func()
}

// main is the entry point. It does the minimum: load config, build the proxy
// server, and start listening. Keeping main tiny is deliberate — all real logic
// lives in testable types (proxyServer now, Firewall later), and main just
// wires them together.
func main() {
	// Config is validated FIRST, and a bad value is fatal before anything else runs
	// — before the firewall is built and, critically, before the listener binds
	// (issue #19). A half-configured firewall that answers requests is worse than one
	// that refuses to start: the developer on the other end cannot tell a
	// misconfigured gate from a strict one, and the natural next move is to route
	// around us. One line, naming every knob at fault, then exit non-zero.
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	fw, err := NewFirewall(cfg)
	if err != nil {
		log.Fatalf("startup failed: %v", err)
	}
	srv := newProxyServer(cfg, fw)

	// TLS-interception mode, when this build has it and it is configured (nil otherwise).
	// Checked before any listener binds, so a bad CA file fails startup with one line.
	intercept, err := setupInterception(cfg, srv)
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	log.Printf("Yellow Jack starting on %s", cfg.ListenAddr)
	// The compiled policy, beside the settings that produced it. Logged here rather
	// than in newProxyServer (where it was first written): that constructor runs once
	// in production but once per case in the tests, so a line there floods every run.
	// fw is non-nil by construction — NewFirewall's error is fatal above.
	log.Printf("  %s", fw.describePolicy())
	log.Printf("  ecosystem:         %s", cfg.Ecosystem)
	log.Printf("  upstream:          %s", cfg.UpstreamRegistry)
	// What we trust on the way OUT, when the operator added to it (#137). Printed only
	// when a bundle is configured: the default deployment trusts the platform's roots
	// and has nothing to compare against, so a line there would be noise. loadConfig has
	// already refused a bundle it could not use, so reaching here means these anchors are
	// live — see upstreamtrust.go.
	if cfg.upstreamTrustLine != "" {
		log.Printf("  %s", cfg.upstreamTrustLine)
	}
	if cfg.PublicURL != "" {
		log.Printf("  public URL:        %s", cfg.PublicURL)
	} else if w := publicURLWarning(cfg); w != "" {
		log.Printf("  WARNING: %s", w)
	}
	// Controls that are SET and that this gate cannot ENFORCE (D299). Said here, beside the
	// settings, while whoever typed them is still looking -- /policy says the same thing
	// later (#150), and both read releaseWindowEnforced so they cannot disagree.
	for _, w := range fw.inertSettingWarnings() {
		log.Printf("  WARNING: %s", w)
	}
	log.Printf("  score threshold:   %.1f", cfg.ScoreThreshold)
	log.Printf("  unscorable policy: %s", cfg.UnscorablePolicy)
	log.Printf("  scorecard mode:    %s", cfg.ScorecardMode)
	// What that mode MEANS for this deployment's threshold, computed rather than
	// described — see stubScoringNotice. "***" rather than "WARNING:" on purpose: every
	// e2e rig runs stub deliberately, and #19's clean-boot property must survive.
	if n := stubScoringNotice(cfg); n != "" {
		log.Printf("  *** %s", n)
	}
	// The unverified posture is only reachable when the cross-check runs at all, so
	// report the pair together — printing "closed" while verification is off would
	// overstate what the gate is doing. Ask the FIREWALL, not the config: the check
	// also requires a mode that can reach deps.dev (repoVerificationEnabled's
	// allowlist), and the DEFAULT mode is stub — so keying off cfg.VerifyRepo alone
	// would advertise a fail-closed posture on an out-of-the-box run that verifies
	// nothing at all.
	if fw.repoVerificationEnabled() {
		log.Printf("  repo verification: on (unverified policy: %s)", cfg.UnverifiedPolicy)
		// OCI is the one ecosystem where "unverified" is a certainty rather than a
		// per-package outcome: deps.dev has no container index. Under the closed
		// default that refuses every image that declares a source repo (D48, #33),
		// which an operator must never discover from the first failed pull.
		if cfg.Ecosystem == "oci" && fw.unverifiedFailsClosed() {
			log.Printf("  *** OCI + closed: deps.dev has no container index, so EVERY image that declares a source repo is refused as unverifiable (D48). Set FW_UNVERIFIED_POLICY=%s to proceed on the self-declared repo with a log instead.", unverifiedPolicyOpen)
		}
		// The "unrecognized value" warning that stood here is gone: loadConfig now
		// REFUSES an unrecognized FW_UNVERIFIED_POLICY outright (#19), so by this line
		// the value is one of the two legal ones. The warning was the weaker
		// instrument — it told the operator their enforcement posture was not what
		// they typed, and then ran that way regardless.
	} else if cfg.VerifyRepo {
		log.Printf("  repo verification: off (scorecard mode %q cannot reach deps.dev)", cfg.ScorecardMode)
	} else {
		log.Printf("  repo verification: off (FW_VERIFY_REPO=false)")
	}
	// Only mentioned when it is NOT the public API. A redirected deps.dev is
	// security-relevant — it is the source of both the score and the repo cross-check,
	// so whoever answers there can hand this gate a 10.0 for anything — and it is
	// exactly the kind of setting that gets left behind after a test. Silence means
	// the public API; a line here means someone chose otherwise, on purpose or not.
	if cfg.DepsDevBase != "" && cfg.DepsDevBase != depsDevBaseURL {
		log.Printf("  deps.dev API:      %s (OVERRIDDEN; default %s)", cfg.DepsDevBase, depsDevBaseURL)
	}
	// THE ENFORCEMENT MODE, and it is deliberately the loudest line in the banner.
	//
	// A gate that is not enforcing while looking healthy is the worst state this product
	// can be in: every dashboard is green, every verdict is computed, and nothing is
	// stopped. So report mode announces itself in capitals and says how to leave it,
	// while enforce mode stays quiet — the default needs no narration.
	if cfg.reporting() {
		log.Printf("  MODE:              *** REPORT ONLY — NOTHING IS BLOCKED *** verdicts are computed and logged; grep \"REPORT MODE: WOULD HAVE REFUSED\" to see them. Set FW_MODE=enforce to start refusing.")
	}
	// The artifact byte gate (#11 / D49 / D72) — npm only today, so only reported there;
	// printing a posture for an ecosystem that doesn't consult it would overstate the
	// gate exactly like the verification line above. Each line says what the mode
	// actually enforces, because "allow-but-log" on its own reads as "nothing is
	// blocked", which has not been true since D72.
	if cfg.Ecosystem == "npm" {
		switch byteGateMode(cfg.ByteGate) {
		case byteGateEnforce:
			log.Printf("  artifact byte gate: enforce (tarball fetches are gated)")
		case byteGateOff:
			log.Printf("  artifact byte gate: off (tarball fetches pass through UNGATED)")
		default:
			log.Printf("  artifact byte gate: allow-but-log (blocked packages ARE refused; unscorable/unverifiable ones are served and logged — set FW_BYTE_GATE=enforce to refuse those too)")
		}
		// Likewise no unrecognized-value warning: an illegal FW_BYTE_GATE never
		// reaches here, because loadConfig refuses to start on it (#19). byteGateMode
		// above still normalizes, since it also serves Configs built in code.
	}
	if cfg.ScorecardMode == "local" {
		log.Printf("  scanner service:   %s", cfg.ScannerURL)
	}
	if cfg.ApprovalURL != "" {
		log.Printf("  approval service:  %s", cfg.ApprovalURL)
	}
	// The interception listener is named beside the cooperative one.
	if intercept != nil {
		log.Printf("  intercept:         %s", intercept.banner)
	}
	// Report only WHETHER an upstream credential is set, never its value — it's a
	// secret, and startup logs are exactly where such things get leaked.
	if cfg.UpstreamAuth != "" {
		log.Printf("  upstream auth:     configured, static (scoped to %s)", cfg.UpstreamRegistry)
	}
	if cfg.UpstreamAuthFile != "" {
		// The PATH is not a secret and naming it is the point: when a rotated token
		// stops working, the first question is which file the operator's refresher
		// should have been writing to. The value it holds is still never logged.
		log.Printf("  upstream auth:     configured, re-read from %s (scoped to %s)", cfg.UpstreamAuthFile, cfg.UpstreamRegistry)
	}

	// The interception listener binds BEFORE the cooperative one: a bind failure here
	// is a configuration error and must stop startup, not leave a gate that answers
	// cooperative clients while silently not intercepting.
	if intercept != nil {
		intercept.start()
	}

	// The cooperative listener, with the same three connection-lifetime bounds as the
	// interception one (#130, cooperativeServer). It runs forever, handling each
	// connection concurrently; srv's ServeHTTP is called per request.
	if err := cooperativeServer(cfg.ListenAddr, srv).ListenAndServe(); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
