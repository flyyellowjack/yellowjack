package main

// The console is Yellow Jack's product admin/review GUI: a small, server-rendered
// web UI over the approval service's REST API. It is deliberately a *separate*
// service that owns NO state of its own — it is purely an HTTP client of the
// approval service (D10 priority #3, D11/D12). Keeping state in exactly one place
// (the approval service + its Postgres) is the architecture rule; the console only
// presents and, later, drives that state over the same configurable HTTP endpoint
// the firewall already uses.
//
// The read view lists the approval queue; the override actions (writes) let a human
// approve/deny a package and correct its repo association. Per DECISIONS.md D19,
// the override path sits behind BASIC GATEWAY AUTH (a shared credential); when no
// credential is configured the console runs READ-ONLY (overrides disabled), and the
// default listen address is loopback-only so an override endpoint is never exposed
// unauthenticated.

import (
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	cfg := config{
		listenAddr:  getEnv("CONSOLE_LISTEN_ADDR", "127.0.0.1:8085"),
		approvalURL: getEnv("CONSOLE_APPROVAL_URL", "http://localhost:8090"),
		authUser:    getEnv("CONSOLE_AUTH_USER", ""),
		authPass:    getEnv("CONSOLE_AUTH_PASS", ""),

		oidcIssuer:       getEnv("CONSOLE_OIDC_ISSUER", ""),
		oidcClientID:     getEnv("CONSOLE_OIDC_CLIENT_ID", ""),
		oidcClientSecret: getEnv("CONSOLE_OIDC_CLIENT_SECRET", ""),
		oidcRedirectURL:  getEnv("CONSOLE_OIDC_REDIRECT_URL", ""),
		oidcSessionTTL:   getEnv("CONSOLE_OIDC_SESSION_TTL", ""),

		listRepo:      getEnv("CONSOLE_LIST_REPO", ""),
		listAllowFile: getEnv("CONSOLE_LIST_ALLOW_FILE", "allow.txt"),
		listDenyFile:  getEnv("CONSOLE_LIST_DENY_FILE", "deny.txt"),
		listEcosystem: getEnv("CONSOLE_LIST_ECOSYSTEM", "npm"),
		listRemote:    getEnv("CONSOLE_LIST_REMOTE", "origin"),
	}

	// The console makes short outbound calls to the approval service. A bounded
	// timeout means a slow/hung approval service surfaces as an error page, not a
	// browser that hangs forever.
	client := &approvalHTTPClient{
		baseURL: cfg.approvalURL,
		http:    &http.Client{Timeout: 10 * time.Second},
	}

	// A nil credential => read-only mode (overrides disabled). Both halves must be
	// set to turn writes on.
	auth := newBasicAuth(cfg.authUser, cfg.authPass)
	srv := &server{approval: client, auth: auth, listEcosystem: cfg.listEcosystem}

	// OIDC sign-in (#148, D280). Off unless all four values are set, so nothing
	// changes for a deployment that has not asked for it.
	//
	// ⚠️ A CONFIGURED-BUT-BROKEN IdP IS FATAL, deliberately. Discovery runs here, at
	// startup, and a failure stops the console rather than leaving it running on
	// basic auth -- because the operator who set these four variables has said "only
	// these people may use this", and quietly serving the previous, weaker posture
	// instead would be a security downgrade nobody would see in a log line. Worse:
	// silent fallback would let an attacker who can merely DoS the IdP downgrade the
	// console to a shared password, turning an availability attack into an
	// authentication one. Same argument as the firewall's trust preflight and as
	// config.go refusing unrecognised values: refuse before the listener binds.
	//
	// 🚩 DO NOT LIFT THIS PATTERN INTO THE GATE. Fatal-at-startup is right HERE
	// because the console is not the enforcement path -- a console that will not
	// start blocks nobody's build. D165 deliberately makes the opposite choice for
	// the firewall (readiness is not liveness) so the gate keeps gating through a
	// dependency failure, and a registry outage does not take every replica out of
	// rotation at once. Same words, opposite correct answer, decided by whether the
	// component is in the request path.
	if (oidcConfig{Issuer: cfg.oidcIssuer, ClientID: cfg.oidcClientID,
		ClientSecret: cfg.oidcClientSecret, RedirectURL: cfg.oidcRedirectURL}).enabled() {
		o, err := newOIDCAuth(oidcConfig{
			Issuer:       cfg.oidcIssuer,
			ClientID:     cfg.oidcClientID,
			ClientSecret: cfg.oidcClientSecret,
			RedirectURL:  cfg.oidcRedirectURL,
			SessionTTL:   durationEnv(cfg.oidcSessionTTL, 12*time.Hour),
		}, &http.Client{Timeout: 10 * time.Second})
		if err != nil {
			log.Fatalf("OIDC is configured but could not be initialised: %v", err)
		}
		srv.oidc = o
		log.Printf("AUTH: OIDC sign-in enabled (issuer %s); overrides are attributed to the signed-in user", cfg.oidcIssuer)
	}

	// Operator list editing (#58 increment 3b, D193). OFF unless CONSOLE_LIST_REPO
	// names a git working tree: the console has authored nothing until a deployer has
	// said where the authoring should be RECORDED, and a default would have to invent
	// that place. A misconfiguration is logged and leaves the page read-only rather
	// than stopping the console -- every other page is still useful, and a console that
	// refused to start over an optional write path would be the worse failure.
	// Asked once, so the page and the log give the same answer. An operator who
	// reads the startup log and one who opens /lists must not be told different
	// things about the same deployment.
	srv.gitMissing = !gitBinaryAvailable()
	if srv.gitMissing {
		log.Printf("operator list editing DISABLED: %v", errNoGitBinary)
	}
	if cfg.listRepo != "" {
		store, err := newGitListStore(cfg.listRepo, cfg.listAllowFile, cfg.listDenyFile,
			cfg.listEcosystem, cfg.listRemote)
		if err != nil {
			log.Printf("operator list editing DISABLED: %v", err)
		} else {
			srv.lists = store
			log.Printf("operator list editing enabled: %s (ecosystem=%s, allow=%s, deny=%s)",
				store.Describe(), cfg.listEcosystem, cfg.listAllowFile, cfg.listDenyFile)
		}
	}

	mode := "READ-ONLY (set CONSOLE_AUTH_USER + CONSOLE_AUTH_PASS to enable overrides)"
	if auth != nil {
		mode = "overrides ENABLED (basic auth)"
	}
	log.Printf("Yellow Jack console starting on %s (approval=%s) — %s", cfg.listenAddr, cfg.approvalURL, mode)
	if err := http.ListenAndServe(cfg.listenAddr, srv); err != nil {
		log.Fatalf("console failed: %v", err)
	}
}

// config holds the injected runtime settings. Same pattern as every other service:
// nothing hardcoded that a deployer would need to change.
type config struct {
	listenAddr  string
	approvalURL string
	authUser    string
	authPass    string

	// Per-user SSO (#148). All four must be set for OIDC to engage; an
	// incomplete set is treated as "not configured" rather than as an error,
	// so a half-written deployment keeps the posture it already had.
	oidcIssuer       string
	oidcClientID     string
	oidcClientSecret string
	oidcRedirectURL  string
	oidcSessionTTL   string

	// The operator-list write path (#58 increment 3b). listRepo is the git working
	// tree the console commits into; listRemote is where it pushes ("" = commit only,
	// which is honest for a single-host deployment and is reported as such rather than
	// presented as a change that has reached the fleet).
	listRepo      string
	listAllowFile string
	listDenyFile  string
	listEcosystem string
	listRemote    string
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
