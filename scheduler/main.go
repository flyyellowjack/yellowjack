package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

// The scheduler service: the firewall's target for on-demand ("local") scoring.
// It launches one run-once scanner container per scan and returns the score. See
// server.go for the request/result correlation and launcher.go for how a scan is
// actually started.
//
// Config is all injected via env, matching the other Yellow Jack services
// (stateless, same binary everywhere). SCHEDULER_LAUNCHER selects how each run-once
// container is started; both implementations satisfy the same launcher interface,
// so the server logic in server.go is identical regardless of the choice.
func main() {
	addr := getEnv("SCHEDULER_LISTEN_ADDR", ":8096")
	selfURL := getEnv("SCHEDULER_SELF_URL", "http://scheduler:8096")
	timeout := getDurationEnv("SCHEDULER_SCAN_TIMEOUT_SECS", 240*time.Second)

	// How many scans may run at once. Each one is a whole scorecard container, so
	// this is the knob that keeps a burst of /scan calls (a big dependency tree
	// arriving cold, or a hostile caller) from exhausting the host — issue #13.
	//
	// Default 8, not an arbitrary number: a scan is dominated by waiting on the
	// GitHub API rather than local CPU, so a handful in parallel keeps throughput up
	// for a real install, while 8 concurrent containers stay comfortable on the
	// small (2-4 GB) host this is expected to run on. Operators with bigger hosts or
	// slower repos should raise it; 0 disables the cap.
	maxConcurrent := getIntEnv("SCHEDULER_MAX_CONCURRENT_SCANS", 8)

	// Shared launcher inputs — the same regardless of launch mechanism.
	kind := getEnv("SCHEDULER_LAUNCHER", "docker-run")
	image := getEnv("SCHEDULER_SCANNER_IMAGE", "yellowjack-scanner:dev")
	token := os.Getenv("GITHUB_TOKEN")
	network := os.Getenv("SCHEDULER_DOCKER_NETWORK")
	scanTimeout := os.Getenv("SCANNER_SCAN_TIMEOUT_SECS")

	var l launcher
	switch kind {
	case "docker-run":
		// Shells out to the docker CLI; the image ships the CLI + a mounted socket.
		l = &dockerRunLauncher{
			docker:  getEnv("SCHEDULER_DOCKER_BIN", "docker"),
			image:   image,
			token:   token,
			network: network,
			timeout: scanTimeout,
		}
	case "docker-api":
		// Talks to the daemon's HTTP API over the unix socket directly — no docker
		// CLI in the image, no Docker SDK dependency (D16). Still needs the socket.
		socket := getEnv("SCHEDULER_DOCKER_SOCKET", "/var/run/docker.sock")
		l = newAPILauncher(socket, image, token, network, scanTimeout)
	default:
		log.Fatalf("unknown SCHEDULER_LAUNCHER=%q (want docker-run or docker-api)", kind)
	}

	s := newScheduler(l, selfURL, timeout, maxConcurrent)

	log.Printf("Yellow Jack scheduler starting on %s", addr)
	log.Printf("  launcher: %s", kind)
	log.Printf("  scanner image: %s", image)
	log.Printf("  self URL (containers report here): %s", selfURL)
	if maxConcurrent > 0 {
		log.Printf("  max concurrent scans: %d (excess callers queue, then get a retryable 503)", maxConcurrent)
	} else {
		log.Printf("  WARNING: SCHEDULER_MAX_CONCURRENT_SCANS=0 — scan launches are UNCAPPED; a burst can exhaust this host")
	}
	if token == "" {
		log.Printf("  WARNING: GITHUB_TOKEN not set — launched scans will hit GitHub rate limits fast")
	}
	if network == "" {
		log.Printf("  WARNING: SCHEDULER_DOCKER_NETWORK not set — launched containers may not be able to reach %s", selfURL)
	}
	if err := http.ListenAndServe(addr, s); err != nil {
		log.Fatalf("scheduler failed: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getIntEnv reads a plain integer from an env var. A malformed value falls back to
// the default loudly rather than silently becoming 0 — which, for a concurrency cap,
// would mean "uncapped" and quietly undo the protection.
func getIntEnv(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		log.Printf("  invalid %s=%q, using default %d", key, v, fallback)
	}
	return fallback
}

// getDurationEnv reads an integer number of seconds from an env var.
func getDurationEnv(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if secs, err := strconv.Atoi(v); err == nil {
			return time.Duration(secs) * time.Second
		}
		log.Printf("  invalid %s=%q, using default %s", key, v, fallback)
	}
	return fallback
}
