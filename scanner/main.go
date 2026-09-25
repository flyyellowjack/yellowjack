package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

// The scanner is a RUN-ONCE container. It reads its inputs from the environment
// (the target repo, a GitHub token, and a results-sink URL), runs OpenSSF
// Scorecard exactly once against that repo, POSTs the result to the sink, and
// exits. There is no long-lived server: one container == one scan == one report.
//
// Why this shape (see DECISIONS.md D16):
//   - The scorecard binary is wrapped as an ephemeral container, never embedded as
//     a Go library — that keeps Scorecard's large dependency tree and its GitHub
//     token out of the firewall's (and our scheduler's) attack surface, and keeps
//     the AGPL/Apache license boundary clean (we invoke a third-party tool, we
//     don't link it).
//   - A separate *scheduler* service (later increment) launches one of these
//     containers per scan and receives the POSTed result. The firewall talks to
//     the scheduler, not to any persistent scanner.
//
// The end user supplies their own GITHUB_TOKEN at runtime; it is never baked into
// the image.
func main() {
	cfg := loadRunConfig()

	runner := &execRunner{bin: cfg.ScorecardBin, token: cfg.Token}

	log.Printf("Yellow Jack scanner (run-once): repo=%s sink=%s", cfg.Repo, cfg.SinkURL)
	log.Printf("  scorecard binary: %s", cfg.ScorecardBin)
	if cfg.Token == "" {
		log.Printf("  WARNING: GITHUB_TOKEN not set — real scans will hit GitHub rate limits fast")
	}

	// Bound the scan: Scorecard can take minutes, and we never want a hung scan to
	// keep the container alive indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	report := runScan(ctx, runner, cfg.Repo)

	// Always try to deliver the report — including failures — so the scheduler
	// learns the outcome instead of waiting for its own timeout. Give delivery its
	// own short deadline, independent of the (possibly exhausted) scan context.
	postCtx, postCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer postCancel()
	if err := postReport(postCtx, http.DefaultClient, cfg.SinkURL, report); err != nil {
		log.Fatalf("failed to deliver result to sink %s: %v", cfg.SinkURL, err)
	}

	if report.Error != "" {
		log.Printf("scan %s failed: %s (reported to sink)", report.Repo, report.Error)
		os.Exit(1)
	}
	log.Printf("scan %s -> score %.1f (delivered to sink)", report.Repo, report.Result.Score)
}

// runConfig is everything the run-once container reads from its environment.
type runConfig struct {
	Repo         string        // target source repo, e.g. github.com/owner/name
	SinkURL      string        // where the ScanResult is POSTed
	Token        string        // GitHub token for Scorecard's API calls
	ScorecardBin string        // path/name of the scorecard binary to invoke
	Timeout      time.Duration // hard cap on the scan
}

// loadRunConfig reads and validates the environment. Repo and sink URL are
// required — without them there is nothing to scan or nowhere to report — so a
// missing one is a fatal misconfiguration, not a runtime fallback.
func loadRunConfig() runConfig {
	cfg := runConfig{
		Repo:         os.Getenv("SCANNER_REPO"),
		SinkURL:      os.Getenv("SCANNER_SINK_URL"),
		Token:        os.Getenv("GITHUB_TOKEN"),
		ScorecardBin: getEnv("SCANNER_SCORECARD_BIN", "scorecard"),
		Timeout:      getDurationEnv("SCANNER_SCAN_TIMEOUT_SECS", 180*time.Second),
	}
	if cfg.Repo == "" {
		log.Fatalf("SCANNER_REPO is required (the source repo to scan)")
	}
	if cfg.SinkURL == "" {
		log.Fatalf("SCANNER_SINK_URL is required (where to POST the result)")
	}
	return cfg
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
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

// scanReport is the envelope the run-once container POSTs to the sink. Exactly one
// of Result / Error is meaningful: Result on a successful scan, Error on failure.
// Repo is always set so the receiver can identify what was scanned even on error.
type scanReport struct {
	Repo   string      `json:"repo"`
	Result *ScanResult `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// runScan runs one Scorecard scan and wraps the outcome in a scanReport. A scan
// failure is a reportable outcome (Error set), not a thrown error — the caller
// still delivers it to the sink.
func runScan(ctx context.Context, runner scorecardRunner, repo string) scanReport {
	result, err := scan(ctx, runner, repo)
	if err != nil {
		return scanReport{Repo: repo, Error: err.Error()}
	}
	return scanReport{Repo: result.Repo, Result: &result}
}

// postReport delivers the report to the sink as JSON. A non-2xx response means the
// sink rejected the delivery, which is an error the caller should surface.
func postReport(ctx context.Context, client *http.Client, sinkURL string, report scanReport) error {
	body, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encoding report: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sinkURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building sink request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("posting to sink: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) // drain so the connection can be reused
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sink returned %s", resp.Status)
	}
	return nil
}
