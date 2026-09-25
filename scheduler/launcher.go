package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// dockerRunLauncher launches the run-once scanner by shelling out to `docker run`.
// This is the first of several possible launchers (a raw Docker Engine API client
// and a Kubernetes Job launcher are planned) — it is the simplest thing that runs
// end-to-end. The scheduler's own image must therefore have the docker CLI and
// access to the daemon socket; the API-based launcher will later remove that
// requirement.
//
// The GitHub token is held here, not passed per-scan, so it never appears in the
// scheduler's request-handling path. The end user supplies it to the scheduler at
// runtime (D16); we only forward it into each ephemeral container.
type dockerRunLauncher struct {
	docker  string // docker binary (default "docker")
	image   string // run-once scanner image to launch
	token   string // GitHub token forwarded to each container
	network string // optional docker network so the container can reach the sink
	timeout string // optional SCANNER_SCAN_TIMEOUT_SECS to pass through
}

func (d *dockerRunLauncher) Launch(ctx context.Context, repo, sinkURL string) error {
	// -d (detached) + --rm: start the container in the background and auto-remove
	// it when it exits. `docker run -d` returns as soon as the container is
	// started (printing its id), so this call is fast and surfaces start-time
	// failures (image not found, bad flag) immediately — instead of blocking for
	// the whole scan and masking such errors behind the scheduler's timeout. The
	// container reports its result out-of-band by POSTing to sinkURL.
	args := []string{"run", "-d", "--rm"}
	if d.network != "" {
		args = append(args, "--network", d.network)
	}
	// -e KEY=VALUE injects the run-once container's inputs. The token is passed by
	// value here; a hardening step later is to pass it via a file/secret rather
	// than an env arg visible in the daemon's inspect output.
	args = append(args,
		"-e", "SCANNER_REPO="+repo,
		"-e", "SCANNER_SINK_URL="+sinkURL,
	)
	if d.token != "" {
		args = append(args, "-e", "GITHUB_TOKEN="+d.token)
	}
	if d.timeout != "" {
		args = append(args, "-e", "SCANNER_SCAN_TIMEOUT_SECS="+d.timeout)
	}
	args = append(args, d.image)

	cmd := exec.CommandContext(ctx, d.docker, args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker run: %w (%s)", err, strings.TrimSpace(out.String()))
	}
	return nil
}
