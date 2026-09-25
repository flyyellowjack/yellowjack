package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// apiLauncher launches the run-once scanner by talking to the Docker daemon's HTTP
// API directly over its unix socket (/var/run/docker.sock), instead of shelling out
// to the `docker` CLI (that's dockerRunLauncher). It is the second implementation
// of the launcher interface (DECISIONS.md D16: "interface now, API later").
//
// Why the raw API and not the Docker SDK: the SDK is a very large dependency, and
// this is security software where every dependency is part of our own attack
// surface. The two calls we need — create + start — are a handful of JSON requests,
// so we make them with stdlib net/http and pay a few dozen lines instead of taking
// on the SDK's whole tree. The tradeoff vs. dockerRunLauncher: the scheduler image
// no longer needs the docker CLI at all (it still needs the mounted socket and, for
// now, root to use it — a K8s-Job launcher removes the socket entirely, later).
//
// The GitHub token is launcher config, exactly as in dockerRunLauncher, so it never
// touches the scheduler's request-handling path (D16: the end user supplies it to
// the scheduler at runtime; we only forward it into each ephemeral container).
type apiLauncher struct {
	client  *http.Client // dials the daemon's unix socket regardless of URL host
	baseURL string       // dummy host; the transport ignores it and dials the socket
	image   string       // run-once scanner image to launch
	token   string       // GitHub token forwarded to each container
	network string       // optional docker network so the container can reach the sink
	timeout string       // optional SCANNER_SCAN_TIMEOUT_SECS to pass through
}

// newAPILauncher builds a launcher whose HTTP client connects to the Docker daemon
// over the given unix socket path (e.g. "/var/run/docker.sock"). The client's
// DialContext ignores the request's host:port and always dials the socket, so we
// address the daemon with an arbitrary but well-formed base URL ("http://docker").
func newAPILauncher(socket, image, token, network, timeout string) *apiLauncher {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &apiLauncher{
		// No overall client timeout: each call carries the scan's context deadline
		// (from the scheduler), so the request is bounded by that instead. A blanket
		// client timeout would fight the per-request context.
		client:  &http.Client{Transport: transport},
		baseURL: "http://docker",
		image:   image,
		token:   token,
		network: network,
		timeout: timeout,
	}
}

// containerCreateRequest is the (minimal) body for POST /containers/create. We set
// only the fields we need; the daemon fills sensible defaults for everything else.
type containerCreateRequest struct {
	Image      string     `json:"Image"`
	Env        []string   `json:"Env"`
	HostConfig hostConfig `json:"HostConfig"`
}

type hostConfig struct {
	// AutoRemove is the API equivalent of `docker run --rm`: the daemon removes the
	// container once it exits. dockerRunLauncher relies on --rm; this keeps exact
	// parity without the scheduler having to track container completion itself (the
	// container reports out-of-band and dies — there is no natural place to hang an
	// explicit remove call).
	AutoRemove bool `json:"AutoRemove"`
	// NetworkMode names the network to attach the container to, so it can resolve
	// the scheduler's SELF_URL to POST its result back. Omitted when empty (the
	// daemon then uses the default bridge) — matching dockerRunLauncher, which only
	// adds --network when one is configured.
	NetworkMode string `json:"NetworkMode,omitempty"`
}

// containerCreateResponse is the part of the create reply we care about.
type containerCreateResponse struct {
	ID string `json:"Id"`
}

// Launch creates one run-once scanner container and starts it. It returns as soon
// as the container is started (like `docker run -d`), so start-time failures (image
// not found, bad config) surface immediately rather than being masked behind the
// scan's full duration and the scheduler's timeout.
func (a *apiLauncher) Launch(ctx context.Context, repo, sinkURL string) error {
	env := []string{
		"SCANNER_REPO=" + repo,
		"SCANNER_SINK_URL=" + sinkURL,
	}
	if a.token != "" {
		env = append(env, "GITHUB_TOKEN="+a.token)
	}
	if a.timeout != "" {
		env = append(env, "SCANNER_SCAN_TIMEOUT_SECS="+a.timeout)
	}

	id, err := a.create(ctx, containerCreateRequest{
		Image:      a.image,
		Env:        env,
		HostConfig: hostConfig{AutoRemove: true, NetworkMode: a.network},
	})
	if err != nil {
		return err
	}
	return a.start(ctx, id)
}

// create issues POST /containers/create and returns the new container's id.
func (a *apiLauncher) create(ctx context.Context, body containerCreateRequest) (string, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal create request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/containers/create", bytes.NewReader(buf))
	if err != nil {
		return "", fmt.Errorf("build create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("create container: %w", err)
	}
	defer resp.Body.Close()

	// The daemon returns 201 Created on success. Anything else is a failure whose
	// body carries the daemon's error message (e.g. "No such image").
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("create container: %s", daemonError(resp))
	}
	var out containerCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode create response: %w", err)
	}
	if out.ID == "" {
		return "", fmt.Errorf("create container: daemon returned no id")
	}
	return out.ID, nil
}

// start issues POST /containers/{id}/start.
func (a *apiLauncher) start(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/containers/"+id+"/start", nil)
	if err != nil {
		return fmt.Errorf("build start request: %w", err)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("start container: %w", err)
	}
	defer resp.Body.Close()

	// 204 No Content = started; 304 Not Modified = already started (harmless). Any
	// other status is a real failure.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		return fmt.Errorf("start container: %s", daemonError(resp))
	}
	return nil
}

// daemonError extracts a human-readable message from a non-success daemon reply.
// Docker error bodies are JSON like {"message":"..."}; fall back to the raw body.
func daemonError(resp *http.Response) string {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil && e.Message != "" {
		return fmt.Sprintf("HTTP %d: %s", resp.StatusCode, e.Message)
	}
	return fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}
