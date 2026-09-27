package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

// A GATE THAT IS STOPPED STOPS ANSWERING ONLY AFTER NOTHING ROUTES TO IT ANY MORE.
//
// Until #163 the gate had no signal handling at all: SIGTERM ended the process, and the
// listener went with it. On Kubernetes that drops requests. When a pod is evicted (a node
// drain, a rolling update), the kubelet sends SIGTERM at the same moment the endpoint is
// withdrawn, and the withdrawal reaches every node's kube-proxy a little later. A client
// connecting in between reaches a gate that has already gone. The first real-cluster run
// measured it: draining a node with the disruption budget ON still dropped 1 request of 44
// (e2e/helm_install.sh, leg 4). The compose rollover measured zero only because nothing
// there routes on a delayed endpoint list.
//
// So on SIGTERM (or an interrupt) the gate:
//  1. reports NOT ready on /readyz, so anything still probing stops routing here;
//  2. keeps SERVING for shutdownLameduck, the window in which routes are withdrawn;
//  3. stops accepting and lets in-flight requests finish, up to shutdownGrace.
//
// Both are constants, not knobs (the #51 budget): 5 s covers endpoint propagation on any
// cluster we have measured, and 5 + 20 s fits inside Kubernetes' default 30 s termination
// grace, and compose's 10 s with the in-flight bound cut short rather than the lameduck.
// The interception listener, when built, keeps serving through the lameduck and stops at
// process exit.
var shutdownLameduck = 5 * time.Second

const shutdownGrace = 20 * time.Second

// serveUntilSignal serves on ln until the listener fails or a signal arrives, then drains.
// A listener failure is returned; a drain returns nil.
func serveUntilSignal(p *proxyServer, srv *http.Server, ln net.Listener, sigs <-chan os.Signal) error {
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case s := <-sigs:
		drainAndStop(p, srv, s.String())
		return nil
	}
}

func drainAndStop(p *proxyServer, srv *http.Server, why string) {
	p.draining.Store(true)
	log.Printf("%s received: draining -- /readyz now answers 503, and requests are still served for %s "+
		"while the orchestrator stops routing here", why, shutdownLameduck)
	time.Sleep(shutdownLameduck)
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("drain: in-flight requests did not finish within %s (%v); stopping anyway", shutdownGrace, err)
		return
	}
	log.Printf("drain: stopped cleanly")
}
