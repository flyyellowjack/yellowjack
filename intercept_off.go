//go:build !intercept

package main

import (
	"errors"
	"net/http"
)

// This build does not include TLS-interception mode. The cooperative gate -- a client
// configured to use this server as its registry -- is the whole product here, and every
// interception hook below is unreachable: each call site first asks intercepted(r),
// which is always false.

// errNoInterception is returned when FW_INTERCEPT_LISTEN is set on a build without the
// mode. Refusing to start is deliberate: an operator who configured interception and got
// a gate that silently does not intercept would believe clients are enforced when they
// can route around it.
var errNoInterception = errors.New("FW_INTERCEPT_LISTEN is set, but this build does not include " +
	"TLS-interception mode; unset FW_INTERCEPT_LISTEN and FW_INTERCEPT_CA_FILE to run the cooperative gate")

func setupInterception(cfg Config, _ http.Handler) (*interception, error) {
	if cfg.InterceptListen == "" {
		return nil, nil
	}
	return nil, errNoInterception
}

func intercepted(*http.Request) bool { return false }

func (p *proxyServer) isFilesHost(string) bool { return false }

func (p *proxyServer) rewriteBearerRealm(http.Header, *http.Request) {}

func (p *proxyServer) proxyInterceptedToken(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}

func (p *proxyServer) proxyInterceptedFile(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}
