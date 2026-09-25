package main

import (
	"io"
	"net/http"
	"time"
)

// cooperativeServer is the http.Server for the cooperative (default) listener.
//
// #130: this listener was http.ListenAndServe, which sets no timeouts at all. A client
// that sent complete headers and then stalled its body held a goroutine and a socket
// for as long as it liked -- a relayed write waits to forward the body, and a refused
// write is DRAINED by net/http before the refusal is even flushed -- and with no cap on
// this listener one client could hold as many as it wanted until file descriptors ran
// out. That is the #1 / D71 shape: an unbounded connection lifetime that presents as
// "the proxy stopped responding". The interception listener measured it on its own
// inner server (intercept_class6_test.go) and bounded three phases; the cooperative
// listener now shares exactly those three, so the two grow one set of lifetime rules
// rather than two.
//
// No WriteTimeout, deliberately: the relay has no whole-body deadline because a large
// artifact download must not be cut (see newProxyServer). And ReadTimeout bounds a
// STALL, not an upload: the relay extends the read deadline as body bytes arrive
// (relayedBody), so a slow but progressing `npm publish` or `mvn deploy` is not cut at
// the window's edge while a body that stops arriving is released at it.
func cooperativeServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: interceptReadHeaderTimeout,
		ReadTimeout:       interceptRequestReadTimeout,
		IdleTimeout:       interceptIdleTimeout,
	}
}

// relayedBody is r.Body prepared for the upstream request: unchanged when there is
// nothing to send or no read bound is armed, deadline-extending otherwise.
//
// The server's ReadTimeout arms ONE deadline at the start of the request, covering
// headers and body together. Left alone it would cut any upload longer than the window
// mid-body, which is the wrong bound: the thing to release is a body that has STOPPED
// arriving. So every Read that delivers bytes pushes the connection's read deadline out
// by another window, and "stalled" means "no bytes for a whole window".
func relayedBody(w http.ResponseWriter, r *http.Request) io.ReadCloser {
	if r.Body == nil || r.ContentLength == 0 || interceptRequestReadTimeout <= 0 {
		return r.Body
	}
	return &progressBody{ReadCloser: r.Body, rc: http.NewResponseController(w), window: interceptRequestReadTimeout}
}

type progressBody struct {
	io.ReadCloser
	rc     *http.ResponseController
	window time.Duration
}

func (b *progressBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		// Best-effort: a ResponseWriter that cannot set deadlines (httptest's recorder,
		// a wrapping middleware) returns ErrNotSupported and the request keeps the
		// deadline it started with -- still bounded, just not extended.
		_ = b.rc.SetReadDeadline(time.Now().Add(b.window))
	}
	return n, err
}
