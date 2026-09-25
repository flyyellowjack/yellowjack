package main

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// Shared by every build: the connection-lifetime bounds (the cooperative listener in
// listener.go uses three of them) and the certificate fingerprint format (upstreamtrust.go).

// #39 CLASS 6 -- the proxy as a crash and hang surface -- is bounded by these four
// lifetimes, and each one is there because a specific way of holding a slot forever was
// named. One product's record is a CONNECT-proxy busy-loop after a mid-request
// interruption with copies accumulating; issue #1 / D71 was our own unbounded-connection
// defect. So every phase of an intercepted connection has a deadline:
//
//   - interceptHandshakeTimeout: after CONNECT, a client that never speaks (or one that
//     rejects our CA, class 2) is released rather than parked on a slot.
//   - interceptReadHeaderTimeout: a client that opens the tunnel, handshakes, and then
//     trickles request headers.
//   - interceptRequestReadTimeout: a client that sends complete headers and then STALLS
//     THE BODY. net/http drains an unread body when the handler returns, and with no
//     ReadTimeout that drain blocks forever -- so 256 stalled PUTs held every slot. A
//     legitimate upload finishes in seconds (npm publish is a small tarball); nothing
//     this mode relays streams a request body for minutes.
//   - interceptIdleTimeout: a keep-alive tunnel with nothing on it.
//
// The COOPERATIVE listener shares the last three since #130 (listener.go), so the two
// listeners have one set of lifetime rules; the relay extends the read bound as body
// bytes arrive, which is what keeps it a bound on a stall rather than on an upload.
//
// The UPSTREAM leg is the cooperative path's own client (ResponseHeaderTimeout, and a
// deliberately unbounded body copy for large artifact downloads -- see newProxyServer),
// so this mode adds no new unbounded lifetime of its own.
var (
	interceptHandshakeTimeout   = 10 * time.Second
	interceptReadHeaderTimeout  = 15 * time.Second
	interceptRequestReadTimeout = 90 * time.Second
	interceptIdleTimeout        = 90 * time.Second
)

// certFingerprint is the SHA-256 fingerprint in the colon-separated upper-case form
// `openssl x509 -fingerprint -sha256` prints, so an operator can compare by eye.
func certFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	parts := make([]string, len(sum))
	for i, x := range sum {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":")
}
