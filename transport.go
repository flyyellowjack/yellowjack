package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
)

// defaultMaxConnsPerHost bounds how many TCP connections the firewall will hold open
// to any ONE host at a time. It is deliberately well above real client parallelism
// (npm resolves ~16-wide, maven similar) so normal traffic never queues, and well
// below the point where a burst overruns a peer's listen backlog.
const defaultMaxConnsPerHost = 64

// pooledTransport returns the transport for every request the firewall makes on its
// OWN behalf — upstream registry probes, deps.dev, the approval service (L2), the
// scheduler. It exists because the stdlib default is wrong for our access pattern.
//
// Our pattern is: many concurrent requests to a SMALL, fixed set of hosts. But
// http.DefaultTransport keeps only 2 idle connections per host
// (http.DefaultMaxIdleConnsPerHost), with no ceiling on concurrent ones. So a cold
// resolve that fans out — hundreds of overlapping package evaluations, each doing an
// L2 score lookup — opens hundreds of simultaneous short-lived connections to the
// approval service and discards all but 2. That is not a theoretical cost:
//
//   - It overruns the peer's accept backlog, which surfaces as "connection refused"
//     on a service that is up and healthy. The firewall (correctly) degrades a failed
//     L2 lookup to "repo is cold" (firewall.go, resolveCachedScore), so every refused
//     lookup launches a redundant background re-scan — the at-most-one-scan-per-repo
//     property breaks under load through no fault of the dedup logic. This is issue #1.
//   - In production it means a cold burst DDoSes our own L2 with connection setup.
//
// Two settings fix it, and they do different jobs:
//
//   - MaxConnsPerHost is the real bound. Once this many connections to a host are in
//     use, further requests BLOCK waiting for one to free up instead of dialing a new
//     socket. This is what converts an unbounded connection stampede into a queue.
//   - MaxIdleConnsPerHost is what makes the queue cheap: without it those connections
//     are closed after each request and the next waiter re-dials, so we would pay the
//     handshake over and over. Matching it to the cap means the burst dials at most
//     `cap` times total and then reuses.
//
// Note the interaction with http.Client.Timeout: time spent waiting for a connection
// slot counts against it. That is the intended tradeoff — a queued request is bounded
// by the client timeout and fails cleanly, whereas an unbounded dial storm fails
// randomly and (as issue #1 shows) in ways that look like a logic bug. At the default
// cap a 240-wide burst against a healthy L2 drains in milliseconds.
//
// maxConnsPerHost <= 0 means "no ceiling" (the stdlib's own semantics for
// MaxConnsPerHost); the idle pool is still sized so connections get reused rather than
// churned. That combination — pool, don't cap — is both the operator escape hatch on the
// firewall's probe client AND the deliberate choice for the proxy's client-facing relay
// path, where a ceiling would queue real artifact downloads behind each other. See
// newProxyServer for why a cap there needs a dial timeout before it would be safe.
//
// It is a Clone of http.DefaultTransport so proxy support, TLS defaults, HTTP/2, and
// every timeout stay exactly as the stdlib sets them — we change connection pooling,
// the root pool when the operator supplied one, and nothing else.
//
// PROXY SUPPORT IS PART OF THE CONTRACT, NOT AN ACCIDENT OF THE CLONE. The clone carries
// http.ProxyFromEnvironment, which is the whole of our support for an enterprise forward
// proxy: HTTPS_PROXY routes us to it and NO_PROXY keeps internal hosts direct, with no
// FW_ knob re-implementing either (#137). That is why TestPooledTransportHonoursTheProxyEnvironment
// exists — set Proxy to nil here and every cooperative deployment behind a corporate
// proxy silently loses its route, with nothing else in the tree to notice.
//
// roots is the operator's upstream CA bundle, already APPENDED to the system roots by
// upstreamRoots (nil = the platform's own roots, which is every deployment that has no
// TLS inspection in front of it). It is threaded through THIS constructor rather than
// applied at the call sites for the same reason observeDials is: a client added later
// must not be able to escape it by forgetting a line.
func pooledTransport(maxConnsPerHost int, roots *x509.CertPool) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()

	if roots != nil {
		// Clone() may or may not hand back a TLSClientConfig -- it is nil until something
		// configures HTTP/2 on http.DefaultTransport and non-nil (carrying NextProtos)
		// afterwards -- so both shapes are handled and neither is assumed. Everything else
		// in it stays at the stdlib's defaults, so this changes WHICH roots are acceptable
		// and nothing about the handshake. ForceAttemptHTTP2 survives the clone, which is what
		// keeps h2 alive: a non-nil TLSClientConfig would otherwise disable the automatic
		// HTTP/2 upgrade, quietly halving our concurrency against registries that speak it.
		if t.TLSClientConfig == nil {
			t.TLSClientConfig = &tls.Config{}
		}
		t.TLSClientConfig.RootCAs = roots
	}

	idlePerHost := maxConnsPerHost
	if maxConnsPerHost <= 0 {
		// Normalize every "no ceiling" spelling to the stdlib's canonical 0 rather than
		// storing a negative literal. net/http gates its queueing on
		// `MaxConnsPerHost > 0` so a negative would behave identically, but the field is
		// readable (tests, future code) and "0 means no limit" is what its documentation
		// says — leaving a -1 in there invites someone to read it as a real limit.
		t.MaxConnsPerHost = 0
		idlePerHost = defaultMaxConnsPerHost
	} else {
		t.MaxConnsPerHost = maxConnsPerHost
	}
	t.MaxIdleConnsPerHost = idlePerHost

	// MaxIdleConns is the process-wide idle total; leaving it at the stdlib's 100
	// would silently cap the per-host pool once we talk to more than one host (we
	// talk to ~4: registry, artifact CDN, deps.dev, approval/scheduler).
	if want := idlePerHost * 4; t.MaxIdleConns < want {
		t.MaxIdleConns = want
	}

	// Make every connection this transport opens observable (issue #27). No-op in
	// production — the hook is nil, so this costs one atomic load per dial — and the
	// single choke point that lets the zero-egress property be MEASURED rather than
	// claimed. Attached here, in the one constructor every outbound client goes through,
	// so a new client cannot be added that quietly escapes observation.
	observeDials(t)
	return t
}

// newTransport is the seam every production transport is built through; it is
// pooledTransport unless a test says otherwise, and production never reassigns it.
//
// It is a variable for one caller: the mode-matrix rig (modematrix_test.go), which
// builds 3,840 firewalls in one process and must let them share a pool the way a single
// long-lived process does. With a fresh pool per firewall the rig dialled 7,511 times per
// run and held every socket open past the run's end (issue #96) — a leak that only
// fails when the host's ephemeral ports are already partly spent, which is why it read
// as a load flake for four sessions. Nothing in the seam's absence would have caught
// that: the transports are correct one per process, and one per process is the only
// shape production has.
var newTransport = pooledTransport

// drainedBodyMax bounds how much of a response body closeDrained reads before it
// gives up on the connection: more than any error page, small enough that a hostile
// upstream cannot hold a probe on a streaming body.
const drainedBodyMax = 64 << 10

// closeDrained closes a response body the way the transport needs it closed to REUSE
// the connection: read to EOF first.
//
// Go's http.Transport returns a connection to its pool only when the body was read to
// EOF; a body closed with bytes unread is discarded, together with the TLS session
// behind it. The firewall closed every non-200 answer unread -- a 404 for a typo'd
// install, a 429, a 503 -- and the OCI auth probe closed its body on every answer, 200
// included. So the pooling that !61/!64 bought applied to the 200 path only; every
// other answer cost a fresh dial and handshake on the next probe. Measured on the mode
// matrix with pools shared across cells: 1,330 dials for 3,840 cells, two per cell in
// the outage scenario, one per OCI lookup (issue #118).
//
// Bounded: past drainedBodyMax the remainder is left unread and Close drops the
// connection, which is the right outcome for a body that size. A decoder that already
// consumed the body costs one zero-length read here.
func closeDrained(body io.ReadCloser) {
	io.CopyN(io.Discard, body, drainedBodyMax) // EOF is the goal, not an error
	body.Close()
}
