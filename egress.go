package main

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
)

// Zero-egress: the observation point that makes the claim checkable (issue #27).
//
// # The claim, worded exactly
//
// "Zero egress" means: **no telemetry to us, and no vendor meter on the customer's
// traffic.** It does NOT mean "no outbound at all" — the gate still fetches metadata from
// the configured registry and scores from the configured scorer, and the cacheless MVP
// adds one upstream fetch per pull. Overclaiming this is how a strong, checkable argument
// gets discredited by the first competent reader (D65).
//
// The checkable form of the claim is therefore: **every outbound connection the firewall
// makes goes to an address the OPERATOR configured.** No host is baked into the binary,
// and in particular none of them is ours. egressDestinations enumerates that set from
// Config, and the test suite asserts the running proxy dials nothing outside it.
//
// # Why a seam in production code rather than a purely external check
//
// Because the property is otherwise unobservable from inside. A test can assert that a
// request succeeded, but not that nothing ELSE was dialled while it ran — and "nothing
// else" is the entire claim. This hook is nil in production (one atomic load per dial,
// no allocation), and exists so the property can be measured instead of asserted in prose.
// Per CLAUDE.md: a behaviour that must not regress needs a test, and "watch out, X
// silently breaks" belongs in an assertion that fails, never a comment.
//
// # What this layer can and cannot see — read before trusting it
//
// It sees every TCP connection made through an http.Transport built by pooledTransport.
// That is ALL firewall-originated egress today, but only because two things are true, and
// each is enforced by its own assertion rather than left to hold by luck:
//
//   - Every outbound client is built on pooledTransport. The flow/health emitter used to
//     be the exception (a bare &http.Client{} on http.DefaultTransport, which this hook
//     cannot see); it now shares the pooled transport. TestEveryOutboundClientIsObservable
//     is what keeps that true.
//   - The firewall binary links NO third-party package. A dependency that constructs its
//     own dialer would bypass this seam entirely — the known weakness of dialler-level
//     egress checking. TestFirewallBinaryLinksOnlyStdlib measures it.
//
// It CANNOT see:
//
//   - DNS. Resolution happens inside the dialer, before the connect this hook wraps, so
//     the hook observes "registry.npmjs.org:443", never the resolver traffic. A DNS
//     server is a destination an operator must allow through their own firewall, and it
//     is listed as such in the deployment guarantee.
//   - Anything a future dependency, cgo, or the Go runtime dials on its own.
//
// Those two blind spots are why the container-level leg exists (e2e): it observes the
// process from OUTSIDE, where neither is invisible. This layer is the fast one; that one
// is the honest one. Neither replaces the other.

// egressObserver is called with the network and address of every connection attempt made
// through a pooledTransport, BEFORE the connection is established — so an attempt that
// fails is still observed. A failed dial to an unexpected host is exactly as much of a
// violation as a successful one, and a check that only saw successes could be defeated by
// a host that happens to be down.
type egressObserver func(network, addr string)

// egressHook holds the installed observer, or nil. Atomic because dials happen on many
// goroutines at once; a plain var would be a data race the -race gate would (correctly)
// fail on.
var egressHook atomic.Pointer[egressObserver]

// setEgressObserver installs an observer and returns a function that removes it. Used by
// tests only; production never calls it, so the hook stays nil and the dial path is the
// stdlib's plus one atomic load.
func setEgressObserver(obs egressObserver) func() {
	egressHook.Store(&obs)
	return func() { egressHook.Store(nil) }
}

// observeDials wraps a transport's existing DialContext with the hook.
//
// It WRAPS rather than replaces: http.DefaultTransport's dialer carries the stdlib's
// connect timeout and keep-alive, and substituting our own would silently drop both. We
// change what is observed, not how connections are made.
func observeDials(t *http.Transport) {
	base := t.DialContext
	if base == nil {
		// A Clone of http.DefaultTransport always has one; guard anyway so this cannot
		// turn into a nil-deref if the transport is ever built some other way.
		var d net.Dialer
		base = d.DialContext
	}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if h := egressHook.Load(); h != nil {
			(*h)(network, addr)
		}
		return base(ctx, network, addr)
	}
}

// egressDestinations is the authoritative list of addresses this configuration permits the
// firewall to dial, as "host:port".
//
// This function IS the deliverable of issue #27 ("the exact list is the deliverable, not
// the slogan"). Every entry comes from a Config field an operator sets; there is no
// literal host anywhere in it, which is the property that makes "nothing phones home to
// Yellow Jack" true by construction rather than by inspection.
//
// Not included, deliberately:
//
//   - ListenAddr — inbound, not egress.
//   - PublicURL — never dialled; it is only woven into minted artifact URLs so a client's
//     next fetch comes back to us.
//   - DNS — see the file comment; not visible at this layer.
func (c Config) egressDestinations() []string {
	seen := map[string]bool{}
	for _, raw := range []string{
		c.UpstreamRegistry, // registry metadata, and npm artifact bytes
		c.FilesUpstream,    // PyPI artifact bytes (a different host from the index)
		c.DepsDevBase,      // api-mode scoring AND repo verification (D33)
		c.ScannerURL,       // the scheduler, in local/async scoring mode only
		c.ApprovalURL,      // approval lookups, plus the flow/health heartbeat (#32)
		c.MalwareFeedURL,   // the hourly known-malware snapshot pull, off the request path (#157)
	} {
		if addr := hostPort(raw); addr != "" {
			seen[addr] = true
		}
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out) // stable output: this list goes into failure messages and docs
	return out
}

// hostPort reduces a configured base URL to the "host:port" a dialer would be handed,
// filling in the scheme's default port when the URL omits it (the dialer always sees an
// explicit port, so a list built without this would never match).
func hostPort(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Port() != "" {
		return u.Host
	}
	switch u.Scheme {
	case "https":
		return net.JoinHostPort(u.Hostname(), "443")
	case "http":
		return net.JoinHostPort(u.Hostname(), "80")
	}
	return u.Host
}
