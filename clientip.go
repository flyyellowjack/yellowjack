package main

import (
	"net"
	"net/http"
	"strings"
)

// clientIP returns the OBSERVED source IP of a request: the address of the host
// that pulled this package, as best we can determine it. It is deliberately named
// for what it is — the connecting peer — not "the developer": behind NAT, a CI
// runner, or a shared egress it is a gateway address shared by many people, and it
// must never be presented as a personal identity. It is an incident-response signal
// ("which host pulled this"), not attribution of a human (#41, D83).
//
// The value comes from one of two sources, and which one is a SECURITY decision:
//
//   - r.RemoteAddr — the kernel-observed peer of the TCP connection. Always
//     trustworthy because an attacker cannot forge the source of an established
//     connection. This is the default and the fallback.
//   - X-Forwarded-For — the client chain a reverse proxy / load balancer records.
//     Trusted ONLY when the immediate peer (RemoteAddr) is itself a configured
//     trusted proxy (FW_TRUSTED_PROXIES). Any client can send an X-Forwarded-For
//     header, so believing it from an arbitrary peer would let anyone spoof the
//     recorded source IP — the exact thing an incident-response record must not
//     allow. When the peer is untrusted the header is ignored completely.
//
// trusted is the parsed FW_TRUSTED_PROXIES set; an empty set means "no proxy is
// trusted", so we always use the raw peer (correct for the default cooperative
// deployment where clients connect to the firewall directly).
//
// An empty return means "we could not observe a source" and stores as the
// absent-field zero value.
func clientIP(r *http.Request, trusted []*net.IPNet) string {
	peer := remoteHost(r.RemoteAddr)
	if len(trusted) == 0 || !ipInNets(peer, trusted) {
		return peer // untrusted (or direct) peer: never believe XFF
	}
	// The peer is a trusted proxy, so X-Forwarded-For is meaningful. Its entries are
	// "client, proxy1, proxy2, …" appended left-to-right as the request traverses
	// proxies, so the RIGHTMOST is the closest hop. Walk right-to-left skipping our
	// own trusted proxies; the first non-trusted, parseable address is the real
	// client. If every hop is trusted (or the header is absent/garbage) we fall back
	// to the peer — a safe, real value rather than a guess.
	fwd := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(fwd) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(fwd[i])
		if ip == "" || net.ParseIP(ip) == nil {
			continue // skip blanks and non-IP junk rather than record them as a source
		}
		if !ipInNets(ip, trusted) {
			return ip
		}
	}
	return peer
}

// remoteHost strips the port from an "host:port" address. r.RemoteAddr is always in
// that form for an HTTP server connection, but if it somehow has no port we return
// it unchanged rather than dropping the value.
func remoteHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// ipInNets reports whether ip (a bare address string) falls inside any of the given
// networks. A value that doesn't parse as an IP is never "in" any net — so junk can
// never be mistaken for a trusted proxy.
func ipInNets(ip string, nets []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// parseTrustedProxies parses the comma-separated FW_TRUSTED_PROXIES value into a set
// of networks. Each entry may be a CIDR ("10.0.0.0/8", "2001:db8::/32") or a bare IP
// ("192.168.1.1"), which is treated as a single-host network. Unparseable entries are
// returned separately (not silently dropped into the trusted set) so the caller can
// warn about them at startup — but they are EXCLUDED from the trusted set, which is
// the fail-safe direction: a typo'd trusted proxy means we fall back to the raw peer
// (still a real IP) rather than accidentally trusting a spoofable header.
func parseTrustedProxies(raw string) (nets []*net.IPNet, invalid []string) {
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(part); err == nil {
			nets = append(nets, n)
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		invalid = append(invalid, part)
	}
	return nets, invalid
}
