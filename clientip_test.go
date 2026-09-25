package main

import (
	"net"
	"net/http"
	"testing"
)

// mustNets parses a trusted-proxy spec for tests, failing the test on any invalid
// entry so a typo in a test fixture is a loud error, not a silently-empty set.
func mustNets(t *testing.T, spec string) []*net.IPNet {
	t.Helper()
	nets, invalid := parseTrustedProxies(spec)
	if len(invalid) != 0 {
		t.Fatalf("parseTrustedProxies(%q): unexpected invalid entries %v", spec, invalid)
	}
	return nets
}

func reqWith(remoteAddr string, xff ...string) *http.Request {
	r := &http.Request{RemoteAddr: remoteAddr, Header: http.Header{}}
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func TestClientIP(t *testing.T) {
	trusted := "10.0.0.0/8, 192.168.0.1"

	cases := []struct {
		name       string
		trusted    string
		remoteAddr string
		xff        []string
		want       string
	}{
		{
			name:       "direct peer, no trusted proxies: raw peer, XFF ignored",
			trusted:    "",
			remoteAddr: "203.0.113.5:5555",
			xff:        []string{"1.2.3.4"}, // present but must be ignored
			want:       "203.0.113.5",
		},
		{
			// NEGATIVE CONTROL. A trusted set is configured, but the PEER is not in it,
			// so its X-Forwarded-For is attacker-controlled and must be dropped. If this
			// returns 1.2.3.4 the spoofing defense is broken — anyone could forge the
			// recorded source IP of a pull. Deleting the untrusted-peer guard in clientIP
			// makes exactly this case fail.
			name:       "untrusted peer's spoofed XFF is ignored (negative control)",
			trusted:    trusted,
			remoteAddr: "203.0.113.5:5555",
			xff:        []string{"1.2.3.4"},
			want:       "203.0.113.5",
		},
		{
			name:       "trusted proxy: believe XFF",
			trusted:    trusted,
			remoteAddr: "10.0.0.1:443",
			xff:        []string{"203.0.113.9"},
			want:       "203.0.113.9",
		},
		{
			name:       "chained trusted proxies: skip our own hops, take the real client",
			trusted:    trusted,
			remoteAddr: "10.0.0.1:443",
			xff:        []string{"203.0.113.9, 10.0.0.2, 10.0.0.3"},
			want:       "203.0.113.9",
		},
		{
			name:       "multiple XFF headers are joined right-to-left",
			trusted:    trusted,
			remoteAddr: "10.0.0.1:443",
			xff:        []string{"203.0.113.9", "10.0.0.2"},
			want:       "203.0.113.9",
		},
		{
			name:       "trusted proxy but no XFF: fall back to the peer",
			trusted:    trusted,
			remoteAddr: "10.0.0.1:443",
			xff:        nil,
			want:       "10.0.0.1",
		},
		{
			name:       "every forwarded hop is trusted: fall back to the peer",
			trusted:    trusted,
			remoteAddr: "10.0.0.1:443",
			xff:        []string{"10.0.0.2, 10.0.0.3"},
			want:       "10.0.0.1",
		},
		{
			name:       "junk rightmost entry is skipped, real client still found",
			trusted:    trusted,
			remoteAddr: "10.0.0.1:443",
			xff:        []string{"203.0.113.9, not-an-ip"},
			want:       "203.0.113.9",
		},
		{
			name:       "bare-IP trusted entry matches exactly",
			trusted:    trusted,
			remoteAddr: "192.168.0.1:443",
			xff:        []string{"198.51.100.7"},
			want:       "198.51.100.7",
		},
		{
			name:       "RemoteAddr without a port is returned unchanged",
			trusted:    "",
			remoteAddr: "203.0.113.5",
			xff:        nil,
			want:       "203.0.113.5",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := clientIP(reqWith(tc.remoteAddr, tc.xff...), mustNets(t, tc.trusted))
			if got != tc.want {
				t.Errorf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseTrustedProxies(t *testing.T) {
	nets, invalid := parseTrustedProxies("10.0.0.0/8, 192.168.1.1 , 2001:db8::/32, , garbage, ")
	if len(invalid) != 1 || invalid[0] != "garbage" {
		t.Fatalf("invalid = %v, want [garbage]", invalid)
	}
	// The blank entries between commas must be skipped, not counted as invalid.
	if len(nets) != 3 {
		t.Fatalf("parsed %d nets, want 3", len(nets))
	}
	checks := []struct {
		ip   string
		want bool
	}{
		{"10.255.1.2", true},   // inside 10.0.0.0/8
		{"11.0.0.1", false},    // outside it
		{"192.168.1.1", true},  // the bare IPv4, as a /32
		{"192.168.1.2", false}, // a neighbor is NOT covered by a bare IP
		{"2001:db8::1", true},  // inside the IPv6 CIDR
		{"2001:dbf::1", false}, // outside it
	}
	for _, c := range checks {
		if got := ipInNets(c.ip, nets); got != c.want {
			t.Errorf("ipInNets(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}
