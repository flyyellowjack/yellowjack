// Command fakedns is a DNS sinkhole that RECORDS every name the firewall tries to
// resolve, for the zero-egress assertion (issue #27).
//
// # Why a DNS sinkhole is the right observation point
//
// The in-process egress check (egress.go) wraps our own dialer, so it sees "host:port"
// for every connection made through pooledTransport. Two things are invisible there, and
// both are exactly what a phone-home would use:
//
//   - DNS itself. Resolution happens INSIDE the dialer, before the connect we wrap, so a
//     name lookup leaves no trace at that layer.
//   - Anything that dials without going through our transport — a future dependency, cgo,
//     or the Go runtime.
//
// From outside the process both become visible, because a connection to any HOSTNAME must
// first ask a resolver, and we are the resolver. So the test configures every legitimate
// destination as an explicit IP (no lookup needed) and points the container's --dns here.
// A silent, best-effort telemetry POST to a hostname — the realistic shape of the thing we
// are ruling out — cannot happen without asking us first.
//
// This does NOT catch egress to a hard-coded IP literal, which needs no DNS. That case is
// the one the in-process dialler check DOES see. The two layers are complementary on
// purpose: neither is sufficient, and the pair covers both spellings.
//
// # Behaviour
//
// Answers every A query with SINK_IP (default 127.0.0.1) so the caller gets a syntactically
// valid reply and proceeds to connect somewhere harmless, and prints one line per query to
// stdout, which is what the test asserts on:
//
//	QUERY <name>
//
// Written in Go with no third-party packages, same rule as e2e/fakescanner: a test fixture
// that pulled in a DNS library would add a dependency to the repo purely to test it.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

func main() {
	sink := net.ParseIP(env("SINK_IP", "127.0.0.1")).To4()
	if sink == nil {
		log.Fatal("SINK_IP must be an IPv4 address")
	}
	conn, err := net.ListenPacket("udp", ":53")
	if err != nil {
		log.Fatalf("listen :53/udp: %v", err)
	}
	defer conn.Close()
	log.Printf("fakedns listening on :53/udp, answering every A query with %s", sink)

	buf := make([]byte, 512)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("read: %v", err)
			continue
		}
		req := buf[:n]
		name, qEnd, ok := parseQuestion(req)
		if !ok {
			continue
		}
		// THE OBSERVATION. Unbuffered stdout via fmt so `docker logs` shows it
		// immediately — a test that reads logs before a flush would see nothing and
		// wrongly report a clean run.
		fmt.Printf("QUERY %s\n", name)
		os.Stdout.Sync()

		if resp, ok := buildReply(req, qEnd, sink); ok {
			_, _ = conn.WriteTo(resp, addr)
		}
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// parseQuestion walks the QNAME labels of the first question and returns the dotted name
// plus the offset just past the question section.
//
// Hand-rolled rather than pulled from a library, and deliberately strict: a malformed
// packet is dropped rather than guessed at, because a sinkhole that invents a name would
// put a false entry in the very log the assertion reads.
func parseQuestion(msg []byte) (name string, qEnd int, ok bool) {
	const header = 12
	if len(msg) < header {
		return "", 0, false
	}
	if qd := int(msg[4])<<8 | int(msg[5]); qd < 1 {
		return "", 0, false
	}
	var labels []string
	i := header
	for {
		if i >= len(msg) {
			return "", 0, false
		}
		l := int(msg[i])
		if l == 0 {
			i++
			break
		}
		// Compression pointers are illegal in a question; refuse rather than follow.
		if l&0xC0 != 0 {
			return "", 0, false
		}
		i++
		if i+l > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[i:i+l]))
		i += l
	}
	if i+4 > len(msg) { // QTYPE + QCLASS
		return "", 0, false
	}
	return strings.Join(labels, "."), i + 4, true
}

// buildReply echoes the question and appends one A record pointing at the sink.
func buildReply(req []byte, qEnd int, sink net.IP) ([]byte, bool) {
	if qEnd > len(req) {
		return nil, false
	}
	resp := make([]byte, 0, qEnd+16)
	resp = append(resp, req[:qEnd]...)

	resp[2], resp[3] = 0x81, 0x80 // QR=1, RD=1, RA=1, RCODE=0
	resp[6], resp[7] = 0x00, 0x01 // ANCOUNT=1
	resp[8], resp[9] = 0x00, 0x00 // NSCOUNT=0
	resp[10], resp[11] = 0x00, 0x00

	resp = append(resp,
		0xC0, 0x0C, // name: pointer to the question's QNAME at offset 12
		0x00, 0x01, // TYPE A
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x00, 0x1E, // TTL 30s
		0x00, 0x04, // RDLENGTH
	)
	return append(resp, sink...), true
}
