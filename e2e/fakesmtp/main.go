// fakesmtp is a throwaway SMTP sink for the alert-email e2e leg (#32 Phase C / C4c).
//
// It exists because the approval service's SMTP conversation — dial, EHLO, MAIL/RCPT,
// DATA, the end-of-data dot, the deadline — is reachable by NO unit test. The unit tests
// substitute a fake mailSender, which is the right call for testing dedup logic but means
// the actual wire protocol runs nowhere until something speaks SMTP back. A mistyped verb,
// an unflushed writer, or a missing terminator would ship green without this.
//
// Stdlib only, its own throwaway module, deliberately NOT part of the main module's
// dependency graph — same rule as e2e/fakescanner. Using a third-party mail-catcher image
// would put an unaudited container in the test path of a security product to save ~120
// lines, and would still not be the thing under test.
//
// Two listeners:
//
//	:1025  SMTP  — accepts mail and remembers it
//	:1080  HTTP  — GET /messages returns what it received, so a shell rig can assert
//
// It is NOT a real mail server: no TLS, no AUTH, no queueing, no delivery. It deliberately
// advertises NO ESMTP extensions, which keeps the client on the plain path (see below).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
)

type sink struct {
	mu   sync.Mutex
	msgs []string
}

func (s *sink) add(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.msgs = append(s.msgs, msg)
	log.Printf("accepted message (%d bytes), %d total", len(msg), len(s.msgs))
}

func (s *sink) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.msgs))
	copy(out, s.msgs)
	return out
}

func main() {
	s := &sink{}

	go func() {
		http.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
			msgs := s.snapshot()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"count":    len(msgs),
				"messages": msgs,
			})
		})
		log.Printf("fakesmtp: HTTP inspection on :1080/messages")
		log.Fatal(http.ListenAndServe(":1080", nil))
	}()

	ln, err := net.Listen("tcp", ":1025")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("fakesmtp: SMTP on :1025")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go s.serve(conn)
	}
}

// serve handles one SMTP conversation, implementing only the verbs a client needs to
// deliver a message.
func (s *sink) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	reply := func(format string, args ...any) bool {
		fmt.Fprintf(w, format+"\r\n", args...)
		return w.Flush() == nil
	}

	if !reply("220 fakesmtp ready") {
		return
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))

		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			// A SINGLE-LINE 250 with no extension lines, on purpose. net/smtp only
			// attempts STARTTLS/AUTH for extensions the server advertises, so
			// advertising none keeps this sink on the plain path it can actually
			// serve. Note what that means for the rig: this leg proves the SMTP
			// CONVERSATION and the alert wiring, NOT the TLS upgrade — that needs a
			// relay with a certificate and is a separate exercise.
			if !reply("250 fakesmtp") {
				return
			}
		case strings.HasPrefix(cmd, "MAIL FROM"), strings.HasPrefix(cmd, "RCPT TO"):
			if !reply("250 ok") {
				return
			}
		case strings.HasPrefix(cmd, "DATA"):
			if !reply("354 end data with <CR><LF>.<CR><LF>") {
				return
			}
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(l, "\r\n") == "." {
					break
				}
				// Undo dot-stuffing so the stored message matches what was sent.
				if strings.HasPrefix(l, "..") {
					l = l[1:]
				}
				b.WriteString(l)
			}
			s.add(b.String())
			// The acceptance verdict belongs HERE, at the end-of-data dot. A client
			// that ignores this reply reports rejected mail as delivered.
			if !reply("250 accepted") {
				return
			}
		case strings.HasPrefix(cmd, "RSET"), strings.HasPrefix(cmd, "NOOP"):
			if !reply("250 ok") {
				return
			}
		case strings.HasPrefix(cmd, "QUIT"):
			reply("221 bye")
			return
		default:
			// Includes STARTTLS and AUTH: refused explicitly rather than ignored, so a
			// client that tries anyway fails loudly instead of hanging.
			if !reply("502 command not implemented") {
				return
			}
		}
	}
}
