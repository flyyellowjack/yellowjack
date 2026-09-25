package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// SMTP delivery for alert emails (#32 Phase C / C4c), the shape D90 fixed: "the appliance
// standard SMTP host / port / credentials / from / to, defaulted sensibly".
//
// WE DO NOT HOST OR ROUTE THE MAIL (D52, zero egress). The message goes to the operator's
// own relay, from their network, under their credentials. Yellow Jack never sees it, and a
// deployment with no route to the internet still alerts perfectly — which is the entire
// point of an on-premise security appliance. Any design where alerts flow through a
// Yellow Jack-operated service would make our uptime a dependency of their incident
// response, and our logs a copy of their infrastructure inventory.
//
// Built on net/smtp, from the standard library. Every mail library on offer would pull a
// dependency tree into a security product's trust boundary to save perhaps thirty lines.

type smtpConfig struct {
	Host     string
	Port     int
	User     string
	Password string // never logged, never included in Describe()
	From     string
	To       []string
	Timeout  time.Duration
}

// loadSMTPConfig reads the mail settings, returning nil when alerting is not configured.
//
// Host AND To are both required to enable: a relay with nobody to mail, or recipients with
// no relay, is a misconfiguration rather than a partial feature, and quietly running in
// either state would give an operator a false sense of coverage.
func loadSMTPConfig() (*smtpConfig, error) {
	host := strings.TrimSpace(os.Getenv("APPROVAL_SMTP_HOST"))
	to := splitList(os.Getenv("APPROVAL_ALERT_TO"))
	if host == "" || len(to) == 0 {
		if host != "" || len(to) > 0 {
			// Exactly one of the two was set. Say so — this is precisely the operator
			// who believes alerting is on.
			return nil, fmt.Errorf("alert email is half-configured: APPROVAL_SMTP_HOST=%q and APPROVAL_ALERT_TO=%q — set both to enable email, or neither to disable it",
				host, os.Getenv("APPROVAL_ALERT_TO"))
		}
		return nil, nil
	}

	// 587 (submission with STARTTLS) rather than 25: 25 is server-to-server relay, widely
	// blocked outbound, and unauthenticated. 587 is what an appliance is expected to use
	// against a corporate relay, and it is what the operator's mail team will assume.
	port := 587
	if v := strings.TrimSpace(os.Getenv("APPROVAL_SMTP_PORT")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 65535 {
			return nil, fmt.Errorf("APPROVAL_SMTP_PORT=%q is not a valid port", v)
		}
		port = n
	}

	from := strings.TrimSpace(os.Getenv("APPROVAL_ALERT_FROM"))
	if from == "" {
		// A sender that names the sending host, so an operator with several deployments
		// can tell which one is shouting without opening the message.
		hostname, err := os.Hostname()
		if err != nil || hostname == "" {
			hostname = "yellowjack"
		}
		from = "yellowjack@" + hostname
	}

	cfg := &smtpConfig{
		Host:     host,
		Port:     port,
		User:     strings.TrimSpace(os.Getenv("APPROVAL_SMTP_USER")),
		Password: os.Getenv("APPROVAL_SMTP_PASSWORD"), // NOT trimmed: whitespace can be meaningful in a password
		From:     from,
		To:       to,
		Timeout:  getEnvDuration("APPROVAL_SMTP_TIMEOUT", 20*time.Second),
	}
	return cfg, nil
}

// splitList parses a comma-separated recipient list, dropping empties so a trailing comma
// is not read as an empty address the relay would reject.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type smtpSender struct{ cfg *smtpConfig }

// Describe deliberately reports the host, port, sender and recipients but NEVER the
// password — and not the username either, since a username is frequently the full address
// and pairs with the password in a leaked log.
func (s *smtpSender) Describe() string {
	auth := "no auth"
	if s.cfg.User != "" {
		auth = "authenticated"
	}
	return fmt.Sprintf("relay %s:%d (%s), from %s, to %d recipient(s)",
		s.cfg.Host, s.cfg.Port, auth, s.cfg.From, len(s.cfg.To))
}

func (s *smtpSender) Send(subject, body string) error {
	msg := buildMessage(s.cfg.From, s.cfg.To, subject, body, time.Now())
	return s.deliver(msg)
}

// deliver opens one SMTP conversation and sends the message.
//
// THE DEADLINE IS THE POINT OF WRITING THIS BY HAND. smtp.SendMail has no timeout, so a
// relay that accepts the TCP connection and then never speaks — a firewall silently
// dropping packets, a wedged mail server — blocks its caller indefinitely. Here that
// caller is the alert sweep, so the failure mode is: the mail server hangs, and Yellow
// Jack stops alerting entirely, silently, with no error anywhere. Dialing with a timeout
// and setting a deadline on the whole conversation turns that into a logged failure and a
// retry on the next sweep.
func (s *smtpSender) deliver(msg []byte) error {
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))

	conn, err := net.DialTimeout("tcp", addr, s.cfg.Timeout)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	// One deadline covering the ENTIRE conversation, not per-read: an adversarial or
	// broken relay can otherwise keep a connection alive forever by dribbling one byte
	// before each timeout expires.
	if err := conn.SetDeadline(time.Now().Add(s.cfg.Timeout)); err != nil {
		conn.Close()
		return fmt.Errorf("set deadline: %w", err)
	}

	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp handshake with %s: %w", addr, err)
	}
	defer c.Close()

	// Upgrade to TLS whenever the relay offers it. We do NOT skip certificate
	// verification and there is no option to: this is security software, and a flag that
	// turns off verification is one that ends up set in production. An internal relay
	// with a private CA is supported the correct way — mount that CA into the container's
	// trust store — which the error below names explicitly, because "x509: certificate
	// signed by unknown authority" out of an alerting subsystem is otherwise a puzzle.
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: s.cfg.Host}); err != nil {
			return fmt.Errorf("starttls with %s: %w (if your relay uses a private CA, add it to this container's trust store rather than disabling verification)", s.cfg.Host, err)
		}
	}

	if s.cfg.User != "" {
		// PlainAuth refuses to hand credentials to a server over an unencrypted
		// connection unless it is localhost. That is the standard library protecting the
		// operator from leaking a mail password onto the wire, so we surface it as
		// guidance rather than working around it.
		if err := c.Auth(smtp.PlainAuth("", s.cfg.User, s.cfg.Password, s.cfg.Host)); err != nil {
			return fmt.Errorf("smtp auth as %q: %w (credentials are only sent over TLS; check the relay advertises STARTTLS on port %d)", s.cfg.User, err, s.cfg.Port)
		}
	}

	if err := c.Mail(s.cfg.From); err != nil {
		return fmt.Errorf("MAIL FROM %q: %w", s.cfg.From, err)
	}
	for _, rcpt := range s.cfg.To {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("RCPT TO %q: %w", rcpt, err)
		}
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		wc.Close()
		return fmt.Errorf("write message: %w", err)
	}
	if err := wc.Close(); err != nil {
		// The relay's acceptance verdict arrives HERE, at the end-of-data dot — not at
		// Write. Ignoring this error would report a rejected message as delivered, which
		// for an alerting system means believing the operator was told when they were not.
		return fmt.Errorf("relay rejected the message: %w", err)
	}
	return c.Quit()
}

// buildMessage renders an RFC 5322 message.
//
// HEADER INJECTION IS A REAL RISK HERE, not a theoretical one. The subject is built from
// an alert Summary, which embeds the INSTANCE NAME — and that name is the firewall's
// self-reported hostname, arriving over the network at POST /v1/health from a client we do
// not fully control. A hostname containing CRLF would otherwise terminate the Subject
// header early and let the remainder be parsed as further headers or as the body: an extra
// Bcc, a forged From, a replaced message. So every value interpolated into a header is
// stripped of CR and LF first.
func buildMessage(from string, to []string, subject, body string, now time.Time) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", sanitizeHeader(from))
	fmt.Fprintf(&b, "To: %s\r\n", sanitizeHeader(strings.Join(to, ", ")))
	fmt.Fprintf(&b, "Subject: %s\r\n", sanitizeHeader(subject))
	fmt.Fprintf(&b, "Date: %s\r\n", now.UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	// Marks the message as automated so a recipient's mail system does not reply to it
	// with an out-of-office, and so filters can classify it.
	b.WriteString("Auto-Submitted: auto-generated\r\n")
	b.WriteString("\r\n") // the blank line that ends the headers
	b.WriteString(body)
	return []byte(b.String())
}

// sanitizeHeader removes the characters that could terminate a header line. Replaced with
// a space rather than dropped, so "fw-1\r\nBcc: x" reads as visibly odd in the delivered
// mail instead of silently becoming a plausible-looking name.
func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}
