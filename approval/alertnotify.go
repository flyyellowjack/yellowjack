package main

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// Email notification for the default alerts (#32 Phase C / C4c), per D90: "we should ship
// it with an email service, because that is easy to do, and the simplest case for alerting
// that can easily be integrated with slack and other things."
//
// The whole increment exists to answer ONE question that the read-time evaluation in
// alerts.go cannot: "have we already told the operator about this?" Everything else about
// alerting stays derived — the console still computes the live list on read, so what is
// displayed can never freeze at whatever a background sweep last managed to write. This
// file adds the minimum state needed to avoid re-sending, and nothing else.
//
// It calls evaluateAlerts — the SAME function the read endpoint calls — deliberately. A
// second implementation of "what counts as an alert" for the email path would drift from
// the one the console shows, and an operator whose inbox and dashboard disagree trusts
// neither.

// alertKey is the identity used for "have we emailed about this?".
//
// IT IS DELIBERATELY (kind, instance) AND NOT THE ALERT'S TEXT. The Detail carries a live
// count — "5 audit events were discarded", then 6, then 7 — so fingerprinting the rendered
// message would make every increment a brand-new alert and mail the operator on a loop
// while the condition persists. That is the exact failure mode that gets an alert address
// filtered to trash, taking the real alerts with it. The pair (kind, instance) is the
// condition's identity; the numbers are just its current reading.
// THE SEPARATOR MUST BE STORABLE IN POSTGRES, which rules out the obvious choice. This was
// written with "\x00" first — the conventional unambiguous delimiter, and one a Go map
// accepts without complaint, so the entire unit suite passed against memStore. Postgres
// then rejected every write with `invalid byte sequence for encoding "UTF8": 0x00`,
// because a TEXT column cannot hold a NUL. The result was invisible in the worst possible
// way: alerts were still evaluated and still displayed, every claim silently failed, and
// NO EMAIL WAS EVER SENT. Only the e2e leg against a real database caught it. See
// TestAlertKeyIsStorable, which now fails on any byte Postgres would refuse.
//
// "|" is unambiguous here because Kind is drawn from our own fixed constant set and never
// contains one, so the FIRST separator always delimits — whatever the client-supplied
// instance name happens to contain.
func alertKey(a Alert) string {
	return a.Kind + "|" + a.Instance
}

// mailSender is the one thing C4c needs from the outside world. An interface (rather than
// calling net/smtp directly) so the notifier's logic — dedup, claim, release, resolve — is
// testable exhaustively without a mail server, and so a future transport (D90's "easily
// integrated with slack and other things") is a new implementation rather than a rewrite.
type mailSender interface {
	// Send delivers one notification. It must block until the message is accepted or
	// has failed, because the caller's claim/release correctness depends on knowing
	// which happened.
	Send(subject, body string) error
	// Describe is a human, CREDENTIAL-FREE summary for the startup log.
	Describe() string
}

// alertNotifier sweeps for newly-active alerts and mails them once.
type alertNotifier struct {
	store  Store
	sender mailSender
	params alertParams
	every  time.Duration

	// now is injectable so the tests can drive staleness without sleeping. Production
	// leaves it nil and gets time.Now().UTC().
	now func() time.Time
}

func (n *alertNotifier) clock() time.Time {
	if n.now != nil {
		return n.now()
	}
	return time.Now().UTC()
}

// startAlertNotifier begins the sweep loop, or explains at startup why it is not running.
//
// Disabled is the DEFAULT, and it says so loudly. An operator who set some of the SMTP
// variables but not enough of them would otherwise get a silent no-op — believing they are
// covered right up until the incident where they were not. Silence about alerting is the
// one thing an alerting feature must never do.
func startAlertNotifier(store Store, sender mailSender, every time.Duration) {
	if sender == nil {
		log.Printf("alert email: DISABLED (set APPROVAL_SMTP_HOST and APPROVAL_ALERT_TO to enable). " +
			"Alerts are still computed and served at GET /v1/alerts.")
		return
	}
	if every <= 0 {
		every = time.Minute
	}
	n := &alertNotifier{store: store, sender: sender, params: defaultAlertParams(), every: every}
	log.Printf("alert email: enabled, %s, checking every %s", sender.Describe(), every)
	go func() {
		for {
			if err := n.sweepOnce(); err != nil {
				// Log and keep sweeping. A failed sweep is a reason to retry, never a
				// reason to take the control plane down or to stop alerting forever.
				log.Printf("alert email sweep: %v", err)
			}
			time.Sleep(every)
		}
	}()
}

// sweepOnce evaluates the current alerts and mails the ones not already notified.
//
// The ordering here is load-bearing:
//
//  1. evaluate (read-only);
//  2. CLAIM each active alert — an atomic insert that succeeds for exactly one caller;
//  3. forget the claims for alerts that are no longer active, so a recurrence re-notifies;
//  4. send ONE email covering everything newly claimed;
//  5. on send failure, RELEASE the claims so the next sweep tries again.
//
// Claim-before-send (rather than send-then-record) is the deliberate choice. The likely
// failure is the mail server being unreachable or misconfigured, which claim-first handles
// exactly: nothing is recorded as notified, and the next sweep retries. It trades that for
// a much rarer window — a crash between the claim and the send would lose one notification
// — and even then the alert stays visible at GET /v1/alerts and in the console. The
// alternative loses the dedup guarantee across replicas, which is the whole point.
func (n *alertNotifier) sweepOnce() error {
	now := n.clock()

	health, err := n.store.ListInstanceHealth()
	if err != nil {
		return fmt.Errorf("list instance health: %w", err)
	}
	// The bounded window, for the same reason the read endpoint uses one: evaluated
	// against lifetime totals, one truncated download would mail forever.
	window, err := n.store.FlowSummary(FlowFilter{From: now.Add(-n.params.Window), To: now})
	if err != nil {
		return fmt.Errorf("flow summary: %w", err)
	}
	active := evaluateAlerts(now, health, window, n.params)

	keys := make([]string, 0, len(active))
	var fresh []Alert
	for _, a := range active {
		k := alertKey(a)
		keys = append(keys, k)
		claimed, err := n.store.ClaimAlertNotification(k, now)
		if err != nil {
			// Skip this one alert rather than abandoning the sweep: a storage hiccup on
			// one condition must not suppress notification of the others.
			log.Printf("alert email: claim %q: %v", a.Kind, err)
			continue
		}
		if claimed {
			fresh = append(fresh, a)
		}
	}

	// Drop the claims for conditions that have cleared. This is what makes an alert
	// re-notifiable: the operator hears about a recurrence, not just the first ever
	// occurrence. Safe to run with an empty active set — reaching here means evaluation
	// SUCCEEDED and genuinely found nothing, since both read errors return above. If a
	// storage error could reach this line with an empty list, it would silently wipe the
	// dedup state and mail everything again on the next sweep.
	if _, err := n.store.ForgetResolvedAlerts(keys); err != nil {
		log.Printf("alert email: forget resolved: %v", err)
	}

	if len(fresh) == 0 {
		return nil
	}

	subject, body := composeAlertMail(fresh, now)
	if err := n.sender.Send(subject, body); err != nil {
		// The send failed, so nobody was told. Releasing every claim we just took is what
		// stops this becoming a PERMANENTLY missed alert: without it the rows would say
		// "already notified" and the condition would never be mailed again, which is
		// strictly worse than a duplicate email.
		for _, a := range fresh {
			if rerr := n.store.ReleaseAlertNotification(alertKey(a)); rerr != nil {
				log.Printf("alert email: release %q after failed send: %v", a.Kind, rerr)
			}
		}
		return fmt.Errorf("send %d alert(s): %w", len(fresh), err)
	}
	log.Printf("alert email: notified %d new alert(s)", len(fresh))
	return nil
}

// composeAlertMail renders ONE message covering every newly-active alert.
//
// One email per sweep, not one per alert: the interesting failures are correlated — a
// control-plane outage silences twelve replicas at once — and twelve separate emails for
// one event is how an alert address gets muted. The subject leads with the count and the
// worst severity so it is triageable from a phone lock screen without opening anything.
func composeAlertMail(alerts []Alert, now time.Time) (subject, body string) {
	worst := SeverityWarning
	for _, a := range alerts {
		if a.Severity == SeverityCritical {
			worst = SeverityCritical
			break
		}
	}

	if len(alerts) == 1 {
		subject = fmt.Sprintf("[Yellow Jack] %s: %s", strings.ToUpper(string(worst)), alerts[0].Summary)
	} else {
		subject = fmt.Sprintf("[Yellow Jack] %s: %d new alerts", strings.ToUpper(string(worst)), len(alerts))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Yellow Jack raised %d new alert(s) at %s.\r\n",
		len(alerts), now.UTC().Format(time.RFC1123Z))
	for _, a := range alerts {
		b.WriteString("\r\n")
		fmt.Fprintf(&b, "[%s] %s\r\n", strings.ToUpper(string(a.Severity)), a.Summary)
		if a.Instance != "" {
			fmt.Fprintf(&b, "Instance: %s\r\n", a.Instance)
		}
		// The Detail text is the same wording the console shows, on purpose: an operator
		// who reads the email and then opens the dashboard must not have to reconcile two
		// different descriptions of one condition.
		fmt.Fprintf(&b, "%s\r\n", a.Detail)
	}
	b.WriteString("\r\nThis condition will not be emailed again until it clears and recurs.\r\n" +
		"The live list is at GET /v1/alerts on the Yellow Jack approval service.\r\n")
	return subject, b.String()
}

// --- the in-memory dedup store -------------------------------------------------------
//
// Note this one is genuinely lossy across a restart, and that is a real (if minor)
// difference from Postgres: an approval service restarted in a crash loop would re-mail
// every standing alert on each boot. That is one more reason APPROVAL_DATABASE_URL is the
// supported production configuration — the memStore is a dev convenience.

// ClaimAlertNotification takes the claim under the write lock. The check and the write are
// one critical section on purpose: splitting them would let two concurrent sweeps both
// observe "not yet notified" and both send.
func (s *memStore) ClaimAlertNotification(key string, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.alertNotified == nil {
		s.alertNotified = make(map[string]time.Time)
	}
	if _, exists := s.alertNotified[key]; exists {
		return false, nil
	}
	s.alertNotified[key] = at
	return true, nil
}

func (s *memStore) ReleaseAlertNotification(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.alertNotified, key)
	return nil
}

// ForgetResolvedAlerts drops the claims for conditions that are no longer active.
func (s *memStore) ForgetResolvedAlerts(active []string) (int64, error) {
	keep := make(map[string]struct{}, len(active))
	for _, k := range active {
		keep[k] = struct{}{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for k := range s.alertNotified {
		if _, ok := keep[k]; !ok {
			delete(s.alertNotified, k)
			n++
		}
	}
	return n, nil
}
