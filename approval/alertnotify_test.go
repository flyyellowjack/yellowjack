package main

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// fakeSender records what would have been mailed, and can be told to fail.
type fakeSender struct {
	sent     []string // subjects, one entry per Send that succeeded
	bodies   []string
	failWith error
	calls    int
}

func (f *fakeSender) Send(subject, body string) error {
	f.calls++
	if f.failWith != nil {
		return f.failWith
	}
	f.sent = append(f.sent, subject)
	f.bodies = append(f.bodies, body)
	return nil
}

func (f *fakeSender) Describe() string { return "fake sender" }

// notifierFixture wires a notifier over a memStore with a movable clock.
type notifierFixture struct {
	store  *memStore
	sender *fakeSender
	n      *alertNotifier
	now    time.Time
}

func newNotifierFixture(t *testing.T) *notifierFixture {
	t.Helper()
	f := &notifierFixture{
		store:  newMemStore(),
		sender: &fakeSender{},
		now:    time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
	}
	f.n = &alertNotifier{
		store:  f.store,
		sender: f.sender,
		params: defaultAlertParams(),
		now:    func() time.Time { return f.now },
	}
	return f
}

// silent registers an instance whose last heartbeat is old enough to alert.
func (f *notifierFixture) silent(t *testing.T, instance string) {
	t.Helper()
	f.heartbeat(t, InstanceHealth{
		Instance:   instance,
		ReportedAt: f.now.Add(-2 * f.n.params.SilentAfter),
	})
}

func (f *notifierFixture) heartbeat(t *testing.T, h InstanceHealth) {
	t.Helper()
	if err := f.store.UpsertInstanceHealth(h); err != nil {
		t.Fatalf("upsert health: %v", err)
	}
}

func (f *notifierFixture) sweep(t *testing.T) {
	t.Helper()
	if err := f.n.sweepOnce(); err != nil {
		t.Fatalf("sweep: %v", err)
	}
}

// A newly-active alert is mailed.
func TestNotifyMailsNewAlert(t *testing.T) {
	f := newNotifierFixture(t)
	f.silent(t, "fw-1")

	f.sweep(t)

	if len(f.sender.sent) != 1 {
		t.Fatalf("sent %d emails, want 1: %v", len(f.sender.sent), f.sender.sent)
	}
	if !strings.Contains(f.sender.sent[0], "CRITICAL") {
		t.Errorf("subject %q should lead with the severity so it triages from a lock screen", f.sender.sent[0])
	}
	if !strings.Contains(f.sender.bodies[0], "fw-1") {
		t.Errorf("body must name the instance; got %q", f.sender.bodies[0])
	}
}

// A healthy deployment mails nothing at all.
func TestNotifyQuietWhenHealthy(t *testing.T) {
	f := newNotifierFixture(t)
	f.heartbeat(t, InstanceHealth{Instance: "fw-1", ReportedAt: f.now.Add(-30 * time.Second)})

	f.sweep(t)

	if f.sender.calls != 0 {
		t.Errorf("sender called %d times for a healthy stack, want 0", f.sender.calls)
	}
}

// THE CORE CONTRACT: a standing condition is mailed once, not once per sweep.
func TestNotifyDoesNotRepeat(t *testing.T) {
	f := newNotifierFixture(t)
	f.silent(t, "fw-1")

	for i := 0; i < 5; i++ {
		f.sweep(t)
		f.now = f.now.Add(time.Minute)
	}

	if len(f.sender.sent) != 1 {
		t.Fatalf("sent %d emails for one standing condition over 5 sweeps, want 1: %v",
			len(f.sender.sent), f.sender.sent)
	}
}

// NEGATIVE CONTROL for the fingerprint trap.
//
// The alert's Detail carries a LIVE COUNT ("5 audit events were discarded", then 6, then
// 7). If the dedup identity were derived from the rendered message rather than from
// (kind, instance), every increment would look like a brand-new alert and the operator
// would be mailed on a loop for as long as the condition persisted — the exact behaviour
// that gets an alert address filtered to trash, taking the real alerts with it.
//
// Sabotage check: change alertKey to include a.Detail and this test sends 3 emails.
func TestNotifyIgnoresChangingCounts(t *testing.T) {
	f := newNotifierFixture(t)
	fresh := f.now.Add(-time.Second)

	for _, dropped := range []int64{5, 6, 7} {
		f.heartbeat(t, InstanceHealth{Instance: "fw-1", ReportedAt: fresh, AuditDropped: dropped})
		f.sweep(t)
	}

	if len(f.sender.sent) != 1 {
		t.Fatalf("sent %d emails as the drop count climbed 5->6->7, want 1 — the count is the condition's reading, not its identity: %v",
			len(f.sender.sent), f.sender.sent)
	}
}

// A condition that clears and later recurs must be mailed AGAIN. Without this, an operator
// hears about the first ever occurrence of a problem and never about any repeat.
func TestNotifyReNotifiesAfterResolution(t *testing.T) {
	f := newNotifierFixture(t)
	f.silent(t, "fw-1")
	f.sweep(t)

	// The replica comes back: heartbeat is current, so the alert clears.
	f.now = f.now.Add(time.Minute)
	f.heartbeat(t, InstanceHealth{Instance: "fw-1", ReportedAt: f.now})
	f.sweep(t)
	if len(f.sender.sent) != 1 {
		t.Fatalf("recovery should not mail; sent %v", f.sender.sent)
	}

	// ...and dies again.
	f.now = f.now.Add(time.Hour)
	f.sweep(t)

	if len(f.sender.sent) != 2 {
		t.Fatalf("sent %d emails, want 2 — a recurrence must be notified, or the dedup row silently suppresses every repeat forever: %v",
			len(f.sender.sent), f.sender.sent)
	}
}

// NEGATIVE CONTROL for the permanently-missed alert.
//
// If a failed send still left the claim in place, the condition would be marked "already
// told them" while nobody was told, and it could never be mailed again — strictly worse
// than a duplicate. So a send failure must release the claim and the next sweep must
// deliver.
//
// Sabotage check: delete the release loop in sweepOnce and this test never sends.
func TestFailedSendIsRetried(t *testing.T) {
	f := newNotifierFixture(t)
	f.silent(t, "fw-1")

	f.sender.failWith = errors.New("relay unreachable")
	if err := f.n.sweepOnce(); err == nil {
		t.Fatal("sweep should report the send failure rather than swallowing it")
	}
	if len(f.sender.sent) != 0 {
		t.Fatalf("nothing was delivered, but %v was recorded as sent", f.sender.sent)
	}

	// The relay comes back.
	f.sender.failWith = nil
	f.now = f.now.Add(time.Minute)
	f.sweep(t)

	if len(f.sender.sent) != 1 {
		t.Fatalf("sent %d emails after the relay recovered, want 1 — a failed send must not mark the condition notified: %v",
			len(f.sender.sent), f.sender.sent)
	}
}

// Correlated failures arrive as ONE email, not one per replica. A control-plane outage
// silences every instance at once; twelve separate emails for one event is how an alert
// address gets muted.
func TestNotifyBatchesIntoOneEmail(t *testing.T) {
	f := newNotifierFixture(t)
	f.silent(t, "fw-1")
	f.silent(t, "fw-2")
	f.silent(t, "fw-3")

	f.sweep(t)

	if f.sender.calls != 1 {
		t.Fatalf("sender called %d times for 3 simultaneous alerts, want 1", f.sender.calls)
	}
	if !strings.Contains(f.sender.sent[0], "3 new alerts") {
		t.Errorf("subject %q should say how many, so the scale is visible before opening it", f.sender.sent[0])
	}
	for _, inst := range []string{"fw-1", "fw-2", "fw-3"} {
		if !strings.Contains(f.sender.bodies[0], inst) {
			t.Errorf("batched body dropped %s — every alert must survive the merge:\n%s", inst, f.sender.bodies[0])
		}
	}
}

// failingHealth makes the HEALTH read fail on demand. That is the read this test must
// break — it is the one that produces the active set, so swallowing its error is what
// yields an empty set and triggers the wipe.
type failingHealth struct {
	Store
	fail bool
}

func (s *failingHealth) ListInstanceHealth() ([]InstanceHealth, error) {
	if s.fail {
		return nil, errors.New("database down")
	}
	return s.Store.ListInstanceHealth()
}

// NEGATIVE CONTROL for "a failed read looks like a clean bill of health".
//
// ForgetResolvedAlerts clears every claim not in the active set, and an empty active set
// legitimately clears the table. So if a storage error could reach that call with an empty
// list, a transient database blip would wipe the dedup state and re-mail every standing
// condition on the following sweep — an alert storm caused purely by our own recovery.
// The guard is that both reads return EARLY on error.
//
// Sabotage check: make the ListInstanceHealth error log-and-continue instead of returning
// (health, _ := ...) and this test re-sends — the failed read is read as "no instances are
// in trouble", the claim is forgotten, and the recovery sweep mails the whole backlog.
func TestSweepErrorDoesNotForgetClaims(t *testing.T) {
	f := newNotifierFixture(t)
	f.silent(t, "fw-1")
	f.sweep(t)
	if len(f.sender.sent) != 1 {
		t.Fatalf("setup: want 1 email, got %v", f.sender.sent)
	}

	// The database goes away for a sweep.
	failing := &failingHealth{Store: f.store, fail: true}
	f.n.store = failing
	if err := f.n.sweepOnce(); err == nil {
		t.Error("a failed storage read should also surface as an error, not a silent no-op sweep")
	}

	// ...and comes back. The condition never changed, so nothing new should be mailed.
	failing.fail = false
	f.now = f.now.Add(time.Minute)
	f.sweep(t)

	if len(f.sender.sent) != 1 {
		t.Fatalf("sent %d emails, want 1 — a storage blip must not be mistaken for 'everything resolved' and re-mail the backlog: %v",
			len(f.sender.sent), f.sender.sent)
	}
}

// The notifier must use the same BOUNDED window as the read endpoint. Evaluated against
// lifetime totals, one truncated download three months ago would mail on the first sweep
// after every restart, forever.
func TestNotifySweepQueriesBoundedWindow(t *testing.T) {
	spy := &windowSpy{Store: newMemStore()}
	n := &alertNotifier{store: spy, sender: &fakeSender{}, params: defaultAlertParams()}

	if err := n.sweepOnce(); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if spy.got.From.IsZero() {
		t.Fatal("sweep asked for a summary with no From — that is a LIFETIME count, so one old truncation would mail forever")
	}
}

// REGRESSION: the dedup key must be storable in a Postgres TEXT column.
//
// This was a REAL BUG, and the way it hid is the point. alertKey originally joined its
// parts with "\x00" — the conventional unambiguous delimiter. A Go map accepts that key
// without complaint, so every unit test above passed against memStore. Postgres refuses it
// outright (`invalid byte sequence for encoding "UTF8": 0x00`), so in the only deployment
// that matters every claim failed, and therefore NO ALERT EMAIL WAS EVER SENT — while the
// service logged normally and the console kept displaying the alert. It took a live e2e
// leg to surface it.
//
// The lesson is not "remember not to use NUL"; it is that a key crossing into a database
// has a validity constraint the in-memory store does not enforce. So this test enforces
// it, and it must run over the REAL alerts rather than a hand-written string, so a new
// alert kind (or a new key component) is covered the day it is added.
func TestAlertKeyIsStorable(t *testing.T) {
	now := alertNow()
	// Every kind at once, plus an instance name full of things a hostname should not
	// contain but a client could still send.
	alerts := evaluateAlerts(now, []InstanceHealth{
		{Instance: "fw-1", ReportedAt: now.Add(-24 * time.Hour), AuditDropped: 1, FlowDropped: 1},
		{Instance: "wéird nàme|with pipes", ReportedAt: now.Add(-24 * time.Hour)},
	}, FlowSummary{Truncated: 1}, defaultAlertParams())
	if len(alerts) < 4 {
		t.Fatalf("setup produced only %v; this test is meant to cover every alert kind", kinds(alerts))
	}

	seen := make(map[string]string)
	for _, a := range alerts {
		k := alertKey(a)
		if strings.ContainsRune(k, 0) {
			t.Errorf("alertKey(%s/%s) contains a NUL byte; Postgres TEXT cannot store it and every claim will fail silently", a.Kind, a.Instance)
		}
		if !utf8.ValidString(k) {
			t.Errorf("alertKey(%s/%s) is not valid UTF-8: %q", a.Kind, a.Instance, k)
		}
		// Distinctness matters as much as storability: two conditions sharing a key would
		// mean the second is silently suppressed as "already notified".
		if prev, dup := seen[k]; dup {
			t.Errorf("alertKey collision between %q and %q (both %q) — one would never be notified",
				prev, a.Kind+"/"+a.Instance, k)
		}
		seen[k] = a.Kind + "/" + a.Instance
	}
}

// --- message construction ------------------------------------------------------------

// HEADER INJECTION. The subject embeds the instance name, which is the firewall's
// self-reported hostname arriving over the network at POST /v1/health. A name containing
// CRLF would otherwise end the Subject header early and let the rest be parsed as more
// headers — an added Bcc, a forged From, a replaced body.
func TestBuildMessageStripsHeaderInjection(t *testing.T) {
	msg := string(buildMessage("fw@example.com", []string{"ops@example.com"},
		"alert on fw-1\r\nBcc: attacker@evil.example\r\nX-Injected: yes",
		"body text\r\n", time.Now()))

	headers, body, ok := strings.Cut(msg, "\r\n\r\n")
	if !ok {
		t.Fatalf("message has no header/body separator:\n%q", msg)
	}
	// The property is per-LINE, not per-substring: after flattening, the text "Bcc:" is
	// still present but as part of the Subject's VALUE, which is inert. A substring check
	// cannot tell that apart from a real injected header — and would fail on the correct
	// implementation, which is how this assertion was first written and caught.
	for _, line := range strings.Split(headers, "\r\n") {
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			t.Errorf("header line is not a header at all — a raw newline reached the message: %q", line)
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "bcc", "x-injected":
			t.Errorf("CRLF in the subject became a real %q header:\n%q", name, headers)
		}
	}
	// The text must still be VISIBLE (flattened, not dropped) so an operator sees
	// something obviously wrong rather than a plausible-looking name.
	if !strings.Contains(headers, "attacker@evil.example") {
		t.Errorf("injected text was silently dropped; flattening it into the subject is what makes tampering visible:\n%q", headers)
	}
	if !strings.Contains(body, "body text") {
		t.Errorf("body lost: %q", body)
	}
}

func TestBuildMessageHasRequiredHeaders(t *testing.T) {
	msg := string(buildMessage("fw@example.com", []string{"a@example.com", "b@example.com"},
		"subject", "body", time.Now()))
	for _, want := range []string{"From: fw@example.com", "To: a@example.com, b@example.com",
		"Subject: subject", "Date: ", "Auto-Submitted: auto-generated"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
}

// --- configuration ---------------------------------------------------------------------

// Unset is disabled, and disabled is not an error.
func TestSMTPConfigDisabledByDefault(t *testing.T) {
	cfg, err := loadSMTPConfig()
	if err != nil {
		t.Fatalf("unconfigured mail must not be an error: %v", err)
	}
	if cfg != nil {
		t.Errorf("got a config with no env set: %+v", cfg)
	}
}

// HALF-configured must FAIL LOUDLY. This is the operator who set the relay and forgot the
// recipients (or vice versa) and now believes alerting is on. Silently disabling is the
// one outcome that leaves them wrong about their coverage until an incident.
func TestSMTPConfigHalfConfiguredIsAnError(t *testing.T) {
	t.Setenv("APPROVAL_SMTP_HOST", "smtp.example.com")
	if _, err := loadSMTPConfig(); err == nil {
		t.Fatal("a relay with no recipients must be an error, not a silent no-op")
	}

	t.Setenv("APPROVAL_SMTP_HOST", "")
	t.Setenv("APPROVAL_ALERT_TO", "ops@example.com")
	if _, err := loadSMTPConfig(); err == nil {
		t.Fatal("recipients with no relay must be an error, not a silent no-op")
	}
}

func TestSMTPConfigDefaults(t *testing.T) {
	t.Setenv("APPROVAL_SMTP_HOST", "smtp.example.com")
	t.Setenv("APPROVAL_ALERT_TO", " ops@example.com , security@example.com , ")

	cfg, err := loadSMTPConfig()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Port != 587 {
		t.Errorf("default port = %d, want 587 (submission+STARTTLS, not the widely-blocked relay port 25)", cfg.Port)
	}
	if len(cfg.To) != 2 {
		t.Errorf("recipients = %v, want 2 — whitespace and the trailing comma must not become empty addresses", cfg.To)
	}
	if cfg.From == "" {
		t.Error("From must default to something the relay can accept")
	}
}

// A credential must never reach a log line.
func TestSMTPDescribeOmitsCredentials(t *testing.T) {
	s := &smtpSender{cfg: &smtpConfig{
		Host: "smtp.example.com", Port: 587,
		User: "alerts@example.com", Password: "hunter2-super-secret",
		From: "fw@example.com", To: []string{"ops@example.com"},
	}}
	d := s.Describe()
	if strings.Contains(d, "hunter2") {
		t.Errorf("Describe leaked the password: %q", d)
	}
	if strings.Contains(d, "alerts@example.com") {
		t.Errorf("Describe leaked the username, which is usually half a credential pair: %q", d)
	}
	if !strings.Contains(d, "smtp.example.com") {
		t.Errorf("Describe must still identify the relay so a startup log is useful: %q", d)
	}
}
