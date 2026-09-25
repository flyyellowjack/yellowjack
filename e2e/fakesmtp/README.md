# fakesmtp — the SMTP sink for the alert-email e2e leg

A ~150-line stdlib SMTP server that accepts mail and exposes what it received over HTTP,
so `e2e/async_local.sh` leg 12 can assert that a real alert email actually left the
approval service.

## Why this exists

The approval service's alert **logic** is unit-tested exhaustively against a fake
`mailSender` — dedup, claim/release, batching, resolution. That fake is the right tool for
those tests, but it means the code that speaks SMTP (`approval/mail.go`'s `deliver`) is
executed by **no unit test at all**. Dial, EHLO, `MAIL FROM`, `RCPT TO`, `DATA`, the
end-of-data dot, the connection deadline, the `wc.Close()` that carries the relay's real
acceptance verdict — a mistake in any of them ships green.

This is the same reasoning that gave legs 9 and 10 their existence: the Postgres SQL runs
nowhere but production, so a live leg is the only thing standing between a mistyped column
and a silent failure. Here, the SMTP conversation is that code.

## Why not a mail-catcher image

MailHog and Mailpit both do this job well. Using one would put a third-party container in
the test path of a **security product** to save roughly 120 lines of standard library, and
it would still not be the thing under test — the thing under test is our client. Same rule
as `e2e/fakescanner`: the fixture is stdlib-only and lives in its own throwaway module, so
it can never contribute a dependency to a shipped binary.

## What it is NOT

- **Not a mail server.** No queueing, no delivery, no retries, no spooling.
- **Not a TLS test.** It advertises *no* ESMTP extensions, so `net/smtp` stays on the
  plain path. That is deliberate — a single-line `250` is what keeps the client from
  attempting STARTTLS against a server with no certificate. **The consequence is that the
  STARTTLS upgrade and SMTP AUTH in `deliver` are still not covered end-to-end.** Covering
  them needs a relay with a real certificate, which is a separate exercise; until then they
  are unit-reasoned and manually verifiable only. Do not read a green leg 12 as "TLS mail
  delivery works".
- **Not authenticated.** It accepts any sender and recipient.

## Interface

| Port | Protocol | Purpose |
|---|---|---|
| 1025 | SMTP | accepts mail (ports >1024 so the nonroot user can bind them) |
| 1080 | HTTP | `GET /messages` → `{"count":N,"messages":["<raw message>", ...]}` |

## Negative control

Leg 12 must be able to fail. Prove it by breaking the delivery path and re-running:

```sh
# In docker-compose.e2e.yml, point the approval service at a relay that is not there:
#   APPROVAL_SMTP_HOST: "nonexistent-relay"
# Leg 12 must then FAIL with "no alert email arrived".
```

A leg that cannot fail is worse than no leg — it converts an unknown into false confidence.
