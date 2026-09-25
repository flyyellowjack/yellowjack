# Quickstart — see it refuse something in about a minute

The point of this page is one thing: **watch a package get refused, and read the reason.**
No account, no database, no network calls to us, no scanner. Two terminals.

If you want the full configuration reference instead, go to
**[docs/CONFIGURATION.md](docs/CONFIGURATION.md)**; for building, testing and the container
stack, **[docs/SETUP.md](docs/SETUP.md)**.

## 1. Build

```bash
go build -o yellowjack .
```

## 2. Decide what you will not allow

Yellow Jack reads an operator deny list: one package name per line, `#` for comments.

```bash
printf 'left-pad\n' > deny.txt
```

## 3. Run it

```bash
FW_ECOSYSTEM=npm \
FW_SCORECARD_MODE=stub \
FW_DENY_LIST="$PWD/deny.txt" \
./yellowjack
```

`FW_SCORECARD_MODE=stub` keeps this first run offline-ish and instant — no deps.dev calls, no
scanner container. `FW_DENY_LIST` **must be an absolute path**: a relative one would be resolved
against whatever directory the process happened to start in, which is how a neighbouring project's
CVE-2025-64726 happened, so we refuse to guess.

It prints what it is enforcing before it serves anything:

```
operator deny-list "/…/deny.txt": 1 package(s) blocked outright [npm], re-read every 5s
Yellow Jack starting on :8080
  ecosystem:         npm
  upstream:          https://registry.npmjs.org
  score threshold:   5.0
```

## 4. Watch it refuse

In a second terminal:

```bash
curl -i localhost:8080/left-pad
```

```
HTTP/1.1 403 Forbidden
X-Yellowjack-Kind: operator-denied
```

```json
{"error":"blocked by firewall: package \"left-pad\" is on this organisation's deny list;
 refused without contacting upstream. This is a local policy decision, not a published
 malware advisory -- ask whoever maintains the firewall's deny list."}
```

Three things worth noticing, because they are the product:

- **It never contacted the registry.** The refusal costs one local lookup.
- **The reason says who decided.** A developer can tell "our organisation blocked this" from
  "this is publicly reported malware" — they go to different people.
- **`X-Yellowjack-Kind` is machine-readable**, so your tooling can branch on the kind of refusal
  without parsing prose.

## 5. Confirm it is not just refusing everything

```bash
curl -o /dev/null -w '%{http_code}\n' localhost:8080/is-number
```

```
200
```

That one went upstream and came back. **A gate that blocks everything is not a gate**, so this
step is the one that makes step 4 mean anything.

## 6. Change your mind, without a restart

With the firewall still running:

```bash
printf 'is-number\n' >> deny.txt
sleep 6
curl -o /dev/null -w '%{http_code}\n' localhost:8080/is-number
```

```
403
```

The list is re-read every five seconds, so unblocking a developer feels immediate. Emptying the
file restores service the same way.

## Point a real client at it

```bash
npm config set registry http://localhost:8080
```

Now `npm install` is gated. Use `FW_ECOSYSTEM` to switch: **`npm`, `pypi`, `oci`, `maven`**.

## What you have not turned on yet

This run used one signal — your own deny list — because it needs nothing else. The rest is off by
default and documented in **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)**:

| you might want | the setting |
|---|---|
| refuse packages in public malware advisories | `FW_MALWARE_LIST` |
| refuse releases younger than N days | `FW_MIN_RELEASE_AGE_DAYS` |
| always allow your own internal packages | `FW_ALLOW_LIST` |
| real OpenSSF Scorecard scoring | `FW_SCORECARD_MODE=api` or `local` |
| watch decisions without enforcing any | `FW_MODE=report` |

**`FW_MODE=report` is the honest way to try this in front of a real build system**: every verdict
is computed and logged, nothing is ever blocked.

> **Dependency confusion:** if you publish internal packages, put their names in `FW_DENY_LIST` so
> a public package claiming one of those names is refused. We cannot detect that for you from
> public data — a private name is absent from every public index by construction — but you know
> your namespace, and this is where you say so.
