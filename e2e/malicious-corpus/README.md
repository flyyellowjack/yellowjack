# Malicious-package corpus (synthetic) — issue #31

A committed set of **synthetic** package fixtures, each encoding one *attack shape* observed in the
a threat study. Used as a **detection floor**: a scanner or gate we adopt must fire on
these, and must NOT fire on the clean control.

## Why these are synthetic, and why that is not a compromise

**1. Real malware cannot be relied on, because the registry deletes it.** Measured 2026-08-04
(**D118**): scanning `flatmap-stream` — the 2018 event-stream payload — returns *"No risks found"*,
not because a scanner missed it but because **npm unpublished the package**; only the
`0.0.1-security` placeholder remains. A corpus that fetches live samples silently decays into a
corpus of empty stubs **that still reports green**. That is the exact false-confidence failure the
"codify, don't re-derive" convention exists to prevent.

**2. Committing live malware is a known own-goal in this category.** GuardDog itself
([#766](https://github.com/DataDog/guarddog/issues/766)) shipped live malware inside its own release
tarball for ~2 years. See also P0 #15 (fixture hygiene).

So every fixture here is **inert**: no network egress, no filesystem destruction, no real payload,
no obfuscated secret. They reproduce the *static shape* an attack presents, which is what a
static analyser keys on — nothing more.

> ⚠️ These directories are deliberately shaped to look suspicious to a scanner. That is the point.
> They are safe to read and safe to scan. **They are not safe to `npm install`** — not because they
> are harmful, but because the install hooks are meant to be observed, not run.

## The shapes, and why each one is here

| Fixture | Shape | Traced to |
|---|---|---|
| `clean-control` | Ordinary package, nothing suspicious | **Negative control** — must score 0. If this ever fires, the corpus is measuring noise. |
| `install-hook-exfil` | Lifecycle hook runs code at install | The axios/`plain-crypto-js` chain: `postinstall` on a brand-new transitive dep |
| `no-hook-calltime` | **No lifecycle hook at all**; triggers when the module is *called* | The Lazarus `react-html2pdf.js` case — *"Most malware will have a preinstall, install, postinstall… we didn't see that"*. **Hook presence is not a reliable signal; this fixture is why.** |
| `self-erasing` | Setup deletes itself and rewrites its own manifest | The axios payload's `fs.unlink(__filename)` + clean `package.json` overwrite. **Everything that inspects an *installed tree* reads a cleaned crime scene — a pull-boundary gate sees the bytes first.** This is a YJ differentiator, so it needs a test. |
| `mcp-handshake` | MCP-server-shaped package that acts on protocol handshake | **D117.** Morphisec's malicious "compliance SDK" fired on `tools/list` **before any prompt existed**; Shai-Hulud 2.0 hunted `mcp-server` names. A prompt-level guardrail is structurally too late here. |

## Running it

```sh
sh e2e/malicious-corpus/scan_corpus.sh            # uses GuardDog via container
```

The runner asserts each fixture against `manifest.json` and **exits non-zero on mismatch** — both a
missed detection *and* a clean-control false positive are failures.

## What this corpus does NOT claim

It is a **floor, not a benchmark**. Passing means "detects the shapes we already know about." It says
nothing about novel-attack recall, and it is not a parity measurement against any vendor — per the
standing rule, parity is measurable only **prospectively**: public corpora overlap heavily with what
every scanner was tuned on.

## The layout trap (cost an hour; do not re-derive)

**A fixture laid out as a bare directory silently scores CLEAN, even when it obviously should not.**

GuardDog resolves a package's manifest at `package/package.json` — the layout npm itself produces
when it packs a tarball. Give it a bare directory and every **metadata** rule (install hooks,
manifest mismatch) is skipped without error; only *content* rules run. The scan then reports
*"No risks found"*, which is indistinguishable from a real clean result.

Measured while building this corpus (2026-08-04): with bare directories, **3 of 4 malicious fixtures
reported 0 risks**. After restructuring the identical files under `package/`, **all 4 fire**. Nothing
about the fixtures changed except the directory layout.

**Rules that follow:**
1. **Every fixture here keeps the `package/` layout.** Do not "tidy" it away.
2. **The clean control is what makes this detectable.** If a layout regression silently disabled the
   metadata rules, the malicious fixtures would go quiet *and so would nothing else* — the run would
   look like a pass. The control cannot catch that on its own, which is why rule 3 exists.
3. **Treat an all-clean corpus run as suspicious, not as success.** If every fixture suddenly scores
   0, check the layout before concluding the scanner regressed.

This generalises beyond GuardDog: **a scanner that cannot find the manifest reports "clean", not
"unknown"** — the exact fail-open-silently class `FW_UNSCORABLE_POLICY` exists to make explicit
(cf. GuardDog #780).

## The PyPI leg, and the `known-gap` state

PyPI fixtures live under `pypi/`. Two are asserted; one is deliberately **not**.

| Fixture | Expect | Note |
|---|---|---|
| `pypi/clean-control` | `clean` | Negative control for the PyPI leg |
| `pypi/obfuscated-calltime` | `flagged` | base64+exec at call time; confirms **content** rules run on a bare directory |
| `pypi/setup-exec` | **`known-gap`** | Install-time execution — reported, never asserted |

**Why `setup-exec` is a documented gap rather than an assertion.** PyPI executes `setup.py` on
install *by design*, so "work happens at install time" is the single most important PyPI shape. But
**GuardDog does not flag an inert version of it.** Measured 2026-08-05 across three variants — a bare
directory, an sdist-style `<name>-<version>/` layout, and a version importing `subprocess`/`socket`/
`base64` — **all scored 0.0/10**. Its PyPI install-time rules appear to require *real* behaviour
(actual network or exec calls), which we will not ship in a fixture.

That is a defensible scanner design, not a defect. But it is a **coverage limit of the tool we
adopted**, so it is recorded where it will be seen rather than discovered later:

- `known-gap` fixtures **never fail the run**. Asserting a detection we cannot obtain would either
  produce a permanently red check that gets ignored, or tempt someone to ship a live payload to make
  it pass. Both are worse than an honest gap.
- **If this ever starts firing, that is good news and the manifest should be updated** — move it to
  `flagged` so the detection is locked in and cannot regress silently.

This is the corpus telling the truth about its own limits, which is the only way a detection floor
stays trustworthy.

## Defanging convention (#46)

Every network reference in these samples is `example.invalid` — RFC 2606-reserved, never
resolvable — so a sample can be *read* by a scanner's network-egress rule without anything
ever being *reached*. `scripts/fixture-hygiene.sh` (run by `sh scripts/dev.sh vet`) fails
the gate on any resolvable host in a sample, any public IP literal, or any bare payload-shaped
domain; a real name is allowed only when listed with a reason in `e2e/fixture-hosts.txt`, and
none of these samples has one. The shipped images are asserted fixture-free by
`e2e/hardening.sh` leg 1b — the guarddog#776 half of the same lesson.
