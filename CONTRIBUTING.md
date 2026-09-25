# Contributing to Yellow Jack

Thanks for your interest. This document covers how to contribute and the one legal
requirement that must be in place **before any outside contribution is merged**.

## Contributor License Agreement (CLA) — required before merge

Yellow Jack is licensed **AGPLv3**. To keep the project's licensing flexible — including
the ability to offer commercial / dual-licensed editions that fund the project — the
maintainers must retain the rights to relicense contributed code. **Every outside
contribution therefore requires agreement to a Contributor License Agreement before it
can be merged.**

Why this matters, briefly: once a contributor's code is merged under AGPL and they have
**not** signed a CLA, that contributor holds copyright on their portion and it is locked
to AGPL — the project could no longer offer a proprietary or commercial edition of any
file they touched. The CLA preserves that freedom. It is cheap to establish now and
effectively impossible to retrofit later (it would require tracking down every past
contributor).

**Status:** the final CLA text and an automated sign-off check are being finalised. Until
then, a maintainer will confirm CLA agreement with you before merging any outside
contribution.

## How to contribute

- Work on a branch and open a **pull request into `main`**.
- The pull request must pass the checks, and the end-to-end tests for the area you touched
  (`sh scripts/dev.sh e2e`, see [`docs/E2E_TESTING.md`](docs/E2E_TESTING.md)).
- Write a clear description: a context paragraph plus what changed and why. Small,
  reviewable, self-contained changes are strongly preferred.
- Keep third-party dependencies to a minimum and justify any new one — this is security
  software, and every dependency is part of our own attack surface.

## Development

See [`docs/SETUP.md`](docs/SETUP.md) for building, running, and testing the stack.
