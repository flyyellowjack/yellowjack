# Console demo

A runbook for showing Yellow Jack on a laptop:
- the real stack, in front of the real npm registry and PyPI;
- real OpenSSF scores;
- a real, signed known-malware feed;
- about thirty pulls that give every console page something true to show.

## What is real and what is not

- **Everything the audience sees is real.** That covers the gates, the console, the audit log, the
  approval queue and every verdict. It also covers:
  - the scores, from the public OpenSSF Scorecard API;
  - the known-malware feed, built from OpenSSF's public
    [malicious-packages](https://github.com/ossf/malicious-packages) data (about 221,000 npm and
    11,700 PyPI advisories when this was written).
- **The feed carries three extra entries.** These are the GitHub advisories for the demo's older npm
  incidents, which predate OpenSSF's dataset:
  - `crossenv`: GHSA-c2m4-w5hm-vqjw
  - `ua-parser-js 0.7.29`: GHSA-pjwm-rvh2-c87w
  - `coa 2.0.3`: GHSA-73qr-pfmq-6rp8

  Every ID the demo shows can be looked up at `osv.dev`.
- **The feed is signed.** `demo.sh` makes an Ed25519 key for this demo, signs the feed with it, and
  gives the gates only the public half. Each gate's log says `signature VERIFIED`.
- **Scores change over time**, so the seed prints what actually happened. Do not promise a package's
  outcome before running it.
- **The offline fallback.** Only if the feed data cannot be downloaded does the demo use a
  four-entry offline list. Its IDs say `DEMO-0001` to `DEMO-0004`, it is unsigned, and
  `sh scripts/demo.sh status` reports it as `OFFLINE`.
- **Hosts, not people.** The seed runs from three throwaway containers, so the audit log shows three
  source addresses. The console never names a person it did not see sign in.

## Before the demo

You need Docker and internet access to:
- the npm registry;
- `pypi.org` and `files.pythonhosted.org`;
- `api.securityscorecards.dev`;
- `codeload.github.com`, for the feed.

Nothing else is needed on the host: the feed is built and signed in containers.

```sh
sh scripts/demo.sh up      # builds the feed and the stack; about 7 minutes the first time
sh scripts/demo.sh seed    # ~30 pulls through the npm and PyPI gates; about 2 minutes
sh scripts/demo.sh status  # the console URL, a generated sign-in, and which feed is in force
```

- **Ports:** the stack uses 8080 (npm gate), 8082 (PyPI gate), 8081 (OCI gate), 8085 (console),
  8090, 8096 and 8071. Stop any other Yellow Jack stack first.
- **Cleanup:** `sh scripts/demo.sh down` removes everything, including `./.demo`.
- **Refreshing the feed:** `sh scripts/demo.sh feed` rebuilds and re-signs it, and the gates pick it
  up within a minute.
- **Seed early.** Seed a day or so before the demo if you want "Waiting 1 day" to show on the
  Decisions page. Waits are measured from when the gate first queued a package.
- **Screen width.** Present at 1400 pixels wide or more, or at 90% browser zoom. Narrower than that,
  the audit log hides its Ecosystem and Threshold columns (the Reason text states both) so that
  Reason stays readable.

## A path through it

1. **Overview** (`http://127.0.0.1:8085`). Four tiles:
   - waiting on you;
   - stopped in the last 24 hours, split into known malware, your block list and policy;
   - allowed;
   - the known-malware list: the total, with each gate's share under it.

   Below them, the packages waiting longest and the newest refusals. The sidebar card says whether
   every gate is reporting.
2. **Decisions.** Open a waiting package: `uuid` or `dotenv` are usually just under the 5.0
   threshold, and `react` currently cannot be scored because its repository moved. The pane says why
   it is waiting, which hosts asked, and what the registry says. **Allow** it. An allow covers every
   version of the package; to allow one release, pin it on the allow list instead.
3. **Stopped → ua-parser-js** (the hijacked release). It is refused on the gate as
   GHSA-pjwm-rvh2-c87w, without contacting the registry. The override is a pinned allow entry, and a
   pin outranks the advisory for that release only. If you apply it, npm answers 404: the release
   was unpublished in 2021, and the gate passes that answer through.
4. **Stopped → event-stream.** Your own block list, which is not an advisory, so the page offers a
   different override: remove it from the list.
5. **Policy.** The rules in the order the gate checks them, with the numbers the gates report. The
   tabs switch between the npm, PyPI and OCI gates. The last row is the release cooldown: versions
   published in the last 14 days are left out of what the registry offers. The engine's own rule
   chains are in the disclosure below.
6. **Allow & block lists.** Add an entry. The edit is a git commit under your name, and the gates
   pick it up within seconds. The page shows both "authored" and "enforced".
7. **Live refusal on npm.** In a terminal:

   ```sh
   npm install --registry http://127.0.0.1:8080 crossenv
   ```

   The developer sees the reason and the advisory ID (GHSA-c2m4-w5hm-vqjw) in npm's own error
   output. Refresh the Overview and the refusal is there.
8. **Live on PyPI: a blocked dependency, and why it does not downgrade you.** In a fresh
   virtual environment:

   ```sh
   pip install --index-url http://127.0.0.1:8082/simple requests
   ```

   - **It fails with `ResolutionImpossible`**, and pip's own output names the blocker:
     `requests … depends on charset-normalizer`. charset-normalizer cannot be scored today (its
     repository moved), and the demo policy sends unscorable packages to a person.
   - **The point to make.** Without the release-age floor (`FW_MAX_RELEASE_AGE_DAYS`, five years on
     this gate), pip would have "succeeded" by backtracking to requests 2.25.1 from 2020, the last
     release that did not need charset-normalizer. That is a silent downgrade to known CVEs. The
     floor holds that fallback back, so the install fails on the real blocker instead.
   - **Decisions → charset-normalizer → Allow**, with a note. Run the same command again: pip
     installs current requests, urllib3 and idna. Its newest release may still be held by the
     14-day cooldown.
   - **pip never prints a refusal's reason; uv does.**
     `uv pip install --index-url http://127.0.0.1:8082/simple num2words` says
     `all versions of num2words were yanked (reason: BLOCKED: …)`. With pip, show the reason in
     the console instead (Stopped → num2words). num2words scores below the threshold, and its
     hijacked 2025 releases are also on the malware list.
9. **Look up a package** and **Capacity** round it out: one package's history, and how much the gates
   moved.

## If something looks wrong

- **`status` says the feed is OFFLINE.** The feed data could not be downloaded. Check access to
  `codeload.github.com`, then run `sh scripts/demo.sh feed`.
- **Every package lands in Decisions as "can't be scored".** The Scorecard API was unreachable.
  Check network access, then run `seed` again.
- **The sidebar says a gate is not reporting.** A gate reports every minute, so give it one. A gate
  that was restarted or recreated is not counted against you: its replacement takes over its
  place. A gate that stopped and was not replaced is reported, which is the point. Check with
  `docker compose -p yellowjack-demo -f docker-compose.yml -f docker-compose.demo.yml ps`.
- **Ports in use.** Another stack is running on the same ports. Stop it, or run
  `sh scripts/demo.sh down` and start again.
