# Console demo

A runbook for showing the console on a laptop: the real stack, the real npm registry, real
OpenSSF scores, and about twenty pulls that give every console page something true to show.

## What is real and what is not

- **Real:** the gate, the console, the audit log, the approval queue, the scores (from the public
  OpenSSF Scorecard API), the npm registry, and every verdict. Scores change over time, so the seed
  prints what actually happened. Do not promise a package's outcome before running it.
- **Invented:** the known-malware list. Its four entries are marked `DEMO-0001` to `DEMO-0004`. The
  packages are real incidents (`crossenv` and `electorn` typosquats, the hijacked `ua-parser-js
  0.7.29` and `coa 2.0.3`), but the advisory IDs are not OSV's.
- **Hosts, not people.** The seed runs from three throwaway containers, so the audit log shows three
  source addresses. The console never names a person it did not see sign in.

## Before the demo

You need Docker and internet access (the npm registry and `api.securityscorecards.dev`).

```sh
sh scripts/demo.sh up      # builds and starts the stack; the first run takes a few minutes
sh scripts/demo.sh seed    # ~20 pulls through the gate; prints each outcome
sh scripts/demo.sh status  # the console URL and a generated sign-in
```

The stack uses the same host ports as `docker compose up` (8080, 8081, 8085, 8090, 8096, 8071).
Stop any other Yellow Jack stack first. `sh scripts/demo.sh down` removes everything, including
`./.demo`.

Seed a day or so before the demo if you want "Waiting 1 day" to show on the Decisions page. Waits are
measured from when the gate first queued a package.

## A path through it

1. **Overview** (`http://127.0.0.1:8085`). Four tiles:
   - waiting on you;
   - stopped in the last 24 hours, split into known malware, your block list and policy;
   - allowed;
   - the known-malware list as the gates report it.

   Below them, the packages waiting longest and the newest refusals. The sidebar card says whether
   every gate is reporting.
2. **Decisions.** Open a waiting package: `uuid` or `chalk` are usually just under the 5.0 threshold,
   and `react` currently cannot be scored because its repository moved. The pane says why it is
   waiting, which hosts asked, and what the registry says. **Allow** it. An allow covers every
   version of the package; to allow one release, pin it on the allow list instead.
3. **Stopped → ua-parser-js** (the hijacked release). It is refused on the gate without contacting
   the registry. The override is a pinned allow entry, and a pin outranks the advisory for that
   release only. If you apply it, npm answers 404: the release was unpublished in 2021, and the gate
   passes that answer through.
4. **Stopped → event-stream.** Your own block list, which is not an advisory, so the page offers a
   different override: remove it from the list.
5. **Policy.** The rules in the order the gate checks them, with the numbers the gates report. The
   tabs switch between the npm and OCI gates. The engine's own rule chains are in the disclosure
   below.
6. **Allow & block lists.** Add an entry. The edit is a git commit under your name, and the gates
   pick it up within seconds. The page shows both "authored" and "enforced".
7. **Live refusal.** In a terminal:

   ```sh
   npm install --registry http://127.0.0.1:8080 crossenv
   ```

   The developer sees the reason in npm's own error output. Refresh the Overview and the refusal is
   there.
8. **Look up a package** and **Capacity** round it out: one package's history, and how much the gates
   moved.

## If something looks wrong

- **Every package lands in Decisions as "can't be scored".** The Scorecard API was unreachable.
  Check network access, then run `seed` again.
- **The sidebar says a gate is not reporting.** A gate reports every minute, so give it one.
  Otherwise `docker compose -p yellowjack-demo -f docker-compose.yml -f docker-compose.demo.yml ps`.
- **Ports in use.** Another stack is running on the same ports. Stop it, or run
  `sh scripts/demo.sh down` and start again.
