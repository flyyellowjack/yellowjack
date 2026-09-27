# Making a client trust your CA — by how the tool was installed

You need this page if developer tools must trust a certificate authority that is not a
public one, such as a private CA on the TLS terminator in front of Yellow Jack
(`docs/SETUP.md`).
If your certificate chains to a CA your machines already trust, you need none of it.

## Read this first: the answer depends on the installation, not the language

The natural way to organise this page is one row per ecosystem — "Python", "Java", "Node".
**That page would be wrong for some installs of every ecosystem it covered.** Measured on
one Ubuntu 24.04 machine, same Java version, same moment:

```
JDK from apt (openjdk 21)     our CA inside the JVM's own cacerts: yes    system store: trusted
Temurin 21 tarball            our CA inside the JVM's own cacerts: no     system store: NOT trusted
```

Both are "Java 21". One is kept in step with the operating system's trust store and one
carries its own copy that the operating system never touches. The same split was measured
for Node (apt vs the nodejs.org tarball). So the tables below are indexed by **how the tool
got onto the machine**, and a developer can add a new row at any time — unpacking a JDK or
Node tarball, or installing `uv`, creates one — without anything being told.

Python shows the same trap in a subtler form, **inside one venv**: `pip` there trusts the
operating system store, because it reads it directly; a program in that same venv that calls
`requests` does not, because the `certifi` package it uses ships its own bundle. Package
installs go through pip, so they are covered; your application's own HTTPS calls are not.

The practical consequence: **installing your CA into the operating system store is
necessary and not sufficient.** It reaches some installations and silently misses others,
and the ones it misses fail later, on someone else's machine, with a certificate error.

## How to read the status column

Every row says what it was verified on. **Nothing here is generalised from one platform to
another**, because the one time that was checked it failed: Go honours `SSL_CERT_FILE` on
Linux and ignores it on Windows, with an error identical to setting nothing.

- **Ubuntu 24.04** — a real Ubuntu 24.04 LTS machine (WSL2, as root), CA installed the
  ordinary way (`/usr/local/share/ca-certificates/` + `update-ca-certificates`) and **no
  other variable set**. Rig: `e2e/debiantrust/`. Each leg was first run *without* the CA
  and had to fail there, and had to prove it reached the test server.
- **Linux containers** — the project's e2e suite (`node:22`, `python:3.12`, Maven and
  crane images), with the per-tool setting applied directly.
- **not measured** — means exactly that. Treat it as unknown, not as "probably the same".

## Step 1 — install the CA in the operating system store

Debian / Ubuntu:

```
sudo cp your-ca.pem /usr/local/share/ca-certificates/your-ca.crt    # must end in .crt
sudo update-ca-certificates                                          # expect "1 added"
```

**Then restart any long-running process that needs to see it** — the Docker daemon above all.
A process reads the system roots when it starts; installing the CA does not reach one that is
already running (measured: see the two Docker rows below).

Other platforms: not measured. Use your platform's own mechanism and then check each tool
with step 3 rather than assuming.

**What that alone reaches** (Ubuntu 24.04, no other setting):

| tool, as installed | trusts the OS store? | why |
|---|---|---|
| `curl`, `openssl` | ✅ yes | they read the system bundle |
| Go programs (including `crane`) | ✅ yes | Go reads the system bundle on Linux |
| Python from **apt**, with apt's `python3-certifi` | ✅ yes | Debian points `certifi` at the system bundle |
| **`pip` in a venv** — the pip `python3 -m venv` ships, or one upgraded from PyPI | ✅ yes | pip reads the OS store itself (upstream pip through `truststore`, its default since pip 24.2 on Python 3.10+; switch that off with `--use-deprecated=legacy-certs` and it fails). Also true of a venv created *before* the CA was installed. Not measured: Python 3.9 or older, or a pip older than 24.2 installed from PyPI |
| **Python code in a venv** calling `requests`, or anything using a pip-installed `certifi` | ❌ **no** | `certifi` ships its own bundle inside the environment. This is your application's traffic, not package installs |
| **`uv`** (installer script) | ❌ **no** | bundled roots; it does not consult the OS store |
| JDK from **apt** | ✅ yes | apt pulls `ca-certificates-java`, whose hook copies the anchor *into* the JVM's own `cacerts` whenever `update-ca-certificates` runs |
| JDK from a **tarball** (Temurin 21; the same artefact sdkman and most CI images use) | ❌ **no** | it ships its own `lib/security/cacerts`, which `update-ca-certificates` never touches — the anchor is measurably absent from it |
| Node from **apt** (`nodejs` 18) | ✅ yes | measured; the apt build links the system OpenSSL. Not verified for NodeSource or snap builds |
| Node from the **nodejs.org tarball** (what `nvm`, `fnm` and most CI images install) | ❌ **no** | upstream Node carries its own compiled-in roots |
| Docker daemon (registry TLS), **restarted after the install** | ✅ yes | measured on Docker 29 from apt (`docker.io`), with no `certs.d` file: a new daemon process reads the system bundle as it now is |
| Docker daemon that was **already running** when you installed the CA | ❌ **no — until you restart it** | the daemon read the system roots when it started and goes on using that copy. `update-ca-certificates` reports success and `curl` works, while `docker pull` still fails with an unknown-authority error |

## Step 2 — for the installations step 1 missed, tell the tool directly

| tool | setting | verified on |
|---|---|---|
| pip | `SSL_CERT_FILE=/path/ca.pem`, or `PIP_CERT=/path/ca.pem` (config: `cert`), or `REQUESTS_CA_BUNDLE` | Linux containers |
| `uv` | `SSL_CERT_FILE=/path/ca.pem` — **`PIP_CERT` and `REQUESTS_CA_BUNDLE` do not work for uv** | Linux containers |
| npm | `cafile=/path/ca.pem` (env: `npm_config_cafile`) | Linux containers |
| Node (anything else) | `NODE_EXTRA_CA_CERTS=/path/ca.pem` | Linux containers |
| Go programs | `SSL_CERT_FILE=/path/ca.pem` — **Linux only**; on Windows Go ignores it and uses the Windows store | Linux containers; the Windows behaviour measured on Windows |
| JVM (Maven, Gradle, …) | `keytool -importcert -cacerts -file ca.pem -alias your-ca` — the JVM ignores `SSL_CERT_FILE` | Linux containers |
| Docker daemon | `/etc/docker/certs.d/<registry-host>/ca.crt` — that one file also covers the registry's token server and blob CDN | a local Docker daemon |
| `crane` | `SSL_CERT_FILE=/path/ca.pem` | Linux containers |

**Do not assume `SSL_CERT_FILE` *adds* your CA to the defaults.** Whether it adds to or
replaces the tool's default roots depends on the tool and on how the machine lays out its
certificates. The one case measured here — a Go program in a minimal container — kept the
public roots, and only because that image happens to keep its bundle in a directory Go
still scans; it is not a guarantee. For Python and `uv` it is not measured. The form that
is safe either way is a file containing your CA **and** the public roots the tool still
needs; otherwise a tool that replaces stops verifying public registries.

## Step 3 — check an installation instead of guessing which row it is

```
# pip: does THIS pip reach your server?  (run it inside the venv you care about)
pip download --no-deps --no-cache-dir -d /tmp/trustcheck \
    --index-url https://your-host.example/simple/ some-package

# Python code using certifi: which bundle is it using?  (run it inside the venv)
python3 -c 'import certifi; print(certifi.where())'

# JVM: is the anchor in THIS JDK's keystore?
keytool -list -cacerts -storepass changeit | grep -i your-ca

# Anything: does it actually reach a server signed by your CA?
curl -sS https://your-host.example/ -o /dev/null && echo trusted
```

A certificate error from the pip command means step 1 did not reach that pip; any other
answer (including "no matching distribution") means the connection was trusted. For the
`certifi` command, a path under `/etc/ssl/` means the OS store is in use and step 1 covered
it; a path under `site-packages/` means it did not. `certifi.where()` says nothing about pip,
which does not use it for this.

## What this page does not cover

- **A systemd-managed Docker daemon** — the measurement above stopped and started a daemon run
  as a plain background process; `systemctl restart docker` is the same operation, but it is not
  what was run.
- **macOS, Windows, RHEL-family Linux** — not measured, apart from the one Go/Windows fact
  above. The per-platform work is tracked in #143.
- **Per-user installations** (`nvm`, `sdkman`, `pyenv`). The Ubuntu measurement ran as
  root, so these are under-represented by construction, and they are exactly the
  installations a system-wide install cannot see. (A developer's own venv is covered for
  pip, above; the code running in it is not.)
- **Keeping it true over time.** A tool upgrade can replace a vendored bundle, and a new
  tarball install starts without your CA. Nothing here re-checks a machine after the day it
  was set up.
