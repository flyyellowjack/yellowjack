#!/bin/sh
# stepca_fips.sh -- does step-ca, built from UNMODIFIED source against Go's certified FIPS
# 140-3 module, run the recipe in docs/CA_INTEGRATION.md? (D374: we owe the customer at least
# one compliant CA we integrate with; D379 records what this measured.)
#
# Manual, not in CI: it compiles two Go programs (~3 min). Needs docker. Run:
#   sh e2e/stepca_fips.sh
#
# Legs, each printed PASS/FAIL, and the exit status is non-zero if any fails:
#   control  Smallstep's PUBLISHED step-cli image is not a FIPS build (the premise that a
#            customer must build it; if this ever fails, the recipe can point at their image)
#   build    step and step-ca report GOFIPS140=v1.0.0-... and fips140=on
#   recipe   CA_INTEGRATION steps 1-2 (root, gate intermediate) work, and the chain verifies
#   server   step ca init, a running step-ca answers health, issues a leaf, the leaf verifies
#   strict   under GODEBUG=fips140=only the root step FAILS, for the named reason (step uses
#            MD5, which strict mode forbids). If this leg fails, strict mode may now work:
#            re-measure and update the doc rather than the assertion.
set -u

STEP_VERSION=v0.30.6          # the CLI version CA_INTEGRATION.md was verified with
STEPCA_VERSION=v0.30.2
GO_IMAGE=golang:1.26          # carries the certified module snapshot (lib/fips140/v1.0.0)
PUBLISHED_CLI=smallstep/step-cli:0.30.6

fails=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; fails=$((fails + 1)); }

# --- control: the published image -----------------------------------------------------
ctr="yj-stepfips-$$"
if docker create --name "$ctr" "$PUBLISHED_CLI" >/dev/null 2>&1 &&
	docker cp "$ctr:/usr/local/bin/step" "${TMPDIR:-/tmp}/step-published-$$" >/dev/null 2>&1; then
	info=$(docker run --rm -v "${TMPDIR:-/tmp}:/t" "$GO_IMAGE" go version -m "/t/step-published-$$" 2>&1)
	case "$info" in
	*GOFIPS140=*) fail "control: $PUBLISHED_CLI is now a FIPS build -- the recipe can use it; re-measure" ;;
	*go1.*) pass "control: $PUBLISHED_CLI is not a FIPS build (no GOFIPS140), so it must be built" ;;
	*) fail "control: could not read the published binary's build info: $info" ;;
	esac
else
	fail "control: could not extract step from $PUBLISHED_CLI"
fi
docker rm "$ctr" >/dev/null 2>&1
rm -f "${TMPDIR:-/tmp}/step-published-$$"

# --- everything else runs inside the Go image -----------------------------------------
out=$(docker run --rm -e STEP_VERSION="$STEP_VERSION" -e STEPCA_VERSION="$STEPCA_VERSION" \
	"$GO_IMAGE" bash -c '
set -u
export CGO_ENABLED=0 GOFIPS140=v1.0.0 GOFLAGS=-mod=mod
go install github.com/smallstep/cli/cmd/step@$STEP_VERSION >/tmp/b.log 2>&1 || { echo "BUILDFAIL step"; tail -3 /tmp/b.log; }
go install github.com/smallstep/certificates/cmd/step-ca@$STEPCA_VERSION >>/tmp/b.log 2>&1 || { echo "BUILDFAIL step-ca"; tail -3 /tmp/b.log; }
for b in step step-ca; do
  m=$(go version -m /go/bin/$b 2>&1)
  case "$m" in *GOFIPS140=v1.0.0-*) echo "FIPSBUILD $b yes" ;; *) echo "FIPSBUILD $b no" ;; esac
  case "$m" in *fips140=on*) echo "FIPSON $b yes" ;; *) echo "FIPSON $b no" ;; esac
done
mkdir /w && cd /w && echo pw > pw
step certificate create "Acme Root CA" root.crt root.key --profile root-ca --password-file pw >/dev/null 2>&1 &&
step certificate create "Yellow Jack proxy CA" proxy.crt proxy.key --profile intermediate-ca \
  --ca root.crt --ca-key root.key --ca-password-file pw --no-password --insecure >/dev/null 2>&1 &&
step certificate verify proxy.crt --roots root.crt >/dev/null 2>&1 && echo "RECIPE ok" || echo "RECIPE failed"
export STEPPATH=/w/sp
step ca init --name T --dns localhost --address 127.0.0.1:9443 --provisioner p --password-file pw >/dev/null 2>&1 || echo "SERVER init failed"
(step-ca /w/sp/config/ca.json --password-file pw >/w/ca.log 2>&1 &)
sleep 4
h=$(step ca health --ca-url https://localhost:9443 --root /w/sp/certs/root_ca.crt 2>&1)
echo "HEALTH $h"
tok=$(step ca token leaf.local --provisioner p --provisioner-password-file pw --ca-url https://localhost:9443 --root /w/sp/certs/root_ca.crt 2>/dev/null)
step ca certificate leaf.local leaf.crt leaf.key --token "$tok" --ca-url https://localhost:9443 --root /w/sp/certs/root_ca.crt >/dev/null 2>&1 &&
step certificate verify leaf.crt --roots /w/sp/certs/root_ca.crt >/dev/null 2>&1 && echo "LEAF ok" || echo "LEAF failed"
mkdir /s && cd /s && echo pw > pw
e=$(STEPDEBUG=1 GODEBUG=fips140=only step certificate create "Acme Root CA" root.crt root.key --profile root-ca --password-file pw 2>&1)
if [ -f root.crt ]; then echo "STRICT worked"; else echo "STRICT failed: $(echo "$e" | grep -o "use of [^,]*not allowed in FIPS 140-only mode" | head -1)"; fi
' 2>&1)

has() { case "$out" in *"$1"*) return 0 ;; esac; return 1; }
if has "BUILDFAIL"; then fail "build: $(echo "$out" | grep -A3 BUILDFAIL)"; fi
if has "FIPSBUILD step yes" && has "FIPSBUILD step-ca yes" && has "FIPSON step yes" && has "FIPSON step-ca yes"; then
	pass "build: step $STEP_VERSION and step-ca $STEPCA_VERSION report GOFIPS140=v1.0.0 and fips140=on"
else
	fail "build: $(echo "$out" | grep -E 'FIPSBUILD|FIPSON' | tr '\n' ' ')"
fi
if has "RECIPE ok"; then pass "recipe: root + gate intermediate created under fips140=on, chain verifies"; else fail "recipe: CA_INTEGRATION steps 1-2 failed under fips140=on"; fi
if has "HEALTH ok" && has "LEAF ok"; then
	pass "server: step-ca answered health, issued a leaf, the leaf verifies"
else
	fail "server: $(echo "$out" | grep -E 'HEALTH|LEAF|SERVER' | tr '\n' ' ')"
fi
if has "STRICT failed: use of MD5 is not allowed in FIPS 140-only mode"; then
	pass "strict: fips140=only refuses the root step, for the named reason (step uses MD5)"
else
	fail "strict: expected the root step to fail under fips140=only for the MD5 reason; got: $(echo "$out" | grep STRICT)"
fi

if [ "$fails" -ne 0 ]; then
	echo "STEP-CA FIPS: $fails leg(s) FAILED"
	exit 1
fi
echo "STEP-CA FIPS: PASS"
