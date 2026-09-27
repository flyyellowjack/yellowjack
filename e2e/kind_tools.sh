#!/bin/sh
# e2e/kind_tools.sh -- install PINNED, checksum-verified kind, kubectl and helm (linux/amd64).
#
# For the real-cluster jobs (e2e/helm_install.sh). The same rule as every other tool a
# security pipeline pulls: an exact version and its published SHA-256, never @latest, and a
# mismatch stops the job rather than running whatever was served.
set -eu
BIN="${1:-/usr/local/bin}"

fetch() { # fetch URL SHA256 OUT
  curl -fsSL -o "$3" "$1"
  echo "$2  $3" | sha256sum -c - >/dev/null 2>&1 || { echo "kind_tools: CHECKSUM MISMATCH for $1"; rm -f "$3"; exit 1; }
}

fetch https://github.com/kubernetes-sigs/kind/releases/download/v0.30.0/kind-linux-amd64 \
  517ab7fc89ddeed5fa65abf71530d90648d9638ef0c4cde22c2c11f8097b8889 "$BIN/kind"
fetch https://dl.k8s.io/release/v1.34.1/bin/linux/amd64/kubectl \
  7721f265e18709862655affba5343e85e1980639395d5754473dafaadcaa69e3 "$BIN/kubectl"
fetch https://get.helm.sh/helm-v3.19.0-linux-amd64.tar.gz \
  a7f81ce08007091b86d8bd696eb4d86b8d0f2e1b9f6c714be62f82f96a594496 /tmp/helm.tgz
tar -xzf /tmp/helm.tgz -C /tmp linux-amd64/helm && mv /tmp/linux-amd64/helm "$BIN/helm" && rm -rf /tmp/helm.tgz /tmp/linux-amd64
chmod +x "$BIN/kind" "$BIN/kubectl" "$BIN/helm"
echo "kind_tools: $("$BIN/kind" version) | kubectl $("$BIN/kubectl" version --client -o json | grep -o '"gitVersion": *"[^"]*"' | head -1) | $("$BIN/helm" version --short)"
