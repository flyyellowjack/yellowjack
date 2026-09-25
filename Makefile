# Yellow Jack — developer task runner (CI / Linux).
#
# NOTE: `make` is NOT installed on the Windows dev host — this Makefile runs in CI
# and on Linux/WSL only. It is a thin alias over the single source of truth,
# `scripts/dev.sh`, so the host (`sh scripts/dev.sh <task>`) and CI run identical
# logic. Put task logic in scripts/dev.sh, not here.
#
# Which ecosystem the e2e suite exercises: npm | pypi | oci | maven | all (default).
ECOSYSTEM ?= all
# Extra args for the race target, e.g. `make race RACE_ARGS=./firewall/...`.
RACE_ARGS ?=

.PHONY: build vet fmt test race e2e up down logs

build:
	sh scripts/dev.sh build

vet:
	sh scripts/dev.sh vet

fmt:
	sh scripts/dev.sh fmt

test:
	sh scripts/dev.sh test

race:
	sh scripts/dev.sh race $(RACE_ARGS)

e2e:
	sh scripts/dev.sh e2e $(ECOSYSTEM)

up:
	sh scripts/dev.sh up

down:
	sh scripts/dev.sh down

logs:
	sh scripts/dev.sh logs
