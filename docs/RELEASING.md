# Releases

## Versions

Releases are tagged `vMAJOR.MINOR.PATCH` and follow [Semantic Versioning](https://semver.org/).
While the major version is 0, a minor release may change behaviour; `CHANGELOG.md` says what
changed and what an operator has to do about it.

A **patch** release carries bug and security fixes only. It adds no configuration and changes
no behaviour a default deployment would notice, so moving from `0.1.0` to `0.1.1` is always
safe to do without reading more than the changelog entry.

Fixes are released on the newest minor line only. No longer support window has been
committed yet; when one is, it will be stated here.

## What a release publishes

A tag publishes, from the tagged commit and nothing else:

| What | Where |
|---|---|
| The gate | `ghcr.io/flyyellowjack/yellowjack-firewall:<version>` |
| The control plane | `ghcr.io/flyyellowjack/yellowjack-approval:<version>` |
| The console | `ghcr.io/flyyellowjack/yellowjack-console:<version>` |
| The Helm chart | `oci://ghcr.io/flyyellowjack/charts/yellowjack`, chart version = `<version>` |
| Release notes | the GitHub release, carrying the `CHANGELOG.md` section and each image's digest |

- **Every image is built for `linux/amd64` and `linux/arm64`**, against Go's certified FIPS 140-3
  module. The gate logs `FIPS 140-3 mode: ON` at startup (`docs/SETUP.md`, "FIPS 140-3 mode").
- **The published chart pins each image by digest** as well as tag, so a cluster pulls exactly
  the bytes that were published even if a tag is later moved. The chart in this repository
  (`deploy/helm/yellowjack`) builds from source instead; the release job rewrites the image
  references in the packaged copy only.
- The optional scoring images (scheduler and scanner) are not published. The chart does not
  deploy them; build them from source if you run local scoring.
- **Images are not signed yet.** Verify by digest: the digests in the release notes and in the
  chart's `values.yaml` must match what your registry mirror holds.

Install a release:

```bash
helm install yellowjack oci://ghcr.io/flyyellowjack/charts/yellowjack --version <version>
```

## Cutting a release (maintainers)

1. Move the `CHANGELOG.md` entries under `## [<version>] - <date>` and set `version` and
   `appVersion` in `deploy/helm/yellowjack/Chart.yaml` to the same version.
2. Push the tag `v<version>` on that commit.
3. `.github/workflows/release.yml` runs `scripts/release.sh`. It refuses a tag that disagrees
   with the changelog or the chart, runs the unit tests, builds and pushes the three images,
   pins them in the chart, pushes the chart, and creates the GitHub release.

`scripts/release.sh` is all the release does, so it can be rehearsed first against a local
registry (`REGISTRY=localhost:5000/test INSECURE=1`). `scripts/release_test.sh` tests the
parts that decide what gets published: the tag grammar, the changelog and chart agreement,
the release notes, and the digest pinning.
