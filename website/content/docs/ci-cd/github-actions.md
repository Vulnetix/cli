---
title: "GitHub Actions"
weight: 1
description: "Integrate Vulnetix CLI into GitHub Actions workflows, from a one-step quickstart to publishing every scan artifact on a GitHub Release."
---

This page builds up from the smallest working workflow to a full release pipeline that attaches every scan artifact to a GitHub Release. Each level adds one idea to the previous one.

{{< callout type="warning" >}}
**Versions in this page are current as of writing** (`Vulnetix/cli@v3.59.4`).

There is **no moving `v1`/`v2`/`v3` major tag** — the action must be pinned to an exact release tag. The action also builds the CLI from the ref you pin, so `actions/setup-go` must run before it.

Check the [latest release](https://github.com/Vulnetix/cli/releases) for current syntax. If anything here is stale, [open an issue](https://github.com/Vulnetix/cli/issues/new) and we will fix the docs.
{{< /callout >}}

## Before You Start

Add two repository secrets under **Settings → Secrets and variables → Actions**:

| Secret | Where to get it |
|--------|-----------------|
| `VULNETIX_ORG_ID` | Organization ID (UUID) from your Vulnetix account |
| `VULNETIX_API_KEY` | API key (hex digest) from your Vulnetix account |

Workflows that run `vulnetix analyze` also need the built-in `GITHUB_TOKEN`, with read access
to repository contents, pull requests, and issues:

```yaml
permissions:
  contents: read
  pull-requests: read
  issues: read
```

`vulnetix gha upload` needs `actions: read` so it can collect artifacts from the current
workflow run. Jobs that upload GitHub Release assets also need `contents: write`.

Two ways to run the CLI in a workflow:

| Approach | When to use |
|----------|-------------|
| **Native action** — `uses: Vulnetix/cli@v3.59.4` | Quickstart, `upload`, and `gha` artifact collection. Requires `actions/setup-go`. |
| **Install script** — `curl -fsSL https://cli.vulnetix.com/install.sh \| sh` | Any subcommand (`scan`, `cbom`, `aibom`, `license`, `secrets`, …). No Go toolchain needed. |

The action exposes only `info`, `upload`, and `gha` tasks. Every other subcommand is run with the install script.

---

## Level 1 — Quick Start

The smallest useful workflow. It authenticates, runs the `info` healthcheck, and confirms your credentials work.

```yaml
name: Vulnetix
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
permissions:
  contents: read

jobs:
  vulnetix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      # The action compiles the CLI from source — Go must be on PATH first.
      - uses: actions/setup-go@v6
        with:
          go-version: stable

      - uses: Vulnetix/cli@v3.59.4
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          api-key: ${{ secrets.VULNETIX_API_KEY }}
```

Omitting `actions/setup-go` fails the run with `Please add actions/setup-go to your workflow before this action`.

### Action Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `org-id` | Organization ID (UUID) | Yes | — |
| `task` | `info`, `upload`, or `gha` | No | `info` |
| `version` | Version string stamped into the built binary | No | `latest` |
| `api-key` | API key (hex digest) | No | — |
| `upload-file` | Artifact path (with `task: upload`) | No | — |
| `upload-format` | Override format: `cyclonedx`, `spdx`, `sarif`, `openvex`, `csaf_vex` | No | — |

{{< callout type="info" >}}
`version` only stamps a version string into the binary via ldflags. It does **not** select which release is built — that is determined by the git ref you pin in `uses:`.
{{< /callout >}}

### Action Outputs

| Output | Description |
|--------|-------------|
| `result` | Result of the CLI execution |
| `summary` | Summary of vulnerabilities processed |
| `upload-uuid` | Pipeline UUID of the uploaded artifact (with `task: upload`) |

---

## Level 2 — One Job Per Scan Subcommand

Each subcommand runs standalone and uploads its findings to Vulnetix automatically when credentials are present in the environment. Set them once at the job level:

```yaml
    env:
      VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
      VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
```

Every example below assumes those two variables are set and the CLI is installed:

```yaml
      - name: Install Vulnetix CLI
        run: curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --version v3.59.4
```

### What Each Subcommand Writes

Results always land under `.vulnetix/` in the scanned directory, whether or not you ask for a copy elsewhere.

| Command | Default result file | Format | Exits `1` when |
|---------|--------------------|--------|----------------|
| `vulnetix sca` | `.vulnetix/sbom.cdx.json` | CycloneDX | a gate flag is passed and breached |
| `vulnetix sast` | `.vulnetix/sast.sarif` | SARIF | `--severity` is met or exceeded |
| `vulnetix secrets` | `.vulnetix/sast.sarif` | SARIF | `--severity` is met or exceeded |
| `vulnetix containers` | `.vulnetix/containers.sarif` | SARIF | `--severity` is met or exceeded |
| `vulnetix iac` | `.vulnetix/sast.sarif` | SARIF | `--severity` is met or exceeded |
| `vulnetix license` | `.vulnetix/sbom.cdx.json` | CycloneDX | `--severity` is met or exceeded |
| `vulnetix cbom` | `.vulnetix/cbom.cdx.json` | CycloneDX (CBOM) | `--fail-on` status is found |
| `vulnetix aibom` | `.vulnetix/ai-bom.cdx.json` | CycloneDX (AIBOM) | never |
| `vulnetix malscan` | `.vulnetix/malscan.sarif` | SARIF | any malware finding |
| `vulnetix scan` | `.vulnetix/sbom.cdx.json` + `.vulnetix/sast.sarif` | both | any passed gate is breached |

{{< callout type="info" >}}
The SARIF-producing scans write their file **only when there are findings** — a clean scan deliberately leaves no empty artifact behind. Guard downstream steps accordingly (see Level 3).
{{< /callout >}}

### SCA — Dependency Vulnerabilities

```yaml
      - name: Software composition analysis
        run: vulnetix sca --severity high
```

### SAST — Source Code Analysis

```yaml
      - name: Static analysis
        run: vulnetix sast --severity high
```

### Secrets — Hardcoded Credentials

```yaml
      - name: Secret detection
        run: vulnetix secrets
```

### Containers — Dockerfile and Image Layers

```yaml
      - name: Container analysis
        run: vulnetix containers
```

### IaC — Terraform, OpenTofu, Nix, Kubernetes

```yaml
      - name: Infrastructure as Code analysis
        run: vulnetix iac
```

### License — SPDX Policy Compliance

```yaml
      - name: License analysis
        run: vulnetix license --allow MIT,Apache-2.0,BSD-3-Clause --severity high
```

### CBOM — Cryptographic Bill of Materials

```yaml
      - name: Cryptography inventory
        run: vulnetix cbom --fail-on quantum-vulnerable
```

`--fail-on` accepts a comma-separated list of PQC statuses (`quantum-vulnerable`, `deprecated`) and defaults to `none`, which never fails the step.

### AIBOM — AI Bill of Materials

```yaml
      - name: AI usage inventory
        run: vulnetix aibom
```

### Malscan — Malware in Installed Dependencies

`malscan` reads the bytes of your **installed** dependencies, so install them first.

```yaml
      - name: Install dependencies
        run: npm ci

      - name: Malware scan
        run: vulnetix malscan
```

---

## Level 3 — Publish the Result File

Each command can write its result to a path you choose, which you then keep as a workflow artifact, feed into GitHub Code Scanning, or attach to a release.

Two different flags do this, depending on the command:

| Flag | Commands | Behaviour |
|------|----------|-----------|
| `--output` / `-o` | `sca`, `sast`, `secrets`, `containers`, `iac`, `scan` | Repeatable. Accepts a file path ending in `.cdx.json` or `.sarif`, or the literals `json-cyclonedx` / `json-sarif` for stdout. |
| `--output-file` | `cbom`, `aibom`, `malscan` | Single path. `-o` on these commands selects the **terminal** format only (`pretty`, `json`, `cyclonedx-json` / `sarif`). |
| *(neither)* | `license` | Writes `.vulnetix/sbom.cdx.json`. `-o json` prints CycloneDX to stdout, `-o json-spdx` prints SPDX 2.3. Copy the file out to publish it. |

### SCA, Publishing CycloneDX

```yaml
      - name: Software composition analysis
        run: vulnetix sca --severity high -o dist/sbom.cdx.json

      - uses: actions/upload-artifact@v6
        if: always()
        with:
          name: sbom
          path: dist/sbom.cdx.json
          retention-days: 7
```

`if: always()` keeps the artifact even when the severity gate fails the step — that is exactly the run you want the evidence from.

### SAST, Publishing SARIF to Code Scanning

```yaml
    permissions:
      security-events: write   # required by upload-sarif
      contents: read
    steps:
      # …

      - name: Static analysis
        run: vulnetix sast --severity high -o dist/sast.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: dist/sast.sarif
```

### Secrets, Publishing SARIF

A clean secrets scan writes no file, so tolerate the missing path rather than failing the job.

```yaml
      - name: Secret detection
        run: vulnetix secrets -o dist/secrets.sarif

      - uses: actions/upload-artifact@v6
        if: always()
        with:
          name: secrets
          path: dist/secrets.sarif
          if-no-files-found: warn
          retention-days: 7
```

### Containers, Publishing SARIF

```yaml
      - name: Container analysis
        run: vulnetix containers -o dist/containers.sarif

      - uses: actions/upload-artifact@v6
        if: always()
        with:
          name: containers
          path: dist/containers.sarif
          if-no-files-found: warn
```

### IaC, Publishing SARIF

```yaml
      - name: Infrastructure as Code analysis
        run: vulnetix iac -o dist/iac.sarif

      - uses: actions/upload-artifact@v6
        if: always()
        with:
          name: iac
          path: dist/iac.sarif
          if-no-files-found: warn
```

### License, Publishing CycloneDX and SPDX

`license` has no `--output-file`. Copy its CycloneDX out of `.vulnetix/`, and redirect stdout for the SPDX view.

```yaml
      - name: License analysis
        run: |
          mkdir -p dist
          vulnetix license --allow MIT,Apache-2.0,BSD-3-Clause
          cp .vulnetix/sbom.cdx.json dist/licenses.cdx.json
          vulnetix license --allow MIT,Apache-2.0,BSD-3-Clause -o json-spdx > dist/licenses.spdx.json

      - uses: actions/upload-artifact@v6
        if: always()
        with:
          name: licenses
          path: dist/licenses.*.json
```

### CBOM, Publishing CycloneDX

```yaml
      - name: Cryptography inventory
        run: vulnetix cbom --output-file dist/cbom.cdx.json --fail-on quantum-vulnerable

      - uses: actions/upload-artifact@v6
        if: always()
        with:
          name: cbom
          path: dist/cbom.cdx.json
```

### AIBOM, Publishing CycloneDX

```yaml
      - name: AI usage inventory
        run: vulnetix aibom --output-file dist/aibom.cdx.json

      - uses: actions/upload-artifact@v6
        with:
          name: aibom
          path: dist/aibom.cdx.json
```

### Malscan, Publishing SARIF

```yaml
      - name: Malware scan
        run: vulnetix malscan --output-file dist/malscan.sarif

      - uses: actions/upload-artifact@v6
        if: always()
        with:
          name: malscan
          path: dist/malscan.sarif
          if-no-files-found: warn
```

---

## Level 4 — Run Them in Parallel

Independent scans belong in independent jobs. A matrix gives you one job per subcommand, a separate log per scan, and `fail-fast: false` so one breached gate does not cancel the others.

```yaml
name: Vulnetix Analysis
on: [push, pull_request]

env:
  VULNETIX_VERSION: v3.59.4

jobs:
  analyze:
    name: ${{ matrix.name }}
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
      issues: read
    env:
      VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
      VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
      GITHUB_TOKEN: ${{ github.token }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - id: sca
            name: SCA
            run: vulnetix sca --severity high -o dist/sbom.cdx.json
            artifact: dist/sbom.cdx.json
          - id: secrets
            name: Secrets
            run: vulnetix secrets -o dist/secrets.sarif
            artifact: dist/secrets.sarif
          - id: license
            name: Licenses
            run: vulnetix license && cp .vulnetix/sbom.cdx.json dist/licenses.cdx.json
            artifact: dist/licenses.cdx.json
          - id: cbom
            name: CBOM
            run: vulnetix cbom --output-file dist/cbom.cdx.json
            artifact: dist/cbom.cdx.json
          - id: aibom
            name: AIBOM
            run: vulnetix aibom --output-file dist/aibom.cdx.json
            artifact: dist/aibom.cdx.json
          - id: analyze
            name: Analyze
            run: vulnetix analyze --output-file dist/analyze.report.json
            artifact: dist/analyze.report.json

    steps:
      - uses: actions/checkout@v5

      - name: Install Vulnetix CLI
        run: |
          curl -fsSL https://cli.vulnetix.com/install.sh \
            | sh -s -- --install-dir "$HOME/.local/bin" --version "$VULNETIX_VERSION"
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

      - name: Run ${{ matrix.name }}
        run: |
          mkdir -p dist
          ${{ matrix.run }}

      - name: Upload ${{ matrix.name }} artifact
        if: always()
        uses: actions/upload-artifact@v6
        with:
          name: ${{ matrix.id }}
          path: ${{ matrix.artifact }}
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7
```

### Collecting Everything into Vulnetix

`task: gha` downloads **every** artifact of the current workflow run and uploads it to Vulnetix. Run it in a final job that `needs:` the scan jobs. It requires `actions: read` and a `GITHUB_TOKEN`.

```yaml
  collect:
    runs-on: ubuntu-latest
    needs: [analyze]
    permissions:
      contents: read
      actions: read
    steps:
      - uses: actions/checkout@v5

      - uses: actions/setup-go@v6
        with:
          go-version: stable

      - name: Upload all run artifacts to Vulnetix
        uses: Vulnetix/cli@v3.59.4
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          api-key: ${{ secrets.VULNETIX_API_KEY }}
          task: gha
        env:
          GITHUB_TOKEN: ${{ github.token }}
```

To upload one specific file instead, use `task: upload`:

```yaml
      - uses: Vulnetix/cli@v3.59.4
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          api-key: ${{ secrets.VULNETIX_API_KEY }}
          task: upload
          upload-file: dist/sbom.cdx.json
          upload-format: cyclonedx
```

---

## Level 5 — Ship the Artifacts with a GitHub Release

The full pipeline: generate everything in parallel, send it all to Vulnetix, and attach the result files to the published GitHub Release so consumers can fetch your SBOM, CBOM, AIBOM, license report, and secret-scan SARIF alongside the tarball.

The `publish` job needs `contents: write` to upload release assets.

```yaml
name: Release Artifacts
on:
  release:
    types: [published]
  workflow_dispatch:

env:
  VULNETIX_VERSION: v3.59.4

jobs:
  analyze:
    name: ${{ matrix.name }}
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
      issues: read
    env:
      VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
      VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
      GITHUB_TOKEN: ${{ github.token }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - id: sbom
            name: SBOM
            run: vulnetix sca -o dist/myproject.sbom.cdx.json
            artifact: dist/myproject.sbom.cdx.json
          - id: cbom
            name: CBOM
            run: vulnetix cbom --output-file dist/myproject.cbom.cdx.json
            artifact: dist/myproject.cbom.cdx.json
          - id: aibom
            name: AIBOM
            run: vulnetix aibom --output-file dist/myproject.aibom.cdx.json
            artifact: dist/myproject.aibom.cdx.json
          - id: license
            name: Licenses
            run: vulnetix license && cp .vulnetix/sbom.cdx.json dist/myproject.licenses.cdx.json
            artifact: dist/myproject.licenses.cdx.json
          - id: secrets
            name: Secrets
            run: vulnetix secrets -o dist/myproject.secrets.sarif || true
            artifact: dist/myproject.secrets.sarif
          - id: analyze
            name: Analyze
            run: vulnetix analyze --output-file dist/myproject.analyze.report.json
            artifact: dist/myproject.analyze.report.json

    steps:
      - uses: actions/checkout@v5

      - name: Install Vulnetix CLI
        run: |
          curl -fsSL https://cli.vulnetix.com/install.sh \
            | sh -s -- --install-dir "$HOME/.local/bin" --version "$VULNETIX_VERSION"
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"

      - name: Run ${{ matrix.name }}
        run: |
          mkdir -p dist
          ${{ matrix.run }}

      - name: Upload ${{ matrix.name }} artifact
        if: always()
        uses: actions/upload-artifact@v6
        with:
          name: ${{ matrix.id }}
          path: ${{ matrix.artifact }}
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

  publish:
    runs-on: ubuntu-latest
    needs: [analyze]
    permissions:
      contents: write   # required to upload release assets
      actions: read     # required by task: gha
    steps:
      - uses: actions/checkout@v5

      - uses: actions/setup-go@v6
        with:
          go-version: stable

      - name: Upload all run artifacts to Vulnetix
        uses: Vulnetix/cli@v3.59.4
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          api-key: ${{ secrets.VULNETIX_API_KEY }}
          task: gha
        env:
          GITHUB_TOKEN: ${{ github.token }}

      - name: Download all scan artifacts
        if: github.event_name == 'release'
        uses: actions/download-artifact@v6
        with:
          path: release-assets
          merge-multiple: true

      - name: Attach artifacts to the GitHub Release
        if: github.event_name == 'release'
        run: gh release upload "$TAG" release-assets/* --clobber
        env:
          GH_TOKEN: ${{ github.token }}
          TAG: ${{ github.event.release.tag_name }}
```

Notes on this workflow:

- `merge-multiple: true` flattens every downloaded artifact into `release-assets/`, so `gh release upload release-assets/*` picks up all of them in one call.
- `--clobber` lets a re-run replace assets already attached to the release instead of erroring.
- `|| true` on the secrets scan keeps the matrix leg green when the scan is clean and writes no SARIF. Drop it if you want a leaked secret to block the release.
- Run `task: gha` **after** the scan jobs so the artifacts exist and can be collected.

---

## Quality Gates

Any scan can fail the workflow. Gates are opt-in — without a gate flag the command reports and exits `0`.

```yaml
      - name: Scan with gates
        run: vulnetix scan --severity high --block-eol --block-malware --exploits active --version-lag 1 --cooldown 3
        env:
          VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
          VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
```

Available gates: `--severity`, `--block-eol`, `--block-malware`, `--block-unpinned`, `--exploits`, `--version-lag`, `--cooldown`. See the [Scan Command Reference]({{< relref "scan" >}}).

`--block-malware` gates on the known-malicious-package verdict **and** the in-process [malscan]({{< relref "malscan" >}}) pass over the installed dependency bytes.

## Custom SAST Rules

Load additional Rego rule packs from a repository. See [Custom Rule Repositories](../sast-rules/custom-rules/) for private repos and SSH access.

```yaml
      - name: Scan with custom SAST rules
        run: vulnetix scan --severity high --rule myorg/security-rules -o results.sarif
        env:
          VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
          VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
          GITHUB_TOKEN: ${{ github.token }}
```

## Permissions Reference

| Permission | Needed for |
|------------|-----------|
| `contents: read` | Checkout (all workflows) |
| `actions: read` | `task: gha` — listing and downloading workflow artifacts |
| `security-events: write` | `github/codeql-action/upload-sarif` |
| `contents: write` | `gh release upload` |

Grant only what the job uses. Split release publishing into its own job so `contents: write` is not held by the scanning jobs.

## Troubleshooting

**`Please add actions/setup-go to your workflow before this action`** — the action compiles the CLI from source. Add `actions/setup-go@v6` before it, or drop the action and use the install script.

**Action reference not found** — there is no moving `v1`/`v2`/`v3` tag. Pin an exact release (`Vulnetix/cli@v3.59.4`) or, for unreleased changes, `Vulnetix/cli@main`.

**`GITHUB_TOKEN environment variable is required`** — `task: gha` reads `GITHUB_TOKEN` from the environment. Pass `env: { GITHUB_TOKEN: ${{ github.token }} }` on the step.

**Missing SARIF artifact after a clean scan** — expected. `sast`, `secrets`, `containers`, and `iac` write SARIF only when there are findings. Use `if-no-files-found: warn` on the upload step.

**Artifact collection finds nothing** — `task: gha` only sees artifacts already uploaded in the current run. Put it in a job with `needs:` on the jobs that call `actions/upload-artifact`.

**Corporate proxy** — set `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` at the job level; the CLI and the Go toolchain both honour them.

## Keeping This Page Honest

Everything above was verified against `Vulnetix/cli` `v3.59.4`. Flags, default output paths, and action inputs change between releases. If a snippet no longer works, [open an issue](https://github.com/Vulnetix/cli/issues/new) with the release you are on and we will correct the documentation.
