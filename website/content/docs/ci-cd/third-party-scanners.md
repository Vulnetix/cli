---
title: "Third-Party Scanners"
weight: 2
description: "Publish gosec, Semgrep, Trivy, Grype, Checkov, KICS and other scanner reports to Vulnetix from GitHub Actions, attributed to the tool that produced them."
---

{{< callout type="info" >}}
This page is generated from the same catalog `vulnetix gha setup` writes from, so every
example here is the exact job the command produces. Regenerate with `just gen-gha-setup`.
{{< /callout >}}

Vulnetix ingests reports from the scanners you already run. Each one is recorded
under its own name and version, in its own scan category, alongside your
first-party Vulnetix scans.

## The quickest way

From inside the repository:

```sh
vulnetix gha setup --list        # what is available
vulnetix gha setup gosec         # write the workflow
vulnetix gha setup trivy-fs      # add another; the first is kept
```

That writes `.github/workflows/vulnetix-scanners.yml`. Set two repository
secrets and push:

| Secret | Value |
|---|---|
| `VULNETIX_ORG_ID` | your organisation uuid |
| `VULNETIX_API_KEY` | an API key for that organisation |

After the run, `vulnetix gha status` reports what landed.

## How it fits together

Each scanner runs as its own job and uploads its report as a workflow artifact.
A single `publish` job then hands every artifact to Vulnetix at once.

Three details in that workflow are load-bearing, and all three fail silently
when they are wrong:

- **`publish` must depend on every scanner.** A job missing from `needs` still
  runs and still uploads its artifact, but the publish job may start before it
  finishes, and its report is never sent. Nothing in the log says so.
- **`publish` must set `if: always()`.** Without it, one failing scanner
  suppresses the publication of every other scanner's results.
- **`publish` needs `permissions: actions: read`.** That is what lets the CLI
  list the run's artifacts. Without it there is nothing to publish.

### Writing SARIF through a shell redirect

Several tools print SARIF to stdout, and the obvious `tool > out.sarif || true`
is wrong in three ways at once: stdout also carries the tool's own log lines,
`|| true` hides the exit code, and a failed run leaves a zero-byte or
half-written file. `if-no-files-found` cannot catch that last one, because the
file exists, so a broken scan gets uploaded as a report.

The generated jobs separate stderr, handle the exit codes that mean success
(terrascan exits `3` on violations and `5` when it finds no IaC; zizmor exits
`14` when it has findings), and validate the result with `jq`, deleting it if it
is not a SARIF document. A scanner that fails then produces no artifact rather
than a corrupt one.

## Versions

The Vulnetix CLI is installed **unpinned**: `install.sh` resolves the latest
release, so a workflow written today keeps working without anyone coming back
to bump a version.

The third-party scanners are **pinned**, because there a reproducible scan
matters more than being current: an unpinned scanner can change its output
shape without any change to your repository.

## Supported scanners

| Tool | Category | Report |
|---|---|---|
| [Checkov](#checkov) | IAC | `results.sarif` |
| [KICS](#kics) | IAC | `kics-out/results.sarif` |
| [Terrascan](#terrascan) | IAC | `terrascan.sarif` |
| [tfsec](#tfsec) | IAC | `tfsec.sarif` |
| [Trivy (config)](#trivy-config) | IAC | `trivy-config.sarif` |
| [Rust Clippy](#clippy) | LINT | `clippy.sarif` |
| [Hadolint](#hadolint) | OCI | `hadolint.sarif` |
| [gosec](#gosec) | SAST | `gosec.sarif` |
| [Semgrep](#semgrep) | SAST | `semgrep.sarif` |
| [zizmor](#zizmor) | SAST | `zizmor.sarif` |
| [Grype](#grype) | SCA | `grype.sarif` |
| [OSV-Scanner](#osv-scanner) | SCA | `osv.sarif` |
| [Syft](#syft) | SCA | `sbom.cdx.json` |
| [Trivy (filesystem)](#trivy-fs) | SCA | `trivy-fs.cdx.json`, `trivy-fs.sarif` |
| [Gitleaks](#gitleaks) | SECRETS | `gitleaks.sarif` |

### Checkov {#checkov}

Policy-as-code checks for Terraform, CloudFormation, Kubernetes and more.

{{< callout type="warning" >}}
Checkov writes its SARIF as results.sarif, the same filename KICS uses. Tool identity comes from the SARIF driver and the artifact name, never the filename.
{{< /callout >}}

```sh
vulnetix gha setup checkov
```

The job it adds:

```yaml
  checkov:
    name: Checkov (IaC)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run Checkov
        continue-on-error: true
        run: |
          python3 -m pip install --quiet --break-system-packages checkov
          checkov -d . -o sarif --output-file-path . --soft-fail || true
      - uses: actions/upload-artifact@v6
        with:
          name: checkov
          path: results.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### KICS {#kics}

Infrastructure-as-code misconfiguration scanning.

```sh
vulnetix gha setup kics
```

The job it adds:

```yaml
  kics:
    name: KICS (IaC)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run KICS
        continue-on-error: true
        run: |
          mkdir -p kics-out
          docker run --rm -v "$PWD:/path" checkmarx/kics:v2.1.20 \
            scan -p /path -o /path/kics-out --report-formats sarif --no-progress || true
      - uses: actions/upload-artifact@v6
        with:
          name: kics
          path: kics-out/results.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Terrascan {#terrascan}

Terraform policy violations.

```sh
vulnetix gha setup terrascan
```

The job it adds:

```yaml
  terrascan:
    name: Terrascan (Terraform)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run Terrascan
        continue-on-error: true
        run: |
          set -uo pipefail
          # terrascan writes SARIF to stdout and logs to stderr, so the redirect must
          # separate them. Exit 3 means violations were found and 5 means no IaC was
          # present; neither is a failure of the scan itself.
          docker run --rm -v "$PWD:/iac" tenable/terrascan:1.19.9 \
            scan -i terraform -d /iac -o sarif >terrascan.sarif 2>terrascan.stderr
          rc=$?
          case "$rc" in
            0|3) ;;
            5)   echo "::notice::terrascan found no IaC files" ;;
            *)   echo "::warning::terrascan exited $rc"; sed -n '1,20p' terrascan.stderr ;;
          esac
          # Without this guard a failed run leaves a zero-byte or half-written file that
          # `if-no-files-found` cannot detect, and it gets published as a "SARIF report".
          if ! jq -e '.version and (.runs | type == "array")' terrascan.sarif >/dev/null 2>&1; then
            echo "::warning::terrascan produced no valid SARIF; dropping the artifact"
            rm -f terrascan.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: terrascan
          path: terrascan.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### tfsec {#tfsec}

Terraform static analysis. Upstream now recommends Trivy config.

```sh
vulnetix gha setup tfsec
```

The job it adds:

```yaml
  tfsec:
    name: tfsec (Terraform)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run tfsec
        continue-on-error: true
        uses: aquasecurity/tfsec-sarif-action@v0.1.4
        with:
          sarif_file: tfsec.sarif
      - uses: actions/upload-artifact@v6
        with:
          name: tfsec
          path: tfsec.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Trivy (config) {#trivy-config}

Misconfiguration scan of IaC and Dockerfiles.

{{< callout type="warning" >}}
The artifact name must stay "trivy-config" so this is not filed as an SCA scan; see the trivy-fs note.
{{< /callout >}}

```sh
vulnetix gha setup trivy-config
```

The job it adds:

```yaml
  trivy-config:
    name: Trivy config (IaC/Dockerfile)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Trivy config
        continue-on-error: true
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          format: sarif
          output: trivy-config.sarif
          scan-ref: .
          scan-type: config
      - uses: actions/upload-artifact@v6
        with:
          name: trivy-config
          path: trivy-config.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Rust Clippy {#clippy}

Rust lints, converted to SARIF.

```sh
vulnetix gha setup clippy
```

The job it adds:

```yaml
  clippy:
    name: Rust Clippy (SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run Clippy
        continue-on-error: true
        run: |
          set -uo pipefail
          rustup component add clippy
          cargo install clippy-sarif sarif-fmt
          # cargo clippy exits non-zero when it emits warnings, which is a successful run.
          cargo clippy --all-targets --all-features --message-format=json \
            | clippy-sarif >clippy.sarif 2>clippy.stderr
          if ! jq -e '.version and (.runs | type == "array")' clippy.sarif >/dev/null 2>&1; then
            echo "::warning::clippy produced no valid SARIF; dropping the artifact"
            sed -n '1,20p' clippy.stderr
            rm -f clippy.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: clippy
          path: clippy.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Hadolint {#hadolint}

Dockerfile linting.

```sh
vulnetix gha setup hadolint
```

The job it adds:

```yaml
  hadolint:
    name: Hadolint (Dockerfile)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run Hadolint
        continue-on-error: true
        uses: hadolint/hadolint-action@v3.1.0
        with:
          dockerfile: Dockerfile
          format: sarif
          no-fail: true
          output-file: hadolint.sarif
      - uses: actions/upload-artifact@v6
        with:
          name: hadolint
          path: hadolint.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### gosec {#gosec}

Go static analysis for common security mistakes.

```sh
vulnetix gha setup gosec
```

The job it adds:

```yaml
  gosec:
    name: gosec (Go SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run gosec
        continue-on-error: true
        uses: securego/gosec@v2.28.0
        with:
          args: -no-fail -fmt sarif -out gosec.sarif ./...
      - uses: actions/upload-artifact@v6
        with:
          name: gosec
          path: gosec.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Semgrep {#semgrep}

Multi-language static analysis with community rulesets.

```sh
vulnetix gha setup semgrep
```

The job it adds:

```yaml
  semgrep:
    name: Semgrep (SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run Semgrep
        continue-on-error: true
        run: |
          python3 -m pip install --quiet --break-system-packages semgrep
          semgrep scan --config auto --sarif --output semgrep.sarif .
      - uses: actions/upload-artifact@v6
        with:
          name: semgrep
          path: semgrep.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### zizmor {#zizmor}

Finds security problems in the workflows themselves.

```sh
vulnetix gha setup zizmor
```

The job it adds:

```yaml
  zizmor:
    name: zizmor (GitHub Actions SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run zizmor
        continue-on-error: true
        env:
          GH_TOKEN: '${{ github.token }}'
        run: |
          set -uo pipefail
          python3 -m pip install --quiet --break-system-packages zizmor
          # zizmor exits 14 when it has findings, which is a successful scan.
          zizmor --format sarif . >zizmor.sarif 2>zizmor.stderr
          rc=$?
          if [ "$rc" -ne 0 ] && [ "$rc" -ne 14 ]; then
            echo "::warning::zizmor exited $rc"; sed -n '1,20p' zizmor.stderr
          fi
          if ! jq -e '.version and (.runs | type == "array")' zizmor.sarif >/dev/null 2>&1; then
            echo "::warning::zizmor produced no valid SARIF; dropping the artifact"
            rm -f zizmor.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: zizmor
          path: zizmor.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Grype {#grype}

Vulnerability matching against the installed dependency set.

```sh
vulnetix gha setup grype
```

The job it adds:

```yaml
  grype:
    name: Grype (SCA)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run Grype
        id: grype
        continue-on-error: true
        uses: anchore/scan-action@v7
        with:
          fail-build: false
          output-format: sarif
          path: .
      - name: Stage Grype SARIF
        continue-on-error: true
        run: |
          cp "${{ steps.grype.outputs.sarif }}" grype.sarif
      - uses: actions/upload-artifact@v6
        with:
          name: grype
          path: grype.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### OSV-Scanner {#osv-scanner}

Dependency vulnerabilities from the OSV database.

```sh
vulnetix gha setup osv-scanner
```

The job it adds:

```yaml
  osv-scanner:
    name: OSV-Scanner (SCA)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run OSV-Scanner
        continue-on-error: true
        uses: google/osv-scanner-action/osv-scanner-action@v2.3.8
        with:
          scan-args: |-
            --format=sarif
            --output=osv.sarif
            ./
      - uses: actions/upload-artifact@v6
        with:
          name: osv-scanner
          path: osv.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Syft {#syft}

CycloneDX software bill of materials.

```sh
vulnetix gha setup syft
```

The job it adds:

```yaml
  syft:
    name: Syft (CycloneDX SBOM)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Generate CycloneDX SBOM
        continue-on-error: true
        uses: anchore/sbom-action@v0.24.0
        with:
          artifact-name: sbom.cdx.json
          format: cyclonedx-json
          output-file: sbom.cdx.json
          path: .
      - uses: actions/upload-artifact@v6
        with:
          name: syft
          path: sbom.cdx.json
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Trivy (filesystem) {#trivy-fs}

Dependency scan of the checked-out tree, as both CycloneDX and SARIF.

{{< callout type="warning" >}}
Trivy reports the driver name "Trivy" for every scan mode, so the artifact name is the only thing that distinguishes a filesystem scan from a config scan. Keep it.
{{< /callout >}}

```sh
vulnetix gha setup trivy-fs
```

The job it adds:

```yaml
  trivy-fs:
    name: Trivy (filesystem CDX + SARIF)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Trivy filesystem (CycloneDX)
        continue-on-error: true
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          format: cyclonedx
          output: trivy-fs.cdx.json
          scan-ref: .
          scan-type: fs
      - name: Trivy filesystem (SARIF)
        continue-on-error: true
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          format: sarif
          output: trivy-fs.sarif
          scan-ref: .
          scan-type: fs
      - uses: actions/upload-artifact@v6
        with:
          name: trivy-fs
          path: |
            trivy-fs.cdx.json
            trivy-fs.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Gitleaks {#gitleaks}

Hardcoded secret detection across the working tree and history.

```sh
vulnetix gha setup gitleaks
```

The job it adds:

```yaml
  gitleaks:
    name: Gitleaks (Secrets)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run Gitleaks
        continue-on-error: true
        run: |
          set -uo pipefail
          # Gitleaks exits 1 when it finds leaks, which is a successful scan.
          docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:v8.24.0 \
            detect --source /repo --report-format sarif --report-path /repo/gitleaks.sarif --no-git || true
          if ! jq -e '.version and (.runs | type == "array")' gitleaks.sarif >/dev/null 2>&1; then
            echo "::warning::gitleaks produced no valid SARIF; dropping the artifact"
            rm -f gitleaks.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: gitleaks
          path: gitleaks.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

## A complete workflow

Setting up several tools produces one file. This is `gosec`, `semgrep` and
`trivy-fs` together, verbatim:

```yaml
# Managed by `vulnetix gha setup`.
# Re-run `vulnetix gha setup <tool>` to add a scanner; edits here are overwritten.
#
# Each scanner runs independently and uploads its report as a workflow
# artifact. The publish job then hands every artifact to Vulnetix in one go,
# attributed to the tool that produced it.

name: Third-Party Scanners

on:
  push:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  gosec:
    name: gosec (Go SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run gosec
        continue-on-error: true
        uses: securego/gosec@v2.28.0
        with:
          args: -no-fail -fmt sarif -out gosec.sarif ./...
      - uses: actions/upload-artifact@v6
        with:
          name: gosec
          path: gosec.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

  semgrep:
    name: Semgrep (SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run Semgrep
        continue-on-error: true
        run: |
          python3 -m pip install --quiet --break-system-packages semgrep
          semgrep scan --config auto --sarif --output semgrep.sarif .
      - uses: actions/upload-artifact@v6
        with:
          name: semgrep
          path: semgrep.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

  trivy-fs:
    name: Trivy (filesystem CDX + SARIF)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Trivy filesystem (CycloneDX)
        continue-on-error: true
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          format: cyclonedx
          output: trivy-fs.cdx.json
          scan-ref: .
          scan-type: fs
      - name: Trivy filesystem (SARIF)
        continue-on-error: true
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          format: sarif
          output: trivy-fs.sarif
          scan-ref: .
          scan-type: fs
      - uses: actions/upload-artifact@v6
        with:
          name: trivy-fs
          path: |
            trivy-fs.cdx.json
            trivy-fs.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

  publish:
    name: Publish to Vulnetix
    runs-on: ubuntu-latest
    needs: [gosec, semgrep, trivy-fs]
    if: always()
    permissions:
      contents: read
      actions: read
    env:
      VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
      VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
    steps:
      - uses: actions/checkout@v5
      - name: Install Vulnetix CLI
        run: |
          curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --install-dir "$HOME/.local/bin"
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - name: Publish scanner reports
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: vulnetix gha upload --org-id "$VULNETIX_ORG_ID" --json --no-banner --no-progress
```

## Self-hosted runners

```sh
vulnetix gha setup gosec --runs-on self-hosted,Linux,X64
```

## Checking what landed

A green check is not proof that anything was published. `gha upload` exits
non-zero when a report fails to publish, and `gha status` reports what the run
actually recorded:

```sh
vulnetix gha status                    # the current run, inside a workflow
vulnetix gha status --run-id 30178087483
vulnetix gha status --json
```

Each tool appears with its own name, version, category and finding counts. A
tool you set up that is missing from that list did not publish.

## A tool that is not listed

Any scanner that writes SARIF, CycloneDX or SPDX can be published. Upload its
report as an artifact and the publish job picks it up. The catalog exists to
save you writing the job, not to restrict what Vulnetix accepts.

The category and the tool's identity are read from the report itself, so a
scanner Vulnetix has never seen is still attributed correctly.
