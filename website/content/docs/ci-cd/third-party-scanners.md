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
| [Conftest](#conftest) | COMPLIANCE | `conftest.sarif` |
| [OWASP ZAP](#owasp-zap) | DAST | `owasp-zap.sarif` |
| [cfn-lint](#cfn-lint) | IAC | `cfn-lint.sarif` |
| [Checkov](#checkov) | IAC | `results.sarif` |
| [KICS](#kics) | IAC | `kics-out/results.sarif` |
| [KubeLinter](#kube-linter) | IAC | `kube-linter.sarif` |
| [Kubescape](#kubescape) | IAC | `kubescape.sarif` |
| [Regula](#regula) | IAC | `regula.sarif` |
| [Snyk IaC](#snyk-iac) | IAC | `snyk-iac.sarif` |
| [Terrascan](#terrascan) | IAC | `terrascan.sarif` |
| [TFLint](#tflint) | IAC | `tflint.sarif` |
| [tfsec](#tfsec) | IAC | `tfsec.sarif` |
| [Trivy (config)](#trivy-config) | IAC | `trivy-config.sarif` |
| [ScanCode Toolkit](#scancode) | LICENSE | `scancode.cdx.json` |
| [Rust Clippy](#clippy) | LINT | `clippy.sarif` |
| [ESLint](#eslint) | LINT | `eslint.sarif` |
| [golangci-lint](#golangci-lint) | LINT | `golangci-lint.sarif` |
| [RuboCop](#rubocop) | LINT | `rubocop.sarif` |
| [Ruff](#ruff) | LINT | `ruff.sarif` |
| [ShellCheck](#shellcheck) | LINT | `shellcheck.sarif` |
| [Stylelint](#stylelint) | LINT | `stylelint.sarif` |
| [SwiftLint](#swiftlint) | LINT | `swiftlint.sarif` |
| [mobsfscan](#mobsfscan) | MOBILE | `mobsfscan.sarif` |
| [Dockle](#dockle) | OCI | `dockle.sarif` |
| [Grype (image)](#grype-image) | OCI | `grype-image.sarif` |
| [Hadolint](#hadolint) | OCI | `hadolint.sarif` |
| [Snyk Container](#snyk-container) | OCI | `snyk-container.sarif` |
| [Syft (image)](#syft-image) | OCI | `syft-image.cdx.json` |
| [Trivy (image)](#trivy-image) | OCI | `trivy-image.sarif` |
| [Nuclei](#nuclei) | PENTEST | `nuclei.sarif` |
| [Bandit](#bandit) | SAST | `bandit.sarif` |
| [Bearer CLI](#bearer) | SAST | `bearer.sarif` |
| [Brakeman](#brakeman) | SAST | `brakeman.sarif` |
| [Cppcheck](#cppcheck) | SAST | `cppcheck.sarif` |
| [detekt](#detekt) | SAST | `detekt.sarif` |
| [Flawfinder](#flawfinder) | SAST | `flawfinder.sarif` |
| [gosec](#gosec) | SAST | `gosec.sarif` |
| [njsscan](#njsscan) | SAST | `njsscan.sarif` |
| [OpenGrep](#opengrep) | SAST | `opengrep.sarif` |
| [PMD](#pmd) | SAST | `pmd-report.sarif` |
| [Psalm](#psalm) | SAST | `psalm.sarif` |
| [Semgrep](#semgrep) | SAST | `semgrep.sarif` |
| [Snyk Code](#snyk-code) | SAST | `snyk-code.sarif` |
| [zizmor](#zizmor) | SAST | `zizmor.sarif` |
| [cdxgen](#cdxgen) | SCA | `cdxgen.cdx.json` |
| [CycloneDX .NET](#cyclonedx-dotnet) | SCA | `cyclonedx-dotnet.cdx.json` |
| [CycloneDX Go](#cyclonedx-go) | SCA | `cyclonedx-go.cdx.json` |
| [CycloneDX Maven Plugin](#cyclonedx-maven) | SCA | `cyclonedx-maven.cdx.json` |
| [CycloneDX npm](#cyclonedx-node) | SCA | `cyclonedx-node.cdx.json` |
| [CycloneDX PHP](#cyclonedx-php) | SCA | `cyclonedx-php.cdx.json` |
| [CycloneDX Python](#cyclonedx-python) | SCA | `cyclonedx-python.cdx.json` |
| [CycloneDX Ruby](#cyclonedx-ruby) | SCA | `cyclonedx-ruby.cdx.json` |
| [CycloneDX Rust](#cyclonedx-rust) | SCA | `cyclonedx-rust.cdx.json` |
| [GitHub SBOM Export](#github-sbom) | SCA | `github-sbom.spdx.json` |
| [govulncheck](#govulncheck) | SCA | `govulncheck.sarif` |
| [Grype](#grype) | SCA | `grype.sarif` |
| [npm audit](#npm-audit) | SCA | `npm-audit.sarif` |
| [OSV-Scanner](#osv-scanner) | SCA | `osv.sarif` |
| [OWASP Dependency-Check](#owasp-dependency-check) | SCA | `dependency-check.sarif` |
| [Retire.js](#retirejs) | SCA | `retirejs.cdx.json` |
| [Snyk Open Source](#snyk-oss) | SCA | `snyk-oss.sarif` |
| [Syft](#syft) | SCA | `sbom.cdx.json` |
| [Trivy (filesystem)](#trivy-fs) | SCA | `trivy-fs.cdx.json`, `trivy-fs.sarif` |
| [CycloneDX Yarn](#yarn-cyclonedx) | SCA | `yarn-cyclonedx.cdx.json` |
| [detect-secrets](#detect-secrets) | SECRETS | `detect-secrets-results.sarif` |
| [Gitleaks](#gitleaks) | SECRETS | `gitleaks.sarif` |
| [Nosey Parker](#noseyparker) | SECRETS | `noseyparker.sarif` |
| [TruffleHog](#trufflehog) | SECRETS | `trufflehog.sarif` |

### Conftest {#conftest}

Runs a repository's own Rego policies and their unit tests.

```sh
vulnetix gha setup conftest
```

The job it adds:

```yaml
  conftest:
    name: Conftest (Rego policy)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run Conftest
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          if ! find . -path ./.git -prune -o -type f -name '*.rego' -print | head -n 1 | grep -q .; then
            echo '::notice::no Rego policies found; skipping Conftest'
            exit 0
          fi
          version=0.62.0
          mkdir -p /tmp/conftest
          curl -fsSL "https://github.com/open-policy-agent/conftest/releases/download/v${version}/conftest_${version}_Linux_x86_64.tar.gz" \
            | tar -xz -C /tmp/conftest 2>/dev/null || true
          if [ ! -x /tmp/conftest/conftest ]; then
            echo '::warning::conftest could not be installed on this runner; skipping'
            exit 0
          fi
          # `verify` runs the policies' own *_test.rego suites, which is the check that
          # means something in a repository whose product IS the policy set.
          /tmp/conftest/conftest verify -p . -o sarif >conftest.sarif 2>conftest.stderr || true
          if ! jq -e '.version and (.runs | type == "array")' conftest.sarif >/dev/null 2>&1; then
            echo '::warning::conftest produced no valid SARIF; dropping the artifact'
            rm -f conftest.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: conftest
          path: conftest.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### OWASP ZAP {#owasp-zap}

Baseline dynamic scan of a running target. Runs only when ZAP_TARGET_URL is set.

{{< callout type="warning" >}}
ZAP's baseline script writes its own JSON, not SARIF, so it is converted here. Only ever point this at a target you are authorised to test.
{{< /callout >}}

```sh
vulnetix gha setup owasp-zap
```

The job it adds:

```yaml
  owasp-zap:
    name: OWASP ZAP (DAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run ZAP baseline
        continue-on-error: true
        env:
          ZAP_TARGET_URL: '${{ vars.ZAP_TARGET_URL }}'
        shell: bash --noprofile --norc {0}
        run: |
          # The converters below need only the standard library, but not every runner
          # image ships python3. uv carries its own interpreter, so this always resolves.
          PY=python3
          if ! command -v python3 >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
            PY="uv run --no-project --python 3.12 python"
          fi
          set -uo pipefail
          if [ -z "${ZAP_TARGET_URL:-}" ]; then
            echo '::notice::ZAP_TARGET_URL is not set; skipping OWASP ZAP'
            exit 0
          fi
          # -I so a warning does not fail the container; findings are the point.
          docker run --rm -v "$PWD:/zap/wrk/:rw" ghcr.io/zaproxy/zaproxy:2.16.1 \
            zap-baseline.py -t "$ZAP_TARGET_URL" -J zap.json -I >/dev/null 2>zap.stderr || true
          $PY <<'PY'
          import json
          import os

          sarif = {
              "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
              "version": "2.1.0",
              "runs": [{
                  "tool": {
                      "driver": {
                          "name": "OWASP ZAP",
                          "informationUri": "https://www.zaproxy.org/",
                          "rules": [],
                      }
                  },
                  "results": [],
              }],
          }
          rules_seen = set()
          # ZAP risk codes: 3 high, 2 medium, 1 low, 0 informational.
          level_map = {"3": "error", "2": "error", "1": "warning", "0": "note"}


          def add_rule(rule_id, name, desc):
              if rule_id in rules_seen:
                  return
              sarif["runs"][0]["tool"]["driver"]["rules"].append({
                  "id": rule_id,
                  "shortDescription": {"text": name[:200]},
                  "fullDescription": {"text": desc[:1000]},
                  "defaultConfiguration": {"level": "warning"},
              })
              rules_seen.add(rule_id)


          if os.path.exists("zap.json") and os.path.getsize("zap.json") > 0:
              with open("zap.json", "r", encoding="utf-8") as fh:
                  try:
                      data = json.load(fh)
                  except json.JSONDecodeError:
                      data = {}
              for site in data.get("site") or []:
                  for alert in site.get("alerts") or []:
                      rule_id = str(alert.get("pluginid") or alert.get("alertRef") or "zap")
                      name = str(alert.get("name") or rule_id)
                      add_rule(rule_id, name, str(alert.get("desc") or ""))
                      level = level_map.get(str(alert.get("riskcode") or "1"), "warning")
                      for instance in (alert.get("instances") or [{}]):
                          uri = str(instance.get("uri") or site.get("@name") or "unknown")
                          sarif["runs"][0]["results"].append({
                              "ruleId": rule_id,
                              "level": level,
                              "message": {"text": f"{name}: {instance.get('evidence') or alert.get('solution') or ''}".strip()},
                              "locations": [{
                                  "physicalLocation": {
                                      "artifactLocation": {"uri": uri},
                                      "region": {"startLine": 1},
                                  }
                              }],
                          })

          with open("owasp-zap.sarif", "w", encoding="utf-8") as fh:
              json.dump(sarif, fh, indent=2)
          PY
          if ! jq -e '.version and (.runs | type == "array")' owasp-zap.sarif >/dev/null 2>&1; then
            echo '::warning::owasp zap produced no valid SARIF; dropping the artifact'
            rm -f owasp-zap.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: owasp-zap
          path: owasp-zap.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### cfn-lint {#cfn-lint}

AWS CloudFormation template linter with SARIF output.

```sh
vulnetix gha setup cfn-lint
```

The job it adds:

```yaml
  cfn-lint:
    name: cfn-lint (CloudFormation IaC)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up uv
        continue-on-error: true
        uses: astral-sh/setup-uv@v6
      - name: Run cfn-lint
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! command -v uvx >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
          fi
          if ! command -v uvx >/dev/null 2>&1; then
            echo '::warning::uv is unavailable on this runner; skipping'
            exit 0
          fi
          templates=$(find . -path ./.git -prune -o -type f \( -name '*.template' -o -name '*.yaml' -o -name '*.yml' -o -name '*.json' \) -print)
          if [ -z "$templates" ]; then
            echo '::notice::no candidate CloudFormation templates found; skipping cfn-lint'
            exit 0
          fi
          uvx --from cfn-lint cfn-lint -f sarif -t $templates >cfn-lint.sarif 2>cfn-lint.stderr
          rc=$?
          if [ $rc -ne 0 ]; then
            echo "::warning::cfn-lint exited $rc"
            sed -n '1,20p' cfn-lint.stderr
          fi
          if ! jq -e '.version and (.runs | type == "array")' cfn-lint.sarif >/dev/null 2>&1; then
            echo '::warning::cfn-lint produced no valid SARIF; dropping the artifact'
            rm -f cfn-lint.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: cfn-lint
          path: cfn-lint.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

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
      - name: Set up uv
        continue-on-error: true
        uses: astral-sh/setup-uv@v6
      - name: Run Checkov
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! command -v uvx >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
          fi
          if ! command -v uvx >/dev/null 2>&1; then
            echo '::warning::uv is unavailable on this runner; skipping'
            exit 0
          fi
          uvx --from checkov checkov -d . -o sarif --output-file-path . --soft-fail || true
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
        shell: bash --noprofile --norc {0}
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

### KubeLinter {#kube-linter}

Kubernetes manifest and Helm chart misconfiguration checks.

```sh
vulnetix gha setup kube-linter
```

The job it adds:

```yaml
  kube-linter:
    name: KubeLinter (Kubernetes)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run KubeLinter
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          mkdir -p /tmp/kl
          curl -fsSL https://github.com/stackrox/kube-linter/releases/download/v0.7.6/kube-linter-linux.tar.gz \
            | tar -xz -C /tmp/kl 2>/dev/null || true
          if [ ! -x /tmp/kl/kube-linter ]; then
            echo '::warning::kube-linter could not be installed on this runner; skipping'
            exit 0
          fi
          # Exit 1 means findings.
          /tmp/kl/kube-linter lint --format sarif . >kube-linter.sarif 2>kube-linter.stderr || true
          if ! jq -e '.version and (.runs | type == "array")' kube-linter.sarif >/dev/null 2>&1; then
            echo '::warning::kube-linter produced no valid SARIF; dropping the artifact'
            rm -f kube-linter.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: kube-linter
          path: kube-linter.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Kubescape {#kubescape}

Kubernetes posture scanning against NSA, MITRE and CIS controls.

```sh
vulnetix gha setup kubescape
```

The job it adds:

```yaml
  kubescape:
    name: Kubescape (Kubernetes)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run Kubescape
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          curl -fsSL https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash >/dev/null 2>&1 || true
          export PATH="$HOME/.kubescape/bin:$HOME/.local/bin:/usr/local/bin:$PATH"
          if ! command -v kubescape >/dev/null 2>&1; then
            echo '::warning::kubescape could not be installed on this runner; skipping'
            exit 0
          fi
          kubescape scan . --format sarif --output kubescape.sarif >/dev/null 2>kubescape.stderr || true
          if ! jq -e '.version and (.runs | type == "array")' kubescape.sarif >/dev/null 2>&1; then
            echo '::warning::kubescape produced no valid SARIF; dropping the artifact'
            rm -f kubescape.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: kubescape
          path: kubescape.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Regula {#regula}

Rego-based policy checks over Terraform, CloudFormation and Kubernetes.

```sh
vulnetix gha setup regula
```

The job it adds:

```yaml
  regula:
    name: Regula (IaC policy)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run Regula
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          version=3.2.1
          mkdir -p /tmp/regula
          curl -fsSL "https://github.com/fugue/regula/releases/download/v${version}/regula_${version}_Linux_x86_64.tar.gz" \
            | tar -xz -C /tmp/regula 2>/dev/null || true
          if [ ! -x /tmp/regula/regula ]; then
            echo '::warning::regula could not be installed on this runner; skipping'
            exit 0
          fi
          # Exit 1 means policy violations.
          /tmp/regula/regula run --format sarif . >regula.sarif 2>regula.stderr || true
          if ! jq -e '.version and (.runs | type == "array")' regula.sarif >/dev/null 2>&1; then
            echo '::warning::regula produced no valid SARIF; dropping the artifact'
            rm -f regula.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: regula
          path: regula.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Snyk IaC {#snyk-iac}

Snyk's infrastructure-as-code scan. Runs only when SNYK_TOKEN is set.

```sh
vulnetix gha setup snyk-iac
```

The job it adds:

```yaml
  snyk-iac:
    name: Snyk IaC
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Node
        continue-on-error: true
        uses: actions/setup-node@v4
        with:
          node-version: 22
      - name: Run Snyk IaC
        continue-on-error: true
        env:
          SNYK_TOKEN: '${{ secrets.SNYK_TOKEN }}'
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          if [ -z "${SNYK_TOKEN:-}" ]; then
            echo '::notice::SNYK_TOKEN is not set; skipping Snyk IaC'
            exit 0
          fi
          npm install -g snyk >/dev/null 2>&1 || true
          snyk iac test --sarif-file-output=snyk-iac.sarif . 2>snyk-iac.stderr || true
          if ! jq -e '.version and (.runs | type == "array")' snyk-iac.sarif >/dev/null 2>&1; then
            echo '::warning::snyk iac produced no valid SARIF; dropping the artifact'
            rm -f snyk-iac.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: snyk-iac
          path: snyk-iac.sarif
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
        shell: bash --noprofile --norc {0}
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

### TFLint {#tflint}

Terraform linting, including provider-specific invalid-configuration checks.

```sh
vulnetix gha setup tflint
```

The job it adds:

```yaml
  tflint:
    name: TFLint (Terraform)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run TFLint
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          if ! find . -path ./.git -prune -o -type f -name '*.tf' -print | head -n 1 | grep -q .; then
            echo '::notice::no Terraform files found; skipping TFLint'
            exit 0
          fi
          curl -fsSL https://raw.githubusercontent.com/terraform-linters/tflint/master/install_linux.sh | bash >/dev/null 2>&1 || true
          export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"
          if ! command -v tflint >/dev/null 2>&1; then
            echo '::warning::tflint could not be installed on this runner; skipping'
            exit 0
          fi
          tflint --init >/dev/null 2>&1 || true
          # tflint exits 2 when it reports issues.
          tflint --recursive --format sarif >tflint.sarif 2>tflint.stderr || true
          if ! jq -e '.version and (.runs | type == "array")' tflint.sarif >/dev/null 2>&1; then
            echo '::warning::tflint produced no valid SARIF; dropping the artifact'
            rm -f tflint.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: tflint
          path: tflint.sarif
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

### ScanCode Toolkit {#scancode}

License, package, and copyright inventory exported as CycloneDX JSON.

```sh
vulnetix gha setup scancode
```

The job it adds:

```yaml
  scancode:
    name: ScanCode Toolkit (license SBOM)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up uv
        continue-on-error: true
        uses: astral-sh/setup-uv@v6
      - name: Run ScanCode Toolkit
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! command -v uvx >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
          fi
          if ! command -v uvx >/dev/null 2>&1; then
            echo '::warning::uv is unavailable on this runner; skipping'
            exit 0
          fi
          uvx --python 3.12 --from scancode-toolkit scancode --license --copyright --package --cyclonedx scancode.cdx.json . || true
          if ! jq -e '.bomFormat == "CycloneDX"' scancode.cdx.json >/dev/null 2>&1; then
            echo '::warning::scancode produced no valid CycloneDX JSON; dropping the artifact'
            rm -f scancode.cdx.json
          else
            # ScanCode writes explicit nulls for the fields it found nothing for — author,
            # description, version, copyright, externalReferences[].comment — and gives
            # some metadata properties array or object values. CycloneDX 1.3 types all of
            # those as strings, so the document fails schema validation on upload even
            # though the inventory in it is fine. A null key carries no information, so
            # dropping it loses nothing; a non-string property value becomes its JSON text.
            jq 'walk(if type == "object" then with_entries(select(.value != null)) else . end)
                | walk(if type == "object" and (.properties? | type) == "array"
                       then .properties |= map(if has("value") then .value |= (if type == "string" then . else tojson end) else . end)
                       else . end)' scancode.cdx.json > scancode.clean.json \
              && mv scancode.clean.json scancode.cdx.json
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: scancode
          path: scancode.cdx.json
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
        shell: bash --noprofile --norc {0}
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

### ESLint {#eslint}

JavaScript and TypeScript lint findings exported as SARIF.

```sh
vulnetix gha setup eslint
```

The job it adds:

```yaml
  eslint:
    name: ESLint (JavaScript lint)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Node.js
        continue-on-error: true
        uses: actions/setup-node@v4
        with:
          node-version: 'lts/*'
      - name: Run ESLint
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if [ ! -f package.json ]; then
            echo '::notice::no package.json found; skipping ESLint'
            exit 0
          fi
          if ! ls eslint.config.* .eslintrc .eslintrc.* >/dev/null 2>&1; then
            echo '::notice::no ESLint config found; skipping ESLint'
            exit 0
          fi
          if [ -f package-lock.json ]; then
            npm ci
          else
            npm install --no-audit --no-fund
          fi
          npm install --no-audit --no-fund --no-save @microsoft/eslint-formatter-sarif
          npx eslint -f @microsoft/eslint-formatter-sarif -o eslint.sarif . || true
          if ! jq -e '.version and (.runs | type == "array")' eslint.sarif >/dev/null 2>&1; then
            echo '::warning::eslint produced no valid SARIF; dropping the artifact'
            rm -f eslint.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: eslint
          path: eslint.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### golangci-lint {#golangci-lint}

Aggregated Go linter suite with SARIF output.

```sh
vulnetix gha setup golangci-lint
```

The job it adds:

```yaml
  golangci-lint:
    name: golangci-lint (Go lint)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Go
        continue-on-error: true
        uses: actions/setup-go@v6
        with:
          go-version: stable
      - name: Run golangci-lint
        continue-on-error: true
        env:
          GO_MODULE_PATTERN: '${{ vars.GO_MODULE_PATTERN }}'
          GO_MODULE_TOKEN: '${{ secrets.PACKAGES_TOKEN }}'
        shell: bash --noprofile --norc {0}
        run: |
          if [ -n "${GO_MODULE_TOKEN:-}" ]; then
            go env -w GOPRIVATE="${GO_MODULE_PATTERN:-github.com/$(echo "${GITHUB_REPOSITORY:-}" | cut -d/ -f1)/*}"
            git config --global url."https://x-access-token:${GO_MODULE_TOKEN}@github.com/".insteadOf "https://github.com/"
          fi
          if [ ! -f go.mod ]; then
            echo '::notice::no go.mod found; skipping golangci-lint'
            exit 0
          fi
          go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
          golangci-lint run --output.sarif.path=golangci-lint.sarif || true
          if ! jq -e '.version and (.runs | type == "array")' golangci-lint.sarif >/dev/null 2>&1; then
            echo '::warning::golangci-lint produced no valid SARIF; dropping the artifact'
            rm -f golangci-lint.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: golangci-lint
          path: golangci-lint.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### RuboCop {#rubocop}

Ruby lint and security cops converted from RuboCop JSON to SARIF.

```sh
vulnetix gha setup rubocop
```

The job it adds:

```yaml
  rubocop:
    name: RuboCop (Ruby lint)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Ruby
        continue-on-error: true
        uses: ruby/setup-ruby@v1
        with:
          ruby-version: ruby
      - name: Run RuboCop
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          # The converters below need only the standard library, but not every runner
          # image ships python3. uv carries its own interpreter, so this always resolves.
          PY=python3
          if ! command -v python3 >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
            PY="uv run --no-project --python 3.12 python"
          fi
          if ! find . -path ./.git -prune -o -type f -name '*.rb' -print | head -n 1 | grep -q .; then
            echo '::notice::no Ruby files found; skipping RuboCop'
            exit 0
          fi
          gem install rubocop
          rubocop --format github --out rubocop.github-actions.txt || true
          rubocop --format json --out rubocop.json || true
          $PY <<'PY'
          import json
          import os

          sarif = {
              "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
              "version": "2.1.0",
              "runs": [{
                  "tool": {
                      "driver": {
                          "name": "RuboCop",
                          "informationUri": "https://github.com/rubocop/rubocop",
                          "rules": [],
                      }
                  },
                  "results": [],
              }],
          }
          rules_seen = set()
          severity_map = {
              "fatal": "error",
              "error": "error",
              "warning": "warning",
              "refactor": "warning",
              "convention": "note",
              "info": "note",
          }

          def to_int(value):
              try:
                  return max(1, int(value))
              except (TypeError, ValueError):
                  return 1

          def add_rule(rule_id):
              if rule_id in rules_seen:
                  return
              sarif["runs"][0]["tool"]["driver"]["rules"].append({
                  "id": rule_id,
                  "shortDescription": {"text": rule_id},
                  "defaultConfiguration": {"level": "warning"},
              })
              rules_seen.add(rule_id)

          if os.path.exists("rubocop.json") and os.path.getsize("rubocop.json") > 0:
              with open("rubocop.json", "r", encoding="utf-8") as fh:
                  data = json.load(fh)
              version = str((data.get("metadata") or {}).get("rubocop_version") or "")
              if version:
                  sarif["runs"][0]["tool"]["driver"]["version"] = version
              for file_info in data.get("files") or []:
                  path = str(file_info.get("path") or "unknown")
                  for offense in file_info.get("offenses") or []:
                      rule_id = str(offense.get("cop_name") or "RuboCop")
                      add_rule(rule_id)
                      location = offense.get("location") or {}
                      level = severity_map.get(str(offense.get("severity") or "").lower(), "warning")
                      result = {
                          "ruleId": rule_id,
                          "level": level,
                          "message": {"text": str(offense.get("message") or rule_id)},
                          "locations": [{
                              "physicalLocation": {
                                  "artifactLocation": {"uri": path},
                                  "region": {
                                      "startLine": to_int(location.get("start_line")),
                                      "startColumn": to_int(location.get("start_column")),
                                  },
                              }
                          }],
                      }
                      end_line = location.get("last_line")
                      end_column = location.get("last_column")
                      if end_line:
                          result["locations"][0]["physicalLocation"]["region"]["endLine"] = to_int(end_line)
                      if end_column:
                          result["locations"][0]["physicalLocation"]["region"]["endColumn"] = to_int(end_column)
                      sarif["runs"][0]["results"].append(result)

          with open("rubocop.sarif", "w", encoding="utf-8") as fh:
              json.dump(sarif, fh, indent=2)
          PY
          if ! jq -e '.version and (.runs | type == "array")' rubocop.sarif >/dev/null 2>&1; then
            echo '::warning::rubocop produced no valid SARIF; dropping the artifact'
            rm -f rubocop.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: rubocop
          path: rubocop.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Ruff {#ruff}

Fast Python linter configured for security rules and SARIF output.

```sh
vulnetix gha setup ruff
```

The job it adds:

```yaml
  ruff:
    name: Ruff (Python lint)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up uv
        continue-on-error: true
        uses: astral-sh/setup-uv@v6
      - name: Run Ruff security rules
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! command -v uvx >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
          fi
          if ! command -v uvx >/dev/null 2>&1; then
            echo '::warning::uv is unavailable on this runner; skipping'
            exit 0
          fi
          if ! find . -path ./.git -prune -o -type f -name '*.py' -print | head -n 1 | grep -q .; then
            echo '::notice::no Python files found; skipping Ruff'
            exit 0
          fi
          uvx --from ruff ruff check --select S --output-format sarif -o ruff.sarif . || true
          if ! jq -e '.version and (.runs | type == "array")' ruff.sarif >/dev/null 2>&1; then
            echo '::warning::ruff produced no valid SARIF; dropping the artifact'
            rm -f ruff.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: ruff
          path: ruff.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### ShellCheck {#shellcheck}

Shell script analysis, including quoting and injection mistakes.

{{< callout type="warning" >}}
ShellCheck has no SARIF writer of its own, so its json1 output is converted here. The driver name must stay "ShellCheck" or the findings are attributed to nothing.
{{< /callout >}}

```sh
vulnetix gha setup shellcheck
```

The job it adds:

```yaml
  shellcheck:
    name: ShellCheck (shell lint)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run ShellCheck
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          # The converters below need only the standard library, but not every runner
          # image ships python3. uv carries its own interpreter, so this always resolves.
          PY=python3
          if ! command -v python3 >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
            PY="uv run --no-project --python 3.12 python"
          fi
          set -uo pipefail
          scripts=$(find . -path ./.git -prune -o -type f \( -name '*.sh' -o -name '*.bash' \) -print)
          if [ -z "$scripts" ]; then
            echo '::notice::no shell scripts found; skipping ShellCheck'
            exit 0
          fi
          if ! command -v shellcheck >/dev/null 2>&1; then
            version=0.11.0
            mkdir -p /tmp/sc
            curl -fsSL "https://github.com/koalaman/shellcheck/releases/download/v${version}/shellcheck-v${version}.linux.x86_64.tar.xz" \
              | tar -xJ -C /tmp/sc 2>/dev/null || true
            export PATH="/tmp/sc/shellcheck-v${version}:$PATH"
          fi
          if ! command -v shellcheck >/dev/null 2>&1; then
            echo '::warning::shellcheck could not be installed on this runner; skipping'
            exit 0
          fi
          # shellcheck exits 1 when it reports anything, which is a successful run.
          # shellcheck disable=SC2086
          shellcheck -f json1 $scripts >shellcheck.json 2>shellcheck.stderr || true
          $PY <<'PY'
          import json
          import os

          sarif = {
              "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
              "version": "2.1.0",
              "runs": [{
                  "tool": {
                      "driver": {
                          "name": "ShellCheck",
                          "informationUri": "https://www.shellcheck.net/",
                          "rules": [],
                      }
                  },
                  "results": [],
              }],
          }
          rules_seen = set()
          level_map = {"error": "error", "warning": "warning", "info": "note", "style": "note"}


          def to_int(value):
              try:
                  return max(1, int(value))
              except (TypeError, ValueError):
                  return 1


          def add_rule(rule_id, comment):
              if rule_id in rules_seen:
                  return
              sarif["runs"][0]["tool"]["driver"]["rules"].append({
                  "id": rule_id,
                  "shortDescription": {"text": comment[:200]},
                  "helpUri": f"https://www.shellcheck.net/wiki/{rule_id}",
                  "defaultConfiguration": {"level": "warning"},
              })
              rules_seen.add(rule_id)


          if os.path.exists("shellcheck.json") and os.path.getsize("shellcheck.json") > 0:
              with open("shellcheck.json", "r", encoding="utf-8") as fh:
                  try:
                      data = json.load(fh)
                  except json.JSONDecodeError:
                      data = {}
              for item in data.get("comments") or []:
                  rule_id = "SC%s" % item.get("code")
                  message = str(item.get("message") or rule_id)
                  add_rule(rule_id, message)
                  sarif["runs"][0]["results"].append({
                      "ruleId": rule_id,
                      "level": level_map.get(str(item.get("level") or "").lower(), "warning"),
                      "message": {"text": message},
                      "locations": [{
                          "physicalLocation": {
                              "artifactLocation": {"uri": str(item.get("file") or "unknown")},
                              "region": {
                                  "startLine": to_int(item.get("line")),
                                  "startColumn": to_int(item.get("column")),
                              },
                          }
                      }],
                  })

          with open("shellcheck.sarif", "w", encoding="utf-8") as fh:
              json.dump(sarif, fh, indent=2)
          PY
          if ! jq -e '.version and (.runs | type == "array")' shellcheck.sarif >/dev/null 2>&1; then
            echo '::warning::shellcheck produced no valid SARIF; dropping the artifact'
            rm -f shellcheck.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: shellcheck
          path: shellcheck.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Stylelint {#stylelint}

CSS and preprocessor lint findings exported as SARIF.

```sh
vulnetix gha setup stylelint
```

The job it adds:

```yaml
  stylelint:
    name: Stylelint (CSS lint)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Node.js
        continue-on-error: true
        uses: actions/setup-node@v4
        with:
          node-version: 'lts/*'
      - name: Run Stylelint
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! find . -path ./.git -prune -o -type f -print | grep -E '\.(css|scss|less)$' | head -n 1 | grep -q .; then
            echo '::notice::no CSS files found; skipping Stylelint'
            exit 0
          fi
          if ! ls .stylelintrc* stylelint.config.* >/dev/null 2>&1; then
            echo '::notice::no Stylelint config found; skipping Stylelint'
            exit 0
          fi
          npm install --no-audit --no-fund --no-save stylelint stylelint-sarif-formatter
          npx stylelint '**/*.{css,scss,less}' --custom-formatter=node_modules/stylelint-sarif-formatter -o stylelint.sarif || true
          if ! jq -e '.version and (.runs | type == "array")' stylelint.sarif >/dev/null 2>&1; then
            echo '::warning::stylelint produced no valid SARIF; dropping the artifact'
            rm -f stylelint.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: stylelint
          path: stylelint.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### SwiftLint {#swiftlint}

Swift code quality findings using SwiftLint native SARIF output.

```sh
vulnetix gha setup swiftlint
```

The job it adds:

```yaml
  swiftlint:
    name: SwiftLint (Swift lint)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run SwiftLint
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! find . -path ./.git -prune -o -type f -name '*.swift' -print | head -n 1 | grep -q .; then
            echo '::notice::no Swift files found; skipping SwiftLint'
            exit 0
          fi
          version=$(curl -fsSL https://api.github.com/repos/realm/SwiftLint/releases/latest | jq -r '.tag_name | ltrimstr("v")')
          if [ -z "$version" ] || [ "$version" = "null" ]; then
            echo '::warning::could not resolve latest SwiftLint container version; skipping SwiftLint'
            exit 0
          fi
          docker run --rm -v "$PWD:/work" -w /work "ghcr.io/realm/swiftlint:${version}" lint --reporter sarif >swiftlint.sarif || true
          if ! jq -e '.version and (.runs | type == "array")' swiftlint.sarif >/dev/null 2>&1; then
            echo '::warning::swiftlint produced no valid SARIF; dropping the artifact'
            rm -f swiftlint.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: swiftlint
          path: swiftlint.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### mobsfscan {#mobsfscan}

Static analysis of Android and iOS application source for insecure patterns.

```sh
vulnetix gha setup mobsfscan
```

The job it adds:

```yaml
  mobsfscan:
    name: mobsfscan (Mobile SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up uv
        continue-on-error: true
        uses: astral-sh/setup-uv@v6
      - name: Run mobsfscan
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! command -v uvx >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
          fi
          if ! command -v uvx >/dev/null 2>&1; then
            echo '::warning::uv is unavailable on this runner; skipping'
            exit 0
          fi
          set -uo pipefail
          # mobsfscan exits 1 when it reports findings.
          uvx --from mobsfscan mobsfscan --sarif -o mobsfscan.sarif . 2>mobsfscan.stderr || true
          if ! jq -e '.version and (.runs | type == "array")' mobsfscan.sarif >/dev/null 2>&1; then
            echo '::warning::mobsfscan produced no valid SARIF; dropping the artifact'
            rm -f mobsfscan.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: mobsfscan
          path: mobsfscan.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Dockle {#dockle}

Container image best-practice scanner with SARIF output.

```sh
vulnetix gha setup dockle
```

The job it adds:

```yaml
  dockle:
    name: Dockle (container image)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Go
        continue-on-error: true
        uses: actions/setup-go@v6
        with:
          go-version: stable
      - name: Run Dockle
        continue-on-error: true
        env:
          GO_MODULE_PATTERN: '${{ vars.GO_MODULE_PATTERN }}'
          GO_MODULE_TOKEN: '${{ secrets.PACKAGES_TOKEN }}'
        shell: bash --noprofile --norc {0}
        run: |
          if [ -n "${GO_MODULE_TOKEN:-}" ]; then
            go env -w GOPRIVATE="${GO_MODULE_PATTERN:-github.com/$(echo "${GITHUB_REPOSITORY:-}" | cut -d/ -f1)/*}"
            git config --global url."https://x-access-token:${GO_MODULE_TOKEN}@github.com/".insteadOf "https://github.com/"
          fi
          if [ ! -f Dockerfile ] && [ ! -f Containerfile ]; then
            echo '::notice::no Dockerfile or Containerfile found; skipping Dockle'
            exit 0
          fi
          dockerfile=Dockerfile
          if [ -f Containerfile ]; then
            dockerfile=Containerfile
          fi
          image="vulnetix-dockle:${GITHUB_SHA:-local}"
          docker build -f "$dockerfile" -t "$image" .
          go install github.com/goodwithtech/dockle/cmd/dockle@latest
          dockle --format sarif --output dockle.sarif "$image" || true
          if ! jq -e '.version and (.runs | type == "array")' dockle.sarif >/dev/null 2>&1; then
            echo '::warning::dockle produced no valid SARIF; dropping the artifact'
            rm -f dockle.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: dockle
          path: dockle.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Grype (image) {#grype-image}

Vulnerability matching against the packages inside the built image.

{{< callout type="warning" >}}
"grype-image" rather than "grype": the artifact name is what files this as a container scan instead of a dependency scan.
{{< /callout >}}

```sh
vulnetix gha setup grype-image
```

The job it adds:

```yaml
  grype-image:
    name: Grype image (OCI)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Build the image
        id: build
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if [ ! -f Dockerfile ] && [ ! -f Containerfile ]; then
            echo '::notice::no Dockerfile or Containerfile found; skipping'
            exit 0
          fi
          dockerfile=Dockerfile
          if [ -f Containerfile ]; then
            dockerfile=Containerfile
          fi
          image="vulnetix-scan:${GITHUB_SHA:-local}"
          if ! docker build -f "$dockerfile" -t "$image" . ; then
            echo '::warning::image build failed; nothing to scan'
            exit 0
          fi
          echo "image=$image" >> "$GITHUB_OUTPUT"
      - name: Run Grype
        id: grype
        continue-on-error: true
        uses: anchore/scan-action@v7
        with:
          fail-build: false
          image: '${{ steps.build.outputs.image }}'
          output-format: sarif
      - name: Stage Grype SARIF
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if [ -n "${{ steps.grype.outputs.sarif }}" ]; then
            cp "${{ steps.grype.outputs.sarif }}" grype-image.sarif || true
          fi
          if ! jq -e '.version and (.runs | type == "array")' grype-image.sarif >/dev/null 2>&1; then
            echo '::warning::grype image produced no valid SARIF; dropping the artifact'
            rm -f grype-image.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: grype-image
          path: grype-image.sarif
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

### Snyk Container {#snyk-container}

Snyk's image scan. Runs only when SNYK_TOKEN is set and the repository builds an image.

```sh
vulnetix gha setup snyk-container
```

The job it adds:

```yaml
  snyk-container:
    name: Snyk Container (OCI)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Node
        continue-on-error: true
        uses: actions/setup-node@v4
        with:
          node-version: 22
      - name: Build the image
        id: build
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if [ ! -f Dockerfile ] && [ ! -f Containerfile ]; then
            echo '::notice::no Dockerfile or Containerfile found; skipping'
            exit 0
          fi
          dockerfile=Dockerfile
          if [ -f Containerfile ]; then
            dockerfile=Containerfile
          fi
          image="vulnetix-scan:${GITHUB_SHA:-local}"
          if ! docker build -f "$dockerfile" -t "$image" . ; then
            echo '::warning::image build failed; nothing to scan'
            exit 0
          fi
          echo "image=$image" >> "$GITHUB_OUTPUT"
      - name: Run Snyk Container
        continue-on-error: true
        env:
          SNYK_TOKEN: '${{ secrets.SNYK_TOKEN }}'
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          if [ -z "${SNYK_TOKEN:-}" ]; then
            echo '::notice::SNYK_TOKEN is not set; skipping Snyk Container'
            exit 0
          fi
          image="${{ steps.build.outputs.image }}"
          if [ -z "$image" ]; then
            echo '::notice::no image was built; skipping Snyk Container'
            exit 0
          fi
          npm install -g snyk >/dev/null 2>&1 || true
          snyk container test "$image" --sarif-file-output=snyk-container.sarif 2>snyk-container.stderr || true
          if ! jq -e '.version and (.runs | type == "array")' snyk-container.sarif >/dev/null 2>&1; then
            echo '::warning::snyk container produced no valid SARIF; dropping the artifact'
            rm -f snyk-container.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: snyk-container
          path: snyk-container.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Syft (image) {#syft-image}

CycloneDX inventory of everything installed inside the built image.

```sh
vulnetix gha setup syft-image
```

The job it adds:

```yaml
  syft-image:
    name: Syft image (CycloneDX SBOM)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Build the image
        id: build
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if [ ! -f Dockerfile ] && [ ! -f Containerfile ]; then
            echo '::notice::no Dockerfile or Containerfile found; skipping'
            exit 0
          fi
          dockerfile=Dockerfile
          if [ -f Containerfile ]; then
            dockerfile=Containerfile
          fi
          image="vulnetix-scan:${GITHUB_SHA:-local}"
          if ! docker build -f "$dockerfile" -t "$image" . ; then
            echo '::warning::image build failed; nothing to scan'
            exit 0
          fi
          echo "image=$image" >> "$GITHUB_OUTPUT"
      - name: Generate image SBOM
        continue-on-error: true
        uses: anchore/sbom-action@v0.24.0
        with:
          format: cyclonedx-json
          image: '${{ steps.build.outputs.image }}'
          output-file: syft-image.cdx.json
          upload-artifact: false
      - name: Validate SBOM
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! jq -e '.bomFormat == "CycloneDX"' syft-image.cdx.json >/dev/null 2>&1; then
            echo '::warning::syft image produced no valid CycloneDX JSON; dropping the artifact'
            rm -f syft-image.cdx.json
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: syft-image
          path: syft-image.cdx.json
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Trivy (image) {#trivy-image}

Vulnerability scan of the image this repository's Dockerfile builds.

{{< callout type="warning" >}}
The artifact name must stay "trivy-image": Trivy reports the driver name "Trivy" in every mode, so this is the only thing separating an image scan from a filesystem or config scan.
{{< /callout >}}

```sh
vulnetix gha setup trivy-image
```

The job it adds:

```yaml
  trivy-image:
    name: Trivy image (OCI)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Build the image
        id: build
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if [ ! -f Dockerfile ] && [ ! -f Containerfile ]; then
            echo '::notice::no Dockerfile or Containerfile found; skipping'
            exit 0
          fi
          dockerfile=Dockerfile
          if [ -f Containerfile ]; then
            dockerfile=Containerfile
          fi
          image="vulnetix-scan:${GITHUB_SHA:-local}"
          if ! docker build -f "$dockerfile" -t "$image" . ; then
            echo '::warning::image build failed; nothing to scan'
            exit 0
          fi
          echo "image=$image" >> "$GITHUB_OUTPUT"
      - name: Trivy image
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          image="${{ steps.build.outputs.image }}"
          if [ -z "$image" ]; then
            echo '::notice::no image was built; skipping Trivy image scan'
            exit 0
          fi
          docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD:/work" -w /work \
            aquasec/trivy:0.68.0 image --format sarif --output trivy-image.sarif --scanners vuln "$image" \
            >/dev/null 2>trivy-image.stderr || true
          if ! jq -e '.version and (.runs | type == "array")' trivy-image.sarif >/dev/null 2>&1; then
            echo '::warning::trivy image produced no valid SARIF; dropping the artifact'
            rm -f trivy-image.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: trivy-image
          path: trivy-image.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Nuclei {#nuclei}

ProjectDiscovery Nuclei scan against a deployed URL. Set the NUCLEI_TARGET_URL repository variable before enabling.

```sh
vulnetix gha setup nuclei
```

The job it adds:

```yaml
  nuclei:
    name: Nuclei (DAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Go
        continue-on-error: true
        uses: actions/setup-go@v6
        with:
          go-version: stable
      - name: Run Nuclei
        continue-on-error: true
        env:
          GO_MODULE_PATTERN: '${{ vars.GO_MODULE_PATTERN }}'
          GO_MODULE_TOKEN: '${{ secrets.PACKAGES_TOKEN }}'
          NUCLEI_TARGET_URL: '${{ vars.NUCLEI_TARGET_URL }}'
        shell: bash --noprofile --norc {0}
        run: |
          if [ -n "${GO_MODULE_TOKEN:-}" ]; then
            go env -w GOPRIVATE="${GO_MODULE_PATTERN:-github.com/$(echo "${GITHUB_REPOSITORY:-}" | cut -d/ -f1)/*}"
            git config --global url."https://x-access-token:${GO_MODULE_TOKEN}@github.com/".insteadOf "https://github.com/"
          fi
          if [ -z "${NUCLEI_TARGET_URL:-}" ]; then
            echo '::notice::NUCLEI_TARGET_URL is not set; skipping Nuclei'
            exit 0
          fi
          go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
          nuclei -u "$NUCLEI_TARGET_URL" -severity critical,high -se nuclei.sarif || true
          if ! jq -e '.version and (.runs | type == "array")' nuclei.sarif >/dev/null 2>&1; then
            echo '::warning::nuclei produced no valid SARIF; dropping the artifact'
            rm -f nuclei.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: nuclei
          path: nuclei.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Bandit {#bandit}

Python security linter that reports common insecure coding patterns as SARIF.

```sh
vulnetix gha setup bandit
```

The job it adds:

```yaml
  bandit:
    name: Bandit (Python SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up uv
        continue-on-error: true
        uses: astral-sh/setup-uv@v6
      - name: Run Bandit
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! command -v uvx >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
          fi
          if ! command -v uvx >/dev/null 2>&1; then
            echo '::warning::uv is unavailable on this runner; skipping'
            exit 0
          fi
          if ! find . -path ./.git -prune -o -type f -name '*.py' -print | head -n 1 | grep -q .; then
            echo '::notice::no Python files found; skipping Bandit'
            exit 0
          fi
          uvx --from 'bandit[sarif]' bandit -r . -f sarif -o bandit.sarif || true
          if ! jq -e '.version and (.runs | type == "array")' bandit.sarif >/dev/null 2>&1; then
            echo '::warning::bandit produced no valid SARIF; dropping the artifact'
            rm -f bandit.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: bandit
          path: bandit.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Bearer CLI {#bearer}

Data-flow static analysis that reports where sensitive data is handled unsafely.

```sh
vulnetix gha setup bearer
```

The job it adds:

```yaml
  bearer:
    name: Bearer (SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run Bearer
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh -s -- -b "$HOME/.local/bin" >/dev/null 2>&1 || true
          export PATH="$HOME/.local/bin:$PATH"
          if ! command -v bearer >/dev/null 2>&1; then
            echo '::warning::bearer could not be installed on this runner; skipping'
            exit 0
          fi
          # --exit-code 0 because a finding is a successful scan, not a broken one.
          bearer scan . --format sarif --output bearer.sarif --exit-code 0 --quiet 2>bearer.stderr || true
          if ! jq -e '.version and (.runs | type == "array")' bearer.sarif >/dev/null 2>&1; then
            echo '::warning::bearer produced no valid SARIF; dropping the artifact'
            rm -f bearer.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: bearer
          path: bearer.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Brakeman {#brakeman}

Ruby on Rails static analyzer with SARIF output.

```sh
vulnetix gha setup brakeman
```

The job it adds:

```yaml
  brakeman:
    name: Brakeman (Ruby on Rails SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Ruby
        continue-on-error: true
        uses: ruby/setup-ruby@v1
        with:
          ruby-version: ruby
      - name: Run Brakeman
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if [ ! -f Gemfile ] || ! grep -E 'rails|railties' Gemfile Gemfile.lock >/dev/null 2>&1; then
            echo '::notice::no Rails app detected; skipping Brakeman'
            exit 0
          fi
          gem install brakeman
          brakeman -f sarif -o brakeman.sarif || true
          if ! jq -e '.version and (.runs | type == "array")' brakeman.sarif >/dev/null 2>&1; then
            echo '::warning::brakeman produced no valid SARIF; dropping the artifact'
            rm -f brakeman.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: brakeman
          path: brakeman.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Cppcheck {#cppcheck}

Static analyzer for C and C++ that can emit SARIF.

```sh
vulnetix gha setup cppcheck
```

The job it adds:

```yaml
  cppcheck:
    name: Cppcheck (C/C++ SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run Cppcheck
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! find . -path ./.git -prune -o -type f -print | grep -E '\.(c|cc|cpp|h|hpp)$' | head -n 1 | grep -q .; then
            echo '::notice::no C/C++ files found; skipping Cppcheck'
            exit 0
          fi
          if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update -qq && sudo apt-get install -y -qq cppcheck
          elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y -q cppcheck
          elif command -v apk >/dev/null 2>&1; then
            sudo apk add --no-cache cppcheck
          fi
          if ! command -v cppcheck >/dev/null 2>&1; then
            echo '::warning::cppcheck could not be installed on this runner; skipping'
            exit 0
          fi
          cppcheck --enable=warning,style,performance,portability --output-format=sarif --output-file=cppcheck.sarif . || true
          if ! jq -e '.version and (.runs | type == "array")' cppcheck.sarif >/dev/null 2>&1; then
            echo '::warning::cppcheck produced no valid SARIF; dropping the artifact'
            rm -f cppcheck.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: cppcheck
          path: cppcheck.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### detekt {#detekt}

Kotlin static analysis, including its security rule set.

```sh
vulnetix gha setup detekt
```

The job it adds:

```yaml
  detekt:
    name: detekt (Kotlin SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Java
        continue-on-error: true
        uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: 17
      - name: Run detekt
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          if ! find . -path ./.git -prune -o -type f -name '*.kt' -print | head -n 1 | grep -q .; then
            echo '::notice::no Kotlin files found; skipping detekt'
            exit 0
          fi
          version=1.23.8
          curl -fsSL -o detekt-cli.zip "https://github.com/detekt/detekt/releases/download/v${version}/detekt-cli-${version}.zip" || true
          if [ ! -s detekt-cli.zip ]; then
            echo '::warning::could not download detekt; skipping'
            exit 0
          fi
          unzip -q -o detekt-cli.zip
          # detekt exits 2 when it reports issues, which is a successful run.
          "detekt-cli-${version}/bin/detekt-cli" --input . --report sarif:detekt.sarif 2>detekt.stderr || true
          if ! jq -e '.version and (.runs | type == "array")' detekt.sarif >/dev/null 2>&1; then
            echo '::warning::detekt produced no valid SARIF; dropping the artifact'
            rm -f detekt.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: detekt
          path: detekt.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Flawfinder {#flawfinder}

C/C++ dangerous-function scanner that emits SARIF findings.

```sh
vulnetix gha setup flawfinder
```

The job it adds:

```yaml
  flawfinder:
    name: Flawfinder (C/C++ SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up uv
        continue-on-error: true
        uses: astral-sh/setup-uv@v6
      - name: Run Flawfinder
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! command -v uvx >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
          fi
          if ! command -v uvx >/dev/null 2>&1; then
            echo '::warning::uv is unavailable on this runner; skipping'
            exit 0
          fi
          if ! find . -path ./.git -prune -o -type f -print | grep -E '\.(c|cc|cpp|h|hpp)$' | head -n 1 | grep -q .; then
            echo '::notice::no C/C++ files found; skipping Flawfinder'
            exit 0
          fi
          uvx --from flawfinder flawfinder --sarif . >flawfinder.sarif 2>flawfinder.stderr
          rc=$?
          if [ $rc -ne 0 ] && [ $rc -ne 1 ]; then
            echo "::warning::flawfinder exited $rc"
            sed -n '1,20p' flawfinder.stderr
          fi
          if ! jq -e '.version and (.runs | type == "array")' flawfinder.sarif >/dev/null 2>&1; then
            echo '::warning::flawfinder produced no valid SARIF; dropping the artifact'
            rm -f flawfinder.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: flawfinder
          path: flawfinder.sarif
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
      - name: Set up Go
        continue-on-error: true
        uses: actions/setup-go@v6
        with:
          go-version: stable
      - name: Run gosec
        continue-on-error: true
        env:
          GO_MODULE_PATTERN: '${{ vars.GO_MODULE_PATTERN }}'
          GO_MODULE_TOKEN: '${{ secrets.PACKAGES_TOKEN }}'
        shell: bash --noprofile --norc {0}
        run: |
          if [ -n "${GO_MODULE_TOKEN:-}" ]; then
            go env -w GOPRIVATE="${GO_MODULE_PATTERN:-github.com/$(echo "${GITHUB_REPOSITORY:-}" | cut -d/ -f1)/*}"
            git config --global url."https://x-access-token:${GO_MODULE_TOKEN}@github.com/".insteadOf "https://github.com/"
          fi
          if [ ! -f go.mod ]; then
            echo '::notice::no go.mod found; skipping gosec'
            exit 0
          fi
          go install github.com/securego/gosec/v2/cmd/gosec@v2.28.0
          gosec -no-fail -fmt sarif -out gosec.sarif ./... || true
          if ! jq -e '.version and (.runs | type == "array")' gosec.sarif >/dev/null 2>&1; then
            echo '::warning::gosec produced no valid SARIF; dropping the artifact'
            rm -f gosec.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: gosec
          path: gosec.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### njsscan {#njsscan}

JavaScript and TypeScript security scanner with SARIF output.

```sh
vulnetix gha setup njsscan
```

The job it adds:

```yaml
  njsscan:
    name: njsscan (Node SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up uv
        continue-on-error: true
        uses: astral-sh/setup-uv@v6
      - name: Run njsscan
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! command -v uvx >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
          fi
          if ! command -v uvx >/dev/null 2>&1; then
            echo '::warning::uv is unavailable on this runner; skipping'
            exit 0
          fi
          if ! find . -path ./.git -prune -o -type f -print | grep -E '\.(js|jsx|ts|tsx)$' | head -n 1 | grep -q .; then
            echo '::notice::no JavaScript or TypeScript files found; skipping njsscan'
            exit 0
          fi
          uvx --from njsscan njsscan --sarif -o njsscan.sarif . || true
          if ! jq -e '.version and (.runs | type == "array")' njsscan.sarif >/dev/null 2>&1; then
            echo '::warning::njsscan produced no valid SARIF; dropping the artifact'
            rm -f njsscan.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: njsscan
          path: njsscan.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### OpenGrep {#opengrep}

Open-source fork of Semgrep's engine, running the community rulesets.

```sh
vulnetix gha setup opengrep
```

The job it adds:

```yaml
  opengrep:
    name: OpenGrep (SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run OpenGrep
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash >/dev/null 2>&1 || true
          export PATH="$HOME/.opengrep/cli/latest:$HOME/.local/bin:$PATH"
          if ! command -v opengrep >/dev/null 2>&1; then
            echo '::warning::opengrep could not be installed on this runner; skipping'
            exit 0
          fi
          # The CLI tracks Semgrep's flags, but the SARIF flag was renamed between
          # releases. Try the current spelling, then the older one.
          opengrep scan --config auto --sarif --output opengrep.sarif . >/dev/null 2>opengrep.stderr \
            || opengrep scan --config auto --sarif-output=opengrep.sarif . >/dev/null 2>>opengrep.stderr \
            || true
          if ! jq -e '.version and (.runs | type == "array")' opengrep.sarif >/dev/null 2>&1; then
            echo '::warning::opengrep produced no valid SARIF; dropping the artifact'
            rm -f opengrep.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: opengrep
          path: opengrep.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### PMD {#pmd}

Java static analysis using the official PMD GitHub Action and SARIF report.

```sh
vulnetix gha setup pmd
```

The job it adds:

```yaml
  pmd:
    name: PMD (Java SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run PMD
        continue-on-error: true
        uses: pmd/pmd-github-action@v2
        with:
          analyzeModifiedFilesOnly: false
          rulesets: rulesets/java/quickstart.xml
          version: latest
      - uses: actions/upload-artifact@v6
        with:
          name: pmd
          path: pmd-report.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Psalm {#psalm}

PHP static analysis with taint tracking.

```sh
vulnetix gha setup psalm
```

The job it adds:

```yaml
  psalm:
    name: Psalm (PHP SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up PHP
        continue-on-error: true
        uses: shivammathur/setup-php@v2
        with:
          coverage: none
          php-version: 8.3
      - name: Run Psalm
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          if [ ! -f composer.json ]; then
            echo '::notice::no composer.json found; skipping Psalm'
            exit 0
          fi
          composer require --dev --no-interaction --quiet vimeo/psalm || true
          if [ ! -x vendor/bin/psalm ]; then
            echo '::warning::psalm could not be installed; skipping'
            exit 0
          fi
          if [ ! -f psalm.xml ] && [ ! -f psalm.xml.dist ]; then
            vendor/bin/psalm --init . 1 >/dev/null 2>&1 || true
          fi
          # Psalm exits non-zero when it reports issues.
          vendor/bin/psalm --no-cache --no-progress --report=psalm.sarif 2>psalm.stderr || true
          if ! jq -e '.version and (.runs | type == "array")' psalm.sarif >/dev/null 2>&1; then
            echo '::warning::psalm produced no valid SARIF; dropping the artifact'
            rm -f psalm.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: psalm
          path: psalm.sarif
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
      - name: Set up uv
        continue-on-error: true
        uses: astral-sh/setup-uv@v6
      - name: Run Semgrep
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! command -v uvx >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
          fi
          if ! command -v uvx >/dev/null 2>&1; then
            echo '::warning::uv is unavailable on this runner; skipping'
            exit 0
          fi
          uvx --from semgrep semgrep scan --config auto --sarif --output semgrep.sarif .
      - uses: actions/upload-artifact@v6
        with:
          name: semgrep
          path: semgrep.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Snyk Code {#snyk-code}

Snyk's static analysis. Runs only when SNYK_TOKEN is set.

{{< callout type="warning" >}}
Snyk reports the driver name "Snyk" for all four of its products, so the artifact name is what separates them.
{{< /callout >}}

```sh
vulnetix gha setup snyk-code
```

The job it adds:

```yaml
  snyk-code:
    name: Snyk Code (SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Node
        continue-on-error: true
        uses: actions/setup-node@v4
        with:
          node-version: 22
      - name: Run Snyk Code
        continue-on-error: true
        env:
          SNYK_TOKEN: '${{ secrets.SNYK_TOKEN }}'
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          if [ -z "${SNYK_TOKEN:-}" ]; then
            echo '::notice::SNYK_TOKEN is not set; skipping Snyk Code'
            exit 0
          fi
          npm install -g snyk >/dev/null 2>&1 || true
          # Exit 1 means issues were found.
          snyk code test --sarif-file-output=snyk-code.sarif 2>snyk-code.stderr || true
          if ! jq -e '.version and (.runs | type == "array")' snyk-code.sarif >/dev/null 2>&1; then
            echo '::warning::snyk code produced no valid SARIF; dropping the artifact'
            rm -f snyk-code.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: snyk-code
          path: snyk-code.sarif
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
      - name: Set up uv
        continue-on-error: true
        uses: astral-sh/setup-uv@v6
      - name: Run zizmor
        continue-on-error: true
        env:
          GH_TOKEN: '${{ github.token }}'
        shell: bash --noprofile --norc {0}
        run: |
          if ! command -v uvx >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
          fi
          if ! command -v uvx >/dev/null 2>&1; then
            echo '::warning::uv is unavailable on this runner; skipping'
            exit 0
          fi
          set -uo pipefail
          # zizmor exits 14 when it has findings, which is a successful scan.
          uvx --from zizmor zizmor --format sarif . >zizmor.sarif 2>zizmor.stderr
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

### cdxgen {#cdxgen}

Multi-language CycloneDX SBOM generator for dependency inventory.

```sh
vulnetix gha setup cdxgen
```

The job it adds:

```yaml
  cdxgen:
    name: cdxgen (multi-ecosystem SBOM)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Node.js
        continue-on-error: true
        uses: actions/setup-node@v4
        with:
          node-version: 'lts/*'
      - name: Run cdxgen
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! find . -maxdepth 4 -type f \( -name package-lock.json -o -name go.mod -o -name requirements.txt -o -name pyproject.toml -o -name pom.xml -o -name build.gradle -o -name Cargo.lock -o -name composer.lock -o -name Gemfile.lock -o -name '*.csproj' \) -print | head -n 1 | grep -q .; then
            echo '::notice::no supported package manifest found; skipping cdxgen'
            exit 0
          fi
          npx --yes @cyclonedx/cdxgen -o cdxgen.cdx.json . || true
          if ! jq -e '.bomFormat == "CycloneDX"' cdxgen.cdx.json >/dev/null 2>&1; then
            echo '::warning::cdxgen produced no valid CycloneDX JSON; dropping the artifact'
            rm -f cdxgen.cdx.json
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: cdxgen
          path: cdxgen.cdx.json
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### CycloneDX .NET {#cyclonedx-dotnet}

CycloneDX SBOM generation for .NET projects and solutions.

```sh
vulnetix gha setup cyclonedx-dotnet
```

The job it adds:

```yaml
  cyclonedx-dotnet:
    name: CycloneDX .NET SBOM
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up .NET
        continue-on-error: true
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: 8.x
      - name: Generate .NET CycloneDX SBOM
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! find . -maxdepth 4 -type f \( -name '*.csproj' -o -name '*.sln' \) -print | head -n 1 | grep -q .; then
            echo '::notice::no .NET project found; skipping CycloneDX .NET'
            exit 0
          fi
          dotnet restore || true
          dotnet tool install --global CycloneDX
          export PATH="$PATH:$HOME/.dotnet/tools"
          dotnet-CycloneDX . -o . -json || true
          if [ -f bom.json ]; then
            mv bom.json cyclonedx-dotnet.cdx.json
          fi
          if ! jq -e '.bomFormat == "CycloneDX"' cyclonedx-dotnet.cdx.json >/dev/null 2>&1; then
            echo '::warning::cyclonedx dotnet produced no valid CycloneDX JSON; dropping the artifact'
            rm -f cyclonedx-dotnet.cdx.json
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: cyclonedx-dotnet
          path: cyclonedx-dotnet.cdx.json
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### CycloneDX Go {#cyclonedx-go}

CycloneDX SBOM generation for Go modules.

```sh
vulnetix gha setup cyclonedx-go
```

The job it adds:

```yaml
  cyclonedx-go:
    name: CycloneDX Go SBOM
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Go
        continue-on-error: true
        uses: actions/setup-go@v6
        with:
          go-version: stable
      - name: Generate Go CycloneDX SBOM
        continue-on-error: true
        env:
          GO_MODULE_PATTERN: '${{ vars.GO_MODULE_PATTERN }}'
          GO_MODULE_TOKEN: '${{ secrets.PACKAGES_TOKEN }}'
        shell: bash --noprofile --norc {0}
        run: |
          if [ -n "${GO_MODULE_TOKEN:-}" ]; then
            go env -w GOPRIVATE="${GO_MODULE_PATTERN:-github.com/$(echo "${GITHUB_REPOSITORY:-}" | cut -d/ -f1)/*}"
            git config --global url."https://x-access-token:${GO_MODULE_TOKEN}@github.com/".insteadOf "https://github.com/"
          fi
          if [ ! -f go.mod ]; then
            echo '::notice::no go.mod found; skipping CycloneDX Go'
            exit 0
          fi
          go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
          cyclonedx-gomod app -json -output cyclonedx-go.cdx.json . || true
          if ! jq -e '.bomFormat == "CycloneDX"' cyclonedx-go.cdx.json >/dev/null 2>&1; then
            echo '::warning::cyclonedx go produced no valid CycloneDX JSON; dropping the artifact'
            rm -f cyclonedx-go.cdx.json
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: cyclonedx-go
          path: cyclonedx-go.cdx.json
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### CycloneDX Maven Plugin {#cyclonedx-maven}

CycloneDX SBOM from a Maven project's resolved dependency tree.

```sh
vulnetix gha setup cyclonedx-maven
```

The job it adds:

```yaml
  cyclonedx-maven:
    name: CycloneDX Maven (SBOM)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Java
        continue-on-error: true
        uses: actions/setup-java@v4
        with:
          cache: maven
          distribution: temurin
          java-version: 17
      - name: Generate Maven CycloneDX SBOM
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          if [ ! -f pom.xml ]; then
            echo '::notice::no pom.xml found; skipping CycloneDX Maven'
            exit 0
          fi
          mvn -B -q org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom \
            -DoutputFormat=json -DoutputName=cyclonedx-maven 2>cyclonedx-maven.stderr || true
          found=$(find . -name 'cyclonedx-maven.json' -print -quit)
          if [ -n "$found" ]; then
            cp "$found" cyclonedx-maven.cdx.json
          fi
          if ! jq -e '.bomFormat == "CycloneDX"' cyclonedx-maven.cdx.json >/dev/null 2>&1; then
            echo '::warning::cyclonedx maven produced no valid CycloneDX JSON; dropping the artifact'
            rm -f cyclonedx-maven.cdx.json
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: cyclonedx-maven
          path: cyclonedx-maven.cdx.json
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### CycloneDX npm {#cyclonedx-node}

CycloneDX SBOM generation for npm projects.

```sh
vulnetix gha setup cyclonedx-node
```

The job it adds:

```yaml
  cyclonedx-node:
    name: CycloneDX npm SBOM
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Node.js
        continue-on-error: true
        uses: actions/setup-node@v4
        with:
          node-version: 'lts/*'
      - name: Generate npm CycloneDX SBOM
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if [ ! -f package-lock.json ]; then
            echo '::notice::no package-lock.json found; skipping CycloneDX npm'
            exit 0
          fi
          npm ci
          npx --yes @cyclonedx/cyclonedx-npm --omit dev --flatten-components --output-format JSON --output-file cyclonedx-node.cdx.json || true
          if ! jq -e '.bomFormat == "CycloneDX"' cyclonedx-node.cdx.json >/dev/null 2>&1; then
            echo '::warning::cyclonedx npm produced no valid CycloneDX JSON; dropping the artifact'
            rm -f cyclonedx-node.cdx.json
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: cyclonedx-node
          path: cyclonedx-node.cdx.json
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### CycloneDX PHP {#cyclonedx-php}

CycloneDX SBOM generation for PHP Composer projects.

```sh
vulnetix gha setup cyclonedx-php
```

The job it adds:

```yaml
  cyclonedx-php:
    name: CycloneDX PHP SBOM
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up PHP
        continue-on-error: true
        uses: shivammathur/setup-php@v2
        with:
          php-version: 8.2
          tools: composer
      - name: Generate PHP CycloneDX SBOM
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if [ ! -f composer.lock ]; then
            echo '::notice::no composer.lock found; skipping CycloneDX PHP'
            exit 0
          fi
          composer require --dev cyclonedx/cyclonedx-php-composer || true
          composer CycloneDX:make-sbom --output-format=JSON --output-file=cyclonedx-php.cdx.json || true
          if ! jq -e '.bomFormat == "CycloneDX"' cyclonedx-php.cdx.json >/dev/null 2>&1; then
            echo '::warning::cyclonedx php produced no valid CycloneDX JSON; dropping the artifact'
            rm -f cyclonedx-php.cdx.json
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: cyclonedx-php
          path: cyclonedx-php.cdx.json
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### CycloneDX Python {#cyclonedx-python}

CycloneDX SBOM generation for Python projects.

```sh
vulnetix gha setup cyclonedx-python
```

The job it adds:

```yaml
  cyclonedx-python:
    name: CycloneDX Python SBOM
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up uv
        continue-on-error: true
        uses: astral-sh/setup-uv@v6
      - name: Generate Python CycloneDX SBOM
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! command -v uvx >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
          fi
          if ! command -v uvx >/dev/null 2>&1; then
            echo '::warning::uv is unavailable on this runner; skipping'
            exit 0
          fi
          # `cyclonedx-py environment` inventories the interpreter it runs under, which
          # under uvx is an isolated environment holding only cyclonedx-bom itself. Every
          # subcommand below reads a lockfile instead, so the SBOM describes the project.
          if [ -f poetry.lock ]; then
            uvx --from cyclonedx-bom cyclonedx-py poetry . \
              --output-format JSON --output-file cyclonedx-python.cdx.json || true
          elif [ -f Pipfile.lock ]; then
            uvx --from cyclonedx-bom cyclonedx-py pipenv . \
              --output-format JSON --output-file cyclonedx-python.cdx.json || true
          elif [ -f requirements.txt ]; then
            uvx --from cyclonedx-bom cyclonedx-py requirements requirements.txt \
              --output-format JSON --output-file cyclonedx-python.cdx.json || true
          else
            echo '::notice::no Python lockfile (poetry.lock, Pipfile.lock, requirements.txt); skipping CycloneDX Python'
            exit 0
          fi
          if ! jq -e '.bomFormat == "CycloneDX"' cyclonedx-python.cdx.json >/dev/null 2>&1; then
            echo '::warning::cyclonedx python produced no valid CycloneDX JSON; dropping the artifact'
            rm -f cyclonedx-python.cdx.json
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: cyclonedx-python
          path: cyclonedx-python.cdx.json
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### CycloneDX Ruby {#cyclonedx-ruby}

CycloneDX SBOM generation for Ruby Bundler projects.

```sh
vulnetix gha setup cyclonedx-ruby
```

The job it adds:

```yaml
  cyclonedx-ruby:
    name: CycloneDX Ruby SBOM
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Ruby
        continue-on-error: true
        uses: ruby/setup-ruby@v1
        with:
          ruby-version: ruby
      - name: Generate Ruby CycloneDX SBOM
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if [ ! -f Gemfile.lock ]; then
            echo '::notice::no Gemfile.lock found; skipping CycloneDX Ruby'
            exit 0
          fi
          gem install cyclonedx-ruby
          cyclonedx-ruby --path . --output cyclonedx-ruby.cdx.json --format JSON || true
          if ! jq -e '.bomFormat == "CycloneDX"' cyclonedx-ruby.cdx.json >/dev/null 2>&1; then
            echo '::warning::cyclonedx ruby produced no valid CycloneDX JSON; dropping the artifact'
            rm -f cyclonedx-ruby.cdx.json
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: cyclonedx-ruby
          path: cyclonedx-ruby.cdx.json
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### CycloneDX Rust {#cyclonedx-rust}

CycloneDX SBOM generation for Rust crates.

```sh
vulnetix gha setup cyclonedx-rust
```

The job it adds:

```yaml
  cyclonedx-rust:
    name: CycloneDX Rust SBOM
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Generate Rust CycloneDX SBOM
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if [ ! -f Cargo.lock ] && [ ! -f Cargo.toml ]; then
            echo '::notice::no Cargo project found; skipping CycloneDX Rust'
            exit 0
          fi
          cargo install cargo-cyclonedx
          cargo cyclonedx --format json --output-cdx cyclonedx-rust.cdx.json || true
          if ! jq -e '.bomFormat == "CycloneDX"' cyclonedx-rust.cdx.json >/dev/null 2>&1; then
            echo '::warning::cyclonedx rust produced no valid CycloneDX JSON; dropping the artifact'
            rm -f cyclonedx-rust.cdx.json
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: cyclonedx-rust
          path: cyclonedx-rust.cdx.json
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### GitHub SBOM Export {#github-sbom}

The dependency graph GitHub already resolved for this repository, as SPDX.

```sh
vulnetix gha setup github-sbom
```

The job it adds:

```yaml
  github-sbom:
    name: GitHub SBOM (SPDX)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Export the dependency graph
        continue-on-error: true
        env:
          GH_TOKEN: '${{ github.token }}'
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          # 404 when the dependency graph is disabled for the repository, which is a
          # setting rather than a failure.
          if ! gh api "repos/${GITHUB_REPOSITORY}/dependency-graph/sbom" --jq '.sbom' >github-sbom.spdx.json 2>github-sbom.stderr; then
            echo '::notice::the dependency graph is not available for this repository; skipping'
            rm -f github-sbom.spdx.json
            exit 0
          fi
          if ! jq -e '.spdxVersion' github-sbom.spdx.json >/dev/null 2>&1; then
            echo '::warning::GitHub returned no valid SPDX; dropping the artifact'
            rm -f github-sbom.spdx.json
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: github-sbom
          path: github-sbom.spdx.json
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### govulncheck {#govulncheck}

Official Go vulnerability scanner with SARIF output for module and package reachability findings.

```sh
vulnetix gha setup govulncheck
```

The job it adds:

```yaml
  govulncheck:
    name: govulncheck (Go SCA)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Go
        continue-on-error: true
        uses: actions/setup-go@v6
        with:
          go-version: stable
      - name: Run govulncheck
        continue-on-error: true
        env:
          GO_MODULE_PATTERN: '${{ vars.GO_MODULE_PATTERN }}'
          GO_MODULE_TOKEN: '${{ secrets.PACKAGES_TOKEN }}'
        shell: bash --noprofile --norc {0}
        run: |
          if [ -n "${GO_MODULE_TOKEN:-}" ]; then
            go env -w GOPRIVATE="${GO_MODULE_PATTERN:-github.com/$(echo "${GITHUB_REPOSITORY:-}" | cut -d/ -f1)/*}"
            git config --global url."https://x-access-token:${GO_MODULE_TOKEN}@github.com/".insteadOf "https://github.com/"
          fi
          if [ ! -f go.mod ]; then
            echo '::notice::no go.mod found; skipping govulncheck'
            exit 0
          fi
          go install golang.org/x/vuln/cmd/govulncheck@latest
          govulncheck -format sarif ./... >govulncheck.sarif 2>govulncheck.stderr
          rc=$?
          if [ $rc -ne 0 ]; then
            echo "::warning::govulncheck exited $rc"
            sed -n '1,20p' govulncheck.stderr
          fi
          if ! jq -e '.version and (.runs | type == "array")' govulncheck.sarif >/dev/null 2>&1; then
            echo '::warning::govulncheck produced no valid SARIF; dropping the artifact'
            rm -f govulncheck.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: govulncheck
          path: govulncheck.sarif
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
        shell: bash --noprofile --norc {0}
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

### npm audit {#npm-audit}

npm dependency audit converted to SARIF for Vulnetix ingestion.

```sh
vulnetix gha setup npm-audit
```

The job it adds:

```yaml
  npm-audit:
    name: npm audit (Node SCA)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Node.js
        continue-on-error: true
        uses: actions/setup-node@v4
        with:
          node-version: 'lts/*'
      - name: Run npm audit
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if [ ! -f package-lock.json ]; then
            echo '::notice::no package-lock.json found; skipping npm audit'
            exit 0
          fi
          npm ci
          npm audit --json >npm-audit.json || true
          npx --yes npm-audit-sarif -i npm-audit.json -o npm-audit.sarif || true
          if ! jq -e '.version and (.runs | type == "array")' npm-audit.sarif >/dev/null 2>&1; then
            echo '::warning::npm audit produced no valid SARIF; dropping the artifact'
            rm -f npm-audit.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: npm-audit
          path: npm-audit.sarif
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

### OWASP Dependency-Check {#owasp-dependency-check}

OWASP Dependency-Check SCA scan with SARIF output. Set NVD_API_KEY as a secret for faster database updates.

```sh
vulnetix gha setup owasp-dependency-check
```

The job it adds:

```yaml
  owasp-dependency-check:
    name: OWASP Dependency-Check (SCA)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Java
        continue-on-error: true
        uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: 21
      - name: Run OWASP Dependency-Check
        continue-on-error: true
        env:
          NVD_API_KEY: '${{ secrets.NVD_API_KEY }}'
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          version=$(curl -fsSL https://api.github.com/repos/jeremylong/DependencyCheck/releases/latest | jq -r '.tag_name | ltrimstr("v")')
          curl -fsSL "https://github.com/jeremylong/DependencyCheck/releases/download/v${version}/dependency-check-${version}-release.zip" -o dependency-check.zip
          unzip -q dependency-check.zip
          mkdir -p dependency-check-out
          args=(--scan . --format SARIF --out dependency-check-out)
          if [ -n "${NVD_API_KEY:-}" ]; then
            args+=(--nvdApiKey "$NVD_API_KEY")
          fi
          dependency-check/bin/dependency-check.sh "${args[@]}" || true
          found=$(find dependency-check-out -name '*.sarif' -print -quit)
          if [ -n "$found" ]; then
            cp "$found" dependency-check.sarif
          fi
          if ! jq -e '.version and (.runs | type == "array")' dependency-check.sarif >/dev/null 2>&1; then
            echo '::warning::dependency-check produced no valid SARIF; dropping the artifact'
            rm -f dependency-check.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: dependency-check
          path: dependency-check.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Retire.js {#retirejs}

JavaScript dependency vulnerability scanner exporting CycloneDX JSON.

```sh
vulnetix gha setup retirejs
```

The job it adds:

```yaml
  retirejs:
    name: Retire.js (JavaScript SCA)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Node.js
        continue-on-error: true
        uses: actions/setup-node@v4
        with:
          node-version: 'lts/*'
      - name: Run Retire.js
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if [ ! -f package.json ] && ! find . -path ./.git -prune -o -type f -name '*.js' -print | head -n 1 | grep -q .; then
            echo '::notice::no JavaScript project detected; skipping Retire.js'
            exit 0
          fi
          npx --yes retire --outputformat cyclonedxJSON --outputpath retirejs.cdx.json --path . || true
          if ! jq -e '.bomFormat == "CycloneDX"' retirejs.cdx.json >/dev/null 2>&1; then
            echo '::warning::retirejs produced no valid CycloneDX JSON; dropping the artifact'
            rm -f retirejs.cdx.json
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: retirejs
          path: retirejs.cdx.json
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### Snyk Open Source {#snyk-oss}

Snyk's dependency scan. Runs only when SNYK_TOKEN is set.

```sh
vulnetix gha setup snyk-oss
```

The job it adds:

```yaml
  snyk-oss:
    name: Snyk Open Source (SCA)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Node
        continue-on-error: true
        uses: actions/setup-node@v4
        with:
          node-version: 22
      - name: Run Snyk Open Source
        continue-on-error: true
        env:
          SNYK_TOKEN: '${{ secrets.SNYK_TOKEN }}'
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          if [ -z "${SNYK_TOKEN:-}" ]; then
            echo '::notice::SNYK_TOKEN is not set; skipping Snyk Open Source'
            exit 0
          fi
          npm install -g snyk >/dev/null 2>&1 || true
          snyk test --all-projects --sarif-file-output=snyk-oss.sarif 2>snyk-oss.stderr || true
          if ! jq -e '.version and (.runs | type == "array")' snyk-oss.sarif >/dev/null 2>&1; then
            echo '::warning::snyk open source produced no valid SARIF; dropping the artifact'
            rm -f snyk-oss.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: snyk-oss
          path: snyk-oss.sarif
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

### CycloneDX Yarn {#yarn-cyclonedx}

CycloneDX SBOM generation for Yarn projects.

```sh
vulnetix gha setup yarn-cyclonedx
```

The job it adds:

```yaml
  yarn-cyclonedx:
    name: CycloneDX Yarn SBOM
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up Node.js
        continue-on-error: true
        uses: actions/setup-node@v4
        with:
          node-version: 'lts/*'
      - name: Generate Yarn CycloneDX SBOM
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if [ ! -f yarn.lock ]; then
            echo '::notice::no yarn.lock found; skipping CycloneDX Yarn'
            exit 0
          fi
          corepack enable
          yarn install --immutable || yarn install --frozen-lockfile || true
          yarn dlx -q @cyclonedx/yarn-plugin-cyclonedx --omit dev --output-format JSON --output-file yarn-cyclonedx.cdx.json || true
          if ! jq -e '.bomFormat == "CycloneDX"' yarn-cyclonedx.cdx.json >/dev/null 2>&1; then
            echo '::warning::cyclonedx yarn produced no valid CycloneDX JSON; dropping the artifact'
            rm -f yarn-cyclonedx.cdx.json
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: yarn-cyclonedx
          path: yarn-cyclonedx.cdx.json
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### detect-secrets {#detect-secrets}

Yelp detect-secrets baseline scan converted to SARIF for exposed-secret findings.

```sh
vulnetix gha setup detect-secrets
```

The job it adds:

```yaml
  detect-secrets:
    name: detect-secrets (secrets)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Set up uv
        continue-on-error: true
        uses: astral-sh/setup-uv@v6
      - name: Run detect-secrets
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          # The converters below need only the standard library, but not every runner
          # image ships python3. uv carries its own interpreter, so this always resolves.
          PY=python3
          if ! command -v python3 >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
            PY="uv run --no-project --python 3.12 python"
          fi
          if ! command -v uvx >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
          fi
          if ! command -v uvx >/dev/null 2>&1; then
            echo '::warning::uv is unavailable on this runner; skipping'
            exit 0
          fi
          if [ -f .secrets.baseline ]; then
            uvx --from detect-secrets detect-secrets scan --baseline .secrets.baseline >detect-secrets-results.json || true
          else
            uvx --from detect-secrets detect-secrets scan --all-files >detect-secrets-results.json || true
          fi
          $PY <<'PY'
          import json
          import os

          sarif = {
              "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
              "version": "2.1.0",
              "runs": [{
                  "tool": {
                      "driver": {
                          "name": "detect-secrets",
                          "informationUri": "https://github.com/Yelp/detect-secrets",
                          "rules": [],
                      }
                  },
                  "results": [],
              }],
          }
          rules_seen = set()

          def to_int(value):
              try:
                  return max(1, int(value))
              except (TypeError, ValueError):
                  return 1

          def add_rule(rule_id, plugin_name):
              if rule_id in rules_seen:
                  return
              sarif["runs"][0]["tool"]["driver"]["rules"].append({
                  "id": rule_id,
                  "shortDescription": {"text": f"Potential leaked credential detected ({plugin_name})"},
                  "defaultConfiguration": {"level": "error"},
              })
              rules_seen.add(rule_id)

          if os.path.exists("detect-secrets-results.json") and os.path.getsize("detect-secrets-results.json") > 0:
              with open("detect-secrets-results.json", "r", encoding="utf-8") as fh:
                  data = json.load(fh)
              results = data.get("results") or {}
              for file_path, findings in results.items():
                  for finding in findings:
                      plugin_name = str(finding.get("type") or "detect-secrets")
                      rule_id = plugin_name.replace(" ", "-") or "detect-secrets"
                      add_rule(rule_id, plugin_name)
                      hashed_secret = finding.get("hashed_secret")
                      message = f"Potential secret exposed. Type: {plugin_name}."
                      if hashed_secret:
                          message += f" Hashed representation: {hashed_secret}"
                      sarif["runs"][0]["results"].append({
                          "ruleId": rule_id,
                          "level": "error",
                          "message": {"text": message},
                          "locations": [{
                              "physicalLocation": {
                                  "artifactLocation": {"uri": file_path},
                                  "region": {"startLine": to_int(finding.get("line_number"))},
                              }
                          }],
                      })

          with open("detect-secrets-results.sarif", "w", encoding="utf-8") as fh:
              json.dump(sarif, fh, indent=2)
          PY
          if ! jq -e '.version and (.runs | type == "array")' detect-secrets-results.sarif >/dev/null 2>&1; then
            echo '::warning::detect-secrets produced no valid SARIF; dropping the artifact'
            rm -f detect-secrets-results.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: detect-secrets
          path: detect-secrets-results.sarif
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
        shell: bash --noprofile --norc {0}
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

### Nosey Parker {#noseyparker}

High-signal secret detection across the working tree and git history.

```sh
vulnetix gha setup noseyparker
```

The job it adds:

```yaml
  noseyparker:
    name: Nosey Parker (secrets)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run Nosey Parker
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          set -uo pipefail
          version=0.24.0
          url="https://github.com/praetorian-inc/noseyparker/releases/download/v${version}/noseyparker-v${version}-x86_64-unknown-linux-gnu.tar.gz"
          mkdir -p /tmp/np
          curl -fsSL "$url" | tar -xz -C /tmp/np 2>/dev/null || true
          bin=$(find /tmp/np -type f -name noseyparker -perm -u+x -print -quit 2>/dev/null)
          if [ -z "$bin" ]; then
            echo '::warning::noseyparker could not be installed on this runner; skipping'
            exit 0
          fi
          "$bin" scan --datastore np.datastore . >/dev/null 2>noseyparker.stderr || true
          "$bin" report --datastore np.datastore --format sarif --output noseyparker.sarif >/dev/null 2>>noseyparker.stderr || true
          if ! jq -e '.version and (.runs | type == "array")' noseyparker.sarif >/dev/null 2>&1; then
            echo '::warning::noseyparker produced no valid SARIF; dropping the artifact'
            rm -f noseyparker.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: noseyparker
          path: noseyparker.sarif
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 7

```

### TruffleHog {#trufflehog}

Verified secret discovery from the working tree, converted from TruffleHog JSONL to SARIF.

```sh
vulnetix gha setup trufflehog
```

The job it adds:

```yaml
  trufflehog:
    name: TruffleHog (secrets)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - name: Run TruffleHog
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          # The converters below need only the standard library, but not every runner
          # image ships python3. uv carries its own interpreter, so this always resolves.
          PY=python3
          if ! command -v python3 >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
            PY="uv run --no-project --python 3.12 python"
          fi
          curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin
          trufflehog filesystem --json . >trufflehog.jsonl || true
          $PY <<'PY'
          import json
          import os

          sarif = {
              "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
              "version": "2.1.0",
              "runs": [{
                  "tool": {
                      "driver": {
                          "name": "TruffleHog",
                          "informationUri": "https://github.com/trufflesecurity/trufflehog",
                          "rules": [],
                      }
                  },
                  "results": [],
              }],
          }
          rules_seen = set()

          def to_int(value):
              try:
                  return max(1, int(value))
              except (TypeError, ValueError):
                  return 1

          def add_rule(rule_id, detector):
              if rule_id in rules_seen:
                  return
              sarif["runs"][0]["tool"]["driver"]["rules"].append({
                  "id": rule_id,
                  "shortDescription": {"text": f"TruffleHog detector: {detector}"},
                  "defaultConfiguration": {"level": "error"},
              })
              rules_seen.add(rule_id)

          def source_location(item):
              metadata = item.get("SourceMetadata") or {}
              data = metadata.get("Data") or {}
              if isinstance(data, dict):
                  for value in data.values():
                      if not isinstance(value, dict):
                          continue
                      path = value.get("file") or value.get("File") or value.get("path") or value.get("Path")
                      if path:
                          line = value.get("line") or value.get("Line") or value.get("line_number") or value.get("LineNumber")
                          return str(path), to_int(line)
              return str(item.get("SourceName") or "unknown"), 1

          if os.path.exists("trufflehog.jsonl"):
              with open("trufflehog.jsonl", "r", encoding="utf-8", errors="replace") as fh:
                  for raw in fh:
                      raw = raw.strip()
                      if not raw:
                          continue
                      try:
                          item = json.loads(raw)
                      except json.JSONDecodeError:
                          continue
                      detector = str(item.get("DetectorName") or item.get("DetectorType") or "TruffleHog")
                      rule_id = detector.replace(" ", "-") or "TruffleHog"
                      add_rule(rule_id, detector)
                      path, line = source_location(item)
                      verified = bool(item.get("Verified"))
                      message = f"TruffleHog detected a {'verified ' if verified else ''}secret with detector {detector}."
                      redacted = item.get("Redacted")
                      if redacted:
                          message += f" Redacted value: {redacted}"
                      sarif["runs"][0]["results"].append({
                          "ruleId": rule_id,
                          "level": "error" if verified else "warning",
                          "message": {"text": message},
                          "locations": [{
                              "physicalLocation": {
                                  "artifactLocation": {"uri": path},
                                  "region": {"startLine": line},
                              }
                          }],
                      })

          with open("trufflehog.sarif", "w", encoding="utf-8") as fh:
              json.dump(sarif, fh, indent=2)
          PY
          if ! jq -e '.version and (.runs | type == "array")' trufflehog.sarif >/dev/null 2>&1; then
            echo '::warning::trufflehog produced no valid SARIF; dropping the artifact'
            rm -f trufflehog.sarif
          fi
      - uses: actions/upload-artifact@v6
        with:
          name: trufflehog
          path: trufflehog.sarif
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
      - name: Set up Go
        continue-on-error: true
        uses: actions/setup-go@v6
        with:
          go-version: stable
      - name: Run gosec
        continue-on-error: true
        env:
          GO_MODULE_PATTERN: '${{ vars.GO_MODULE_PATTERN }}'
          GO_MODULE_TOKEN: '${{ secrets.PACKAGES_TOKEN }}'
        shell: bash --noprofile --norc {0}
        run: |
          if [ -n "${GO_MODULE_TOKEN:-}" ]; then
            go env -w GOPRIVATE="${GO_MODULE_PATTERN:-github.com/$(echo "${GITHUB_REPOSITORY:-}" | cut -d/ -f1)/*}"
            git config --global url."https://x-access-token:${GO_MODULE_TOKEN}@github.com/".insteadOf "https://github.com/"
          fi
          if [ ! -f go.mod ]; then
            echo '::notice::no go.mod found; skipping gosec'
            exit 0
          fi
          go install github.com/securego/gosec/v2/cmd/gosec@v2.28.0
          gosec -no-fail -fmt sarif -out gosec.sarif ./... || true
          if ! jq -e '.version and (.runs | type == "array")' gosec.sarif >/dev/null 2>&1; then
            echo '::warning::gosec produced no valid SARIF; dropping the artifact'
            rm -f gosec.sarif
          fi
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
      - name: Set up uv
        continue-on-error: true
        uses: astral-sh/setup-uv@v6
      - name: Run Semgrep
        continue-on-error: true
        shell: bash --noprofile --norc {0}
        run: |
          if ! command -v uvx >/dev/null 2>&1; then
            curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || true
            export PATH="$HOME/.local/bin:$PATH"
          fi
          if ! command -v uvx >/dev/null 2>&1; then
            echo '::warning::uv is unavailable on this runner; skipping'
            exit 0
          fi
          uvx --from semgrep semgrep scan --config auto --sarif --output semgrep.sarif .
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
