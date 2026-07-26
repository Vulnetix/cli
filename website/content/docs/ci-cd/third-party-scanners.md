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
| [cfn-lint](#cfn-lint) | IAC | `cfn-lint.sarif` |
| [Checkov](#checkov) | IAC | `results.sarif` |
| [KICS](#kics) | IAC | `kics-out/results.sarif` |
| [Terrascan](#terrascan) | IAC | `terrascan.sarif` |
| [tfsec](#tfsec) | IAC | `tfsec.sarif` |
| [Trivy (config)](#trivy-config) | IAC | `trivy-config.sarif` |
| [ScanCode Toolkit](#scancode) | LICENSE | `scancode.cdx.json` |
| [Rust Clippy](#clippy) | LINT | `clippy.sarif` |
| [ESLint](#eslint) | LINT | `eslint.sarif` |
| [golangci-lint](#golangci-lint) | LINT | `golangci-lint.sarif` |
| [RuboCop](#rubocop) | LINT | `rubocop.sarif` |
| [Ruff](#ruff) | LINT | `ruff.sarif` |
| [Stylelint](#stylelint) | LINT | `stylelint.sarif` |
| [SwiftLint](#swiftlint) | LINT | `swiftlint.sarif` |
| [Dockle](#dockle) | OCI | `dockle.sarif` |
| [Hadolint](#hadolint) | OCI | `hadolint.sarif` |
| [Nuclei](#nuclei) | PENTEST | `nuclei.sarif` |
| [Bandit](#bandit) | SAST | `bandit.sarif` |
| [Brakeman](#brakeman) | SAST | `brakeman.sarif` |
| [Cppcheck](#cppcheck) | SAST | `cppcheck.sarif` |
| [Flawfinder](#flawfinder) | SAST | `flawfinder.sarif` |
| [gosec](#gosec) | SAST | `gosec.sarif` |
| [njsscan](#njsscan) | SAST | `njsscan.sarif` |
| [PMD](#pmd) | SAST | `pmd-report.sarif` |
| [Semgrep](#semgrep) | SAST | `semgrep.sarif` |
| [zizmor](#zizmor) | SAST | `zizmor.sarif` |
| [cdxgen](#cdxgen) | SCA | `cdxgen.cdx.json` |
| [CycloneDX .NET](#cyclonedx-dotnet) | SCA | `cyclonedx-dotnet.cdx.json` |
| [CycloneDX Go](#cyclonedx-go) | SCA | `cyclonedx-go.cdx.json` |
| [CycloneDX npm](#cyclonedx-node) | SCA | `cyclonedx-node.cdx.json` |
| [CycloneDX PHP](#cyclonedx-php) | SCA | `cyclonedx-php.cdx.json` |
| [CycloneDX Python](#cyclonedx-python) | SCA | `cyclonedx-python.cdx.json` |
| [CycloneDX Ruby](#cyclonedx-ruby) | SCA | `cyclonedx-ruby.cdx.json` |
| [CycloneDX Rust](#cyclonedx-rust) | SCA | `cyclonedx-rust.cdx.json` |
| [govulncheck](#govulncheck) | SCA | `govulncheck.sarif` |
| [Grype](#grype) | SCA | `grype.sarif` |
| [npm audit](#npm-audit) | SCA | `npm-audit.sarif` |
| [OSV-Scanner](#osv-scanner) | SCA | `osv.sarif` |
| [OWASP Dependency-Check](#owasp-dependency-check) | SCA | `dependency-check.sarif` |
| [Retire.js](#retirejs) | SCA | `retirejs.cdx.json` |
| [Syft](#syft) | SCA | `sbom.cdx.json` |
| [Trivy (filesystem)](#trivy-fs) | SCA | `trivy-fs.cdx.json`, `trivy-fs.sarif` |
| [CycloneDX Yarn](#yarn-cyclonedx) | SCA | `yarn-cyclonedx.cdx.json` |
| [detect-secrets](#detect-secrets) | SECRETS | `detect-secrets-results.sarif` |
| [Gitleaks](#gitleaks) | SECRETS | `gitleaks.sarif` |
| [TruffleHog](#trufflehog) | SECRETS | `trufflehog.sarif` |

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
      - name: Set up Python
        continue-on-error: true
        uses: actions/setup-python@v5
        with:
          python-version: 3.x
      - name: Run cfn-lint
        continue-on-error: true
        run: |
          templates=$(find . -path ./.git -prune -o -type f \( -name '*.template' -o -name '*.yaml' -o -name '*.yml' -o -name '*.json' \) -print)
          if [ -z "$templates" ]; then
            echo '::notice::no candidate CloudFormation templates found; skipping cfn-lint'
            exit 0
          fi
          python3 -m pip install --quiet --break-system-packages cfn-lint
          cfn-lint -f sarif -t $templates >cfn-lint.sarif 2>cfn-lint.stderr
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
      - name: Set up Python
        continue-on-error: true
        uses: actions/setup-python@v5
        with:
          python-version: 3.x
      - name: Run ScanCode Toolkit
        continue-on-error: true
        run: |
          python3 -m pip install --quiet --break-system-packages scancode-toolkit
          scancode --license --copyright --package --cyclonedx scancode.cdx.json . || true
          if ! jq -e '.bomFormat == "CycloneDX"' scancode.cdx.json >/dev/null 2>&1; then
            echo '::warning::scancode produced no valid CycloneDX JSON; dropping the artifact'
            rm -f scancode.cdx.json
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
        run: |
          if [ ! -f go.mod ]; then
            echo '::notice::no go.mod found; skipping golangci-lint'
            exit 0
          fi
          go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
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
        run: |
          if ! find . -path ./.git -prune -o -type f -name '*.rb' -print | head -n 1 | grep -q .; then
            echo '::notice::no Ruby files found; skipping RuboCop'
            exit 0
          fi
          gem install rubocop
          rubocop --format github --out rubocop.github-actions.txt || true
          rubocop --format json --out rubocop.json || true
          python3 <<'PY'
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
      - name: Set up Python
        continue-on-error: true
        uses: actions/setup-python@v5
        with:
          python-version: 3.x
      - name: Run Ruff security rules
        continue-on-error: true
        run: |
          if ! find . -path ./.git -prune -o -type f -name '*.py' -print | head -n 1 | grep -q .; then
            echo '::notice::no Python files found; skipping Ruff'
            exit 0
          fi
          python3 -m pip install --quiet --break-system-packages ruff
          ruff check --select S --output-format sarif -o ruff.sarif . || true
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
        run: |
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
          NUCLEI_TARGET_URL: '${{ vars.NUCLEI_TARGET_URL }}'
        run: |
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
      - name: Set up Python
        continue-on-error: true
        uses: actions/setup-python@v5
        with:
          python-version: 3.x
      - name: Run Bandit
        continue-on-error: true
        run: |
          if ! find . -path ./.git -prune -o -type f -name '*.py' -print | head -n 1 | grep -q .; then
            echo '::notice::no Python files found; skipping Bandit'
            exit 0
          fi
          python3 -m pip install --quiet --break-system-packages 'bandit[sarif]'
          bandit -r . -f sarif -o bandit.sarif || true
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
        run: |
          if ! find . -path ./.git -prune -o -type f -print | grep -E '\.(c|cc|cpp|h|hpp)$' | head -n 1 | grep -q .; then
            echo '::notice::no C/C++ files found; skipping Cppcheck'
            exit 0
          fi
          sudo apt-get update
          sudo apt-get install -y cppcheck
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
      - name: Set up Python
        continue-on-error: true
        uses: actions/setup-python@v5
        with:
          python-version: 3.x
      - name: Run Flawfinder
        continue-on-error: true
        run: |
          if ! find . -path ./.git -prune -o -type f -print | grep -E '\.(c|cc|cpp|h|hpp)$' | head -n 1 | grep -q .; then
            echo '::notice::no C/C++ files found; skipping Flawfinder'
            exit 0
          fi
          python3 -m pip install --quiet --break-system-packages flawfinder
          flawfinder --sarif . >flawfinder.sarif 2>flawfinder.stderr
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
      - name: Set up Python
        continue-on-error: true
        uses: actions/setup-python@v5
        with:
          python-version: 3.x
      - name: Run njsscan
        continue-on-error: true
        run: |
          if ! find . -path ./.git -prune -o -type f -print | grep -E '\.(js|jsx|ts|tsx)$' | head -n 1 | grep -q .; then
            echo '::notice::no JavaScript or TypeScript files found; skipping njsscan'
            exit 0
          fi
          python3 -m pip install --quiet --break-system-packages njsscan
          njsscan --sarif -o njsscan.sarif . || true
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
        run: |
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
      - name: Set up Python
        continue-on-error: true
        uses: actions/setup-python@v5
        with:
          python-version: 3.x
      - name: Generate Python CycloneDX SBOM
        continue-on-error: true
        run: |
          if [ ! -f requirements.txt ] && [ ! -f pyproject.toml ] && ! find . -path ./.git -prune -o -type f -name '*.py' -print | head -n 1 | grep -q .; then
            echo '::notice::no Python project detected; skipping CycloneDX Python'
            exit 0
          fi
          if [ -f requirements.txt ]; then
            python3 -m pip install --quiet --break-system-packages -r requirements.txt || true
          fi
          python3 -m pip install --quiet --break-system-packages cyclonedx-bom
          if [ -f requirements.txt ]; then
            cyclonedx-py requirements requirements.txt --output-format JSON --output-file cyclonedx-python.cdx.json || true
          else
            cyclonedx-py environment --output-format JSON --output-file cyclonedx-python.cdx.json || true
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
        run: |
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
      - name: Set up Python
        continue-on-error: true
        uses: actions/setup-python@v5
        with:
          python-version: 3.x
      - name: Run detect-secrets
        continue-on-error: true
        run: |
          python3 -m pip install --quiet --break-system-packages detect-secrets
          if [ -f .secrets.baseline ]; then
            detect-secrets scan --baseline .secrets.baseline >detect-secrets-results.json || true
          else
            detect-secrets scan --all-files >detect-secrets-results.json || true
          fi
          python3 <<'PY'
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
      - name: Set up Python
        continue-on-error: true
        uses: actions/setup-python@v5
        with:
          python-version: 3.x
      - name: Run TruffleHog
        continue-on-error: true
        run: |
          curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin
          trufflehog filesystem --json . >trufflehog.jsonl || true
          python3 <<'PY'
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
