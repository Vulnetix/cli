---
title: "GitHub Actions"
weight: 1
description: "Integrate Vulnetix CLI into GitHub Actions workflows."
---

Comprehensive guide for using Vulnetix CLI in GitHub Actions workflows.

## Quick Start

```yaml
name: Vulnetix
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
jobs:
  vulnetix:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Setup Go (required by Vulnetix action)
      uses: actions/setup-go@v5
      with:
        go-version: stable

    - name: Run Vulnetix
      uses: Vulnetix/cli@v1
      with:
        org-id: ${{ secrets.VULNETIX_ORG_ID }}
```

## Action Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `org-id` | Organization ID (UUID) for Vulnetix operations | Yes | - |
| `task` | Task to perform: `info`, `upload`, `gha` | No | `info` |
| `version` | Version of Vulnetix CLI to use | No | `latest` |
| `api-key` | Direct API Key for authentication (hex digest) | No | - |
| `upload-file` | Path to artifact file to upload (used with `task: upload`) | No | - |
| `upload-format` | Override auto-detected artifact format (`cyclonedx`, `spdx`, `sarif`, `openvex`, `csaf_vex`) | No | - |

> **Note:** The action builds the CLI from source and requires Go to be available. Add `actions/setup-go` to your workflow before this action.

## Action Outputs

| Output | Description |
|--------|-------------|
| `result` | Result of the Vulnetix CLI execution |
| `summary` | Summary of vulnerabilities processed |
| `upload-uuid` | Pipeline UUID of the uploaded artifact (when `task: upload`) |

## Usage Examples

### Basic Usage

```yaml
name: Basic Security Assessment

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  vulnetix:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: stable

      - name: Run Vulnetix
        uses: Vulnetix/cli@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
```

### Security Assessment

```yaml
name: Vulnetix
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
jobs:
  # Security assessment jobs that generate artifacts
  sast-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run SAST with Semgrep
        run: |
          pip install semgrep
          semgrep --config=auto --sarif --output=sast-results.sarif .

      - name: Upload SAST results
        uses: actions/upload-artifact@v4
        with:
          name: vulnetix-${{ github.repository_owner }}-${{ github.event.repository.name }}-${{ github.run_id }}-sast-sarif-results
          path: sast-results.sarif
          retention-days: 7

  sca-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Generate SBOM with Syft
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          syft dir:. -o spdx-json=sbom.json

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: vulnetix-${{ github.repository_owner }}-${{ github.event.repository.name }}-${{ github.run_id }}-sca-sbom-report
          path: sbom.json
          retention-days: 7

  secrets-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run secrets scan with Gitleaks
        run: |
          curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.18.0_linux_x64.tar.gz | tar -xz
          ./gitleaks detect --source=. --report-format=sarif --report-path=secrets-results.sarif

      - name: Upload secrets scan results
        uses: actions/upload-artifact@v4
        with:
          name: vulnetix-${{ github.repository_owner }}-${{ github.event.repository.name }}-${{ github.run_id }}-secrets-sarif-results
          path: secrets-results.sarif
          retention-days: 7

  vulnetix:
    runs-on: ubuntu-latest
    needs: [sast-scan, sca-scan, secrets-scan]
    permissions:
      actions: read      # Required for accessing workflow artifacts
      contents: read     # Required for repository context
    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Setup Go
      uses: actions/setup-go@v5
      with:
        go-version: stable

    - name: Upload artifacts to Vulnetix
      uses: Vulnetix/cli@v1
      with:
        task: gha
        org-id: ${{ secrets.VULNETIX_ORG_ID }}
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Gate on Vulnerabilities and Supply Chain

Use `vulnetix scan` directly in a workflow to enforce policy gates. The scan exits with code `1` when any gate is breached, failing the CI step.

```yaml
name: Vulnetix Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Vulnetix CLI
        run: curl -fsSL https://vulnetix.com/install.sh | sh

      - name: Scan with gates
        run: vulnetix scan --block-eol --severity high --version-lag 1 --cooldown 3
        env:
          VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
```

Available gates: `--severity`, `--block-eol`, `--block-malware`, `--block-unpinned`, `--exploits`, `--version-lag`, `--cooldown`. See the [Scan Command Reference]({{< relref "scan" >}}) for details.

### SAST with Custom Rules

Run built-in SAST rules alongside SCA, optionally loading additional rules from a repository. Upload the SARIF output to GitHub Code Scanning for tracking in the Security tab.

```yaml
name: Vulnetix SAST + SCA
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # Required to upload SARIF to GitHub Code Scanning
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Install Vulnetix CLI
        run: curl -fsSL https://vulnetix.com/install.sh | sh

      - name: Scan with SAST and SCA
        run: vulnetix scan --severity high --output results.sarif
        env:
          VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

The `--output results.sarif` flag writes a combined SARIF file (SCA + SAST findings) while still showing the pretty summary on stdout. The `.vulnetix/sast.sarif` file is also written automatically with SAST-only findings.

To load custom rules from a private GitHub repository:

```yaml
      - name: Scan with custom SAST rules
        run: vulnetix scan --severity high --rule myorg/security-rules --output results.sarif
        env:
          VULNETIX_API_KEY: ${{ secrets.VULNETIX_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Edge Cases & Advanced Configuration

### Corporate Proxy Support

```yaml
name: Corporate Environment Assessment

on: [push, pull_request]

jobs:
  vulnetix:
    runs-on: ubuntu-latest
    env:
      HTTP_PROXY: ${{ secrets.CORPORATE_HTTP_PROXY }}
      HTTPS_PROXY: ${{ secrets.CORPORATE_HTTPS_PROXY }}
      NO_PROXY: ${{ secrets.CORPORATE_NO_PROXY }}
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure proxy for tools
        run: |
          # Configure git for proxy
          git config --global http.proxy $HTTP_PROXY
          git config --global https.proxy $HTTPS_PROXY

          # Configure npm proxy
          npm config set proxy $HTTP_PROXY
          npm config set https-proxy $HTTPS_PROXY

          # Configure pip proxy
          mkdir -p ~/.pip
          cat > ~/.pip/pip.conf << EOF
          [global]
          proxy = $HTTP_PROXY
          EOF

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: stable

      - name: Run Vulnetix
        uses: Vulnetix/cli@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
        env:
          HTTP_PROXY: ${{ secrets.CORPORATE_HTTP_PROXY }}
          HTTPS_PROXY: ${{ secrets.CORPORATE_HTTPS_PROXY }}
```

### Self-Hosted Runners

```yaml
name: Self-Hosted Runner Security Assessment

on: [push, pull_request]

jobs:
  vulnetix:
    runs-on: [self-hosted, linux, security-scanner]
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Verify runner environment
        run: |
          # Check for required tools
          command -v docker >/dev/null 2>&1 || { echo "Docker not found"; exit 1; }
          command -v git >/dev/null 2>&1 || { echo "Git not found"; exit 1; }

          # Check disk space
          df -h

          # Check network connectivity
          curl -I https://app.vulnetix.com/api/check

      - name: Clean workspace
        run: |
          # Clean previous artifacts
          rm -rf vulnetix-output/ security-reports/

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: stable

      - name: Run Vulnetix
        uses: Vulnetix/cli@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}

      - name: Cleanup after scan
        if: always()
        run: |
          # Cleanup sensitive data
          rm -rf ~/.vulnetix/cache
```

### Matrix Strategy for Multiple Projects

```yaml
name: Multi-Project Security Assessment

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  vulnetix:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        project:
          - name: "frontend"
            path: "./frontend"
            team: "Frontend Team"
          - name: "backend"
            path: "./backend"
            team: "Backend Team"
          - name: "api"
            path: "./api"
            team: "API Team"
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: stable

      - name: Run Vulnetix for ${{ matrix.project.name }}
        uses: Vulnetix/cli@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
        env:
          WORKING_DIRECTORY: ${{ matrix.project.path }}
```

### Conditional Execution

```yaml
name: Conditional Security Assessment

on:
  pull_request:
    branches: [ main ]

jobs:
  detect-changes:
    runs-on: ubuntu-latest
    outputs:
      security-files: ${{ steps.changes.outputs.security }}
      source-files: ${{ steps.changes.outputs.source }}
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Detect changes
        uses: dorny/paths-filter@v2
        id: changes
        with:
          filters: |
            security:
              - '.github/workflows/security.yml'
              - 'security/**'
              - '.vulnetix.yml'
            source:
              - 'src/**'
              - 'lib/**'
              - '**/*.go'
              - '**/*.js'
              - '**/*.py'

  vulnetix:
    runs-on: ubuntu-latest
    needs: detect-changes
    if: needs.detect-changes.outputs.source-files == 'true' || needs.detect-changes.outputs.security-files == 'true'
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: stable

      - name: Run Vulnetix for security changes
        if: needs.detect-changes.outputs.security-files == 'true'
        uses: Vulnetix/cli@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}

      - name: Run Vulnetix for source changes
        if: needs.detect-changes.outputs.source-files == 'true' && needs.detect-changes.outputs.security-files == 'false'
        uses: Vulnetix/cli@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
```

### Integration with GitHub Security Features

```yaml
name: GitHub Security Integration

on: [push, pull_request]

jobs:
  vulnetix:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
      actions: read
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      # Run CodeQL analysis
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v2
        with:
          languages: javascript, python, go

      - name: Autobuild
        uses: github/codeql-action/autobuild@v2

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v2

      # Upload additional SARIF results
      - name: Upload custom SARIF
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: vulnetix-output/results.sarif
```

## Troubleshooting

### Common Issues

#### Action Not Found

```yaml
# Issue: Action vulnetix/cli@v1 not found
# Solution: Verify action reference and version

steps:
  - name: Debug action reference
    run: |
      curl -s https://api.github.com/repos/vulnetix/cli/releases/latest

  - name: Use specific version
    uses: Vulnetix/cli@v1.2.3  # Use specific version
    # or
    uses: Vulnetix/cli@main    # Use latest from main branch
```

#### Permission Denied

```yaml
# Issue: Permission denied accessing artifacts
# Solution: Add required permissions

jobs:
  vulnetix:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
      id-token: read
      security-events: write  # For SARIF upload
    steps:
      # ... scan steps
```

#### Network Connectivity Issues

```yaml
# Issue: Cannot connect to Vulnetix API
# Solution: Debug network connectivity

steps:
  - name: Debug network connectivity
    run: |
      echo "Testing connectivity..."
      curl -I https://app.vulnetix.com/api/
      nslookup app.vulnetix.com

  - name: Test with verbose output
    uses: Vulnetix/cli@v1
    with:
      org-id: ${{ secrets.VULNETIX_ORG_ID }}
    env:
      VULNETIX_LOG_LEVEL: debug
```

#### Artifact Collection Timeout

```yaml
# Issue: Timeout waiting for artifacts
# Solution: Increase timeout and debug

steps:
  - name: Run with extended timeout
    uses: Vulnetix/cli@v1
    with:
      org-id: ${{ secrets.VULNETIX_ORG_ID }}

  - name: Debug artifacts
    run: |
      gh api repos/${{ github.repository }}/actions/runs/${{ github.run_id }}/artifacts
    env:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

#### Large Repository Handling

```yaml
# Solution: Handle large repositories

steps:
  - name: Sparse checkout for security assessment
    uses: actions/checkout@v4
    with:
      sparse-checkout: |
        src/
        lib/
        security/
      sparse-checkout-cone-mode: false

  - name: Run Vulnetix
    uses: Vulnetix/cli@v1
    with:
      org-id: ${{ secrets.VULNETIX_ORG_ID }}
      # Limit scan scope for performance
```

### Minimal Permissions

```yaml
# Grant only necessary permissions
jobs:
  vulnetix:
    runs-on: ubuntu-latest
    permissions:
      contents: read        # Read repository contents
      actions: read         # Read workflow artifacts
      id-token: read        # OIDC token for authentication
      # security-events: write  # Only if uploading SARIF
```

### Secure Artifact Handling

```yaml
steps:
  - name: Upload security artifacts
    uses: actions/upload-artifact@v4
    with:
      name: security-reports
      path: security-reports/
      retention-days: 7     # Limit retention
      # if-no-files-found: warn
```
