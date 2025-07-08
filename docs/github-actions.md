# Vulnetix GitHub Actions Reference

Comprehensive guide for using Vulnetix CLI in GitHub Actions workflows.

## Quick Start

```yaml
name: Vulnetix Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Run Vulnetix scan
        uses: vulnetix/vulnetix@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
```

## Action Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `org-id` | Organization ID (UUID) for Vulnetix operations | Yes | - |
| `task` | Task to perform (scan, release, report, triage) | No | `scan` |
| `version` | Version of Vulnetix CLI to use | No | `latest` |
| `project-name` | Name of the project being scanned | No | Repository name |
| `team-name` | Team responsible for the project | No | - |
| `product-name` | Product name for reporting | No | - |
| `group-name` | Group name for organization | No | - |
| `tags` | Comma-separated tags for categorization | No | - |
| `config-file` | Path to configuration file | No | - |
| `output-dir` | Directory for output files | No | `./vulnetix-output` |
| `production-branch` | Production branch name (for release task) | No | `main` |
| `release-branch` | Release branch name (for release task) | No | Current branch |
| `workflow-run-timeout` | Timeout for artifact collection (minutes) | No | `30` |
| `tools` | JSON/YAML configuration for security tools | No | - |

## Action Outputs

| Output | Description |
|--------|-------------|
| `result` | Result of the Vulnetix CLI execution |
| `scan-id` | Unique identifier for the scan |
| `report-url` | URL to the generated report |
| `findings-count` | Number of security findings |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high severity findings |

## Usage Examples

### Basic Vulnerability Scanning

```yaml
name: Basic Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        
      - name: Run Vulnetix vulnerability scan
        uses: vulnetix/vulnetix@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          task: scan
          project-name: ${{ github.repository }}
          team-name: "Security Team"
          tags: "ci,automated,security"
```

### Release Readiness Assessment

```yaml
name: Release Security Assessment

on:
  pull_request:
    branches: [ main ]

jobs:
  # Security scanning jobs that generate artifacts
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

  # Release readiness assessment
  release-assessment:
    runs-on: ubuntu-latest
    needs: [sast-scan, sca-scan, secrets-scan]
    permissions:
      actions: read      # Required for accessing workflow artifacts
      contents: read     # Required for repository context
      id-token: read     # Required for artifact fetching
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Vulnetix Release Assessment
        uses: vulnetix/vulnetix@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          task: release
          project-name: ${{ github.repository }}
          team-name: "DevSecOps"
          workflow-run-timeout: "45"
          tools: |
            - category: "SAST"
              tool_name: "sast-tool"
              artifact_name: "sast-sarif-results"
              format: "SARIF"
            - category: "SCA"
              tool_name: "sca-tool"
              artifact_name: "sca-sbom-report"
              format: "JSON"
            - category: "SECRETS"
              tool_name: "secrets-tool"
              artifact_name: "secrets-sarif-results"
              format: "SARIF"
```

### Comprehensive Security Pipeline

```yaml
name: Comprehensive Security Pipeline

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  # Multi-language security scanning
  security-analysis:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        scan-type: [sast, sca, secrets, container]
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        
      - name: Set up scan environment
        run: |
          mkdir -p security-reports
          
      - name: SAST Scan
        if: matrix.scan-type == 'sast'
        run: |
          # Semgrep for multiple languages
          pip install semgrep
          semgrep --config=auto --sarif --output=security-reports/sast-semgrep.sarif .
          
          # CodeQL for additional coverage
          if [ -f ".github/codeql/codeql-config.yml" ]; then
            echo "CodeQL scan will be handled by separate workflow"
          fi
          
      - name: SCA Scan
        if: matrix.scan-type == 'sca'
        run: |
          # Generate SBOM
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          syft dir:. -o spdx-json=security-reports/sbom.json
          
          # Language-specific dependency scans
          if [ -f "package.json" ]; then
            npm audit --audit-level=moderate --json > security-reports/npm-audit.json || true
          fi
          
          if [ -f "requirements.txt" ]; then
            pip install safety
            safety check --json --output security-reports/python-safety.json || true
          fi
          
          if [ -f "go.mod" ]; then
            go install golang.org/x/vuln/cmd/govulncheck@latest
            govulncheck -json ./... > security-reports/go-vulncheck.json || true
          fi
          
      - name: Secrets Scan
        if: matrix.scan-type == 'secrets'
        run: |
          curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.18.0_linux_x64.tar.gz | tar -xz
          ./gitleaks detect --source=. --report-format=sarif --report-path=security-reports/secrets-gitleaks.sarif
          
          # Additional secrets scanning with TruffleHog
          docker run --rm -v "$PWD:/workspace" trufflesecurity/trufflehog:latest filesystem /workspace --format sarif > security-reports/secrets-trufflehog.sarif
          
      - name: Container Scan
        if: matrix.scan-type == 'container' && hashFiles('**/Dockerfile') != ''
        run: |
          # Build image for scanning
          docker build -t scan-target:latest .
          
          # Scan with Grype
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
          grype scan-target:latest -o sarif=security-reports/container-grype.sarif
          
          # Scan with Trivy
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
          trivy image --format sarif --output security-reports/container-trivy.sarif scan-target:latest
          
      - name: Upload scan artifacts
        uses: actions/upload-artifact@v4
        with:
          name: vulnetix-${{ github.repository_owner }}-${{ github.event.repository.name }}-${{ github.run_id }}-${{ matrix.scan-type }}-results
          path: security-reports/
          retention-days: 30

  # Aggregate security assessment
  security-assessment:
    runs-on: ubuntu-latest
    needs: [security-analysis]
    permissions:
      actions: read
      contents: read
      id-token: read
      security-events: write  # For uploading SARIF results
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        
      - name: Download all artifacts
        uses: actions/download-artifact@v4
        with:
          path: security-reports
          
      - name: Vulnetix Comprehensive Assessment
        id: vulnetix-scan
        uses: vulnetix/vulnetix@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          task: release
          project-name: ${{ github.repository }}
          team-name: "Security Engineering"
          product-name: "Core Platform"
          workflow-run-timeout: "60"
          tools: |
            - category: "SAST"
              tool_name: "sast-tool"
              artifact_name: "sast-results"
              format: "SARIF"
            - category: "SCA"
              tool_name: "sca-tool"
              artifact_name: "sca-results"
              format: "JSON"
            - category: "SECRETS"
              tool_name: "secrets-tool"
              artifact_name: "secrets-results"
              format: "SARIF"
            - category: "CONTAINER"
              tool_name: "container-tool"
              artifact_name: "container-results"
              format: "SARIF"
              
      - name: Upload security findings to GitHub
        if: always()
        run: |
          # Upload SARIF files to GitHub Security tab
          find security-reports -name "*.sarif" -exec gh api repos/${{ github.repository }}/code-scanning/sarifs --input {} \;
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          
      - name: Generate security summary
        if: always()
        run: |
          echo "## Security Scan Results" >> $GITHUB_STEP_SUMMARY
          echo "- Scan ID: ${{ steps.vulnetix-scan.outputs.scan-id }}" >> $GITHUB_STEP_SUMMARY
          echo "- Total Findings: ${{ steps.vulnetix-scan.outputs.findings-count }}" >> $GITHUB_STEP_SUMMARY
          echo "- Critical: ${{ steps.vulnetix-scan.outputs.critical-count }}" >> $GITHUB_STEP_SUMMARY
          echo "- High: ${{ steps.vulnetix-scan.outputs.high-count }}" >> $GITHUB_STEP_SUMMARY
          echo "- Report: ${{ steps.vulnetix-scan.outputs.report-url }}" >> $GITHUB_STEP_SUMMARY
```

### Scheduled Security Reports

```yaml
name: Weekly Security Report

on:
  schedule:
    - cron: '0 9 * * 1'  # Mondays at 9 AM
  workflow_dispatch:    # Manual trigger

jobs:
  security-report:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        
      - name: Generate weekly security report
        uses: vulnetix/vulnetix@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          task: report
          project-name: ${{ github.repository }}
          team-name: "Security Team"
          product-name: "Platform Services"
          output-dir: ./reports
          
      - name: Upload report artifacts
        uses: actions/upload-artifact@v4
        with:
          name: weekly-security-report-${{ github.run_number }}
          path: ./reports/
          retention-days: 90
          
      - name: Send report notification
        if: always()
        run: |
          # Send notification to team (Slack, email, etc.)
          echo "Weekly security report generated and available in artifacts"
```

## Edge Cases & Advanced Configuration

### Corporate Proxy Support

```yaml
name: Corporate Environment Scan

on: [push, pull_request]

jobs:
  security-scan:
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
          
      - name: Run Vulnetix scan with proxy
        uses: vulnetix/vulnetix@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
        env:
          HTTP_PROXY: ${{ secrets.CORPORATE_HTTP_PROXY }}
          HTTPS_PROXY: ${{ secrets.CORPORATE_HTTPS_PROXY }}
```

### Self-Hosted Runners

```yaml
name: Self-Hosted Runner Security Scan

on: [push, pull_request]

jobs:
  security-scan:
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
          curl -I https://app.vulnetix.com/api/
          
      - name: Clean workspace
        run: |
          # Clean previous artifacts
          rm -rf vulnetix-output/ security-reports/
          docker system prune -f
          
      - name: Run Vulnetix scan
        uses: vulnetix/vulnetix@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          version: "latest"
          
      - name: Cleanup after scan
        if: always()
        run: |
          # Cleanup sensitive data
          rm -rf ~/.vulnetix/cache
          docker system prune -f
```

### Matrix Strategy for Multiple Projects

```yaml
name: Multi-Project Security Scan

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  security-scan:
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
        
      - name: Scan ${{ matrix.project.name }}
        uses: vulnetix/vulnetix@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          project-name: ${{ matrix.project.name }}
          team-name: ${{ matrix.project.team }}
        env:
          WORKING_DIRECTORY: ${{ matrix.project.path }}
```

### Conditional Scanning

```yaml
name: Conditional Security Scan

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

  security-scan:
    runs-on: ubuntu-latest
    needs: detect-changes
    if: needs.detect-changes.outputs.source-files == 'true' || needs.detect-changes.outputs.security-files == 'true'
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Run comprehensive scan for security changes
        if: needs.detect-changes.outputs.security-files == 'true'
        uses: vulnetix/vulnetix@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          task: scan
          tags: "comprehensive,security-config-change"
          
      - name: Run quick scan for source changes
        if: needs.detect-changes.outputs.source-files == 'true' && needs.detect-changes.outputs.security-files == 'false'
        uses: vulnetix/vulnetix@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          task: scan
          tags: "quick,source-change"
```

### Integration with GitHub Security Features

```yaml
name: GitHub Security Integration

on: [push, pull_request]

jobs:
  security-scan:
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
        
      # Run Vulnetix scan
      - name: Run Vulnetix scan
        uses: vulnetix/vulnetix@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          
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
# Issue: Action vulnetix/vulnetix@v1 not found
# Solution: Verify action reference and version

steps:
  - name: Debug action reference
    run: |
      curl -s https://api.github.com/repos/vulnetix/vulnetix/releases/latest
      
  - name: Use specific version
    uses: vulnetix/vulnetix@v1.2.3  # Use specific version
    # or
    uses: vulnetix/vulnetix@main    # Use latest from main branch
```

#### Permission Denied

```yaml
# Issue: Permission denied accessing artifacts
# Solution: Add required permissions

jobs:
  security-scan:
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
    uses: vulnetix/vulnetix@v1
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
    uses: vulnetix/vulnetix@v1
    with:
      org-id: ${{ secrets.VULNETIX_ORG_ID }}
      task: release
      workflow-run-timeout: "60"  # Increase timeout
      
  - name: Debug artifacts
    run: |
      gh api repos/${{ github.repository }}/actions/runs/${{ github.run_id }}/artifacts
    env:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Performance Issues

#### Slow Scans

```yaml
# Solution: Optimize scan performance

steps:
  - name: Run optimized scan
    uses: vulnetix/vulnetix@v1
    with:
      org-id: ${{ secrets.VULNETIX_ORG_ID }}
      task: scan
      # Add performance optimizations
    env:
      VULNETIX_PARALLEL_JOBS: "4"
      VULNETIX_CACHE_ENABLED: "true"
```

#### Large Repository Handling

```yaml
# Solution: Handle large repositories

steps:
  - name: Sparse checkout for security scan
    uses: actions/checkout@v4
    with:
      sparse-checkout: |
        src/
        lib/
        security/
      sparse-checkout-cone-mode: false
      
  - name: Run targeted scan
    uses: vulnetix/vulnetix@v1
    with:
      org-id: ${{ secrets.VULNETIX_ORG_ID }}
      # Limit scan scope for performance
```

## Security Best Practices

### Secrets Management

```yaml
# Use GitHub Secrets for sensitive data
steps:
  - name: Run secure scan
    uses: vulnetix/vulnetix@v1
    with:
      org-id: ${{ secrets.VULNETIX_ORG_ID }}
      # Never hardcode secrets in workflow files
    env:
      VULNETIX_API_TOKEN: ${{ secrets.VULNETIX_API_TOKEN }}
```

### Minimal Permissions

```yaml
# Grant only necessary permissions
jobs:
  security-scan:
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

For more examples and advanced configurations, see the [main documentation](../USAGE.md) and other [reference guides](./README.md).
