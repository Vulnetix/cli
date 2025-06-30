# Using the Vulnetix GitHub Action

This repository provides a GitHub Action that makes the Vulnetix CLI available in your workflows.

## Quick Start

Add the following to your workflow file (`.github/workflows/vulnetix.yml`):

```yaml
name: Vulnetix Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

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

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `org-id` | Organization ID (UUID) for Vulnetix operations | Yes | - |
| `version` | Version of Vulnetix CLI to use | No | `latest` |

## Outputs

| Output | Description |
|--------|-------------|
| `result` | Result of the Vulnetix CLI execution |

## Examples

### Basic Usage

```yaml
- name: Run Vulnetix
  uses: vulnetix/vulnetix@v1
  with:
    org-id: '123e4567-e89b-12d3-a456-426614174000'
```

### With Specific Version

```yaml
- name: Run Vulnetix
  uses: vulnetix/vulnetix@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
    version: 'v1.2.3'
```

### Complete Workflow Example

```yaml
name: Security and Compliance

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  vulnerability-scan:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        
      - name: Run Vulnetix vulnerability scan
        uses: vulnetix/vulnetix@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
        
      - name: Upload scan results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: vulnetix-scan-results
          path: vulnetix-results.json
          retention-days: 3
```

## Task-Based Configuration

Vulnetix supports different task types for various security workflows:

### Default Vulnerability Scanning

```yaml
- name: Vulnerability Scan
  uses: vulnetix/vulnetix@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
    task: scan  # Default task
    project-name: "My Web App"
    team-name: "Security Team"
    tags: '["critical", "frontend", "api"]'
```

### Release Readiness Assessment

For comprehensive release validation across multiple security tools:

```yaml
name: Release Security Assessment

on:
  pull_request:
    branches: [ main ]

jobs:
  # Example security scanning jobs that produce artifacts
  sast-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run SAST
        run: |
          # Your SAST tool here
          echo "Running SAST scan..."
      - name: Upload SARIF
        uses: actions/upload-artifact@v4
        with:
          name: vulnetix-myrepo-${{ github.run_id }}-sast-sarif-results
          path: sarif-results.json

  sca-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate SBOM
        run: |
          # Your SBOM generation here
          echo "Generating SBOM..."
      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: vulnetix-myrepo-${{ github.run_id }}-sca-sbom-report
          path: sbom.json

  # Release readiness assessment
  release-assessment:
    runs-on: ubuntu-latest
    needs: [sast-scan, sca-scan]
    permissions:
      actions: read      # Required for accessing workflow artifacts
      contents: read     # Required for repository context
      id-token: read     # Required for artifact fetching
    steps:
      - name: Vulnetix Release Assessment
        uses: vulnetix/vulnetix@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          task: release
          workflow-run-timeout: "45"
          tools: |
            - category: "SAST"
              artifact_name: "sarif-results"
              format: "SARIF"
              customer_identifier: "team-backend"
            - category: "SCA"
              artifact_name: "sbom-report"
              format: "SBOM"
              customer_identifier: "team-backend"
```

### Outside PR Context

When not running in a pull request, specify branches explicitly:

```yaml
- name: Release Assessment
  uses: vulnetix/vulnetix@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
    task: release
    production-branch: "main"
    release-branch: "release/v2.1.0"
    tools: |
      - category: "SECRETS"
        artifact_name: "secrets-scan"
        format: "SARIF"
        customer_identifier: "security-team"
```

### Report Generation

```yaml
- name: Generate Security Reports
  uses: vulnetix/vulnetix@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
    task: report
    project-name: "Production API"
    product-name: "Core Platform"
```

### Automated Triage

```yaml
- name: Auto Triage Vulnerabilities
  uses: vulnetix/vulnetix@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
    task: triage
    team-name: "DevSecOps"
```

## Configuration

### Setting up Organization ID

1. Get your organization ID from the Vulnetix dashboard
2. Add it as a repository secret named `VULNETIX_ORG_ID`
3. Use `${{ secrets.VULNETIX_ORG_ID }}` in your workflow

## Supported Platforms

The action supports the following platforms:
- Linux (x64, ARM64)
- macOS (x64, ARM64) 
- Windows (x64, ARM64)

## CLI Usage

You can also use the Vulnetix CLI directly:

```bash
# Download and run locally
curl -L https://github.com/vulnetix/vulnetix/releases/latest/download/vulnetix-linux-amd64 -o vulnetix
chmod +x vulnetix
./vulnetix --org-id "your-org-id-here"
```

## Troubleshooting

### Invalid UUID Error
Ensure your organization ID is a valid UUID format:
```
123e4567-e89b-12d3-a456-426614174000
```

### Permission Issues
Make sure the repository has the necessary permissions to run the action and access secrets.

### Binary Not Found
If you encounter binary not found errors, the action will automatically download the appropriate binary for your platform.

## Support

For issues and questions:
- Check the [Issues](https://github.com/vulnetix/vulnetix/issues) page
- Visit the [Vulnetix Documentation](https://docs.vulnetix.com)
- Contact support at support@vulnetix.com
