# Using the Vulnetix GitHub Action

This repository provides a GitHub Action that makes the Vulnetix CLI available in your workflows.

## Quick Start

### GitHub Action

Add the following to your workflow file (`.github/workflows/vulnetix.yml`):

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
      
    - name: Run Vulnetix
      uses: Vulnetix/cli@v1
      with:
        org-id: ${{ secrets.VULNETIX_ORG_ID }}
        project-name: ${{ github.repository }}
        team-name: "DevSecOps"
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
        tags: '["Public", "Crown Jewels"]'
```

### Go Install

Install directly from source using Go (requires Go 1.21+):

```bash
# Install latest version
go install github.com/vulnetix/cli@latest

# Install specific version
go install github.com/vulnetix/cli@v1.2.3

# Auth healthcheck (default task)
vulnetix

# Triage task
vulnetix --org-id "your-org-id-here" --task triage
```

### Local Binary

```bash
# Download and run locally
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64 -o vulnetix
chmod +x vulnetix
./vulnetix --org-id "your-org-id-here"

# Upload SARIF file
vulnetix upload --file my-scan-results.sarif --org-id "your-org-id-here"
```

## Installation

Choose the installation method that works best for your environment:

### Quick Install Script

Use the installation script to automatically detect your platform:

```bash
# Install latest version (auto-detects platform)
curl -fsSL https://raw.githubusercontent.com/vulnetix/cli/main/install.sh | sh

# Install to specific directory
curl -fsSL https://raw.githubusercontent.com/vulnetix/cli/main/install.sh | sh -s -- --install-dir=/usr/local/bin

# Install specific version
curl -fsSL https://raw.githubusercontent.com/vulnetix/cli/main/install.sh | sh -s -- --version=v1.2.3
```

### Go Install

Install directly from source using Go (requires Go 1.21+):

```bash
# Install latest version
go install github.com/vulnetix/cli@latest

# Install specific version  
go install github.com/vulnetix/cli@v1.2.3

# Auth healthcheck (default task)
vulnetix

# Triage task with tags
vulnetix --org-id "your-org-id-here" --task triage --tags '["Public", "Crown Jewels"]'
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
  uses: Vulnetix/cli@v1
  with:
    org-id: '123e4567-e89b-12d3-a456-426614174000'
```

### With Specific Version

```yaml
- name: Run Vulnetix
  uses: Vulnetix/cli@v1
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
        uses: Vulnetix/cli@v1
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

### Default Info/Healthcheck

Running without arguments shows authentication status:

```bash
vulnetix
```

### Report Generation

```yaml
- name: Vulnerability Report
  uses: Vulnetix/cli@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
    task: report
    project-name: "My Web App"
    team-name: "Security Team"
    tags: '["critical", "frontend", "api"]'
```

