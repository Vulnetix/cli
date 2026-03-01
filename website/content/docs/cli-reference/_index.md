---
title: "CLI Reference"
weight: 2
description: "Complete reference for all Vulnetix CLI commands, flags, and usage patterns."
---

Complete reference for all Vulnetix CLI commands, flags, and usage patterns.

## Commands

### vulnetix (main command)

Run vulnerability management tasks.

```bash
vulnetix [flags]
```

### vulnetix SARIF

Upload and validate SARIF files.

```bash
vulnetix --task sarif [flags] [SARIF_FILE]
```

**Example:**
```bash
vulnetix --task sarif --org-id "123e4567-e89b-12d3-a456-426614174000" --file scan-results.sarif
```

### vulnetix version

Print the version number of Vulnetix CLI.

```bash
vulnetix version
```

### vulnetix completion

Generate the autocompletion script for the specified shell.

```bash
vulnetix completion [bash|zsh|fish|powershell]
```

## Global Flags

| Flag | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `--org-id` | string | **Yes** | - | Organization ID (UUID) for Vulnetix operations |
| `--task` | string | No | `scan` | Task to perform: scan, release, report, triage, sarif |
| `--project-name` | string | No | - | Project name for vulnerability management context |
| `--team-name` | string | No | - | Team name responsible for the project |
| `--group-name` | string | No | - | Group name for organizational hierarchy |
| `--product-name` | string | No | - | Product name for vulnerability management context |
| `--production-branch` | string | No | `main` | Production branch name (for release task) |
| `--release-branch` | string | No | - | Release branch name (for release task) |
| `--tags` | string | No | - | YAML list of tags for categorization (e.g., `'["Public", "Crown Jewels"]'`) |
| `--tools` | string | No | - | YAML array of tool configurations |
| `--workflow-timeout` | int | No | `30` | Timeout in minutes to wait for sibling job artifacts (for release task) |
| `--help` | - | No | - | Help for vulnetix |

## Tasks

### scan (default)

Perform vulnerability scanning.

```bash
vulnetix --org-id "your-org-id" --task release
vulnetix --org-id "your-org-id" --task release --project-name "my-app"
vulnetix --org-id "your-org-id" --task release --team-name "security-team"
```

### release

Perform release readiness assessment.

```bash
vulnetix --org-id "your-org-id" --task release
vulnetix --org-id "your-org-id" --task release \
  --production-branch "main" \
  --release-branch "release/v1.2.0"
vulnetix --org-id "your-org-id" --task release \
  --project-name "web-app" \
  --team-name "frontend-team" \
  --workflow-timeout 45
```

### report

Generate vulnerability reports.

```bash
vulnetix --org-id "your-org-id" --task report
vulnetix --org-id "your-org-id" --task report \
  --project-name "api-service" \
  --tags '["Public", "Crown Jewels"]'
```

### triage

Perform vulnerability triage.

```bash
vulnetix --org-id "your-org-id" --task triage
vulnetix --org-id "your-org-id" --task triage \
  --team-name "security-team" \
  --tags '["Public", "Crown Jewels"]'
```

### sarif

Upload and validate SARIF files (can also be used as a task).

```bash
vulnetix --task sarif --org-id "your-org-id" --file scan-results.sarif
vulnetix --task sarif --org-id "your-org-id" --project-name "my-app" --file results.sarif
```

## Tools Configuration

The `--tools` flag accepts a YAML array of tool configurations:

```bash
TOOLS_CONFIG='[
  {
    "category": "SAST",
    "tool_name": "semgrep",
    "artifact_name": "sast-results",
    "format": "SARIF"
  },
  {
    "category": "SCA",
    "tool_name": "trivy",
    "artifact_name": "dependency-scan",
    "format": "SARIF"
  }
]'

vulnetix --org-id "your-org-id" --task release --tools "${TOOLS_CONFIG}"
```

### Tool Configuration Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `category` | string | Yes | Tool category (SAST, SCA, SECRETS, etc.) |
| `tool_name` | string | Yes | Name of the security tool |
| `artifact_name` | string | Yes | Name of the artifact/result file |
| `format` | string | Yes | Format of the results (SARIF, JSON, etc.) |

## Environment Variables

You can set configuration via environment variables:

| Variable | Description | Equivalent Flag |
|----------|-------------|-----------------|
| `VULNETIX_ORG_ID` | Organization ID | `--org-id` |

```bash
export VULNETIX_ORG_ID="123e4567-e89b-12d3-a456-426614174000"
vulnetix --task release  # Uses VULNETIX_ORG_ID automatically
```

## Common Usage Patterns

### Basic Scanning
```bash
# Simple scan
vulnetix --org-id "your-org-id"

# Scan with context
vulnetix --org-id "your-org-id" \
  --project-name "web-app" \
  --team-name "frontend-team" \
  --tags '["Public", "Crown Jewels"]'
```

### Release Management
```bash
# Basic release assessment
vulnetix --org-id "your-org-id" --task release \
  --production-branch "main" \
  --release-branch "release/v1.0.0"

# Release assessment with team context
vulnetix --org-id "your-org-id" --task release \
  --project-name "api-service" \
  --team-name "backend-team" \
  --production-branch "main" \
  --release-branch "release/v2.1.0" \
  --workflow-timeout 60
```

### SARIF Upload
```bash
# Upload single SARIF file
vulnetix --task sarif --org-id "your-org-id" --file scan-results.sarif

# Upload with context
vulnetix --task sarif --org-id "your-org-id" \
  --project-name "my-app" \
  --team-name "security-team" \
  --file security-scan.sarif
```

### Reporting
```bash
# Generate reports
vulnetix --org-id "your-org-id" --task report

# Generate targeted reports
vulnetix --org-id "your-org-id" --task report \
  --project-name "critical-service" \
  --tags '["Public", "Crown Jewels"]'
```

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | Success |
| `1` | General error |
| `2` | Invalid arguments |
| `3` | Authentication error |
| `4` | Network error |
| `5` | File not found |

## Examples by Use Case

### CI/CD Integration
```bash
# GitHub Actions
vulnetix --org-id "$VULNETIX_ORG_ID" --task release

# GitLab CI
vulnetix --org-id "$VULNETIX_ORG_ID" --task release \
  --project-name "$CI_PROJECT_NAME"

# Jenkins
vulnetix --org-id "$VULNETIX_ORG_ID" --task release \
  --project-name "$JOB_NAME"
```

### Multi-Project Environments
```bash
# Frontend team
vulnetix --org-id "your-org-id" --task release \
  --project-name "web-frontend" \
  --team-name "frontend-team" \
  --tags '["javascript", "react"]'

# Backend team
vulnetix --org-id "your-org-id" --task release \
  --project-name "api-backend" \
  --team-name "backend-team" \
  --tags '["golang", "api"]'

# DevOps team
vulnetix --org-id "your-org-id" --task release \
  --project-name "infrastructure" \
  --team-name "devops-team" \
  --tags '["terraform", "kubernetes"]'
```

### Different Environments
```bash
# Development
vulnetix --org-id "your-org-id" --task release \
  --tags '["development", "non-critical"]'

# Staging
vulnetix --org-id "your-org-id" --task release \
  --production-branch "main" \
  --release-branch "staging" \
  --tags '["staging", "pre-production"]'

# Production
vulnetix --org-id "your-org-id" --task release \
  --production-branch "main" \
  --release-branch "release/v1.0.0" \
  --tags '["production", "critical"]'
```
