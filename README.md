# Vulnetix CLI & GitHub Action

This GitHub Action provides the Vulnetix CLI for your workflows, enabling automated vulnerability management directly in your CI/CD pipeline.

Please also check out our [GitHub App](https://github.com/marketplace/vulnetix) for additional integrations.

## Platform Support

Vulnetix supports all major platforms and installation methods:

| Method | Linux | macOS | Windows | CI/CD | Enterprise | Installation |
|--------|-------|-------|---------|-------|------------|-------------|
| [**Go Install**](./docs/go-install.md) | ✅ | ✅ | ✅ | ✅ | ✅ | `go install github.com/vulnetix/cli@latest` |
| [**Binary Download**](./docs/curl.md) | ✅ | ✅ | ✅ | ✅ | ✅ | Direct download with curl |
| [**From Source**](./docs/from-source.md) | ✅ | ✅ | ✅ | ✅ | ✅ | Full customization |
| [**GitHub Actions**](./docs/github-actions.md) | ✅ | ✅ | ✅ | ✅ | ✅ | Native GitHub integration |
| [**GitLab CI**](./docs/gitlab-ci.md) | ✅ | ✅ | ✅ | ✅ | ✅ | GitLab pipeline integration |
| [**Azure DevOps**](./docs/azure-devops.md) | ✅ | ✅ | ✅ | ✅ | ✅ | Azure pipeline integration |
| [**Bitbucket**](./docs/bitbucket.md) | ✅ | ✅ | ✅ | ✅ | ✅ | Bitbucket pipeline integration |

**Architecture Support:** AMD64, ARM64, ARM, 386 across all platforms

### Quick Start Examples

#### GitHub Action

```yaml
# In a Pull Request workflow
- name: Vulnetix Release Assessment
  uses: Vulnetix/cli@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
    task: release
    tools: |
      - category: "SAST"
        artifact_name: "sarif-results"
        format: "SARIF"
        tool_name: "semgrep"
      - category: "SCA" 
        artifact_name: "sbom-report"
        format: "SBOM"
        tool_name: "syft"
```

Required Permissions

```yaml
permissions:
  # Required for accessing workflow run artifacts
  actions: read
  # Required for accessing repository context
  contents: read
  # Required if fetching artifacts from other jobs
  id-token: read
```

#### Go Install

```bash
go install github.com/vulnetix/cli@latest
vulnetix --org-id "your-org-id" --task scan
```

#### Local Binary

Download and run the binary directly:

```bash
# Linux AMD64
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64 -o vulnetix
chmod +x vulnetix && ./vulnetix --org-id "your-org-id-here"

# macOS (Intel)
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-darwin-amd64 -o vulnetix
chmod +x vulnetix && ./vulnetix --org-id "your-org-id-here"

# macOS (Apple Silicon)
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-darwin-arm64 -o vulnetix
chmod +x vulnetix && ./vulnetix --org-id "your-org-id-here"

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-windows-amd64.exe" -OutFile "vulnetix.exe"
.\vulnetix.exe --org-id "your-org-id-here"
```

[📖 **View detailed usage examples →**](./USAGE.md)

## Available Tasks

Vulnetix supports multiple task types to cover different aspects of vulnerability management:

| Task | Description | Use Case | Required Flags |
|------|-------------|----------|----------------|
| `release` | Release readiness assessment | Pre-release security validation | `--org-id`, `--production-branch`, `--release-branch` |
| `sarif` | Upload and validate SARIF files | Integrate with external security tools | `--org-id`, `<sarif-file>` |

### Configuration Options

| Flag | Description | Default | Example |
|------|-------------|---------|---------|
| `--org-id` | Organization ID (UUID) - **Required** | - | `123e4567-e89b-12d3-a456-426614174000` |
| `--task` | Task to perform | - | `release` `sarif` |
| `--project-name` | Project name for context | - | `my-web-app` |
| `--team-name` | Team responsible for the project | - | `security-team` |
| `--production-branch` | Production branch name | `main` | `main`, `master`, `production` |
| `--release-branch` | Release branch name | - | `release/v2.1.0`, `feature/auth` |
| `--workflow-timeout` | Timeout for CI artifact collection (minutes) | `30` | `45`, `60` |
| `--tags` | YAML list of tags for categorization | - | `'["Public", "Crown Jewels"]'` |
| `--tools` | YAML array of tool configurations | - | See [tool configuration](#tool-configuration) |
| `--group-name` | Group name for organizational hierarchy | - | `engineering`, `security` |
| `--product-name` | Product name for context | - | `core-platform`, `mobile-app` |

### Tool Configuration

The `--tools` flag accepts a YAML array for configuring multiple security tools:

```yaml
# Example tools configuration
  - category: "SAST"
    tool_name: "semgrep"
    artifact_name: "sast-results"
    format: "SARIF"
  - category: "SCA"
    tool_name: "trivy"
    artifact_name: "dependency-scan"
    format: "SARIF"
  - category: "SECRETS"
    tool_name: "trufflehog"
    artifact_name: "secrets-scan"
    format: "JSON"
```

Alternatively, you can use JSON format:

```json
[
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
  },
  {
    "category": "SECRETS",
    "tool_name": "trufflehog",
    "artifact_name": "secrets-scan",
    "format": "JSON"
  }
]
```

## Documentation

- **[Installation](docs/README.md)** - Installation guides for all platforms
- **[CLI Reference](docs/CLI-REFERENCE.md)** - Complete command-line documentation
- **[Usage Examples](USAGE.md)** - Comprehensive usage guide
- **[GitHub Actions Artifact Upload](docs/GHA_COMMAND.md)** - Upload workflow artifacts to Vulnetix
- **[Distribution](docs/PUBLISHING.md)** - How we distribute across platforms

## Distribution

Vulnetix CLI is published on each release:

- **GitHub Releases** -- Go Install, Binary Downloads
- **GitHub Marketplace** -- GitHub Actions integration
