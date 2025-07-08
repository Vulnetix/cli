# Vulnetix CLI & GitHub Action

### Automate vulnerability triage which prioritizes remediation over discovery

This GitHub Action provides the Vulnetix CLI for your workflows, enabling automated vulnerability management directly in your CI/CD pipeline.

Please also check out our [GitHub App](https://github.com/marketplace/vulnetix) for additional integrations.

## Platform Support

Vulnetix supports all major platforms and installation methods:

| Method | Linux | macOS | Windows | CI/CD | Enterprise | Installation |
|--------|-------|-------|---------|-------|------------|-------------|
| **Docker** | ✅ | ✅ | ✅ | ✅ | ✅ | `docker pull vulnetix/vulnetix` |
| **Go Install** | ✅ | ✅ | ✅ | ✅ | ✅ | `go install github.com/vulnetix/vulnetix@latest` |
| **Homebrew** | ✅ | ✅ | ❌ | ✅ | ✅ | `brew tap vulnetix/vulnetix && brew install vulnetix` |
| **Chocolatey** | ❌ | ❌ | ✅ | ✅ | ✅ | `choco install vulnetix` |
| **Binary Download** | ✅ | ✅ | ✅ | ✅ | ✅ | Direct download with curl |
| **From Source** | ✅ | ✅ | ✅ | ✅ | ✅ | Full customization |
| **GitHub Actions** | ✅ | ✅ | ✅ | ✅ | ✅ | Native GitHub integration |
| **GitLab CI** | ✅ | ✅ | ✅ | ✅ | ✅ | GitLab pipeline integration |
| **Azure DevOps** | ✅ | ✅ | ✅ | ✅ | ✅ | Azure pipeline integration |
| **Bitbucket** | ✅ | ✅ | ✅ | ✅ | ✅ | Bitbucket pipeline integration |
| **Kubernetes** | ✅ | ✅ | ✅ | ✅ | ✅ | Uses Docker images |
| **Podman** | ✅ | ✅ | ✅ | ✅ | ✅ | Uses Docker images |

**Architecture Support:** AMD64, ARM64, ARM, 386 across all platforms

### Quick Start Examples

**Docker (Recommended)**
```bash
# Basic vulnerability scan
docker run --rm vulnetix/vulnetix:latest --org-id "your-org-id"

# Release security assessment
docker run --rm vulnetix/vulnetix:latest \
  --org-id "your-org-id" --task release \
  --project-name "my-app" --production-branch main
```

**Go Install**
```bash
go install github.com/vulnetix/vulnetix@latest
vulnetix --org-id "your-org-id" --task scan
```

**Homebrew/Chocolatey**
```bash
# After installation via package manager
vulnetix --org-id "your-org-id" --project-name "my-app"
```

### GitHub Action

#### Basic Vulnerability Scanning

```yaml
- name: Run Vulnetix scan
  uses: vulnetix/vulnetix@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
```

### Docker

Run Vulnetix CLI using Docker without installing anything locally:

```bash
# Quick vulnerability scan
docker run --rm vulnetix/vulnetix:latest --org-id "123e4567-e89b-12d3-a456-426614174000"

# Mount current directory for file access
docker run --rm -v $(pwd):/workspace vulnetix/vulnetix:latest --org-id "123e4567-e89b-12d3-a456-426614174000"

# Using environment variable for org ID
docker run --rm -e VULNETIX_ORG_ID="123e4567-e89b-12d3-a456-426614174000" vulnetix/vulnetix:latest

# Different tasks
docker run --rm vulnetix/vulnetix:latest --org-id "your-org-id" --task release
docker run --rm vulnetix/vulnetix:latest --org-id "your-org-id" --task report
docker run --rm vulnetix/vulnetix:latest --org-id "your-org-id" --task triage

# Get help
docker run --rm vulnetix/vulnetix:latest --help
```

### GitHub Action Advanced Usage

#### Release Readiness Assessment

For assessing release readiness by collecting artifacts from multiple security tools:

**GitHub Action Example:**
```yaml
# In a Pull Request workflow
- name: Vulnetix Release Assessment
  uses: vulnetix/vulnetix@v1
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

### Required Permissions

When using release mode, ensure your GitHub Action has the following permissions:

```yaml
permissions:
  # Required for accessing workflow run artifacts
  actions: read
  # Required for accessing repository context
  contents: read
  # Required if fetching artifacts from other jobs
  id-token: read
```

**Shell/Bash Example with Docker:**
```bash
# Set up environment
export VULNETIX_ORG_ID="your-org-id-here"
mkdir -p reports

# Run security scans and generate reports
docker run --rm -v $(pwd):/src returntocorp/semgrep \
  --config=auto --sarif --output=/src/reports/sast.sarif /src

docker run --rm -v $(pwd):/workspace anchore/syft \
  /workspace -o spdx-json=/workspace/reports/sbom.json

# Run Vulnetix release assessment
docker run --rm -v $(pwd):/workspace -e VULNETIX_ORG_ID vulnetix/vulnetix:latest \
  --task release --production-branch main --release-branch feature/new-fixes \
  --tools '[{"category":"SAST","tool_name":"semgrep","artifact_name":"sast-results","format":"SARIF"}]'
```

**Shell/Bash Example with Go Install:**
```bash
# Install and run
go install github.com/vulnetix/vulnetix@latest
export VULNETIX_ORG_ID="your-org-id-here"

# Generate reports with your preferred tools, then:
vulnetix --task release --production-branch main --release-branch $(git branch --show-current) \
  --tools '[{"category":"SAST","tool_name":"semgrep","artifact_name":"sast-results","format":"SARIF"}]'
```

#### Other Available Tasks

```yaml
# Generate vulnerability reports
- name: Generate Reports
  uses: vulnetix/vulnetix@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
    task: report

# Automated vulnerability triage
- name: Auto Triage
  uses: vulnetix/vulnetix@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
    task: triage
```

### Go Install

Install directly from source using Go (requires Go 1.21+):

```bash
# Install latest version
go install github.com/vulnetix/vulnetix@latest

# Basic vulnerability scan (default task)
vulnetix --org-id "123e4567-e89b-12d3-a456-426614174000"

# Install specific version
go install github.com/vulnetix/vulnetix@v1.2.3

# Release assessment with project context
vulnetix --org-id "your-org-id" --task release \
  --project-name "my-app" --team-name "security-team"

# Generate reports
vulnetix --org-id "your-org-id" --task report --project-name "my-app"

# Upload SARIF files
vulnetix sarif --org-id "your-org-id" scan-results.sarif
```

### Local Binary

Download and run the binary directly:

```bash
# Linux AMD64
curl -L https://github.com/vulnetix/vulnetix/releases/latest/download/vulnetix-linux-amd64 -o vulnetix
chmod +x vulnetix && ./vulnetix --org-id "your-org-id-here"

# macOS (Intel)
curl -L https://github.com/vulnetix/vulnetix/releases/latest/download/vulnetix-darwin-amd64 -o vulnetix
chmod +x vulnetix && ./vulnetix --org-id "your-org-id-here"

# macOS (Apple Silicon)
curl -L https://github.com/vulnetix/vulnetix/releases/latest/download/vulnetix-darwin-arm64 -o vulnetix
chmod +x vulnetix && ./vulnetix --org-id "your-org-id-here"

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/vulnetix/vulnetix/releases/latest/download/vulnetix-windows-amd64.exe" -OutFile "vulnetix.exe"
.\vulnetix.exe --org-id "your-org-id-here"
```

[📖 **View detailed usage examples →**](./USAGE.md)

## Available Tasks

Vulnetix supports multiple task types to cover different aspects of vulnerability management:

| Task | Description | Use Case | Required Flags |
|------|-------------|----------|----------------|
| `scan` | Default vulnerability scanning and analysis | Continuous vulnerability monitoring | `--org-id` |
| `release` | Release readiness assessment | Pre-release security validation | `--org-id`, `--production-branch`, `--release-branch` |
| `report` | Generate comprehensive vulnerability reports | Compliance and stakeholder reporting | `--org-id` |
| `triage` | Automated vulnerability triage and prioritization | Streamline manual review processes | `--org-id` |
| `sarif` | Upload and validate SARIF files | Integrate with external security tools | `--org-id`, `<sarif-file>` |

### CLI Reference

```bash
# Basic vulnerability scan (default task)
vulnetix --org-id "your-org-id"

# Release assessment with branch context
vulnetix --task release --org-id "your-org-id" \
  --production-branch main --release-branch "feature/new-feature"

# Generate reports with project context
vulnetix --task report --org-id "your-org-id" \
  --project-name "my-app" --team-name "security-team"

# Upload SARIF results from external tools
vulnetix sarif --org-id "your-org-id" scan-results.sarif

# Triage with tags for categorization
vulnetix --task triage --org-id "your-org-id" \
  --tags '["critical", "frontend"]'
```

### Configuration Options

| Flag | Description | Default | Example |
|------|-------------|---------|---------|
| `--org-id` | Organization ID (UUID) - **Required** | - | `123e4567-e89b-12d3-a456-426614174000` |
| `--task` | Task to perform | `scan` | `release`, `report`, `triage`, `sarif` |
| `--project-name` | Project name for context | - | `my-web-app` |
| `--team-name` | Team responsible for the project | - | `security-team` |
| `--production-branch` | Production branch name | `main` | `main`, `master`, `production` |
| `--release-branch` | Release branch name | - | `release/v2.1.0`, `feature/auth` |
| `--workflow-timeout` | Timeout for CI artifact collection (minutes) | `30` | `45`, `60` |
| `--tags` | YAML list of tags for categorization | - | `'["critical", "frontend", "api"]'` |
| `--tools` | YAML array of tool configurations | - | See [tool configuration](#tool-configuration) |
| `--group-name` | Group name for organizational hierarchy | - | `engineering`, `security` |
| `--product-name` | Product name for context | - | `core-platform`, `mobile-app` |

### Tool Configuration

The `--tools` flag accepts a YAML array for configuring multiple security tools:

```yaml
# Example tools configuration
tools:
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

## Documentation

- **[Complete Documentation](docs/README.md)** - Installation guides for all platforms
- **[CLI Reference](docs/CLI-REFERENCE.md)** - Complete command-line documentation  
- **[Publishing Guide](docs/PUBLISHING.md)** - How we distribute across platforms
- **[Release Security Assessment Examples](USAGE.md)** - Comprehensive usage guide

## Distribution

Vulnetix is automatically published to multiple platforms on each release:

- **GitHub Releases** → Go Install, Binary Downloads, Homebrew, Chocolatey
- **Docker Hub** → Docker, Kubernetes, Podman, CI/CD systems  
- **Package Managers** → Homebrew (macOS/Linux), Chocolatey (Windows)
- **GitHub Marketplace** → GitHub Actions integration

See [Publishing Guide](docs/PUBLISHING.md) for technical details.
