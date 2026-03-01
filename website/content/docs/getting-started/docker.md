---
title: "Docker"
weight: 1
description: "Run Vulnetix CLI in Docker containers without installing anything locally."
---

Run Vulnetix CLI using Docker containers without installing anything locally.

## Quick Start

```bash
# Basic vulnerability scan
docker run --rm vulnetix/vulnetix:latest --org-id "your-org-id-here"

# Mount current directory for file access
docker run --rm -v $(pwd):/workspace vulnetix/vulnetix:latest --org-id "your-org-id-here"
```

## Available Images

### Official Images

```bash
# Latest stable release
docker pull vulnetix/vulnetix:latest

# Specific version
docker pull vulnetix/vulnetix:v1.2.3

# Development/nightly builds
docker pull vulnetix/vulnetix:nightly
```

### Platform-Specific Images

```bash
# Multi-architecture support (automatically selected)
docker pull vulnetix/vulnetix:latest

# Specific architectures
docker pull vulnetix/vulnetix:latest-amd64    # Intel/AMD 64-bit
docker pull vulnetix/vulnetix:latest-arm64    # ARM 64-bit (Apple Silicon, etc.)
docker pull vulnetix/vulnetix:latest-arm      # ARM 32-bit
```

## Configuration

### Environment Variables

```bash
# Set organization ID
export VULNETIX_ORG_ID="123e4567-e89b-12d3-a456-426614174000"

# Run with environment variable
docker run --rm -e VULNETIX_ORG_ID vulnetix/vulnetix:latest

# Multiple environment variables
docker run --rm \
  -e VULNETIX_ORG_ID="your-org-id" \
  -e VULNETIX_API_URL="https://app.vulnetix.com/api/" \
  -e VULNETIX_LOG_LEVEL="debug" \
  vulnetix/vulnetix:latest --task release
```

### Volume Mounts

```bash
# Mount current directory as workspace
docker run --rm -v $(pwd):/workspace -w /workspace vulnetix/vulnetix:latest --org-id "your-org-id"

# Mount specific directories for SARIF upload
docker run --rm \
  -v $(pwd)/reports:/reports \
  vulnetix/vulnetix:latest \
  sarif --org-id "your-org-id" /reports/scan-results.sarif

# Mount with read-only access for scanning
docker run --rm \
  -v $(pwd):/workspace:ro \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id" \
  --task release
```

## Usage Examples

### Basic Scanning

```bash
# Simple vulnerability scan
docker run --rm vulnetix/vulnetix:latest \
  --org-id "your-org-id-here" \
  --task release

# Scan with project metadata
docker run --rm vulnetix/vulnetix:latest \
  --org-id "your-org-id-here" \
  --task release \
  --project-name "My Application" \
  --team-name "Security Team"
```

### Release Assessment

```bash
# Release readiness assessment
docker run --rm \
  -v $(pwd):/workspace \
  -w /workspace \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id-here" \
  --task release \
  --production-branch "main" \
  --release-branch "feature/security-updates" \
  --tools '[
    {
      "category": "SAST",
      "tool_name": "sast-tool",
      "artifact_name": "./reports/sast-results.sarif",
      "format": "SARIF"
    },
    {
      "category": "SCA",
      "tool_name": "sca-tool",
      "artifact_name": "./reports/sbom.json",
      "format": "JSON"
    }
  ]'
```

### Report Generation

```bash
# Generate comprehensive security reports
docker run --rm vulnetix/vulnetix:latest \
  --org-id "your-org-id-here" \
  --task report \
  --project-name "my-application" \
  --team-name "security-team"

# Generate reports with tags
docker run --rm vulnetix/vulnetix:latest \
  --org-id "your-org-id-here" \
  --task report \
  --tags '["Public", "Crown Jewels"]'
```

### Multi-Stage Pipeline

```bash
#!/bin/bash
# comprehensive-scan.sh - Multi-stage security pipeline with Vulnetix

set -e

export VULNETIX_ORG_ID="your-org-id-here"
PROJECT_NAME="my-application"
TEAM_NAME="security-team"
REPORTS_DIR="$(pwd)/security-reports"

# Ensure reports directory exists
mkdir -p "$REPORTS_DIR"

echo "🔍 Running comprehensive security assessment for $PROJECT_NAME..."

# Step 1: SAST Scan with Semgrep
echo "📊 Running SAST analysis..."
docker run --rm \
  -v $(pwd):/src \
  -v "$REPORTS_DIR":/reports \
  returntocorp/semgrep \
  --config=auto \
  --sarif \
  --output=/reports/sast-results.sarif \
  /src

# Step 2: SCA Scan with Syft for SBOM
echo "📦 Generating Software Bill of Materials..."
docker run --rm \
  -v $(pwd):/workspace \
  -v "$REPORTS_DIR":/reports \
  anchore/syft \
  /workspace \
  -o spdx-json=/reports/sbom.json

# Step 3: Container Scan with Trivy (if Dockerfile exists)
if [ -f "Dockerfile" ]; then
  echo "🐳 Scanning container vulnerabilities..."
  docker run --rm \
    -v $(pwd):/workspace \
    -v "$REPORTS_DIR":/reports \
    aquasec/trivy \
    fs /workspace \
    --format sarif \
    --output /reports/container-scan.sarif
fi

# Step 4: Secrets Scan with TruffleHog
echo "🔐 Scanning for secrets..."
docker run --rm \
  -v $(pwd):/workspace \
  -v "$REPORTS_DIR":/reports \
  trufflesecurity/trufflehog:latest \
  filesystem /workspace \
  --json > "$REPORTS_DIR/secrets-scan.json"

# Step 5: Upload SARIF results to Vulnetix
echo "📤 Uploading SARIF results to Vulnetix..."
for sarif_file in "$REPORTS_DIR"/*.sarif; do
  if [ -f "$sarif_file" ]; then
    echo "Uploading: $sarif_file"
    docker run --rm \
      -v "$REPORTS_DIR":/reports \
      vulnetix/vulnetix:latest \
      sarif \
      --org-id "$VULNETIX_ORG_ID" \
      --project-name "$PROJECT_NAME" \
      --team-name "$TEAM_NAME" \
      "/reports/$(basename "$sarif_file")"
  fi
done

# Step 6: Run Vulnetix comprehensive assessment
echo "🎯 Running Vulnetix assessment..."
docker run --rm vulnetix/vulnetix:latest \
  --org-id "$VULNETIX_ORG_ID" \
  --task release \
  --project-name "$PROJECT_NAME" \
  --team-name "$TEAM_NAME" \
  --tags '["Public", "Crown Jewels"]'

echo "✅ Comprehensive security assessment completed!"
```

# Step 5: Vulnetix Release Assessment
echo "🚀 Running Vulnetix release assessment..."
docker run --rm \
  -v $(pwd):/workspace \
  -v "$REPORTS_DIR":/reports \
  -w /workspace \
  -e VULNETIX_ORG_ID \
  vulnetix/vulnetix:latest \
  --task release \
  --production-branch "main" \
  --release-branch "$(git branch --show-current)" \
  --project-name "$PROJECT_NAME" \
  --tools '[
    {
      "category": "SAST",
      "tool_name": "sast-scanner",
      "artifact_name": "/reports/sast-results.sarif",
      "format": "SARIF"
    },
    {
      "category": "SCA",
      "tool_name": "sca-scanner",
      "artifact_name": "/reports/sbom.json",
      "format": "JSON"
    },
    {
      "category": "SECRETS",
      "tool_name": "secrets-scanner",
      "artifact_name": "/reports/secrets-scan.sarif",
      "format": "SARIF"
    }
  ]'

echo "✅ Security assessment complete! Reports available in: $REPORTS_DIR"
```

## Edge Cases & Advanced Configuration

### Corporate Proxy Support

```bash
# HTTP proxy
docker run --rm \
  -e HTTP_PROXY="http://proxy.company.com:8080" \
  -e HTTPS_PROXY="http://proxy.company.com:8080" \
  -e NO_PROXY="localhost,127.0.0.1,.company.com" \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id-here"

# Authenticated proxy
docker run --rm \
  -e HTTP_PROXY="http://username:password@proxy.company.com:8080" \
  -e HTTPS_PROXY="http://username:password@proxy.company.com:8080" \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id-here"

# SOCKS proxy
docker run --rm \
  -e ALL_PROXY="socks5://proxy.company.com:1080" \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id-here"
```

### Custom CA Certificates

```bash
# Mount custom CA certificates
docker run --rm \
  -v /etc/ssl/certs:/etc/ssl/certs:ro \
  -v /usr/share/ca-certificates:/usr/share/ca-certificates:ro \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id-here"

# Add custom CA certificate
docker run --rm \
  -v $(pwd)/custom-ca.crt:/usr/local/share/ca-certificates/custom-ca.crt:ro \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id-here"
```

### Resource Constraints

```bash
# Limit memory and CPU usage
docker run --rm \
  --memory="512m" \
  --cpus="1.0" \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id-here"

# Set ulimits
docker run --rm \
  --ulimit nofile=65536:65536 \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id-here"
```

### Non-Root User

```bash
# Run as specific user (security best practice)
docker run --rm \
  --user $(id -u):$(id -g) \
  -v $(pwd):/workspace \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id-here"

# Run with read-only filesystem
docker run --rm \
  --read-only \
  --tmpfs /tmp \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id-here"
```

### Air-Gapped Environments

```bash
# Save image for offline use
docker save vulnetix/vulnetix:latest > vulnetix-latest.tar

# Load image in air-gapped environment
docker load < vulnetix-latest.tar

# Run without internet access
docker run --rm \
  --network none \
  -v $(pwd):/workspace \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id-here" \
  --offline-mode
```

## Docker Compose Integration

```yaml
# docker-compose.yml
version: '3.8'

services:
  vulnetix:
    image: vulnetix/vulnetix:latest
    environment:
      - VULNETIX_ORG_ID=${VULNETIX_ORG_ID}
    volumes:
      - ./:/workspace
      - ./reports:/reports
    working_dir: /workspace
    command: ["--task", "scan", "--output-dir", "/reports"]

  # Security scanning pipeline
  security-pipeline:
    image: vulnetix/vulnetix:latest
    depends_on:
      - sast-scan
      - sca-scan
    environment:
      - VULNETIX_ORG_ID=${VULNETIX_ORG_ID}
    volumes:
      - ./:/workspace
      - ./reports:/reports
    working_dir: /workspace
    command: [
      "--task", "release",
      "--production-branch", "main",
      "--release-branch", "${BRANCH_NAME:-feature}",
      "--tools", "[{\"category\":\"SAST\",\"tool_name\":\"sast-tool\",\"artifact_name\":\"/reports/sast.sarif\",\"format\":\"SARIF\"}]"
    ]

  sast-scan:
    image: returntocorp/semgrep
    volumes:
      - ./:/src
      - ./reports:/reports
    command: ["--config=auto", "--sarif", "--output=/reports/sast.sarif", "/src"]

  sca-scan:
    image: anchore/syft
    volumes:
      - ./:/workspace
      - ./reports:/reports
    command: ["/workspace", "-o", "spdx-json=/reports/sbom.json"]
```

```bash
# Run with docker-compose
export VULNETIX_ORG_ID="your-org-id-here"
export BRANCH_NAME="$(git branch --show-current)"
docker-compose up security-pipeline
```

## Troubleshooting

### Common Issues

#### Permission Denied

```bash
# Issue: Permission denied when mounting volumes
# Solution: Run with correct user permissions
docker run --rm \
  --user $(id -u):$(id -g) \
  -v $(pwd):/workspace \
  vulnetix/vulnetix:latest

# Or fix ownership after run
sudo chown -R $(id -u):$(id -g) ./reports
```

#### Network Connectivity

```bash
# Issue: Cannot connect to Vulnetix API
# Solution: Check network connectivity
docker run --rm vulnetix/vulnetix:latest --help

# Test with verbose output
docker run --rm \
  -e VULNETIX_LOG_LEVEL="debug" \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id-here"
```

#### Image Pull Issues

```bash
# Issue: Cannot pull image
# Solution: Check Docker registry access
docker pull vulnetix/vulnetix:latest

# Use specific registry if needed
docker pull ghcr.io/vulnetix/vulnetix:latest

# Or load from saved tar file
docker load < vulnetix-image.tar
```

#### Volume Mount Problems

```bash
# Issue: Files not accessible in container
# Solution: Check volume mount syntax and permissions

# Correct absolute path mounting
docker run --rm \
  -v "$(pwd)":/workspace \
  -w /workspace \
  vulnetix/vulnetix:latest

# Debug volume mounts
docker run --rm \
  -v $(pwd):/workspace \
  vulnetix/vulnetix:latest \
  ls -la /workspace
```

### Performance Issues

```bash
# Issue: Slow performance
# Solution: Allocate more resources

# Increase memory and CPU
docker run --rm \
  --memory="2g" \
  --cpus="2.0" \
  vulnetix/vulnetix:latest

# Use faster storage
docker run --rm \
  -v $(pwd):/workspace:cached \
  vulnetix/vulnetix:latest
```

### Environment-Specific Issues

#### Windows

```powershell
# Use PowerShell syntax for volume mounts
docker run --rm `
  -v ${PWD}:/workspace `
  vulnetix/vulnetix:latest `
  --org-id "your-org-id-here"

# Or Command Prompt
docker run --rm ^
  -v %CD%:/workspace ^
  vulnetix/vulnetix:latest ^
  --org-id "your-org-id-here"
```

#### macOS

```bash
# Performance optimization for macOS
docker run --rm \
  -v $(pwd):/workspace:delegated \
  vulnetix/vulnetix:latest

# Handle file permissions on macOS
docker run --rm \
  --user 1000:1000 \
  -v $(pwd):/workspace \
  vulnetix/vulnetix:latest
```

## Security Best Practices

### Run as Non-Root

```bash
# Always run as non-root user when possible
docker run --rm \
  --user $(id -u):$(id -g) \
  vulnetix/vulnetix:latest
```

### Minimal Privileges

```bash
# Use read-only filesystem
docker run --rm \
  --read-only \
  --tmpfs /tmp \
  vulnetix/vulnetix:latest

# Drop capabilities
docker run --rm \
  --cap-drop=ALL \
  vulnetix/vulnetix:latest
```

### Network Security

```bash
# Restrict network access when possible
docker run --rm \
  --network none \
  vulnetix/vulnetix:latest \
  --offline-mode

# Use custom network
docker network create vulnetix-net
docker run --rm \
  --network vulnetix-net \
  vulnetix/vulnetix:latest
```

## Integration Examples

### CI/CD Integration

```bash
# Jenkins Pipeline
docker run --rm \
  -v $WORKSPACE:/workspace \
  -e VULNETIX_ORG_ID="$VULNETIX_ORG_ID" \
  vulnetix/vulnetix:latest \
  --task release \
  --project-name "$JOB_NAME" \
  --build-id "$BUILD_NUMBER"

# GitLab CI
docker run --rm \
  -v $CI_PROJECT_DIR:/workspace \
  -e VULNETIX_ORG_ID="$VULNETIX_ORG_ID" \
  vulnetix/vulnetix:latest \
  --task release \
  --project-name "$CI_PROJECT_NAME" \
  --build-id "$CI_PIPELINE_ID"
```

### Development Workflow

```bash
# Pre-commit hook
#!/bin/bash
# .git/hooks/pre-commit

docker run --rm \
  -v $(pwd):/workspace \
  -e VULNETIX_ORG_ID="$VULNETIX_ORG_ID" \
  vulnetix/vulnetix:latest \
  --task release \
  --quick-scan
```

For more examples and advanced configurations, see the [main documentation](../USAGE.md) and other [reference guides](./README.md).
