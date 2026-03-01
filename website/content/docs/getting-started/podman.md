---
title: "Podman"
weight: 8
description: "Run Vulnetix CLI using Podman as a rootless, daemonless container runtime."
---

Run Vulnetix CLI using Podman containers with the same Docker images.

## Quick Start

```bash
# Basic vulnerability scan
podman run --rm vulnetix/vulnetix:latest --org-id "your-org-id-here"

# Mount current directory for file access
podman run --rm -v $(pwd):/workspace:Z vulnetix/vulnetix:latest --org-id "your-org-id-here"
```

## Installation

Vulnetix uses the same Docker images as documented in [Docker Reference](docker.md). Podman can run these images without modification.

### Available Images

```bash
# Pull images (same as Docker)
podman pull vulnetix/vulnetix:latest
podman pull vulnetix/vulnetix:v1.2.3

# List available images
podman images | grep vulnetix
```

### Platform-Specific Images

```bash
# Multi-architecture support (automatically selected)
podman pull vulnetix/vulnetix:latest

# Specific architectures (if needed)
podman pull vulnetix/vulnetix:latest-amd64    # Intel/AMD 64-bit
podman pull vulnetix/vulnetix:latest-arm64    # ARM 64-bit (Apple Silicon, etc.)
podman pull vulnetix/vulnetix:latest-arm      # ARM 32-bit
```

## Configuration

### Environment Variables

```bash
# Set organization ID
export VULNETIX_ORG_ID="123e4567-e89b-12d3-a456-426614174000"

# Run with environment variable
podman run --rm -e VULNETIX_ORG_ID vulnetix/vulnetix:latest

# Multiple environment variables
podman run --rm \
  -e VULNETIX_ORG_ID="your-org-id" \
  -e VULNETIX_API_URL="https://app.vulnetix.com/api/" \
  vulnetix/vulnetix:latest --task release
```

### Volume Mounts

```bash
# Mount current directory as workspace (note the :Z for SELinux)
podman run --rm -v $(pwd):/workspace:Z -w /workspace vulnetix/vulnetix:latest --org-id "your-org-id"

# Mount specific directories for SARIF upload
podman run --rm \
  -v $(pwd)/reports:/reports:Z \
  vulnetix/vulnetix:latest \
  sarif --org-id "your-org-id" /reports/scan-results.sarif

# Mount with read-only access for scanning
podman run --rm \
  -v $(pwd):/workspace:Z,ro \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id" \
  --task release
```

## Usage Examples

### Basic Scanning

```bash
# Simple vulnerability scan
podman run --rm vulnetix/vulnetix:latest \
  --org-id "your-org-id-here" \
  --task release

# Scan with project metadata
podman run --rm vulnetix/vulnetix:latest \
  --org-id "your-org-id-here" \
  --task release \
  --project-name "My Application" \
  --team-name "Security Team"
```

### Release Assessment

```bash
# Release readiness assessment
podman run --rm \
  -v $(pwd):/workspace:Z \
  -w /workspace \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id-here" \
  --task release \
  --production-branch "main" \
  --release-branch "feature/security-updates" \
  --tools '[
    {
      "category": "SAST",
      "tool_name": "semgrep",
      "artifact_name": "sast-results",
      "format": "SARIF"
    }
  ]'
```

### Report Generation

```bash
# Generate comprehensive security reports
podman run --rm vulnetix/vulnetix:latest \
  --org-id "your-org-id-here" \
  --task report \
  --project-name "my-application" \
  --team-name "security-team"

# Generate reports with tags
podman run --rm vulnetix/vulnetix:latest \
  --org-id "your-org-id-here" \
  --task report \
  --tags '["Public", "Crown Jewels"]'
```

### Multi-Stage Pipeline

```bash
#!/bin/bash
# comprehensive-scan.sh - Multi-stage security pipeline with Podman

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
podman run --rm \
  -v $(pwd):/src:Z \
  -v "$REPORTS_DIR":/reports:Z \
  docker.io/returntocorp/semgrep \
  --config=auto \
  --sarif \
  --output=/reports/sast-results.sarif \
  /src

# Step 2: SCA Scan with Syft for SBOM
echo "📦 Generating Software Bill of Materials..."
podman run --rm \
  -v $(pwd):/workspace:Z \
  -v "$REPORTS_DIR":/reports:Z \
  docker.io/anchore/syft \
  /workspace \
  -o spdx-json=/reports/sbom.json

# Step 3: Container Scan with Trivy (if Dockerfile exists)
if [ -f "Dockerfile" ]; then
  echo "🐳 Scanning container vulnerabilities..."
  podman run --rm \
    -v $(pwd):/workspace:Z \
    -v "$REPORTS_DIR":/reports:Z \
    docker.io/aquasec/trivy \
    fs /workspace \
    --format sarif \
    --output /reports/container-scan.sarif
fi

# Step 4: Secrets Scan with TruffleHog
echo "🔐 Scanning for secrets..."
podman run --rm \
  -v $(pwd):/workspace:Z \
  -v "$REPORTS_DIR":/reports:Z \
  docker.io/trufflesecurity/trufflehog:latest \
  filesystem /workspace \
  --json > "$REPORTS_DIR/secrets-scan.json"

# Step 5: Upload SARIF results to Vulnetix
echo "📤 Uploading SARIF results to Vulnetix..."
for sarif_file in "$REPORTS_DIR"/*.sarif; do
  if [ -f "$sarif_file" ]; then
    echo "Uploading: $sarif_file"
    podman run --rm \
      -v "$REPORTS_DIR":/reports:Z \
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
podman run --rm vulnetix/vulnetix:latest \
  --org-id "$VULNETIX_ORG_ID" \
  --task release \
  --project-name "$PROJECT_NAME" \
  --team-name "$TEAM_NAME" \
  --tags '["Public", "Crown Jewels"]'

echo "✅ Comprehensive security assessment completed!"
```

## Podman-Specific Features

### Rootless Operation

```bash
# Podman runs rootless by default (safer than Docker)
podman run --rm vulnetix/vulnetix:latest --org-id "your-org-id"

# Check if running rootless
podman info | grep -A2 "rootless"
```

### Pod Support

```bash
# Create a pod for related containers
podman pod create --name vulnetix-pod

# Run Vulnetix in the pod
podman run --pod vulnetix-pod --rm vulnetix/vulnetix:latest \
  --org-id "your-org-id" \
  --task release

# Run additional tools in the same pod
podman run --pod vulnetix-pod --rm docker.io/aquasec/trivy \
  --help
```

### SystemD Integration

```bash
# Generate SystemD unit for automated scans
podman generate systemd --new --name vulnetix-daily-scan \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id" \
  --task release

# Enable and start the service
systemctl --user enable container-vulnetix-daily-scan.service
systemctl --user start container-vulnetix-daily-scan.service
```

## CI/CD Integration

### GitLab CI with Podman

```yaml
# .gitlab-ci.yml
security-scan:
  image: registry.fedoraproject.org/fedora:latest
  before_script:
    - dnf install -y podman
  script:
    - podman run --rm vulnetix/vulnetix:latest
        --org-id "$VULNETIX_ORG_ID"
        --task release
        --project-name "$CI_PROJECT_NAME"
  only:
    - main
```

### Jenkins with Podman

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        VULNETIX_ORG_ID = credentials('vulnetix-org-id')
    }

    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    podman run --rm \
                      -e VULNETIX_ORG_ID="${VULNETIX_ORG_ID}" \
                      vulnetix/vulnetix:latest \
                      --task release \
                      --project-name "${JOB_NAME}"
                '''
            }
        }
    }
}
```

## Security Considerations

### SELinux Support

```bash
# Podman automatically handles SELinux labels
# Use :Z for private mounts
podman run --rm -v $(pwd):/workspace:Z vulnetix/vulnetix:latest

# Use :z for shared mounts
podman run --rm -v $(pwd):/workspace:z vulnetix/vulnetix:latest
```

### User Namespaces

```bash
# Check user namespace mapping
podman unshare cat /proc/self/uid_map
podman unshare cat /proc/self/gid_map

# Run with specific user mapping if needed
podman run --rm --uidmap 0:1000:1000 vulnetix/vulnetix:latest
```

### Network Security

```bash
# Run with no network access (if local scanning only)
podman run --rm --network none vulnetix/vulnetix:latest --help

# Use custom network
podman network create vulnetix-net
podman run --rm --network vulnetix-net vulnetix/vulnetix:latest
```

## Troubleshooting

### Image Pull Issues

```bash
# Pull from Docker Hub explicitly
podman pull docker.io/vulnetix/vulnetix:latest

# Check registries configuration
podman info | grep -A10 registries

# Clear cache if needed
podman system prune -a
```

### SELinux Permission Denied

```bash
# Use :Z for volume mounts
podman run --rm -v $(pwd):/workspace:Z vulnetix/vulnetix:latest

# Check SELinux status
getenforce

# Set SELinux labels manually if needed
chcon -Rt container_file_t ./reports/
```

### Rootless Networking

```bash
# Check rootless networking
podman network ls

# Create custom network if needed
podman network create --driver bridge vulnetix-network
```

## Performance Optimization

### Resource Limits

```bash
# Set CPU and memory limits
podman run --rm \
  --cpus 2 \
  --memory 1g \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id"
```

### Caching

```bash
# Use named volumes for caching
podman volume create vulnetix-cache
podman run --rm \
  -v vulnetix-cache:/cache \
  vulnetix/vulnetix:latest \
  --org-id "your-org-id"
```

## Related Documentation

- [Docker Reference](docker.md) - Base Docker image documentation
- [Kubernetes Reference](kubernetes.md) - Kubernetes deployment
- [CLI Reference](CLI-REFERENCE.md) - Complete CLI flag reference

## Differences from Docker

| Feature | Docker | Podman |
|---------|--------|--------|
| Daemon | Requires Docker daemon | Daemonless |
| Root | Runs as root by default | Rootless by default |
| Security | Additional security setup | Built-in security features |
| SystemD | Limited integration | Native SystemD support |
| SELinux | Manual configuration | Automatic label handling |

All Vulnetix functionality works identically between Docker and Podman - only the runtime differs.
