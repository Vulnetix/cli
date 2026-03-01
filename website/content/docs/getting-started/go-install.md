---
title: "Go Install"
weight: 2
description: "Install Vulnetix CLI directly from Go modules using go install."
---

Install Vulnetix CLI directly from Go modules without building from source.

## Quick Start

```bash
# Install latest version
go install github.com/vulnetix/cli@latest

# Run Vulnetix
vulnetix
```

## Prerequisites

### Go Version Requirements

```bash
# Check Go version (requires 1.21+)
go version

# If Go is not installed or too old:
# macOS: brew install go
# Linux: sudo apt install golang-go  # or equivalent
# Windows: Download from https://golang.org/dl/
```

### Environment Setup

```bash
# Check Go environment
go env GOPATH
go env GOBIN
go env GOPROXY

# Set GOBIN if not set (optional)
export GOBIN="$HOME/go/bin"
echo 'export GOBIN="$HOME/go/bin"' >> ~/.bashrc
```

## Installation

### Latest Version

```bash
# Install latest stable release
go install github.com/vulnetix/cli@latest

# Verify installation
vulnetix --version
which vulnetix
```

### Specific Version

```bash
# Install specific version
go install github.com/vulnetix/cli@v1.2.3

# Install pre-release
go install github.com/vulnetix/cli@v1.3.0-beta.1

# Install from specific commit
go install github.com/vulnetix/cli@abc1234
```

### Development Version

```bash
# Install from main branch (development)
go install github.com/vulnetix/cli@main

# Install from specific branch
go install github.com/vulnetix/cli@feature/new-feature
```

## Configuration

### Environment Variables

```bash
# Set organization ID
export VULNETIX_ORG_ID="123e4567-e89b-12d3-a456-426614174000"

# Optional: Set API endpoint
export VULNETIX_API_URL="https://app.vulnetix.com/api/"

# Optional: Set log level
export VULNETIX_LOG_LEVEL="info"  # debug, info, warn, error

# Add to shell profile for persistence
echo 'export VULNETIX_ORG_ID="your-org-id-here"' >> ~/.bashrc
source ~/.bashrc
```

### PATH Configuration

```bash
# Check if GOBIN is in PATH
echo $PATH | grep -q "$(go env GOBIN)" && echo "GOBIN in PATH" || echo "GOBIN not in PATH"

# Add GOBIN to PATH if needed
export PATH="$(go env GOBIN):$PATH"
echo 'export PATH="$(go env GOBIN):$PATH"' >> ~/.bashrc

# Alternative: Add GOPATH/bin to PATH
export PATH="$(go env GOPATH)/bin:$PATH"
echo 'export PATH="$(go env GOPATH)/bin:$PATH"' >> ~/.bashrc
```

## Usage Examples

### Basic Operations

```bash
# Run Vulnetix
vulnetix

# Upload artifacts
vulnetix upload --file <artifact-path>
```

### Security Assessment

```bash
# Generate security reports first
mkdir -p reports

# Example with common Go security tools
if command -v govulncheck >/dev/null 2>&1; then
  govulncheck -json ./... > reports/govulncheck.json
fi

if command -v gosec >/dev/null 2>&1; then
  gosec -fmt sarif -out reports/gosec.sarif ./...
fi

if command -v nancy >/dev/null 2>&1; then
  go list -json -deps ./... | nancy sleuth --format sarif > reports/nancy.sarif
fi

# Upload artifacts
vulnetix upload --file ./reports/govulncheck.json
vulnetix upload --file ./reports/gosec.sarif
```

### Upload Artifacts

```bash
# Upload artifacts
vulnetix upload --file <artifact-path>
```

## Multi-Architecture Support

### Cross-Compilation

```bash
# Install for different architectures
GOOS=linux GOARCH=amd64 go install github.com/vulnetix/cli@latest
GOOS=linux GOARCH=arm64 go install github.com/vulnetix/cli@latest
GOOS=darwin GOARCH=amd64 go install github.com/vulnetix/cli@latest
GOOS=darwin GOARCH=arm64 go install github.com/vulnetix/cli@latest
GOOS=windows GOARCH=amd64 go install github.com/vulnetix/cli@latest

# List installed binaries
ls -la $(go env GOPATH)/bin/
```

### Platform-Specific Installation

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go install github.com/vulnetix/cli@latest

# Linux ARM64 (Raspberry Pi, etc.)
GOOS=linux GOARCH=arm64 go install github.com/vulnetix/cli@latest

# macOS Intel
GOOS=darwin GOARCH=amd64 go install github.com/vulnetix/cli@latest

# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 go install github.com/vulnetix/cli@latest

# Windows
GOOS=windows GOARCH=amd64 go install github.com/vulnetix/cli@latest
```

## Edge Cases & Advanced Configuration

### Corporate Proxy Support

```bash
# Configure Go proxy settings
go env -w GOPROXY="https://proxy.company.com/goproxy,direct"
go env -w GOSUMDB="off"  # Disable checksum verification if needed

# HTTP proxy for downloads
export HTTP_PROXY="http://proxy.company.com:8080"
export HTTPS_PROXY="http://proxy.company.com:8080"
export NO_PROXY="localhost,127.0.0.1,.company.com"

# Authenticated proxy
export HTTP_PROXY="http://username:password@proxy.company.com:8080"
export HTTPS_PROXY="http://username:password@proxy.company.com:8080"

# Install with proxy settings
go install github.com/vulnetix/cli@latest
```

### Private Module Repository

```bash
# Configure for private Go modules
go env -w GOPRIVATE="github.com/yourcompany/*"
go env -w GONOPROXY="github.com/yourcompany/*"
go env -w GONOSUMDB="github.com/yourcompany/*"

# GitHub private repos with token
git config --global url."https://token@github.com/".insteadOf "https://github.com/"

# Install from private repository
go install github.com/yourcompany/vulnetix@latest
```

### Air-Gapped Environments

```bash
# Download module for offline use (requires internet first)
go mod download github.com/vulnetix/cli@latest

# Create module cache archive
tar -czf vulnetix-modules.tar.gz -C $(go env GOMODCACHE) .

# In air-gapped environment:
# 1. Extract modules to GOMODCACHE
# 2. Set GOPROXY=off
export GOPROXY=off
go install github.com/vulnetix/cli@latest
```

### Custom Build Flags

```bash
# Install with custom build flags
go install -ldflags="-X main.version=custom" github.com/vulnetix/cli@latest

# Install with debug information
go install -gcflags="all=-N -l" github.com/vulnetix/cli@latest

# Install with optimizations disabled
go install -gcflags="all=-N" github.com/vulnetix/cli@latest
```

### Version Management

```bash
# Install multiple versions
go install github.com/vulnetix/cli@v1.0.0
mv $(go env GOPATH)/bin/vulnetix $(go env GOPATH)/bin/vulnetix-v1.0.0

go install github.com/vulnetix/cli@v1.1.0
mv $(go env GOPATH)/bin/vulnetix $(go env GOPATH)/bin/vulnetix-v1.1.0

go install github.com/vulnetix/cli@latest
# Latest version available as 'vulnetix'

# Create version switcher script
cat > switch-vulnetix.sh << 'EOF'
#!/bin/bash
VERSION=${1:-latest}
if [ "$VERSION" = "latest" ]; then
    ln -sf $(go env GOPATH)/bin/vulnetix $(go env GOPATH)/bin/vulnetix-current
else
    ln -sf $(go env GOPATH)/bin/vulnetix-$VERSION $(go env GOPATH)/bin/vulnetix-current
fi
echo "Switched to vulnetix $VERSION"
EOF
chmod +x switch-vulnetix.sh
```

## Development Workflow Integration

### Pre-commit Hooks

```bash
# .git/hooks/pre-commit
#!/bin/bash

export VULNETIX_ORG_ID="your-org-id-here"

echo "Running Vulnetix..."
vulnetix

if [ $? -ne 0 ]; then
    echo "Vulnetix check failed. Commit aborted."
    exit 1
fi

echo "Vulnetix check passed."
```

### Make Integration

```makefile
# Makefile
.PHONY: security-check security-install

security-install:
	@echo "Installing Vulnetix CLI..."
	go install github.com/vulnetix/cli@latest

security-check: security-install
	@echo "Running Vulnetix..."
	vulnetix upload --file <artifact-path>

security-release: security-install
	@echo "Running security assessment..."
	vulnetix upload --file <artifact-path>
```

### GitHub Actions Integration

```yaml
# .github/workflows/security.yml
name: Vulnetix

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Install Vulnetix
        run: go install github.com/vulnetix/cli@latest

      - name: Run Vulnetix
        env:
          VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
        run: vulnetix upload --file <artifact-path>
```

## Troubleshooting

### Common Issues

#### Installation Fails

```bash
# Issue: go install fails with permission errors
# Solution: Check GOPATH and GOBIN permissions
ls -la $(go env GOPATH)
ls -la $(go env GOBIN)

# Fix permissions
chmod 755 $(go env GOPATH)
chmod 755 $(go env GOBIN)

# Alternative: Install to user directory
export GOBIN="$HOME/.local/bin"
mkdir -p "$GOBIN"
go install github.com/vulnetix/cli@latest
```

#### Binary Not Found

```bash
# Issue: vulnetix command not found
# Solution: Add GOBIN to PATH
echo $PATH | grep -q "$(go env GOBIN)"

# Add to PATH
export PATH="$(go env GOBIN):$PATH"
echo 'export PATH="$(go env GOBIN):$PATH"' >> ~/.bashrc
source ~/.bashrc

# Verify
which vulnetix
vulnetix --version
```

#### Module Download Issues

```bash
# Issue: Cannot download modules
# Solution: Check proxy and network settings
go env GOPROXY
go env GOSUMDB

# Reset proxy settings
go env -w GOPROXY="https://proxy.golang.org,direct"
go env -w GOSUMDB="sum.golang.org"

# Clear module cache
go clean -modcache

# Retry installation
go install github.com/vulnetix/cli@latest
```

#### Version Conflicts

```bash
# Issue: Multiple versions installed
# Solution: Clean and reinstall
go clean -cache
go clean -modcache
rm $(go env GOPATH)/bin/vulnetix*

# Reinstall specific version
go install github.com/vulnetix/cli@latest
```

#### Corporate Firewall Issues

```bash
# Issue: Cannot access golang.org
# Solution: Configure proxy and certificates

# Set proxy
export HTTPS_PROXY="http://proxy.company.com:8080"
export HTTP_PROXY="http://proxy.company.com:8080"

# Add corporate CA certificates
export SSL_CERT_DIR="/etc/ssl/certs:/usr/share/ca-certificates"

# Use company Go proxy if available
go env -w GOPROXY="https://goproxy.company.com,direct"

# Disable checksum verification if necessary
go env -w GOSUMDB="off"
```

### Platform-Specific Issues

#### Windows

```powershell
# PowerShell: Add GOBIN to PATH
$env:PATH += ";$(go env GOBIN)"

# Permanently add to user PATH
[Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";$(go env GOBIN)", "User")

# Install in PowerShell
go install github.com/vulnetix/cli@latest

# Run with PowerShell
vulnetix.exe --org-id "your-org-id-here"
```

#### macOS

```bash
# macOS: Handle Apple Silicon vs Intel
# For universal binary compatibility
go install github.com/vulnetix/cli@latest

# Force specific architecture if needed
GOARCH=amd64 go install github.com/vulnetix/cli@latest  # Intel
GOARCH=arm64 go install github.com/vulnetix/cli@latest  # Apple Silicon
```

#### Linux

```bash
# Linux: Handle different distributions
# Ubuntu/Debian
sudo apt update && sudo apt install golang-go

# CentOS/RHEL
sudo yum install golang

# Arch Linux
sudo pacman -S go

# Alpine Linux
apk add go

# After installing Go
go install github.com/vulnetix/cli@latest
```

### Performance Issues

```bash
# Issue: Slow installation
# Solution: Use module proxy and parallel downloads
go env -w GOPROXY="https://proxy.golang.org,direct"
go env -w GOMAXPROCS="$(nproc)"

# Clear cache if corrupted
go clean -cache
go clean -modcache

# Reinstall
go install github.com/vulnetix/cli@latest
```

### Environment Debugging

```bash
# Debug Go environment
go env
go version

# Check module cache
ls -la $(go env GOMODCACHE)

# Check binary location
which vulnetix
ls -la $(go env GOBIN)/vulnetix*
ls -la $(go env GOPATH)/bin/vulnetix*

# Test installation
vulnetix --help
vulnetix --version
```

## Security Best Practices

### Verify Installation

```bash
# Verify checksum (if available)
go mod download -json github.com/vulnetix/cli@latest | jq -r .Sum

# Check binary signatures
# (Implementation depends on signing setup)
```

### Secure Environment

```bash
# Use minimal permissions
umask 022

# Verify source authenticity
git config --global user.signingkey YOUR_GPG_KEY
git config --global commit.gpgsign true

# Use secure proxy
go env -w GOPROXY="https://proxy.golang.org,direct"
go env -w GOSUMDB="sum.golang.org"
```

For more advanced usage patterns and integrations, see the [main documentation](../USAGE.md) and other [reference guides](./README.md).
