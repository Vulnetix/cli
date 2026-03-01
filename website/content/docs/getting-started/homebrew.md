---
title: "Homebrew"
weight: 3
description: "Install Vulnetix CLI using Homebrew package manager on macOS and Linux."
---

Install Vulnetix CLI using Homebrew package manager on macOS and Linux.

## Quick Start

```bash
# Add the Vulnetix tap
brew tap vulnetix/vulnetix

# Install vulnetix
brew install vulnetix

# Run vulnerability scan
vulnetix --org-id "your-org-id-here"
```

## Prerequisites

### Install Homebrew

**macOS:**
```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Verify installation
brew --version
```

**Linux:**
```bash
# Install Homebrew on Linux
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Add to PATH (follow installer instructions)
echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' >> ~/.bashrc
eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"

# Verify installation
brew --version
```

## Installation

### Standard Installation

```bash
# Add Vulnetix tap (one-time setup)
brew tap vulnetix/vulnetix

# Install latest version
brew install vulnetix

# Verify installation
vulnetix --version
which vulnetix
```

### Specific Version

```bash
# Install specific version
brew install vulnetix@1.2.3

# Pin to prevent automatic updates
brew pin vulnetix
```

### Development Version

```bash
# Install HEAD (development) version
brew install vulnetix --HEAD

# Switch between versions
brew unlink vulnetix
brew link vulnetix@1.2.3
```

## Configuration

### Environment Variables

```bash
# Set organization ID
export VULNETIX_ORG_ID="123e4567-e89b-12d3-a456-426614174000"

# Add to shell profile for persistence
echo 'export VULNETIX_ORG_ID="your-org-id-here"' >> ~/.zshrc  # macOS (zsh)
echo 'export VULNETIX_ORG_ID="your-org-id-here"' >> ~/.bashrc # Linux (bash)
source ~/.zshrc  # or ~/.bashrc
```

### Homebrew Configuration

```bash
# Configure Homebrew for corporate environments
export HOMEBREW_NO_ANALYTICS=1
export HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_NO_INSTALL_CLEANUP=1

# Add to shell profile
echo 'export HOMEBREW_NO_ANALYTICS=1' >> ~/.zshrc
echo 'export HOMEBREW_NO_AUTO_UPDATE=1' >> ~/.zshrc
```

## Usage Examples

### Basic Operations

```bash
# Basic vulnerability scan
vulnetix --org-id "your-org-id-here" --task release

# Using environment variable
export VULNETIX_ORG_ID="your-org-id-here"
vulnetix --task release

# Scan with project metadata
vulnetix --task release \
  --project-name "My Application" \
  --team-name "Security Team" \
  --tags '["Public", "Crown Jewels"]'
```

### Release Assessment Workflow

```bash
#!/bin/bash
# comprehensive-security-scan.sh

set -e

export VULNETIX_ORG_ID="your-org-id-here"
PROJECT_NAME="$(basename $(pwd))"
CURRENT_BRANCH="$(git branch --show-current)"
REPORTS_DIR="./security-reports"

# Ensure reports directory exists
mkdir -p "$REPORTS_DIR"

echo "🔍 Running comprehensive security assessment for $PROJECT_NAME..."

# Install security tools via Homebrew if not present
echo "📦 Ensuring security tools are installed..."

# SAST tools
if ! command -v semgrep >/dev/null 2>&1; then
  echo "Installing Semgrep..."
  brew install semgrep
fi

# SCA tools for different languages
if ! command -v syft >/dev/null 2>&1; then
  echo "Installing Syft (SBOM generator)..."
  brew install syft
fi

# Secrets scanning
if ! command -v gitleaks >/dev/null 2>&1; then
  echo "Installing Gitleaks..."
  brew install gitleaks
fi

# Container scanning
if ! command -v grype >/dev/null 2>&1; then
  echo "Installing Grype..."
  brew install grype
fi

# Language-specific tools
if [ -f "go.mod" ] && ! command -v govulncheck >/dev/null 2>&1; then
  echo "Installing govulncheck for Go..."
  go install golang.org/x/vuln/cmd/govulncheck@latest
fi

if [ -f "package.json" ] && ! command -v npm >/dev/null 2>&1; then
  echo "Installing npm audit tools..."
  brew install node
fi

if [ -f "requirements.txt" ] && ! command -v safety >/dev/null 2>&1; then
  echo "Installing Safety for Python..."
  pip3 install safety
fi

echo "🔍 Starting security scans..."

# SAST Scan with Semgrep
echo "📊 Running SAST analysis with Semgrep..."
semgrep --config=auto --sarif --output="$REPORTS_DIR/sast-semgrep.sarif" .

# Generate SBOM
echo "📦 Generating Software Bill of Materials..."
syft dir:. -o spdx-json="$REPORTS_DIR/sbom.json"

# Secrets scanning
echo "🔐 Scanning for secrets with Gitleaks..."
gitleaks detect --source=. --report-format=sarif --report-path="$REPORTS_DIR/secrets-gitleaks.sarif"

# Container scanning (if Dockerfile exists)
if [ -f "Dockerfile" ]; then
  echo "🐳 Scanning container vulnerabilities..."
  grype dir:. -o sarif="$REPORTS_DIR/container-grype.sarif"
fi

# Language-specific scans
if [ -f "go.mod" ] && command -v govulncheck >/dev/null 2>&1; then
  echo "🔍 Running Go vulnerability check..."
  govulncheck -json ./... > "$REPORTS_DIR/go-vulncheck.json"
fi

if [ -f "package.json" ]; then
  echo "📦 Running npm audit..."
  npm audit --audit-level=moderate --json > "$REPORTS_DIR/npm-audit.json" || true
fi

if [ -f "requirements.txt" ] && command -v safety >/dev/null 2>&1; then
  echo "🐍 Running Python safety check..."
  safety check --json --output "$REPORTS_DIR/python-safety.json" || true
fi

# Prepare tools configuration for Vulnetix
TOOLS_CONFIG='[
  {
    "category": "SAST",
    "tool_name": "semgrep",
    "artifact_name": "'$REPORTS_DIR'/sast-semgrep.sarif",
    "format": "SARIF"
  },
  {
    "category": "SBOM",
    "tool_name": "sbom-tool",
    "artifact_name": "'$REPORTS_DIR'/sbom.json",
    "format": "JSON"
  },
  {
    "category": "SECRETS",
    "tool_name": "gitleaks",
    "artifact_name": "'$REPORTS_DIR'/secrets-gitleaks.sarif",
    "format": "SARIF"
  }'

# Add container scan if Dockerfile exists
if [ -f "Dockerfile" ]; then
  TOOLS_CONFIG=$(echo "$TOOLS_CONFIG" | sed 's/]$/,/')
  TOOLS_CONFIG="$TOOLS_CONFIG"',
  {
    "category": "CONTAINER",
    "tool_name": "grype",
    "artifact_name": "'$REPORTS_DIR'/container-grype.sarif",
    "format": "SARIF"
  }]'
else
  TOOLS_CONFIG="$TOOLS_CONFIG"']'
fi

# Run Vulnetix release assessment
echo "🚀 Running Vulnetix release assessment..."
vulnetix \
  --task release \
  --production-branch "main" \
  --release-branch "$CURRENT_BRANCH" \
  --project-name "$PROJECT_NAME" \
  --team-name "Engineering" \
  --tools "$TOOLS_CONFIG"

echo "✅ Security assessment complete!"
echo "📊 Reports generated in: $REPORTS_DIR"
echo "🔍 Summary:"
echo "  - SAST findings: $(jq '.runs[0].results | length' "$REPORTS_DIR/sast-semgrep.sarif" 2>/dev/null || echo 'N/A')"
echo "  - Secrets found: $(jq '.runs[0].results | length' "$REPORTS_DIR/secrets-gitleaks.sarif" 2>/dev/null || echo 'N/A')"
echo "  - SBOM components: $(jq '.components | length' "$REPORTS_DIR/sbom.json" 2>/dev/null || echo 'N/A')"
```

### Report Generation

```bash
# Generate comprehensive reports
vulnetix --task report \
  --project-name "Production API" \
  --product-name "Core Platform" \
  --output-dir "$(brew --prefix)/var/vulnetix-reports" \
  --format "json,html,pdf"

# Team-specific reports
vulnetix --task report \
  --team-name "DevSecOps" \
  --filter-by-team \
  --include-metrics
```

### Automated Triage

```bash
# Auto-triage vulnerabilities
vulnetix --task triage \
  --team-name "Security Team" \
  --auto-assign \
  --priority-threshold "high"
```

## Management & Updates

### Update Vulnetix

```bash
# Update to latest version
brew update && brew upgrade vulnetix

# Update specific package
brew upgrade vulnetix

# Update all packages
brew update && brew upgrade
```

### Version Management

```bash
# List installed versions
brew list --versions vulnetix

# Switch between versions
brew switch vulnetix 1.2.3

# Rollback to previous version
brew switch vulnetix 1.2.2

# Pin version to prevent auto-updates
brew pin vulnetix

# Unpin to allow updates
brew unpin vulnetix
```

### Cleanup

```bash
# Clean up old versions
brew cleanup vulnetix

# Clean up all packages
brew cleanup

# Remove package completely
brew uninstall vulnetix

# Remove tap
brew untap vulnetix/vulnetix
```

## Edge Cases & Advanced Configuration

### Corporate Proxy Support

```bash
# Configure Homebrew for corporate proxy
export HTTP_PROXY="http://proxy.company.com:8080"
export HTTPS_PROXY="http://proxy.company.com:8080"
export NO_PROXY="localhost,127.0.0.1,.company.com"

# Add to shell profile
echo 'export HTTP_PROXY="http://proxy.company.com:8080"' >> ~/.zshrc
echo 'export HTTPS_PROXY="http://proxy.company.com:8080"' >> ~/.zshrc
echo 'export NO_PROXY="localhost,127.0.0.1,.company.com"' >> ~/.zshrc

# Authenticated proxy
export HTTP_PROXY="http://username:password@proxy.company.com:8080"
export HTTPS_PROXY="http://username:password@proxy.company.com:8080"

# Install with proxy
brew install vulnetix
```

### Custom CA Certificates

```bash
# macOS: Add corporate CA certificates
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain corporate-ca.crt

# Linux: Add to ca-certificates
sudo cp corporate-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# Configure curl (used by Homebrew)
echo 'capath=/etc/ssl/certs/' >> ~/.curlrc
echo 'cacert=/etc/ssl/certs/ca-certificates.crt' >> ~/.curlrc
```

### Alternative Installation Methods

```bash
# Install from bottle (pre-compiled binary)
brew install vulnetix --force-bottle

# Install from source
brew install vulnetix --build-from-source

# Install specific commit
brew install vulnetix --HEAD
```

### Custom Homebrew Installation

```bash
# Use custom Homebrew location
export HOMEBREW_PREFIX="/opt/homebrew"
export PATH="$HOMEBREW_PREFIX/bin:$PATH"

# Install to custom location
HOMEBREW_PREFIX="/custom/path" brew install vulnetix
```

### Offline Installation

```bash
# Download bottle for offline installation
brew fetch vulnetix

# Create offline installer bundle
brew bundle dump --file=Brewfile.vulnetix --describe
# Transfer Brewfile.vulnetix to offline system

# Install from bundle (offline system)
brew bundle install --file=Brewfile.vulnetix
```

## Integration Examples

### Makefile Integration

```makefile
# Makefile
.PHONY: security-install security-scan security-update

# Install security tools via Homebrew
security-install:
	@echo "Installing security tools..."
	@command -v brew >/dev/null 2>&1 || { echo "Homebrew not installed. Please install Homebrew first."; exit 1; }
	@brew tap vulnetix/vulnetix 2>/dev/null || true
	@brew install vulnetix semgrep gitleaks syft grype 2>/dev/null || brew upgrade vulnetix semgrep gitleaks syft grype

security-scan: security-install
	@echo "Running security scan..."
	@vulnetix --org-id "$(VULNETIX_ORG_ID)" --task release

security-update:
	@echo "Updating security tools..."
	@brew update && brew upgrade vulnetix semgrep gitleaks syft grype

# Development workflow
dev-setup: security-install
	@echo "Setting up development environment..."
	@brew install git pre-commit
	@pre-commit install
```

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash

# Install tools if not present
if ! command -v vulnetix >/dev/null 2>&1; then
  echo "Installing Vulnetix via Homebrew..."
  brew tap vulnetix/vulnetix
  brew install vulnetix
fi

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "Installing Gitleaks via Homebrew..."
  brew install gitleaks
fi

# Quick security scan
echo "Running quick security scan..."
export VULNETIX_ORG_ID="${VULNETIX_ORG_ID:-your-default-org-id}"

# Run secrets check
gitleaks protect --verbose --redact --source=.

# Run Vulnetix quick scan
vulnetix --task release --quick-scan

if [ $? -ne 0 ]; then
    echo "Security scan failed. Commit aborted."
    exit 1
fi

echo "Security scan passed."
```

### CI/CD Integration

```bash
# Jenkins Pipeline (macOS agents)
#!/bin/bash

# Ensure Homebrew is available
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

# Install/update tools
brew tap vulnetix/vulnetix
brew install vulnetix semgrep gitleaks

# Run security pipeline
export VULNETIX_ORG_ID="$VULNETIX_ORG_ID"
vulnetix --task release --project-name "$JOB_NAME" --build-id "$BUILD_NUMBER"
```

## Troubleshooting

### Common Issues

#### Homebrew Installation Fails

```bash
# Issue: Homebrew installation fails
# Solution: Check Homebrew installation
brew doctor

# Fix common issues
brew update
brew upgrade

# Reinstall if corrupted
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/uninstall.sh)"
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### Tap Not Found

```bash
# Issue: Cannot find vulnetix tap
# Solution: Add tap manually
brew tap vulnetix/vulnetix https://github.com/vulnetix/homebrew-vulnetix.git

# Verify tap
brew tap | grep vulnetix

# Update tap
brew tap vulnetix/vulnetix --force
```

#### Permission Issues

```bash
# Issue: Permission denied during installation
# Solution: Fix Homebrew permissions
sudo chown -R $(whoami) $(brew --prefix)/*
sudo chmod -R 755 $(brew --prefix)/*

# Or reinstall Homebrew for current user
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/uninstall.sh)"
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### Binary Not Found

```bash
# Issue: vulnetix command not found after installation
# Solution: Check PATH and reinstall
echo $PATH | grep -q "$(brew --prefix)/bin"

# Add Homebrew to PATH
export PATH="$(brew --prefix)/bin:$PATH"
echo 'export PATH="$(brew --prefix)/bin:$PATH"' >> ~/.zshrc

# Verify installation
which vulnetix
vulnetix --version

# Reinstall if needed
brew uninstall vulnetix
brew install vulnetix
```

#### Network Issues

```bash
# Issue: Cannot download packages
# Solution: Check network and proxy settings
curl -I https://github.com

# Test Homebrew connectivity
brew update --verbose

# Configure proxy if needed
export HTTP_PROXY="http://proxy.company.com:8080"
export HTTPS_PROXY="http://proxy.company.com:8080"
```

### Platform-Specific Issues

#### macOS

```bash
# Issue: Xcode command line tools missing
# Solution: Install Xcode command line tools
xcode-select --install

# Issue: Apple Silicon compatibility
# Solution: Use native ARM64 Homebrew
arch -arm64 brew install vulnetix

# For Intel compatibility on Apple Silicon
arch -x86_64 brew install vulnetix
```

#### Linux

```bash
# Issue: Missing dependencies on Linux
# Solution: Install required packages
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential curl file git

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install curl file git

# Issue: Homebrew not in PATH on Linux
# Solution: Add to shell profile
echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' >> ~/.bashrc
eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
```

### Version Issues

```bash
# Issue: Wrong version installed
# Solution: Install specific version
brew uninstall vulnetix
brew install vulnetix@1.2.3

# Issue: Multiple versions conflict
# Solution: Clean up and reinstall
brew cleanup vulnetix
brew uninstall vulnetix --force
brew install vulnetix

# Issue: Formula outdated
# Solution: Update tap and formula
brew update
brew tap vulnetix/vulnetix --force
brew install vulnetix
```

## Security Best Practices

### Verify Installation

```bash
# Verify Homebrew installation integrity
brew doctor

# Check formula authenticity
brew info vulnetix

# Verify binary signature (if available)
codesign -v $(which vulnetix)  # macOS only
```

### Secure Configuration

```bash
# Disable analytics
export HOMEBREW_NO_ANALYTICS=1

# Disable auto-updates during install
export HOMEBREW_NO_AUTO_UPDATE=1

# Use secure transport
export HOMEBREW_FORCE_BREWED_CA_CERTIFICATES=1

# Add to shell profile
echo 'export HOMEBREW_NO_ANALYTICS=1' >> ~/.zshrc
echo 'export HOMEBREW_NO_AUTO_UPDATE=1' >> ~/.zshrc
```

### Regular Updates

```bash
# Create update script
cat > update-security-tools.sh << 'EOF'
#!/bin/bash
echo "Updating security tools..."
brew update
brew upgrade vulnetix semgrep gitleaks syft grype
echo "Update complete."
EOF

chmod +x update-security-tools.sh

# Run weekly (add to cron or launchd)
# Cron example: 0 0 * * 0 /path/to/update-security-tools.sh
```

For more advanced usage patterns and integrations, see the [main documentation](../USAGE.md) and other [reference guides](./README.md).
