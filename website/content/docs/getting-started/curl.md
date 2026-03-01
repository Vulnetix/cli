---
title: "Direct Download (curl)"
weight: 5
description: "Download and install the Vulnetix CLI binary directly using curl."
---

Direct binary downloads provide the fastest way to install Vulnetix without package managers or dependency on external tools.

## Quick Start

### Auto-Detection Script

```bash
# Download and install latest version (auto-detects platform/architecture)
curl -fsSL https://raw.githubusercontent.com/vulnetix/cli/main/install.sh | sh

# Install to custom directory
curl -fsSL https://raw.githubusercontent.com/vulnetix/cli/main/install.sh | sh -s -- --install-dir=~/.local/bin

# Install specific version
curl -fsSL https://raw.githubusercontent.com/vulnetix/cli/main/install.sh | sh -s -- --version=v1.2.3
```

### Manual Binary Download

```bash
# Linux AMD64
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64.tar.gz | tar -xz
sudo mv vulnetix /usr/local/bin/

# Linux ARM64
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-arm64.tar.gz | tar -xz
sudo mv vulnetix /usr/local/bin/

# macOS AMD64
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-darwin-amd64.tar.gz | tar -xz
sudo mv vulnetix /usr/local/bin/

# macOS ARM64 (Apple Silicon)
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-darwin-arm64.tar.gz | tar -xz
sudo mv vulnetix /usr/local/bin/

# Windows AMD64 (PowerShell)
Invoke-WebRequest -Uri "https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-windows-amd64.zip" -OutFile "vulnetix.zip"
Expand-Archive vulnetix.zip -DestinationPath "C:\Tools\Vulnetix"
$env:PATH += ";C:\Tools\Vulnetix"
```

## Platform-Specific Downloads

### Linux

#### AMD64 (x86_64)
```bash
# Download and install
curl -L -o vulnetix.tar.gz https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64.tar.gz
tar -xzf vulnetix.tar.gz
sudo install vulnetix /usr/local/bin/
rm vulnetix vulnetix.tar.gz

# Verify installation
vulnetix --version
```

#### ARM64 (aarch64)
```bash
# Download and install
curl -L -o vulnetix.tar.gz https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-arm64.tar.gz
tar -xzf vulnetix.tar.gz
sudo install vulnetix /usr/local/bin/
rm vulnetix vulnetix.tar.gz

# Verify installation
vulnetix --version
```

#### ARM (armv7)
```bash
# Download and install
curl -L -o vulnetix.tar.gz https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-arm.tar.gz
tar -xzf vulnetix.tar.gz
sudo install vulnetix /usr/local/bin/
rm vulnetix vulnetix.tar.gz

# Verify installation
vulnetix --version
```

#### 386 (i386)
```bash
# Download and install
curl -L -o vulnetix.tar.gz https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-386.tar.gz
tar -xzf vulnetix.tar.gz
sudo install vulnetix /usr/local/bin/
rm vulnetix vulnetix.tar.gz

# Verify installation
vulnetix --version
```

### macOS

#### Intel Macs (AMD64)
```bash
# Download and install
curl -L -o vulnetix.tar.gz https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-darwin-amd64.tar.gz
tar -xzf vulnetix.tar.gz
sudo mv vulnetix /usr/local/bin/
rm vulnetix.tar.gz

# Add to PATH if needed
echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# Verify installation
vulnetix --version
```

#### Apple Silicon Macs (ARM64)
```bash
# Download and install
curl -L -o vulnetix.tar.gz https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-darwin-arm64.tar.gz
tar -xzf vulnetix.tar.gz
sudo mv vulnetix /usr/local/bin/
rm vulnetix.tar.gz

# Add to PATH if needed
echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# Verify installation
vulnetix --version
```

### Windows

#### PowerShell (Recommended)
```powershell
# Create installation directory
New-Item -ItemType Directory -Force -Path "C:\Tools\Vulnetix"

# Download and extract
Invoke-WebRequest -Uri "https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-windows-amd64.zip" -OutFile "$env:TEMP\vulnetix.zip"
Expand-Archive -Path "$env:TEMP\vulnetix.zip" -DestinationPath "C:\Tools\Vulnetix" -Force

# Add to PATH permanently
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($currentPath -notlike "*C:\Tools\Vulnetix*") {
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;C:\Tools\Vulnetix", "Machine")
}

# Refresh current session PATH
$env:PATH += ";C:\Tools\Vulnetix"

# Clean up
Remove-Item "$env:TEMP\vulnetix.zip"

# Verify installation
vulnetix --version
```

#### Command Prompt
```cmd
# Create directory and download (requires curl or wget)
mkdir "C:\Tools\Vulnetix"
curl -L -o "%TEMP%\vulnetix.zip" https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-windows-amd64.zip

# Extract (requires PowerShell or 7zip)
powershell -Command "Expand-Archive -Path '%TEMP%\vulnetix.zip' -DestinationPath 'C:\Tools\Vulnetix' -Force"

# Add to PATH
setx PATH "%PATH%;C:\Tools\Vulnetix" /M

# Verify installation (restart cmd)
vulnetix --version
```

## Version-Specific Downloads

### Latest Release
```bash
# Get latest version dynamically
LATEST_VERSION=$(curl -s https://api.github.com/repos/vulnetix/cli/releases/latest | grep -o '"tag_name": "[^"]*' | cut -d'"' -f4)
echo "Latest version: $LATEST_VERSION"

# Download latest for current platform
curl -L -o vulnetix.tar.gz "https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m | sed 's/x86_64/amd64/').tar.gz"
```

### Specific Version
```bash
# Download specific version
VERSION="v1.2.3"
PLATFORM="linux-amd64"
curl -L -o vulnetix.tar.gz "https://github.com/Vulnetix/cli/releases/download/${VERSION}/vulnetix-${PLATFORM}.tar.gz"
tar -xzf vulnetix.tar.gz
sudo install vulnetix /usr/local/bin/
```

### Pre-release Versions
```bash
# List all releases including pre-releases
curl -s https://api.github.com/repos/vulnetix/cli/releases | jq -r '.[].tag_name'

# Download pre-release
VERSION="v1.3.0-beta.1"
PLATFORM="linux-amd64"
curl -L -o vulnetix.tar.gz "https://github.com/Vulnetix/cli/releases/download/${VERSION}/vulnetix-${PLATFORM}.tar.gz"
```

## Advanced Installation Scripts

### Multi-Platform Auto-Detection

```bash
#!/bin/bash
# install-vulnetix.sh - Advanced installation script

set -e

# Configuration
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"
FORCE_INSTALL="${FORCE_INSTALL:-false}"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

# Detect platform and architecture
detect_platform() {
    local os arch

    case "$(uname -s)" in
        Linux*)     os="linux" ;;
        Darwin*)    os="darwin" ;;
        CYGWIN*|MINGW*|MSYS*) os="windows" ;;
        *)          error "Unsupported operating system: $(uname -s)" ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)   arch="amd64" ;;
        arm64|aarch64)  arch="arm64" ;;
        armv7l|armv6l)  arch="arm" ;;
        i386|i686)      arch="386" ;;
        *)              error "Unsupported architecture: $(uname -m)" ;;
    esac

    echo "${os}-${arch}"
}

# Get latest version
get_latest_version() {
    curl -s https://api.github.com/repos/vulnetix/cli/releases/latest | \
        grep -o '"tag_name": "[^"]*' | \
        cut -d'"' -f4
}

# Download and install
install_vulnetix() {
    local platform version download_url temp_dir

    platform=$(detect_platform)

    if [ "$VERSION" = "latest" ]; then
        version=$(get_latest_version)
        log "Latest version detected: $version"
    else
        version="$VERSION"
    fi

    download_url="https://github.com/Vulnetix/cli/releases/download/${version}/vulnetix-${platform}.tar.gz"
    temp_dir=$(mktemp -d)

    log "Downloading from: $download_url"

    # Download with retry logic
    local retry_count=0
    local max_retries=3

    while [ $retry_count -lt $max_retries ]; do
        if curl -L --fail -o "${temp_dir}/vulnetix.tar.gz" "$download_url"; then
            break
        else
            retry_count=$((retry_count + 1))
            warn "Download failed, retrying ($retry_count/$max_retries)..."
            sleep 2
        fi
    done

    if [ $retry_count -eq $max_retries ]; then
        error "Failed to download after $max_retries attempts"
    fi

    # Extract and install
    log "Extracting to $temp_dir"
    tar -xzf "${temp_dir}/vulnetix.tar.gz" -C "$temp_dir"

    # Check if binary exists and is executable
    if [ ! -f "${temp_dir}/vulnetix" ]; then
        error "Binary not found in archive"
    fi

    chmod +x "${temp_dir}/vulnetix"

    # Install binary
    log "Installing to $INSTALL_DIR"

    if [ ! -w "$INSTALL_DIR" ]; then
        log "Installing with sudo (requires password)"
        sudo install "${temp_dir}/vulnetix" "$INSTALL_DIR/"
    else
        install "${temp_dir}/vulnetix" "$INSTALL_DIR/"
    fi

    # Cleanup
    rm -rf "$temp_dir"

    # Verify installation
    if command -v vulnetix >/dev/null 2>&1; then
        log "Installation successful!"
        vulnetix --version
    else
        error "Installation failed - vulnetix not found in PATH"
    fi
}

# Pre-installation checks
check_dependencies() {
    local missing_deps=""

    for cmd in curl tar; do
        if ! command -v $cmd >/dev/null 2>&1; then
            missing_deps="$missing_deps $cmd"
        fi
    done

    if [ -n "$missing_deps" ]; then
        error "Missing required dependencies:$missing_deps"
    fi
}

# Check for existing installation
check_existing() {
    if command -v vulnetix >/dev/null 2>&1 && [ "$FORCE_INSTALL" != "true" ]; then
        local current_version
        current_version=$(vulnetix --version 2>/dev/null | head -n1 || echo "unknown")
        warn "Vulnetix is already installed: $current_version"
        warn "Use FORCE_INSTALL=true to reinstall"
        exit 0
    fi
}

# Main installation flow
main() {
    log "Starting Vulnetix installation..."

    check_dependencies
    check_existing
    install_vulnetix

    log "Vulnetix installation completed successfully!"
}

# Run installation
main "$@"
```

### Enterprise Installation Script

```bash
#!/bin/bash
# enterprise-install.sh - Enterprise installation with validation

set -e

# Enterprise configuration
ENTERPRISE_REGISTRY="${ENTERPRISE_REGISTRY:-https://packages.company.com}"
ENTERPRISE_TOKEN="${ENTERPRISE_TOKEN:-}"
INSTALL_DIR="${INSTALL_DIR:-/opt/vulnetix}"
CONFIG_DIR="${CONFIG_DIR:-/etc/vulnetix}"
VALIDATE_CHECKSUM="${VALIDATE_CHECKSUM:-true}"

# Create installation directory
sudo mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"

# Download with enterprise authentication
if [ -n "$ENTERPRISE_TOKEN" ]; then
    curl -H "Authorization: Bearer $ENTERPRISE_TOKEN" \
         -L -o vulnetix.tar.gz \
         "$ENTERPRISE_REGISTRY/vulnetix/releases/latest/vulnetix-linux-amd64.tar.gz"

    if [ "$VALIDATE_CHECKSUM" = "true" ]; then
        curl -H "Authorization: Bearer $ENTERPRISE_TOKEN" \
             -L -o vulnetix.tar.gz.sha256 \
             "$ENTERPRISE_REGISTRY/vulnetix/releases/latest/vulnetix-linux-amd64.tar.gz.sha256"

        sha256sum -c vulnetix.tar.gz.sha256
    fi
else
    # Fallback to public GitHub
    curl -L -o vulnetix.tar.gz \
         "https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64.tar.gz"
fi

# Extract and install
tar -xzf vulnetix.tar.gz
sudo install vulnetix "$INSTALL_DIR/"
sudo ln -sf "$INSTALL_DIR/vulnetix" /usr/local/bin/vulnetix

# Create enterprise configuration
sudo tee "$CONFIG_DIR/config.yaml" > /dev/null <<EOF
org_id: ${VULNETIX_ORG_ID}
api_endpoint: ${VULNETIX_API_ENDPOINT:-https://app.vulnetix.com/api}
default_team: ${VULNETIX_DEFAULT_TEAM:-security}
proxy:
  http_proxy: ${HTTP_PROXY:-}
  https_proxy: ${HTTPS_PROXY:-}
  no_proxy: ${NO_PROXY:-}
EOF

# Set permissions
sudo chown -R root:root "$INSTALL_DIR" "$CONFIG_DIR"
sudo chmod 755 "$INSTALL_DIR/vulnetix"
sudo chmod 644 "$CONFIG_DIR/config.yaml"

# Cleanup
rm -f vulnetix vulnetix.tar.gz vulnetix.tar.gz.sha256

echo "Enterprise installation completed successfully"
vulnetix --version
```

## CI/CD Integration Examples

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Vulnetix

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4

    - name: Download Vulnetix
      run: |
        curl -L -o vulnetix.tar.gz https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64.tar.gz
        tar -xzf vulnetix.tar.gz
        sudo mv vulnetix /usr/local/bin/
        vulnetix --version

    - name: Run Vulnetix
      env:
        VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
      run: |
        vulnetix --task triage --project-name "$(basename $(pwd))"

    - name: Upload SARIF results
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: security-results.sarif
```

### GitLab CI

```yaml
# .gitlab-ci.yml
image: alpine:latest

stages:
  - security

security_check:
  stage: security
  before_script:
    - apk add --no-cache curl tar
    - curl -L -o vulnetix.tar.gz https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64.tar.gz
    - tar -xzf vulnetix.tar.gz
    - mv vulnetix /usr/local/bin/
    - vulnetix --version
  script:
    - vulnetix --task triage --project-name "$CI_PROJECT_NAME"
  artifacts:
    reports:
      security: security-results.json
```

### Jenkins

```groovy
// Jenkinsfile
pipeline {
    agent any

    stages {
        stage('Install Vulnetix') {
            steps {
                sh '''
                    curl -L -o vulnetix.tar.gz https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64.tar.gz
                    tar -xzf vulnetix.tar.gz
                    sudo mv vulnetix /usr/local/bin/
                    vulnetix --version
                '''
            }
        }

        stage('Security Check') {
            steps {
                withCredentials([string(credentialsId: 'vulnetix-org-id', variable: 'VULNETIX_ORG_ID')]) {
                    sh 'vulnetix --task triage --project-name "${JOB_NAME}"'
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-results.json', fingerprint: true
                }
            }
        }
    }
}
```

## Edge Cases and Troubleshooting

### Corporate Networks

#### Proxy Configuration
```bash
# Set proxy for curl download
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1,.company.com

# Download through proxy
curl --proxy $HTTP_PROXY -L -o vulnetix.tar.gz https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64.tar.gz
```

#### Custom CA Certificates
```bash
# Add custom CA certificate
sudo cp company-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# Download with custom CA
curl --cacert /usr/local/share/ca-certificates/company-ca.crt -L -o vulnetix.tar.gz https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64.tar.gz
```

#### Internal Mirror
```bash
# Download from internal mirror
INTERNAL_MIRROR="https://artifacts.vulnetix.com"
curl -L -o vulnetix.tar.gz "$INTERNAL_MIRROR/releases/latest/vulnetix-linux-amd64.tar.gz"
```

### Air-Gapped Environments

#### Offline Installation Package
```bash
#!/bin/bash
# create-offline-package.sh - Create offline installation package

set -e

PACKAGE_DIR="vulnetix-offline-$(date +%Y%m%d)"
mkdir -p "$PACKAGE_DIR"

# Download all supported platforms
platforms=(
    "linux-amd64"
    "linux-arm64"
    "linux-arm"
    "linux-386"
    "darwin-amd64"
    "darwin-arm64"
    "windows-amd64"
)

for platform in "${platforms[@]}"; do
    echo "Downloading $platform..."
    curl -L -o "$PACKAGE_DIR/vulnetix-$platform.tar.gz" \
        "https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-$platform.tar.gz"
done

# Create installation script
cat > "$PACKAGE_DIR/install-offline.sh" << 'EOF'
#!/bin/bash
# Offline installation script

set -e

# Detect platform
detect_platform() {
    local os arch

    case "$(uname -s)" in
        Linux*)     os="linux" ;;
        Darwin*)    os="darwin" ;;
        *)          echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)   arch="amd64" ;;
        arm64|aarch64)  arch="arm64" ;;
        armv7l|armv6l)  arch="arm" ;;
        i386|i686)      arch="386" ;;
        *)              echo "Unsupported arch: $(uname -m)" >&2; exit 1 ;;
    esac

    echo "${os}-${arch}"
}

# Install
platform=$(detect_platform)
archive="vulnetix-${platform}.tar.gz"

if [ ! -f "$archive" ]; then
    echo "Error: $archive not found" >&2
    exit 1
fi

echo "Installing vulnetix for $platform..."
tar -xzf "$archive"
sudo install vulnetix /usr/local/bin/
rm vulnetix

echo "Installation completed successfully!"
vulnetix --version
EOF

chmod +x "$PACKAGE_DIR/install-offline.sh"

# Create package
tar -czf "${PACKAGE_DIR}.tar.gz" "$PACKAGE_DIR"
echo "Offline package created: ${PACKAGE_DIR}.tar.gz"
```

### Permission Issues

#### Non-root Installation
```bash
# Install to user directory
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

curl -L -o vulnetix.tar.gz https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64.tar.gz
tar -xzf vulnetix.tar.gz
mv vulnetix "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/vulnetix"

# Add to PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

#### Alternative Installation Locations
```bash
# Install to /opt (requires sudo)
sudo mkdir -p /opt/vulnetix
curl -L -o vulnetix.tar.gz https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64.tar.gz
tar -xzf vulnetix.tar.gz
sudo mv vulnetix /opt/vulnetix/
sudo ln -sf /opt/vulnetix/cli /usr/local/bin/vulnetix

# Install to custom location
CUSTOM_DIR="/usr/local/security-tools"
sudo mkdir -p "$CUSTOM_DIR"
curl -L -o vulnetix.tar.gz https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64.tar.gz
tar -xzf vulnetix.tar.gz
sudo mv vulnetix "$CUSTOM_DIR/"
sudo chmod +x "$CUSTOM_DIR/vulnetix"
echo "export PATH=\"$CUSTOM_DIR:\$PATH\"" | sudo tee /etc/profile.d/vulnetix.sh
```

### Checksum Verification

#### Manual Verification
```bash
# Download binary and checksum
curl -L -o vulnetix.tar.gz https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64.tar.gz
curl -L -o vulnetix.tar.gz.sha256 https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64.tar.gz.sha256

# Verify checksum
sha256sum -c vulnetix.tar.gz.sha256

# If verification passes, install
tar -xzf vulnetix.tar.gz
sudo install vulnetix /usr/local/bin/
```

#### Automated Verification Script
```bash
#!/bin/bash
# secure-install.sh - Installation with automatic verification

set -e

PLATFORM="linux-amd64"
BASE_URL="https://github.com/Vulnetix/cli/releases/latest/download"

# Download binary and checksum
curl -L -o vulnetix.tar.gz "$BASE_URL/vulnetix-$PLATFORM.tar.gz"
curl -L -o vulnetix.tar.gz.sha256 "$BASE_URL/vulnetix-$PLATFORM.tar.gz.sha256"

# Verify checksum
if sha256sum -c vulnetix.tar.gz.sha256; then
    echo "Checksum verification passed"
    tar -xzf vulnetix.tar.gz
    sudo install vulnetix /usr/local/bin/
    rm vulnetix vulnetix.tar.gz vulnetix.tar.gz.sha256
    echo "Installation completed successfully"
    vulnetix --version
else
    echo "Checksum verification failed!" >&2
    rm vulnetix.tar.gz vulnetix.tar.gz.sha256
    exit 1
fi
```

## Troubleshooting

### Download Issues
```bash
# Test connectivity
curl -I https://github.com/Vulnetix/cli/releases/latest

# Check DNS resolution
nslookup github.com

# Test with verbose output
curl -v -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64.tar.gz

# Alternative download methods
wget https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64.tar.gz
```

### Architecture Detection Issues
```bash
# Check architecture manually
uname -m
uname -s

# Alternative architecture detection
lscpu | grep Architecture
file /bin/bash
```

### Permission Fixes
```bash
# Fix binary permissions
chmod +x vulnetix

# Fix directory permissions
sudo chown -R $USER:$USER ~/.local/bin
sudo chmod -R 755 ~/.local/bin
```

---

**Next Steps:**
- See [From Source](from-source.md) for building from source code
- See [Multi-Architecture](multi-arch.md) for cross-platform considerations
- See [Corporate Proxy](corporate-proxy.md) for enterprise network configuration
