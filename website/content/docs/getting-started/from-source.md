---
title: "From Source"
weight: 6
description: "Build and install the Vulnetix CLI from source code for maximum flexibility."
---

Building from source provides the most flexible installation method and allows for customization, development, and installation on unsupported platforms.

## Quick Start

### Prerequisites

```bash
# Install Go 1.21 or later
# Visit https://golang.org/dl/ for installation instructions

# Verify Go installation
go version  # Should show 1.21 or later

# Install Git
sudo apt-get install git     # Ubuntu/Debian
sudo yum install git         # CentOS/RHEL
brew install git             # macOS
```

### Basic Build

```bash
# Clone repository
git clone https://github.com/Vulnetix/cli.git
cd vulnetix

# Build binary
go build -o vulnetix .

# Install to system PATH
sudo install vulnetix /usr/local/bin/

# Verify installation
vulnetix --version
```

### Development Build

```bash
# Clone and install in development mode
git clone https://github.com/Vulnetix/cli.git
cd vulnetix

# Install dependencies
go mod download

# Run tests
go test ./...

# Build with development flags
go build -tags dev -o vulnetix .

# Run without installing
./vulnetix --version
```

## Build Configurations

### Release Build

```bash
# Build optimized release binary
go build -ldflags="-s -w" -o vulnetix .

# Build with version information
VERSION=$(git describe --tags --always --dirty)
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT=$(git rev-parse HEAD)

go build \
  -ldflags="-s -w -X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -X main.GitCommit=$GIT_COMMIT" \
  -o vulnetix .

# Verify build info
./vulnetix version --verbose
```

### Debug Build

```bash
# Build with debug symbols and race detection
go build -race -ldflags="-X main.Debug=true" -o vulnetix-debug .

# Build with extra debug information
go build -gcflags="all=-N -l" -o vulnetix-debug .

# Run with debug output
./vulnetix-debug --debug
```

### Static Binary

```bash
# Build statically linked binary (useful for containers)
CGO_ENABLED=0 go build -ldflags="-s -w -extldflags=-static" -o vulnetix-static .

# Verify static linking
ldd vulnetix-static  # Should show "not a dynamic executable"

# Build minimal static binary
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o vulnetix-minimal .
```

## Cross-Platform Builds

### Multi-Platform Script

```bash
#!/bin/bash
# build-all.sh - Build for all supported platforms

set -e

VERSION=$(git describe --tags --always --dirty)
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT=$(git rev-parse HEAD)

LDFLAGS="-s -w -X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -X main.GitCommit=$GIT_COMMIT"

# Build platforms
platforms=(
    "linux/amd64"
    "linux/arm64"
    "linux/arm"
    "linux/386"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/386"
    "freebsd/amd64"
    "openbsd/amd64"
    "netbsd/amd64"
)

# Create output directory
mkdir -p dist

echo "Building Vulnetix $VERSION for ${#platforms[@]} platforms..."

for platform in "${platforms[@]}"; do
    IFS='/' read -r GOOS GOARCH <<< "$platform"

    output_name="vulnetix-$GOOS-$GOARCH"
    if [ $GOOS = "windows" ]; then
        output_name+='.exe'
    fi

    echo "Building for $GOOS/$GOARCH..."

    env CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH \
        go build -ldflags="$LDFLAGS" -o "dist/$output_name" .

    if [ $? -ne 0 ]; then
        echo "Failed to build for $GOOS/$GOARCH"
        exit 1
    fi
done

echo "Build completed successfully!"
ls -la dist/
```

### Individual Platform Builds

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o vulnetix-linux-amd64 .

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -o vulnetix-linux-arm64 .

# macOS AMD64
GOOS=darwin GOARCH=amd64 go build -o vulnetix-darwin-amd64 .

# macOS ARM64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o vulnetix-darwin-arm64 .

# Windows AMD64
GOOS=windows GOARCH=amd64 go build -o vulnetix-windows-amd64.exe .

# FreeBSD AMD64
GOOS=freebsd GOARCH=amd64 go build -o vulnetix-freebsd-amd64 .
```

## Custom Build Configurations

### Enterprise Build

```bash
#!/bin/bash
# enterprise-build.sh - Enterprise customized build

set -e

# Enterprise configuration
ENTERPRISE_CONFIG_URL="https://config.company.com/vulnetix"
ENTERPRISE_REGISTRY="packages.company.com"
SUPPORT_CONTACT="security@company.com"

# Build with enterprise defaults
go build \
  -ldflags="-s -w \
    -X main.DefaultConfigURL=$ENTERPRISE_CONFIG_URL \
    -X main.DefaultRegistry=$ENTERPRISE_REGISTRY \
    -X main.SupportContact=$SUPPORT_CONTACT \
    -X main.Enterprise=true" \
  -o vulnetix-enterprise .

echo "Enterprise build completed"
./vulnetix-enterprise --version
```

### Plugin Support Build

```bash
# Build with plugin support
go build -buildmode=exe -ldflags="-s -w" -o vulnetix-plugins .

# Build plugin example
go build -buildmode=plugin -o vulnetix-plugin-example.so ./plugins/example/
```

### Development Build with Hot Reload

```bash
# Install air for hot reloading
go install github.com/cosmtrek/air@latest

# Create .air.toml for configuration
cat > .air.toml << 'EOF'
root = "."
testdata_dir = "testdata"
tmp_dir = "tmp"

[build]
  args_bin = ["--debug"]
  bin = "./tmp/vulnetix"
  cmd = "go build -o ./tmp/vulnetix ."
  delay = 1000
  exclude_dir = ["assets", "tmp", "vendor", "testdata"]
  exclude_file = []
  exclude_regex = ["_test.go"]
  exclude_unchanged = false
  follow_symlink = false
  full_bin = ""
  include_dir = []
  include_ext = ["go", "tpl", "tmpl", "html"]
  kill_delay = "0s"
  log = "build-errors.log"
  send_interrupt = false
  stop_on_root = false

[color]
  app = ""
  build = "yellow"
  main = "magenta"
  runner = "green"
  watcher = "cyan"

[log]
  time = false

[misc]
  clean_on_exit = false
EOF

# Start development server with hot reload
air
```

## Advanced Build Features

### Build with Embedded Assets

```bash
# Install go-embed for asset embedding
go install github.com/golang/go/embed

# Build with embedded configuration templates
go build -tags embed -o vulnetix-embedded .
```

### Reproducible Builds

```bash
#!/bin/bash
# reproducible-build.sh - Create reproducible builds

set -e

# Set reproducible build environment
export CGO_ENABLED=0
export GOPROXY=https://proxy.golang.org,direct
export GOSUMDB=sum.golang.org

# Use fixed timestamp for reproducibility
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)

# Build with trimpath for reproducible paths
go build \
  -trimpath \
  -ldflags="-s -w -buildid=" \
  -o vulnetix .

# Verify reproducibility
echo "Build completed with deterministic output"
sha256sum vulnetix
```

### Performance Optimized Build

```bash
# Build with performance optimizations
go build \
  -ldflags="-s -w" \
  -gcflags="-l=4" \
  -asmflags="-trimpath" \
  -o vulnetix-optimized .

# Profile-guided optimization (Go 1.21+)
# First, run with profiling
go build -pgo=cpu.pprof -o vulnetix-pgo .
```

## Testing and Validation

### Comprehensive Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run tests with race detection
go test -race ./...

# Run benchmarks
go test -bench=. ./...

# Run integration tests
go test -tags integration ./...
```

### Build Validation

```bash
#!/bin/bash
# validate-build.sh - Validate built binary

set -e

BINARY="./vulnetix"

# Basic functionality tests
echo "Testing basic functionality..."
$BINARY --version
$BINARY --help

# Test basic functionality
echo "Testing task functionality..."
$BINARY --version

# Test configuration loading
echo "Testing configuration..."
$BINARY config validate

# Test plugin loading (if applicable)
if $BINARY plugins list &>/dev/null; then
    echo "Testing plugin system..."
    $BINARY plugins list
fi

echo "Build validation completed successfully!"
```

### Security Validation

```bash
#!/bin/bash
# security-validation.sh - Security checks for built binary

set -e

BINARY="./vulnetix"

# Check for hardcoded secrets (using trufflehog or similar)
echo "Checking for hardcoded secrets..."
if command -v trufflehog &> /dev/null; then
    trufflehog filesystem . --exclude-paths=.trufflehogignore
fi

# Check binary security features
echo "Checking binary security features..."
if command -v checksec &> /dev/null; then
    checksec --file=$BINARY
fi

# Check for debug symbols
echo "Checking for debug symbols..."
if file $BINARY | grep -q "not stripped"; then
    echo "WARNING: Binary contains debug symbols"
fi

# Check dependencies for vulnerabilities
echo "Checking dependencies for vulnerabilities..."
go list -json -deps ./... | nancy sleuth

echo "Security validation completed!"
```

## Custom Installation

### System-wide Installation

```bash
#!/bin/bash
# system-install.sh - System-wide installation from source

set -e

# Build optimized binary
echo "Building Vulnetix from source..."
go build -ldflags="-s -w" -o vulnetix .

# Install binary
echo "Installing binary..."
sudo install -m 755 vulnetix /usr/local/bin/

# Install man page (if available)
if [ -f "docs/vulnetix.1" ]; then
    sudo install -m 644 docs/vulnetix.1 /usr/local/share/man/man1/
    sudo mandb
fi

# Install shell completions
mkdir -p ~/.local/share/bash-completion/completions
vulnetix completion bash > ~/.local/share/bash-completion/completions/vulnetix

mkdir -p ~/.local/share/zsh/site-functions
vulnetix completion zsh > ~/.local/share/zsh/site-functions/_vulnetix

# Install configuration templates
sudo mkdir -p /etc/vulnetix
if [ -d "configs" ]; then
    sudo cp -r configs/* /etc/vulnetix/
fi

echo "System-wide installation completed!"
vulnetix --version
```

### User Installation

```bash
#!/bin/bash
# user-install.sh - User-specific installation from source

set -e

# Create user directories
mkdir -p ~/.local/bin
mkdir -p ~/.config/vulnetix

# Build and install binary
echo "Building and installing Vulnetix..."
go build -ldflags="-s -w" -o ~/.local/bin/vulnetix .

# Add to PATH if not already there
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    echo "Added ~/.local/bin to PATH in ~/.bashrc"
fi

# Install configuration
if [ -f "config/vulnetix.yaml.example" ]; then
    cp config/vulnetix.yaml.example ~/.config/vulnetix/config.yaml
fi

echo "User installation completed!"
~/.local/bin/vulnetix --version
```

## Development Environment

### VS Code Configuration

```json
// .vscode/settings.json
{
    "go.toolsManagement.checkForUpdates": "local",
    "go.useLanguageServer": true,
    "go.gopath": "",
    "go.goroot": "",
    "go.lintTool": "golangci-lint",
    "go.lintFlags": [
        "--fast"
    ],
    "go.vetFlags": [
        "-atomic",
        "-bool",
        "-copylocks",
        "-nilfunc",
        "-printf",
        "-rangeloops",
        "-unreachable"
    ],
    "go.buildTags": "dev",
    "go.testFlags": ["-v", "-race"],
    "go.coverMode": "atomic"
}
```

```json
// .vscode/launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug Vulnetix",
            "type": "go",
            "request": "launch",
            "mode": "debug",
            "program": "${workspaceFolder}",
            "args": ["--debug"],
            "env": {
                "VULNETIX_DEBUG": "true"
            }
        },
        {
            "name": "Test Current Package",
            "type": "go",
            "request": "launch",
            "mode": "test",
            "program": "${workspaceFolder}/${relativeFileDirname}"
        }
    ]
}
```

### Git Hooks

```bash
#!/bin/bash
# .git/hooks/pre-commit - Pre-commit hook for quality checks

set -e

echo "Running pre-commit checks..."

# Format code
echo "Formatting Go code..."
go fmt ./...

# Run linter
echo "Running linter..."
if command -v golangci-lint &> /dev/null; then
    golangci-lint run
fi

# Run tests
echo "Running tests..."
go test -race -short ./...

# Check for security issues
echo "Running security checks..."
if command -v gosec &> /dev/null; then
    gosec ./...
fi

# Check dependencies
echo "Checking dependencies..."
go mod verify
go mod tidy

echo "Pre-commit checks completed successfully!"
```

### Makefile for Development

```makefile
# Makefile for Vulnetix development

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=vulnetix
BINARY_UNIX=$(BINARY_NAME)_unix

# Version information
VERSION ?= $(shell git describe --tags --always --dirty)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GIT_COMMIT ?= $(shell git rev-parse HEAD)

# Linker flags
LDFLAGS=-ldflags "-s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"

.PHONY: all build clean test coverage lint security install dev

all: test build

build:
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) -v

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)

test:
	$(GOTEST) -v ./...

test-race:
	$(GOTEST) -race -v ./...

coverage:
	$(GOTEST) -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out

lint:
	golangci-lint run

security:
	gosec ./...

deps:
	$(GOGET) -u -v ./...
	$(GOCMD) mod tidy

install: build
	sudo install $(BINARY_NAME) /usr/local/bin/

dev:
	$(GOBUILD) -tags dev -race $(LDFLAGS) -o $(BINARY_NAME) -v

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_UNIX) -v
```

## Troubleshooting

### Common Build Issues

#### Go Version Compatibility
```bash
# Check Go version
go version

# Update Go if needed
sudo rm -rf /usr/local/go
curl -L https://go.dev/dl/go1.21.0.linux-amd64.tar.gz | sudo tar -C /usr/local -xz

# Update PATH
export PATH=/usr/local/go/bin:$PATH
echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc
```

#### Dependency Issues
```bash
# Clean module cache
go clean -modcache

# Re-download dependencies
go mod download

# Update dependencies
go get -u ./...
go mod tidy
```

#### CGO Issues
```bash
# Install build tools
sudo apt-get install build-essential  # Ubuntu/Debian
sudo yum groupinstall "Development Tools"  # CentOS/RHEL

# Disable CGO if not needed
CGO_ENABLED=0 go build -o vulnetix .
```

### Build Performance

#### Parallel Builds
```bash
# Use all CPU cores
GOMAXPROCS=$(nproc) go build -p $(nproc) -o vulnetix .

# Increase parallel workers
go build -p 8 -o vulnetix .
```

#### Build Cache
```bash
# Clean build cache
go clean -cache

# Check cache status
go env GOCACHE

# Warm up cache
go build -i .
```

### Cross-Compilation Issues

#### Missing Libraries
```bash
# Install cross-compilation support
sudo apt-get install gcc-multilib  # For 32-bit builds on 64-bit
sudo apt-get install gcc-aarch64-linux-gnu  # For ARM64 builds
```

#### Windows Builds on Linux
```bash
# Install mingw for Windows builds
sudo apt-get install gcc-mingw-w64

# Build Windows executable
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build -o vulnetix.exe .
```

---

**Next Steps:**
- See [Multi-Architecture](multi-arch.md) for cross-platform considerations
- See [GitHub Actions](github-actions.md) for automated builds and releases
