# Release Process

This document outlines the release process for Vulnetix CLI to enable `go install` functionality and prebuilt binary distribution.

## Prerequisites

- Go 1.21+ installed
- GitHub CLI (`gh`) installed and authenticated
- Write access to the repository
- Git tags permissions

## Release Steps

### 1. Prepare Release

```bash
# Ensure clean working directory
git status

# Update version in relevant files if needed
# Run tests to ensure everything works
make test

# Build and test locally
make build-release VERSION=v1.2.3
```

### 2. Create Release

#### Option A: Automatic Release (Recommended)

```bash
# Create and push a git tag
git tag v1.2.3
git push origin v1.2.3

# GitHub Actions will automatically:
# - Build binaries for all platforms
# - Create GitHub release
# - Upload artifacts
# - Test go install functionality
```

#### Option B: Manual Release

```bash
# Use GitHub CLI to create release
gh release create v1.2.3 \
  --title "Release v1.2.3" \
  --notes "Release notes here" \
  bin/*

# Or trigger workflow manually
gh workflow run release.yml -f version=v1.2.3
```

### 3. Verify Release

```bash
# Test go install with new version
go install github.com/vulnetix/cli@v1.2.3

# Test binary download
curl -fsSL https://raw.githubusercontent.com/vulnetix/cli/main/install.sh | sh -s -- --version=v1.2.3
```

## Supported Platforms

The release process builds binaries for:

- **Linux**: AMD64, ARM64, ARM, 386
- **macOS**: AMD64 (Intel), ARM64 (Apple Silicon)  
- **Windows**: AMD64, ARM64, ARM, 386

## Go Module Compatibility

### Requirements

1. **Module Path**: The module must be accessible at `github.com/vulnetix/cli`
2. **Semantic Versioning**: Tags must follow `vX.Y.Z` format
3. **Go Version**: `go.mod` must specify minimum Go version (1.21+)
4. **Main Package**: Must be in the root directory with `package main`

### go.mod Configuration

Ensure your `go.mod` has:

```go
module github.com/vulnetix/cli

go 1.21

// ... dependencies
```

### Version Management

- Use semantic versioning: `v1.2.3`
- Pre-release versions: `v1.2.3-alpha.1`
- Development versions: Use commit hashes or `@main`

## Troubleshooting

### Go Install Not Working

1. **Check module proxy**: Ensure the module is available on proxy.golang.org
2. **Verify tags**: Make sure git tags are properly pushed
3. **Module cache**: Users may need to clear their module cache

### Binary Not Found

1. **Release artifacts**: Verify all platform binaries are uploaded
2. **File permissions**: Ensure binaries are executable
3. **Download URLs**: Check that URLs in documentation match actual release assets

### Installation Script Issues

1. **Platform detection**: Test on different platforms
2. **Download failures**: Check network connectivity and URLs
3. **Permission errors**: Verify installation directory permissions

## Automation

The release process is automated through GitHub Actions:

- **Triggered by**: Git tags or manual workflow dispatch
- **Builds**: Cross-platform binaries
- **Tests**: Go install functionality
- **Publishes**: GitHub release with artifacts

This ensures consistent releases and enables all installation methods documented in README.md and USAGE.md.
