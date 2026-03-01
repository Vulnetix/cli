---
title: "Publishing & Distribution"
weight: 2
description: "How Vulnetix CLI is published and distributed across platforms and package managers."
---

This document outlines how Vulnetix CLI is published and distributed across different platforms and package managers.

## Overview

Vulnetix CLI is distributed through multiple channels to support various user preferences and deployment scenarios:

| Distribution Method | Automation | Registry/Repository | Maintenance |
|-------------------|------------|-------------------|-------------|
| **GitHub Releases** | Automated | GitHub Releases | Auto-published on tags |
| **Docker Hub** | Automated | docker.io/vulnetix/vulnetix | Multi-arch images |
| **Go Install** | Automated | GitHub Releases | Uses GitHub releases |
| **Homebrew** | Automated | vulnetix/homebrew-vulnetix | Formula auto-updated |
| **Chocolatey** | Automated | Chocolatey Gallery | Package auto-published |
| **GitHub Actions** | Automated | GitHub Marketplace | Action metadata in repo |

## Publishing Process

### 1. GitHub Releases (Binary Distribution)

**Trigger:** Git tags matching `v*` (e.g., `v1.2.3`)

**Artifacts:**
- Multi-platform binaries (Linux, macOS, Windows)
- Multiple architectures (AMD64, ARM64, ARM, 386)
- Checksums file
- Release notes

**Workflow:** `.github/workflows/release.yml` -> `release` job

**Usage by end users:**
```bash
# Direct download
curl -L https://github.com/vulnetix/vulnetix/releases/latest/download/vulnetix-linux-amd64 -o vulnetix

# Go install (uses GitHub releases)
go install github.com/vulnetix/vulnetix@latest
go install github.com/vulnetix/vulnetix@v1.2.3
```

### 2. Docker Hub (Container Distribution)

**Registry:** `docker.io/vulnetix/vulnetix`

**Images:**
- Latest: `vulnetix/vulnetix:latest`
- Versioned: `vulnetix/vulnetix:v1.2.3`
- Architecture-specific: `vulnetix/vulnetix:latest-amd64`, `vulnetix/vulnetix:latest-arm64`

**Platforms:** `linux/amd64`, `linux/arm64`, `linux/arm/v7`

**Workflow:** `.github/workflows/release.yml` -> `docker` job

**Required Secrets:**
- `DOCKER_USERNAME`: Docker Hub username
- `DOCKER_PASSWORD`: Docker Hub password/token

**Usage by end users:**
```bash
# Pull and run
docker pull vulnetix/vulnetix:latest
docker run --rm vulnetix/vulnetix:latest --help

# Kubernetes (uses same images)
kubectl run vulnetix --image=vulnetix/vulnetix:latest --restart=Never

# Podman (uses same images)
podman run --rm vulnetix/vulnetix:latest --help
```

### 3. Homebrew (macOS/Linux Package Manager)

**Tap Repository:** `vulnetix/homebrew-vulnetix`

**Formula:** `vulnetix.rb`

**Workflow:** `.github/workflows/release.yml` -> `homebrew` job

**Required Secrets:**
- `HOMEBREW_TAP_TOKEN`: GitHub token with write access to tap repository

**Automation:** Formula automatically updated with new release URL and SHA256

**Usage by end users:**
```bash
brew tap vulnetix/vulnetix
brew install vulnetix
```

### 4. Chocolatey (Windows Package Manager)

**Gallery:** [Chocolatey Community Gallery](https://community.chocolatey.org/)

**Package ID:** `vulnetix`

**Workflow:** `.github/workflows/release.yml` -> `chocolatey` job

**Required Secrets:**
- `CHOCOLATEY_API_KEY`: Chocolatey API key for publishing

**Package Contents:**
- Nuspec metadata file
- Install script (downloads from GitHub releases)
- Uninstall script

**Usage by end users:**
```powershell
choco install vulnetix
choco install vulnetix --version 1.2.3
```

### 5. GitHub Actions (CI/CD Integration)

**Marketplace:** GitHub Actions Marketplace

**Action:** `vulnetix/vulnetix@v1`

**Configuration:** `action.yml` in repository root

**No separate publishing process** - action is automatically available when `action.yml` exists

**Usage by end users:**
```yaml
- name: Run Vulnetix
  uses: vulnetix/vulnetix@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
```

## Repository Setup Requirements

### 1. Docker Hub

**Setup:**
1. Create Docker Hub account/organization: `vulnetix`
2. Create repository: `vulnetix/vulnetix`
3. Generate access token
4. Add secrets to GitHub repository:
   - `DOCKER_USERNAME`
   - `DOCKER_PASSWORD`

### 2. Homebrew Tap

**Setup:**
1. Create GitHub repository: `vulnetix/homebrew-vulnetix`
2. Generate GitHub token with `repo` permissions
3. Add secret to main repository:
   - `HOMEBREW_TAP_TOKEN`

**Tap Repository Structure:**
```
vulnetix/homebrew-vulnetix/
├── Formula/
│   └── vulnetix.rb
└── README.md
```

### 3. Chocolatey

**Setup:**
1. Create account on [Chocolatey.org](https://chocolatey.org/)
2. Generate API key
3. Add secret to GitHub repository:
   - `CHOCOLATEY_API_KEY`

## Shared Resources

### Docker Images for Multiple Use Cases

The same Docker images published to Docker Hub are used by:

- **Docker users:** `docker run vulnetix/vulnetix:latest`
- **Kubernetes users:** `image: vulnetix/vulnetix:latest`
- **Podman users:** `podman run vulnetix/vulnetix:latest`
- **CI/CD systems:** All container-based CI systems

**No separate publishing needed** - one Docker registry serves all container use cases.

### GitHub Releases for Multiple Use Cases

The same GitHub releases are used by:

- **Go install:** `go install github.com/vulnetix/vulnetix@latest`
- **Direct downloads:** `curl -L https://github.com/.../vulnetix-linux-amd64`
- **Homebrew:** Formula downloads from releases
- **Chocolatey:** Install script downloads from releases

**No separate publishing needed** - one release serves multiple distribution methods.

## Release Checklist

When creating a new release:

1. **Tag the release:** `git tag v1.2.3 && git push --tags`
2. **Monitor automation:** Check GitHub Actions workflows
3. **Verify distributions:**
   - [ ] GitHub releases created with binaries
   - [ ] Docker images pushed to Docker Hub
   - [ ] Homebrew formula updated
   - [ ] Chocolatey package published
4. **Test installation methods:**
   - [ ] `go install github.com/vulnetix/vulnetix@v1.2.3`
   - [ ] `docker pull vulnetix/vulnetix:v1.2.3`
   - [ ] `brew install vulnetix/vulnetix/vulnetix`
   - [ ] `choco install vulnetix --version 1.2.3`

## Troubleshooting

### Failed Docker Build
- Check multi-architecture support
- Verify Docker Hub credentials
- Review Dockerfile for cross-platform compatibility

### Homebrew Update Failed
- Verify tap repository permissions
- Check formula syntax
- Ensure GitHub token has correct permissions

### Chocolatey Publishing Failed
- Verify API key is valid
- Check package validation errors
- Review nuspec file format

### Release Not Available
- Check if release workflow completed successfully
- Verify tag format matches `v*` pattern
- Allow time for package managers to sync (5-30 minutes)

## Manual Publishing (Emergency)

### Docker
```bash
# Build and push manually
docker buildx build --platform linux/amd64,linux/arm64 \
  -t vulnetix/vulnetix:v1.2.3 \
  -t vulnetix/vulnetix:latest \
  --push .
```

### Homebrew
```bash
# Update formula manually in tap repository
# Edit Formula/vulnetix.rb with new version and SHA256
```

### Chocolatey
```bash
# Create and push package manually
choco pack vulnetix.nuspec
choco push vulnetix.1.2.3.nupkg --api-key YOUR_API_KEY
```
