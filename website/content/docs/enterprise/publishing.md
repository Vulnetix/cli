---
title: "Publishing & Distribution"
weight: 2
description: "How Vulnetix CLI is published and distributed across platforms."
---

This document outlines how Vulnetix CLI is published and distributed.

## Overview

Vulnetix CLI is distributed through the following channels:

| Distribution Method | Automation | Registry/Repository | Maintenance |
|-------------------|------------|-------------------|-------------|
| **GitHub Releases** | Automated | GitHub Releases | Auto-published on tags |
| **Go Install** | Automated | Go Module Proxy | Uses GitHub releases |
| **Homebrew Tap** | Automated | [Vulnetix/homebrew-tap](https://github.com/Vulnetix/homebrew-tap) | Formula updated on release |
| **Scoop Bucket** | Automated | [Vulnetix/scoop-bucket](https://github.com/Vulnetix/scoop-bucket) | Manifest updated on release |
| **Nix Flake** | Automated | [Vulnetix/cli](https://github.com/Vulnetix/cli) flake.nix | Version updated on release |
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
curl -L https://github.com/vulnetix/cli/releases/latest/download/vulnetix-linux-amd64 -o vulnetix
chmod +x vulnetix

# Go install (uses GitHub releases via Go module proxy)
go install github.com/vulnetix/cli@latest
go install github.com/vulnetix/cli@v1.2.3
```

### 2. Go Install (Module Distribution)

Go install works automatically once a tagged release exists on GitHub. The Go module proxy (`proxy.golang.org`) indexes the module and makes it available for installation.

**No separate publishing process needed** -- tagging a release on GitHub is sufficient.

**Usage by end users:**
```bash
go install github.com/vulnetix/cli@latest
go install github.com/vulnetix/cli@v1.2.3
```

### 3. GitHub Actions (CI/CD Integration)

**Marketplace:** GitHub Actions Marketplace

**Action:** `vulnetix/cli@v1`

**Configuration:** `action.yml` in repository root

**No separate publishing process** -- the action is automatically available when `action.yml` exists in the repository.

**Usage by end users:**
```yaml
- name: Run Vulnetix
  uses: vulnetix/cli@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
```

### 4. Homebrew Tap

**Repository:** [Vulnetix/homebrew-tap](https://github.com/Vulnetix/homebrew-tap)

The Homebrew tap contains formulae for the Vulnetix CLI (`vulnetix`) and the VDB Search TUI (`vvd-search`). Formulae are updated when new releases are tagged.

**Usage by end users:**
```bash
brew tap vulnetix/tap
brew install vulnetix

# VDB vulnerability search TUI
brew install vvd-search
```

### 5. Scoop Bucket (Windows)

**Repository:** [Vulnetix/scoop-bucket](https://github.com/Vulnetix/scoop-bucket)

The Scoop bucket contains a manifest for the Vulnetix CLI with `checkver` and `autoupdate` configuration that tracks GitHub releases automatically.

**Supported architectures:** 64bit (AMD64), 32bit (386), ARM64

**Usage by end users:**
```powershell
scoop bucket add vulnetix https://github.com/Vulnetix/scoop-bucket
scoop install vulnetix
```

### 6. Nix Flake

**Location:** `flake.nix` in the [Vulnetix/cli](https://github.com/Vulnetix/cli) repository

The Nix flake builds from source using `buildGoModule` and supports all default Nix systems (x86_64-linux, aarch64-linux, x86_64-darwin, aarch64-darwin). The version in `flake.nix` is updated when new releases are tagged.

**Usage by end users:**
```bash
# Run without installing
nix run github:Vulnetix/cli

# Install to profile
nix profile install github:Vulnetix/cli
```

## Shared Resources

### GitHub Releases for Multiple Use Cases

The same GitHub releases serve all distribution methods:

- **Go install:** `go install github.com/vulnetix/cli@latest`
- **Direct downloads:** `curl -L https://github.com/.../vulnetix-linux-amd64`
- **Install script:** `curl -fsSL https://raw.githubusercontent.com/vulnetix/cli/main/install.sh | sh`

**No separate publishing needed** -- one release serves multiple distribution methods.

## Release Checklist

When creating a new release:

1. **Tag the release:** `git tag v1.2.3 && git push --tags`
2. **Monitor automation:** Check GitHub Actions workflows
3. **Verify distributions:**
   - [ ] GitHub releases created with binaries
   - [ ] `go install github.com/vulnetix/cli@v1.2.3` works
   - [ ] Install script downloads correct version
   - [ ] Homebrew formula updated in `Vulnetix/homebrew-tap`
   - [ ] Scoop manifest updated in `Vulnetix/scoop-bucket` (hashes from checksums.txt)
   - [ ] `flake.nix` version updated in `Vulnetix/cli`
4. **Test installation methods:**
   - [ ] `brew upgrade vulnetix`
   - [ ] `scoop update vulnetix`
   - [ ] `nix run github:Vulnetix/cli`
   - [ ] `go install github.com/vulnetix/cli@v1.2.3`
   - [ ] `curl -L https://github.com/vulnetix/cli/releases/latest/download/vulnetix-linux-amd64 -o vulnetix`

## Troubleshooting

### Go Install Not Working

1. **Check module proxy**: Ensure the module is available on proxy.golang.org
2. **Verify tags**: Make sure git tags are properly pushed
3. **Module cache**: Users may need to clear their module cache with `go clean -modcache`

### Release Not Available

- Check if release workflow completed successfully
- Verify tag format matches `v*` pattern
- Allow time for Go module proxy to sync (5-15 minutes)

### Binary Not Found

1. **Release artifacts**: Verify all platform binaries are uploaded
2. **File permissions**: Ensure binaries are executable
3. **Download URLs**: Check that URLs in documentation match actual release assets
