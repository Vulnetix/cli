# Vulnetix CLI & GitHub Action

This GitHub Action provides the Vulnetix CLI for your workflows, enabling automated vulnerability management directly in your CI/CD pipeline.

Please also check out our [GitHub App](https://github.com/marketplace/vulnetix) for additional integrations.

## Platform Support

Vulnetix supports all major platforms and installation methods:

| Method | Linux | macOS | Windows | CI/CD | Enterprise | Installation |
|--------|-------|-------|---------|-------|------------|-------------|
| [**Go Install**](./docs/go-install.md) | ✅ | ✅ | ✅ | ✅ | ✅ | `go install github.com/vulnetix/cli@latest` |
| [**Binary Download**](./docs/curl.md) | ✅ | ✅ | ✅ | ✅ | ✅ | Direct download with curl |
| [**From Source**](./docs/from-source.md) | ✅ | ✅ | ✅ | ✅ | ✅ | Full customization |
| [**GitHub Actions**](./docs/github-actions.md) | ✅ | ✅ | ✅ | ✅ | ✅ | Native GitHub integration |
| [**GitLab CI**](./docs/gitlab-ci.md) | ✅ | ✅ | ✅ | ✅ | ✅ | GitLab pipeline integration |
| [**Azure DevOps**](./docs/azure-devops.md) | ✅ | ✅ | ✅ | ✅ | ✅ | Azure pipeline integration |
| [**Bitbucket**](./docs/bitbucket.md) | ✅ | ✅ | ✅ | ✅ | ✅ | Bitbucket pipeline integration |

**Architecture Support:** AMD64, ARM64, ARM, 386 across all platforms

### Quick Start Examples

#### Go Install

```bash
go install github.com/vulnetix/cli@latest
vulnetix
```

#### Local Binary

Download and run the binary directly:

```bash
# Linux AMD64
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64 -o vulnetix
chmod +x vulnetix && ./vulnetix --org-id "your-org-id-here"

# macOS (Intel)
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-darwin-amd64 -o vulnetix
chmod +x vulnetix && ./vulnetix --org-id "your-org-id-here"

# macOS (Apple Silicon)
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-darwin-arm64 -o vulnetix
chmod +x vulnetix && ./vulnetix --org-id "your-org-id-here"

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-windows-amd64.exe" -OutFile "vulnetix.exe"
.\vulnetix.exe --org-id "your-org-id-here"
```

[📖 **View detailed usage examples →**](./USAGE.md)

## Available Tasks

Vulnetix supports multiple task types to cover different aspects of vulnerability management:

| Task | Description | Use Case | Required Flags |
|------|-------------|----------|----------------|
| `info` | Auth healthcheck (default) | Verify credential setup | - |

## Documentation

- **[Installation](docs/README.md)** - Installation guides for all platforms
- **[CLI Reference](docs/CLI-REFERENCE.md)** - Complete command-line documentation
- **[Usage Examples](USAGE.md)** - Comprehensive usage guide
- **[GitHub Actions Artifact Upload](docs/GHA_COMMAND.md)** - Upload workflow artifacts to Vulnetix
- **[Distribution](docs/PUBLISHING.md)** - How we distribute across platforms

## Distribution

Vulnetix CLI is published on each release:

- **GitHub Releases** -- Go Install, Binary Downloads
- **GitHub Marketplace** -- GitHub Actions integration
