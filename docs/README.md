# Vulnetix Documentation

This directory contains comprehensive documentation for Vulnetix CLI installation, usage, and integration.

## 📖 Core Documentation

- [**CLI Reference**](./CLI-REFERENCE.md) - Complete command-line interface documentation
- [**Publishing Guide**](./PUBLISHING.md) - How Vulnetix is distributed across platforms

## 🚀 Installation Methods

### Package Managers
- [**Homebrew**](./homebrew.md) - macOS and Linux package manager
- [**Chocolatey**](./chocolatey.md) - Windows package manager  
- [**Go Install**](./go-install.md) - Direct installation from Go modules

### Container Platforms
- [**Docker**](./docker.md) - Container-based usage (recommended)
- [**Kubernetes**](./kubernetes.md) - Kubernetes deployments (uses Docker images)
- [**Podman**](./podman.md) - Rootless container runtime (uses Docker images)

### Direct Installation
- [**Binary Download**](./curl.md) - Direct download with curl/wget
- [**From Source**](./from-source.md) - Build from source code

## 🔄 CI/CD Integrations

### GitHub Ecosystem
- [**GitHub Actions**](./github-actions.md) - GitHub's native CI/CD

### Popular CI/CD Platforms
- [**GitLab CI**](./gitlab-ci.md) - GitLab's integrated CI/CD
- [**Bitbucket Pipelines**](./bitbucket.md) - Atlassian's CI/CD solution
- [**Azure DevOps**](./azure-devops.md) - Microsoft's DevOps platform

## 🏢 Enterprise & Specialized

### Network & Proxy
- [**Corporate Proxy**](./corporate-proxy.md) - Enterprise proxy configuration

## 🔧 Getting Help

1. **Installation Issues** - Check the specific installation method documentation
2. **CLI Usage** - See [CLI Reference](./CLI-REFERENCE.md)
3. **Publishing/Distribution** - See [Publishing Guide](./PUBLISHING.md)
4. **Enterprise Setup** - See [Corporate Proxy](./corporate-proxy.md)

### Architecture Support
- [**Multi-Architecture**](./multi-arch.md) - ARM64, AMD64, ARM, 386 support

## Enterprise & Advanced Configurations

- [**Corporate Proxy**](./corporate-proxy.md) - Behind corporate firewalls
- [**Air-Gapped Environments**](./air-gapped.md) - Offline/restricted networks
- [**Enterprise Distribution**](./enterprise.md) - Internal package repositories

## Getting Help

If you can't find what you're looking for:

1. Check the [main USAGE.md](../USAGE.md) for general documentation
2. Browse the specific reference for your platform/CI system
3. Open an [issue](https://github.com/vulnetix/vulnetix/issues) with details about your environment
4. Contact support at support@vulnetix.com

## Contributing

Found an issue or have improvements? Please:

1. Fork the repository
2. Update the relevant reference page
3. Test your changes
4. Submit a pull request

Each reference page should be comprehensive yet focused on its specific use case.
