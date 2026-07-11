<p align="center">
  <img src="pix.svg" alt="Pix, the Vulnetix AI coding assistant" width="140">
</p>

# Vulnetix CLI & GitHub Action

Automated vulnerability management for your CI/CD pipelines and development workflows.

## Contents

- [GitHub Action](#github-action)
- [Claude Code Plugin](#pix-ai-coding-assistant)
- [CLI Installation](#cli-installation)
- [Available Tasks](#available-tasks)
- [Documentation](#documentation)
- [CLI Documentation](https://docs.cli.vulnetix.com/)
- [Claude Code Plugin Documentation](https://ai-docs.vulnetix.com)
- [VDB API Reference](https://redocly.github.io/redoc/?url=https://api.vdb.vulnetix.com/v1/spec)
- [GitHub App](https://github.com/marketplace/vulnetix)

---

## GitHub Action

This GitHub Action provides the Vulnetix CLI for your workflows, enabling automated vulnerability scanning directly in your CI/CD pipeline.

### Basic Usage

```yaml
- name: Vulnetix Scan
  uses: Vulnetix/cli@v3.59.3
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
    api-key: ${{ secrets.VULNETIX_API_KEY }}
```

### Workflow Examples

#### Scan on Pull Request

```yaml
name: Security Scan
on: [pull_request]
permissions:
  contents: read

jobs:
  vulnetix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-go@v6
        with:
          go-version: stable
      - uses: Vulnetix/cli@v3.59.3
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
          api-key: ${{ secrets.VULNETIX_API_KEY }}
```

#### Upload Artifacts

```yaml
- uses: Vulnetix/cli@v3.59.3
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
    api-key: ${{ secrets.VULNETIX_API_KEY }}
    task: upload
    artifact-path: ./reports/
```

See [GitHub Actions documentation](./docs/github-actions.md) for complete configuration options, and [Artifact Upload guide](./docs/GHA_COMMAND.md) for uploading workflow artifacts to Vulnetix.

### Other CI/CD Platforms

| Platform | Guide |
|----------|-------|
| [GitLab CI](./docs/gitlab-ci.md) | GitLab pipeline integration |
| [Azure DevOps](./docs/azure-devops.md) | Azure pipeline integration |
| [Bitbucket](./docs/bitbucket.md) | Bitbucket pipeline integration |

---

## Claude Code Plugin

Integrate Vulnetix vulnerability intelligence directly into Claude Code with automated pre-commit scanning, six interactive analysis skills, and multi-hook architecture.

### Install

Add the marketplace:

```
/plugin marketplace add Vulnetix/pix-ai-coding-assistant
```

Install the plugin:

```
/plugin install vulnetix@vulnetix-plugins
```

### Upgrade

```
/plugin update vulnetix
```

**Requires:** [Vulnetix CLI](#cli-installation) installed and authenticated (`vulnetix auth login`).

[Full plugin documentation](https://ai-docs.vulnetix.com) | [Plugin repository](https://github.com/Vulnetix/pix-ai-coding-assistant)

---

## CLI Installation

| Method | Platforms | Installation |
|--------|-----------|-------------|
| [Install Script](./docs/curl.md) | Linux, macOS | `curl -fsSL https://cli.vulnetix.com/install.sh \| sh` |
| [Homebrew](./docs/homebrew.md) | Linux, macOS | `brew install vulnetix/tap/vulnetix` |
| [Scoop](./docs/scoop.md) | Windows | `scoop install vulnetix` |
| [Nix](./docs/nix.md) | Linux, macOS | `nix profile install github:Vulnetix/cli` |
| [Go Install](./docs/go-install.md) | All | `go install github.com/vulnetix/cli/v3@latest` |
| [Binary Download](./docs/curl.md) | All | [Direct download](https://github.com/Vulnetix/cli/releases/latest) |
| [From Source](./docs/from-source.md) | All | Build from source |

Architecture support: AMD64, ARM64, ARM, 386.

### Quick Start

```bash
brew install vulnetix/tap/vulnetix
vulnetix auth login
vulnetix vdb status
```

See [CLI Documentation](https://docs.cli.vulnetix.com/) for complete usage and command reference.

---

## Available Tasks

| Task | Description | Use Case |
|------|-------------|----------|
| `info` | Auth healthcheck (default) | Verify credential setup |

---

## Documentation

- [CLI Documentation](https://docs.cli.vulnetix.com/)
- [Claude Code Plugin Documentation](https://ai-docs.vulnetix.com)
- [VDB API Reference](https://redocly.github.io/redoc/?url=https://api.vdb.vulnetix.com/v1/spec)
- [Installation Guides](docs/README.md)
- [Usage Examples](USAGE.md)
- [GitHub Actions Artifact Upload](docs/GHA_COMMAND.md)
- [Distribution](docs/PUBLISHING.md)
- [GitHub App](https://github.com/marketplace/vulnetix)
