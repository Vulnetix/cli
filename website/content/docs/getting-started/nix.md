---
title: "Nix"
weight: 2
description: "Install the Vulnetix CLI with Nix flakes on Linux and macOS."
---

Install Vulnetix CLI using the Nix flake included in the repository. Works on Linux and macOS with Nix flakes enabled.

## Prerequisites

Nix must be installed with flakes enabled. If you don't have Nix yet:

```bash
# Install Nix
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh

# Or enable flakes on existing Nix install
# Add to ~/.config/nix/nix.conf:
# experimental-features = nix-command flakes
```

## Quick Start

```bash
# Run without installing
nix run github:Vulnetix/cli

# Install to your profile
nix profile install github:Vulnetix/cli

# Verify installation
vulnetix --version
```

## Install a Specific Version

```bash
# Run a specific release tag
nix run github:Vulnetix/cli/v1.1.1

# Install a specific release
nix profile install github:Vulnetix/cli/v1.1.1
```

## Upgrade

```bash
# Upgrade to latest
nix profile upgrade '.*vulnetix.*'
```

Or use the built-in self-updater (works regardless of install method):

```bash
vulnetix update
```

## Development Shell

The flake includes a development shell with Go tooling:

```bash
# Enter dev shell (from cloned repo)
nix develop github:Vulnetix/cli

# Or from a local checkout
git clone https://github.com/Vulnetix/cli.git
cd cli
nix develop
```

## Uninstall

```bash
# Remove from profile
nix profile remove '.*vulnetix.*'

# Garbage collect unused store paths
nix-collect-garbage
```

## Troubleshooting

### Flakes Not Enabled

If you see `error: experimental Nix feature 'flakes' is disabled`:

```bash
# Add to ~/.config/nix/nix.conf
mkdir -p ~/.config/nix
echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf
```

### Build Fails

Ensure you have a working internet connection for fetching Go dependencies:

```bash
# Try with verbose output
nix build github:Vulnetix/cli --print-build-logs
```

### Hash Mismatch After Update

If the flake vendorHash is outdated after a dependency update, the build will fail with a hash mismatch. This is fixed in the repository when dependencies change.
