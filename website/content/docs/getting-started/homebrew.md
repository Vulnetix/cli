---
title: "Homebrew"
weight: 1
description: "Install the Vulnetix CLI with Homebrew on macOS and Linux."
---

Install Vulnetix CLI using the official Homebrew tap. This is the recommended installation method for macOS and Linux.

## Quick Start

```bash
brew tap vulnetix/tap
brew install vulnetix

# Verify installation
vulnetix --version
```

Or in a single command:

```bash
brew install vulnetix/tap/vulnetix
```

## Upgrade

```bash
# Update formulae and upgrade
brew update && brew upgrade vulnetix
```

Or use the built-in self-updater (works regardless of install method):

```bash
vulnetix update
```

## Install a Specific Version

```bash
# List available versions
brew search vulnetix

# Pin to current version (prevent auto-upgrade)
brew pin vulnetix

# Unpin when ready to upgrade
brew unpin vulnetix
```

## VDB Search TUI

The Homebrew tap also includes `vvd-search`, a terminal UI for searching the Vulnetix vulnerability database:

```bash
brew install vulnetix/tap/vvd-search
```

## Uninstall

```bash
brew uninstall vulnetix

# Optionally remove the tap
brew untap vulnetix/tap
```

## Troubleshooting

### Tap Not Found

```bash
# Re-add the tap
brew tap vulnetix/tap https://github.com/Vulnetix/homebrew-tap
```

### Formula Outdated After Release

The Homebrew formula is updated shortly after each GitHub release. If the latest version is not yet available:

```bash
brew update
brew upgrade vulnetix
```
