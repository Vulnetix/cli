---
title: "Scoop (Windows)"
weight: 2
description: "Install the Vulnetix CLI with Scoop on Windows."
---

Install Vulnetix CLI using the official Scoop bucket. This is the recommended installation method for Windows.

## Quick Start

```powershell
scoop bucket add vulnetix https://github.com/Vulnetix/scoop-bucket
scoop install vulnetix

# Verify installation
vulnetix --version
```

## Upgrade

```powershell
scoop update vulnetix
```

Or use the built-in self-updater (works regardless of install method):

```powershell
vulnetix update
```

## Architecture Support

Scoop automatically selects the correct binary for your system:

| Architecture | Scoop Key | Binary |
|-------------|-----------|--------|
| x86_64 (AMD64) | `64bit` | `vulnetix-windows-amd64.exe` |
| x86 (386) | `32bit` | `vulnetix-windows-386.exe` |
| ARM64 | `arm64` | `vulnetix-windows-arm64.exe` |

## Uninstall

```powershell
scoop uninstall vulnetix

# Optionally remove the bucket
scoop bucket rm vulnetix
```

## Troubleshooting

### Bucket Not Found

```powershell
# Re-add the bucket
scoop bucket rm vulnetix
scoop bucket add vulnetix https://github.com/Vulnetix/scoop-bucket
```

### Version Not Updated After Release

The Scoop manifest includes `autoupdate` configuration that tracks GitHub releases. If the latest version is not yet available:

```powershell
scoop update
scoop update vulnetix
```

### Scoop Not Installed

Install Scoop first:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression
```
