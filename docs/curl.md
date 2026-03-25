# Binary Download

This documentation has moved to **[docs.cli.vulnetix.com/docs/getting-started/curl](https://docs.cli.vulnetix.com/docs/getting-started/curl/)**.

## Quick Start

```bash
# Linux AMD64
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-linux-amd64 -o vulnetix
chmod +x vulnetix
./vulnetix auth login
```

```bash
# macOS (Apple Silicon)
curl -L https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-darwin-arm64 -o vulnetix
chmod +x vulnetix
./vulnetix auth login
```

```powershell
# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/Vulnetix/cli/releases/latest/download/vulnetix-windows-amd64.exe" -OutFile "vulnetix.exe"
.\vulnetix.exe auth login
```

All binaries are available at [GitHub Releases](https://github.com/Vulnetix/cli/releases/latest).
