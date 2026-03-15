---
title: "Scan Command Reference"
weight: 4
description: "Auto-discover manifest files and SBOMs, then scan for known vulnerabilities via the VDB API."
---

The `scan` command auto-discovers package manifest files and SBOM documents in a directory tree, then submits them to the Vulnetix VDB API for vulnerability analysis.

> **Note:** The scan command always uses API v2 automatically.

## Usage

```bash
vulnetix scan [flags]
vulnetix scan status <scan-id> [flags]
```

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Directory to scan |
| `--depth` | int | `3` | Maximum recursion depth for file discovery |
| `--file` | string | - | Scan a single file (skips auto-discovery) |
| `--type` | string | auto | Override detected file type: `manifest`, `spdx`, `cyclonedx` |
| `--manifest-type` | string | auto | Override manifest type (e.g. `package-lock.json`) |
| `--ecosystem` | string | auto | Override ecosystem for manifest scan |
| `--exclude` | stringArray | - | Exclude paths matching glob pattern (repeatable) |
| `--no-poll` | bool | `false` | Print scan IDs without waiting for results |
| `--poll-interval` | int | `5` | Polling interval in seconds |
| `-o, --output` | string | `pretty` | Output format: `json`, `pretty` |

## Scan Status

Check the status of a previously submitted scan.

```bash
vulnetix scan status <scan-id> [flags]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--poll` | bool | `false` | Poll until scan completes |
| `--poll-interval` | int | `5` | Polling interval in seconds |
| `-o, --output` | string | `pretty` | Output format: `json`, `pretty` |

## Supported Manifest Files

The scanner recognizes these package manager manifest and lock files:

| Filename | Ecosystem | Language | Lock file? |
|----------|-----------|----------|------------|
| `package-lock.json` | npm | JavaScript | Yes |
| `package.json` | npm | JavaScript | No |
| `yarn.lock` | npm | JavaScript | Yes |
| `pnpm-lock.yaml` | npm | JavaScript | Yes |
| `requirements.txt` | PyPI | Python | No |
| `Pipfile.lock` | PyPI | Python | Yes |
| `poetry.lock` | PyPI | Python | Yes |
| `uv.lock` | PyPI | Python | Yes |
| `go.sum` | Go | Go | Yes |
| `go.mod` | Go | Go | No |
| `Gemfile.lock` | RubyGems | Ruby | Yes |
| `Cargo.lock` | Cargo | Rust | Yes |
| `pom.xml` | Maven | Java | No |
| `gradle.lockfile` | Maven | Java | Yes |
| `composer.lock` | Composer | PHP | Yes |
| `packages.lock.json` | NuGet | C# | Yes |
| `Package.resolved` | Swift | Swift | Yes |
| `pubspec.lock` | Pub | Dart | Yes |
| `mix.lock` | Hex | Elixir | Yes |
| `build.lock` | Maven | Scala | Yes |
| `build.gradle.kts` | Maven | Kotlin | No |

Not all manifest types are supported by the backend for vulnerability scanning yet. Currently supported for scanning:

- `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- `requirements.txt`, `Pipfile.lock`
- `go.sum`, `go.mod`
- `Cargo.lock`
- `Gemfile.lock`
- `pom.xml`
- `composer.lock`

## Supported SBOM Formats

The scanner detects and supports these SBOM document formats:

| Format | Supported Versions |
|--------|-------------------|
| SPDX | 2.3 |
| CycloneDX | 1.4, 1.5, 1.6 |

SBOM detection is performed on `.json` files by checking for format-specific fields (`spdxVersion`/`SPDXID` for SPDX, `bomFormat`/`specVersion` for CycloneDX).

## Auto-Discovery

When run without `--file`, the scanner walks the directory tree starting from `--path` up to `--depth` levels deep. It automatically skips common non-project directories:

- `node_modules`, `.git`, `.hg`
- `__pycache__`, `.tox`, `.venv`
- `vendor`, `.cargo`

Use `--exclude` to skip additional paths by glob pattern.

## Examples

### Auto-discover and scan the current directory

```bash
vulnetix scan
```

### Scan a specific project directory

```bash
vulnetix scan --path /path/to/project --depth 5
```

### Scan a single manifest file

```bash
vulnetix scan --file package-lock.json
```

### Scan a CycloneDX SBOM

```bash
vulnetix scan --file sbom.cdx.json --type cyclonedx
```

### Exclude test fixtures and vendor directories

```bash
vulnetix scan --exclude "test/**" --exclude "vendor/**"
```

### Fire-and-forget mode (no polling)

```bash
vulnetix scan --no-poll
# Returns scan IDs immediately — check later with:
vulnetix scan status <scan-id> --poll
```

### JSON output for scripting

```bash
vulnetix scan --output json | jq '.results'
```

### Check scan status

```bash
# One-shot check
vulnetix scan status abc123def

# Poll until complete
vulnetix scan status abc123def --poll --poll-interval 10
```
