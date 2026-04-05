---
title: "Scan Command Reference"
weight: 4
description: "Discover manifest files locally, query the VDB for vulnerabilities, and write a CycloneDX SBOM — no file uploads."
---

The `scan` command walks your project directory, parses package manifests locally, and queries the Vulnetix VDB API to identify vulnerable dependencies. **No file contents are ever uploaded to any server.** Results are saved to `.vulnetix/` and printed to your terminal.

> **Credentials are optional.** When no credentials are configured the community fallback is used automatically.

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
| `--exclude` | stringArray | - | Exclude paths matching glob pattern (repeatable) |
| `-f, --format` | string | pretty summary | Output format written to stdout: `cdx17`, `cdx16`, `json`; omit for a human-readable summary |
| `--concurrency` | int | `5` | Max concurrent VDB queries |
| `--no-progress` | bool | `false` | Suppress the progress bar |
| `--paths` | bool | `false` | Show full transitive dependency paths (requires Go toolchain for Go modules) |
| `--no-exploits` | bool | `false` | Suppress the detailed exploit intelligence section |
| `--no-remediation` | bool | `false` | Suppress the detailed remediation section |
| `--severity` | string | - | Exit with code `1` if any vulnerability meets or exceeds this level: `low`, `medium`, `high`, `critical`. Severity is coerced from all available scoring sources (CVSS, EPSS, Coalition ESS, SSVC). |

## Output Files

After every scan the following files are written under your project root:

| Path | Description |
|------|-------------|
| `.vulnetix/sbom.cdx.json` | CycloneDX 1.7 SBOM for all scanned packages |
| `.vulnetix/memory.yaml` | Scan state record (timestamp, counts, git context) |

## Scan Status

Check the status of a previously submitted (legacy) remote scan.

```bash
vulnetix scan status <scan-id> [flags]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--poll` | bool | `false` | Poll until scan completes |
| `--poll-interval` | int | `5` | Polling interval in seconds |
| `-o, --output` | string | `pretty` | Output format: `json`, `pretty` |

## Package Scope Support

Vulnerabilities and packages are organised by dependency scope where the package manager provides that information:

| Package Manager | Scopes |
|----------------|--------|
| npm | `production`, `development`, `peer`, `optional` |
| Python (Pipfile) | `production`, `development` |
| Python (requirements.txt) | `production` |
| Go | `production` (no scope distinction in go.mod / go.sum) |
| Rust | `production` (no scope distinction in Cargo.lock) |
| Ruby | `production` (group info requires Gemfile) |
| Maven | `production`, `test`, `provided`, `runtime`, `system` |
| Composer | `production`, `development` |
| Yarn / pnpm | `production` (scope requires correlation with package.json) |

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

Currently supported for local scanning:

- `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- `requirements.txt`, `Pipfile.lock`
- `go.sum`, `go.mod`
- `Cargo.lock`
- `Gemfile.lock`
- `pom.xml`
- `composer.lock`

## Auto-Discovery

The scanner walks the directory tree starting from `--path` up to `--depth` levels deep. It automatically skips common non-project directories:

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

### Exclude test fixtures and vendor directories

```bash
vulnetix scan --exclude "test/**" --exclude "vendor/**"
```

### Emit CycloneDX 1.7 JSON to stdout

```bash
vulnetix scan -f cdx17
```

### Emit CycloneDX 1.6 JSON to stdout

```bash
vulnetix scan -f cdx16
```

### Raw JSON findings for scripting

```bash
vulnetix scan -f json | jq '.[].vulnerabilities'
```

### Suppress progress bar (useful in CI without a TTY)

```bash
vulnetix scan --no-progress
```

### Break the build on high or critical vulnerabilities

```bash
# Exit 1 if any high or critical vulnerability is found
vulnetix scan --severity high

# Exit 1 on any scored severity and emit a CycloneDX BOM
vulnetix scan --severity low -f cdx17
```

### Suppress extra sections

```bash
# Skip exploit intelligence and remediation details
vulnetix scan --no-exploits --no-remediation
```

### Check scan status (legacy remote scan)

```bash
# One-shot check
vulnetix scan status abc123def

# Poll until complete
vulnetix scan status abc123def --poll --poll-interval 10
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully (no threshold breach) |
| `1` | `--severity` threshold was breached, or a fatal error occurred |
