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
| `--no-licenses` | bool | `false` | Skip license analysis during scan (license analysis runs by default) |
| `--severity` | string | - | Exit with code `1` if any vulnerability meets or exceeds this level: `low`, `medium`, `high`, `critical`. Severity is coerced from all available scoring sources (CVSS, EPSS, Coalition ESS, SSVC). |
| `--dry-run` | bool | `false` | Detect files and parse packages locally, check memory, then exit — zero API calls |
| `--from-memory` | bool | `false` | Reconstruct scan pretty output from `.vulnetix/sbom.cdx.json` without API calls |
| `--fresh-exploits` | bool | `false` | With `--from-memory`: fetch latest exploit intel from API |
| `--fresh-advisories` | bool | `false` | With `--from-memory`: fetch latest remediation plans from API |
| `--fresh-vulns` | bool | `false` | With `--from-memory`: re-fetch affected version checks and latest scoring from API |

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
| Maven / Gradle | `production`, `test`, `provided`, `runtime`, `system` |
| Composer | `production`, `development` |
| Yarn / pnpm | `production` (scope requires correlation with package.json) |
| NuGet | `production` |
| Swift | `production` |
| Pub (Dart) | `production`, `development` |
| Hex (Elixir) | `production` |
| sbt (Scala) | `production` |
| CocoaPods | `production` |
| Conan (C/C++) | `production` |
| vcpkg (C/C++) | `production` |

## Supported Manifest Files

The scanner recognizes these package manager manifest and lock files:

### JavaScript / TypeScript

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `package.json` | npm | No |
| `package-lock.json` | npm | Yes |
| `yarn.lock` | npm | Yes |
| `pnpm-lock.yaml` | npm | Yes |

### Python

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `pyproject.toml` | PyPI | No |
| `requirements.txt` | PyPI | No |
| `requirements.in` | PyPI | No |
| `Pipfile` | PyPI | No |
| `Pipfile.lock` | PyPI | Yes |
| `poetry.lock` | PyPI | Yes |
| `uv.lock` | PyPI | Yes |

### Go

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `go.mod` | Go | No |
| `go.sum` | Go | Yes |

### Rust

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `Cargo.toml` | Cargo | No |
| `Cargo.lock` | Cargo | Yes |

### Deno

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `deno.json` | Deno | No |
| `deno.lock` | Deno | Yes |

### Ruby

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `Gemfile` | RubyGems | No |
| `Gemfile.lock` | RubyGems | Yes |

### Java / Kotlin / Scala

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `pom.xml` | Maven | No |
| `build.gradle` | Maven | No |
| `build.gradle.kts` | Maven | No |
| `gradle.lockfile` | Maven | Yes |
| `build.sbt` | Maven | No |
| `build.lock` | Maven | Yes |

### C# / .NET

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `*.csproj` | NuGet | No |
| `packages.lock.json` | NuGet | Yes |
| `paket.dependencies` | NuGet | No |
| `paket.lock` | NuGet | Yes |

### PHP

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `composer.json` | Composer | No |
| `composer.lock` | Composer | Yes |

### Swift / iOS

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `Package.swift` | Swift | No |
| `Package.resolved` | Swift | Yes |
| `Podfile` | CocoaPods | No |
| `Podfile.lock` | CocoaPods | Yes |
| `Cartfile` | Carthage | No |
| `Cartfile.resolved` | Carthage | Yes |

### Dart

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `pubspec.yaml` | Pub | No |
| `pubspec.lock` | Pub | Yes |

### Elixir

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `mix.exs` | Hex | No |
| `mix.lock` | Hex | Yes |

### Erlang

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `rebar.config` | Hex | No |
| `rebar.lock` | Hex | Yes |

### C / C++

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `vcpkg.json` | vcpkg | No |
| `conanfile.txt` | Conan | No |
| `conanfile.py` | Conan | No |
| `conan.lock` | Conan | Yes |
| `CMakeLists.txt` | CPM | No |
| `CPM.cmake` | CPM | No |
| `meson.build` | Meson | No |

`CMakeLists.txt` is only recognized when the file contains `CPMAddPackage`.

### Haskell

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `*.cabal` | Cabal | No |
| `cabal.project.freeze` | Cabal | Yes |
| `stack.yaml` | Stack | No |

### OCaml

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `opam` | opam | No |
| `*.opam` | opam | No |

### Nix

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `flake.nix` | Nix | No |
| `flake.lock` | Nix | Yes |

### Julia

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `Project.toml` | Julia | No |
| `Manifest.toml` | Julia | Yes |

### Crystal

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `shard.yml` | Crystal | No |
| `shard.lock` | Crystal | Yes |

### R

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `DESCRIPTION` | CRAN | No |
| `renv.lock` | CRAN | Yes |

### Zig

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `build.zig.zon` | Zig | No |

### Bazel / Buck

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `MODULE.bazel` | Bazel | No |
| `WORKSPACE` | Bazel | No |
| `WORKSPACE.bazel` | Bazel | No |
| `BUCK` | Buck | No |
| `BUCK2` | Buck | No |

### Containers

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `Dockerfile` | Docker | No |
| `Containerfile` | Docker | No |
| `*.dockerfile` | Docker | No |
| `*.containerfile` | Docker | No |

### Infrastructure as Code

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `*.tf` | Terraform | No |

### CI/CD

| Filename | Ecosystem | Lock file? |
|----------|-----------|------------|
| `.github/workflows/*.yml` | GitHub Actions | No |
| `.github/workflows/*.yaml` | GitHub Actions | No |

### Existing SBOMs

The scanner also detects and ingests existing SBOM documents:

- **SPDX** JSON documents (identified by `spdxVersion` and `SPDXID` fields)
- **CycloneDX** JSON documents (identified by `bomFormat: "CycloneDX"` and `specVersion`)

## License Analysis

By default, `vulnetix scan` also runs license analysis on all discovered packages. License findings appear in the pretty output after the vulnerability summary and are stored in the CycloneDX BOM with source `vulnetix-license-analyzer`.

License resolution uses a multi-source pipeline (manifests, filesystem, container metadata, deps.dev, GitHub). See the [License Command Reference](license/) for full details on resolution sources, evaluation rules, and conflict detection.

To skip license analysis:

```bash
vulnetix scan --no-licenses
```

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

### Skip license analysis

```bash
vulnetix scan --no-licenses
```

### Dry run (detect files, no API calls)

```bash
vulnetix scan --dry-run
```

### Reconstruct results from previous scan

```bash
# From memory — no API calls
vulnetix scan --from-memory

# From memory with fresh exploit intel
vulnetix scan --from-memory --fresh-exploits

# From memory with fresh remediation plans
vulnetix scan --from-memory --fresh-advisories
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
