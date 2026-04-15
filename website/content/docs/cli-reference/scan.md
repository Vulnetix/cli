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
| `-o, --output` | stringArray | - | Output target (repeatable): `json-cyclonedx` or `json-sarif` for stdout; file path (`.cdx.json`, `.cdx`, `.bom.json`, `.sbom.json`) for CycloneDX to file; file path (`.sarif`, `.sarif.json`) for SARIF to file. Multiple flags combine file outputs with pretty display. |
| `-f, --format` | string | - | **Deprecated** — maps to `--output json-cyclonedx`. Use `--output` instead. |
| `--concurrency` | int | `5` | Max concurrent VDB queries |
| `--no-progress` | bool | `false` | Suppress the progress bar |
| `--paths` | bool | `false` | Show full transitive dependency paths (npm, Python, Rust, Ruby, PHP, Go). Edges are built from locally installed packages (`node_modules/`, venv, `vendor/`, `cargo metadata`). |
| `--no-exploits` | bool | `false` | Suppress the detailed exploit intelligence section |
| `--no-remediation` | bool | `false` | Suppress the detailed remediation section |
| `--no-licenses` | bool | `false` | Skip license analysis during scan (license analysis runs by default) |
| `--severity` | string | - | Exit with code `1` if any vulnerability meets or exceeds this level: `low`, `medium`, `high`, `critical`. Severity is coerced from all available scoring sources (CVSS, EPSS, Coalition ESS, SSVC). Also gates on SAST findings. |
| `--block-malware` | bool | `false` | Exit with code `1` when any dependency is a known malicious package. |
| `--block-eol` | bool | `false` | Exit with code `1` when a runtime or package dependency is end-of-life. Runtimes: Go, Node.js, Python, Ruby. Package-level checks activate when VDB has EOL data (404s are silently skipped). |
| `--block-unpinned` | bool | `false` | Exit with code `1` when any direct dependency uses a version range (`^`, `~`, `>=`) instead of an exact pin. |
| `--exploits` | string | - | Exit with code `1` when exploit maturity reaches the threshold: `poc` (any public exploit), `active` (CISA/EU KEV / actively exploited), `weaponized` (in-the-wild only). |
| `--results-only` | bool | `false` | Only output when findings exist; completely silent when the scan is clean. Also suppresses exploit and remediation detail sections. |
| `--version-lag` | int | `0` | Exit with code `1` when any dependency is within the N most recently published versions of that package (0 = disabled). |
| `--cooldown` | int | `0` | Exit with code `1` when any dependency version was published within the last N days (0 = disabled, best-effort). |
| `--disable-sast` | bool | `false` | Skip SAST analysis entirely |
| `--disable-default-rules` | bool | `false` | Skip built-in default SAST rules (external `--rule` repos still loaded) |
| `--list-default-rules` | bool | `false` | Print built-in SAST rules and exit |
| `-R, --rule` | stringArray | - | External SAST rule repo in `org/repo` format (repeatable); fetched from GitHub or `--rule-registry` |
| `--rule-registry` | string | `https://github.com` | Override default registry URL for all `--rule` repos |
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
| `.vulnetix/sast.sarif` | SARIF 2.1.0 report from SAST analysis (written unless `--disable-sast` is set) |
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

## SAST (Static Application Security Testing)

By default, `vulnetix scan` also runs SAST analysis alongside SCA. SAST evaluates Rego-based rules against your source files to detect code-level security issues — weak cryptography, hardcoded credentials, missing lock files, insecure deserialization, and more.

SAST findings appear in the pretty output after the SCA summary and are written to `.vulnetix/sast.sarif` in SARIF 2.1.0 format. Each finding includes CWE, CAPEC, and MITRE ATT&CK technique mappings, plus stable fingerprints for tracking results across runs.

### Disabling SAST

```bash
# Skip SAST analysis entirely
vulnetix scan --disable-sast

# Skip built-in rules only (external rule repos still loaded)
vulnetix scan --disable-default-rules --rule myorg/my-rules
```

### Listing Built-in Rules

Print all 27 built-in rules with their IDs, names, severities, and language targets, then exit:

```bash
vulnetix scan --list-default-rules
```

### External Rule Repos

Load additional Rego rules from Git repositories. Rules are fetched from GitHub by default or from a custom registry.

```bash
# Load rules from a GitHub repo
vulnetix scan --rule myorg/custom-rules

# Load multiple external rule repos
vulnetix scan --rule myorg/rules-a --rule myorg/rules-b

# Use a custom registry (e.g. GitLab or self-hosted Gitea)
vulnetix scan --rule myorg/rules --rule-registry https://gitlab.example.com
```

### SAST Severity Gating

SAST findings participate in `--severity` gating alongside SCA vulnerabilities. When any SAST finding meets or exceeds the threshold, the scan exits with code `1`:

```bash
# Exit 1 on high or critical SAST findings (or SCA vulnerabilities)
vulnetix scan --severity high
```

### Built-in Rules

27 rules ship with the CLI. Run `vulnetix scan --list-default-rules` for full descriptions and CWE/CAPEC/ATT&CK mappings.

#### Cryptography

| Rule ID | Severity | Name | Languages |
|---------|----------|------|-----------|
| `VNX-CRYPTO-001` | medium | MD5 usage detected | Python, Node, Go, Java, Ruby, PHP |
| `VNX-CRYPTO-002` | medium | SHA-1 usage detected | Python, Node, Go, Java, Ruby, PHP |

#### Container Security

| Rule ID | Severity | Name | Applies to |
|---------|----------|------|------------|
| `VNX-DOCKER-001` | medium | Dockerfile missing USER directive | Dockerfile, Containerfile |
| `VNX-DOCKER-002` | medium | Dockerfile FROM :latest tag | Dockerfile, Containerfile |

#### Go

| Rule ID | Severity | Name |
|---------|----------|------|
| `VNX-GO-001` | high | Missing go.sum |
| `VNX-GO-002` | high | Command injection via exec.Command |

#### Java

| Rule ID | Severity | Name |
|---------|----------|------|
| `VNX-JAVA-001` | high | Command injection via Runtime.exec() |
| `VNX-JAVA-002` | medium | Spring actuator endpoints exposed |

#### Node.js

| Rule ID | Severity | Name |
|---------|----------|------|
| `VNX-NODE-001` | high | Missing npm lock file |
| `VNX-NODE-002` | high | eval() or new Function() in JavaScript |
| `VNX-NODE-003` | high | Command injection via child_process |
| `VNX-NODE-004` | medium | Express app without helmet |
| `VNX-NODE-005` | medium | innerHTML or dangerouslySetInnerHTML usage |

#### PHP

| Rule ID | Severity | Name |
|---------|----------|------|
| `VNX-PHP-001` | high | Missing composer.lock |
| `VNX-PHP-002` | high | Dangerous function in PHP |

#### Python

| Rule ID | Severity | Name |
|---------|----------|------|
| `VNX-PY-001` | high | Missing Python lock file |
| `VNX-PY-002` | high | eval()/exec() usage in Python |
| `VNX-PY-003` | high | Insecure deserialization with pickle |
| `VNX-PY-004` | high | yaml.load() without SafeLoader |
| `VNX-PY-005` | medium | Weak PRNG for security operations |
| `VNX-PY-006` | medium | Django DEBUG=True |

#### Ruby

| Rule ID | Severity | Name |
|---------|----------|------|
| `VNX-RUBY-001` | high | Missing Gemfile.lock |
| `VNX-RUBY-002` | high | eval() or system() in Ruby |

#### Rust

| Rule ID | Severity | Name |
|---------|----------|------|
| `VNX-RUST-001` | high | Missing Cargo.lock |

#### Secrets & Credentials

| Rule ID | Severity | Name |
|---------|----------|------|
| `VNX-SEC-001` | critical | AWS access key ID |
| `VNX-SEC-002` | critical | Private key committed |
| `VNX-SEC-004` | critical | GitHub or GitLab token |

### SARIF Output

SAST results are always written to `.vulnetix/sast.sarif`. To write a combined SARIF report (SCA + SAST) to a custom path, use `--output`:

```bash
# Write combined SARIF to a file; pretty summary still goes to stdout
vulnetix scan --output results.sarif

# Write both CycloneDX and SARIF files alongside pretty output
vulnetix scan --output sbom.cdx.json --output results.sarif
```

The auto-written `.vulnetix/sast.sarif` contains SAST-only findings. The `--output *.sarif` file contains all scan findings (SCA + SAST) in SARIF format.

## Auto-Discovery

The scanner walks the directory tree starting from `--path` up to `--depth` levels deep. It automatically skips common non-project directories:

- `node_modules`, `.git`, `.hg`
- `__pycache__`, `.tox`, `.venv`
- `vendor`, `.cargo`

Use `--exclude` to skip additional paths by glob pattern.

### Dependency graph from installed packages

After parsing manifests, the scanner also reads locally installed package directories to build a complete transitive dependency graph. This improves SBOM `dependencies` section accuracy and powers `--paths` output — no extra flags required.

| Ecosystem | Install directory |
|-----------|-------------------|
| npm | `node_modules/` (follows symlinks for pnpm) |
| Python | venv `site-packages/*.dist-info/METADATA` |
| Rust | `cargo metadata` subprocess |
| Ruby | `vendor/bundle/` or `GEM_HOME` gemspec files |
| PHP | `vendor/*/composer.json` |
| Go | `go mod graph` subprocess |

If the install directory is not present, the scanner falls back to lock-file edge parsing where available.

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

### Emit CycloneDX JSON to stdout

```bash
vulnetix scan --output json-cyclonedx
```

### Emit SARIF JSON to stdout

```bash
vulnetix scan --output json-sarif
```

### Write CycloneDX to a file (pretty output still goes to stdout)

```bash
vulnetix scan --output /tmp/sbom.cdx.json
```

### Write SARIF to a file (pretty output still goes to stdout)

```bash
vulnetix scan --output /tmp/results.sarif
```

### Write both CycloneDX and SARIF files alongside pretty output

```bash
vulnetix scan --output /tmp/sbom.cdx.json --output /tmp/results.sarif
```

### Raw CycloneDX JSON for scripting

```bash
vulnetix scan -o json-cyclonedx | jq '.components'
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

### Gate on EOL runtimes and packages

```bash
# Exit 1 when a runtime or package dependency is end-of-life
vulnetix scan --block-eol

# Combine with severity gating
vulnetix scan --block-eol --severity high
```

### Gate on version lag (supply chain freshness)

```bash
# Exit 1 if using the very latest published version of any dependency
vulnetix scan --version-lag 1

# Exit 1 if any dependency is within the 3 most recent releases
vulnetix scan --version-lag 3
```

### Gate on recently published dependencies (cooldown period)

```bash
# Exit 1 if any dependency was published in the last 3 days
vulnetix scan --cooldown 3

# Combine multiple supply chain gates
vulnetix scan --block-malware --block-unpinned --version-lag 1 --cooldown 3 --severity high
```

### Suppress output when clean (results-only mode)

```bash
# No output when scan is clean; table appears only when findings exist
vulnetix scan --results-only
```

### SAST — list, disable, and load custom rules

```bash
# List all 27 built-in SAST rules and exit
vulnetix scan --list-default-rules

# Skip SAST analysis entirely
vulnetix scan --disable-sast

# Skip built-in rules but load a custom rule repo from GitHub
vulnetix scan --disable-default-rules --rule myorg/custom-rules

# Load additional rules on top of the built-in set
vulnetix scan --rule myorg/extra-rules

# Use a self-hosted registry for custom rules
vulnetix scan --rule myorg/rules --rule-registry https://git.example.com
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
| `1` | A gate was breached (`--severity`, `--block-eol`, `--block-malware`, `--block-unpinned`, `--exploits`, `--version-lag`, `--cooldown`), or a fatal error occurred |
