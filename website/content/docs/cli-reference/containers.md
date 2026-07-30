---
title: "Containers Command Reference"
weight: 8
description: "Run only container file analysis — checks Dockerfiles and Containerfiles for security misconfigurations."
---

The `containers` command runs a focused scan that evaluates only container-security Rego rules (rules with `kind: oci`) against Dockerfile and Containerfile manifests. It is equivalent to running:

```bash
vulnetix scan --enable-containers --no-sast --no-sca --no-secrets --no-iac --no-licenses
```

Package vulnerability analysis, general SAST rules, license analysis, secret detection, and IaC analysis are all disabled. Only rules that analyse container build files run.

The command also runs a local ELF binary analysis pass and can inspect unpacked container root filesystems or saved image/rootfs tar archives. Rootfs/archive inspection reads installed OS package databases such as `dpkg`, `apk`, and `pacman` and scans discovered ELF binaries without pulling images or requiring a Docker/Podman daemon.

Binaries are also read for the packages compiled into them — Go build info, Rust
`cargo auditable` crate lists and JVM archive coordinates — and, where a package
database is present, each binary is attributed to the package that installed it.
Discovered packages are printed and merged into `.vulnetix/sbom.cdx.json`
(existing components, findings and VEX statements are left in place). Disable this
pass with `--no-binary-package-analysis`; the ELF weakness scan still runs. See
[Binary package discovery](../cdx/#binary-package-discovery) for what each format
yields.

> **Credentials are optional.** When no credentials are configured the community fallback is used automatically.

## Usage

```bash
vulnetix containers [flags]
```

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Directory to scan |
| `--depth` | int | `3` | Maximum recursion depth for file discovery |
| `--exclude` | stringArray | - | Exclude paths matching glob pattern (repeatable) |
| `-o, --output` | stringArray | - | Output target: `json-sarif` for stdout; `.sarif` file path for file output |
| `--no-progress` | bool | `false` | Suppress the progress bar |
| `--severity` | string | - | Exit `1` if any finding meets or exceeds: `low`, `medium`, `high`, `critical` |
| `--results-only` | bool | `false` | Only output when findings exist |
| `--dry-run` | bool | `false` | Report what this command would scan — rule kinds, external rule packs, discovered files — then replay stored results. Zero API calls. |
| `--list-default-rules` | bool | `false` | Print the built-in rule table and exit |
| `--snippet-context` | int | `-1` | Source lines captured around each SARIF finding (`-1` = dynamic, `0` disables) |
| `--containers-include-ignored` | bool | `false` | Include files matched by `.gitignore` (default: gitignored paths are skipped) |
| `--container-rootfs` | stringArray | - | Inspect a container root filesystem directory for installed packages and ELF binaries |
| `--container-archive` | stringArray | - | Inspect a Docker/OCI/rootfs tar archive for installed packages and ELF binaries |
| `--no-binary-package-analysis` | bool | `false` | Skip package discovery from compiled binaries (Go build info, cargo-auditable, JVM archives); the ELF weakness scan still runs |

## Detected File Types

The `containers` command scans files identified as container, Kubernetes and Helm manifests, extracting the referenced images as `pkg:oci/…` components (each annotated with its registry type and a private-registry flag):

| Filename | Language | What is extracted |
|----------|----------|-------------------|
| `Dockerfile` / `Containerfile` / `*.dockerfile` | docker | `FROM` base images + `RUN`-installed OS packages |
| `compose.yaml` / `docker-compose.yml` | docker | service `image:` references |
| `*.yaml` with `apiVersion` + `kind` | kubernetes | pod-template images (Pod / Deployment / StatefulSet / DaemonSet / Job / CronJob, incl. init & ephemeral containers) |
| `Chart.yaml` | helm | chart `dependencies` (`pkg:helm/…`) + sibling `values.yaml` images |

## What Gets Detected

Container security rules check for common Dockerfile misconfigurations:

| Rule ID | Severity | Name |
|---------|----------|------|
| VNX-DOCKER-001 | Medium | Missing USER directive (running as root) |
| VNX-DOCKER-002 | Medium | FROM with `:latest` tag (unpinned base image) |
| VNX-DOCKER-003 | Medium | Missing HEALTHCHECK instruction |
| VNX-DOCKER-004 | Medium | Package manager cache not cleared in same layer |
| VNX-DOCKER-005 | High | Secrets or credentials in ENV instruction |
| VNX-DOCKER-006 | Medium | Privileged port exposure (< 1024) |
| VNX-DOCKER-007 | Medium | ADD instruction used instead of COPY |
| VNX-DOCKER-008 | Medium | Multiple RUN instructions that could be combined |

See the [Docker rules](../sast-rules/#docker) section for full details.

## Examples

```bash
# Container scan of the current directory
vulnetix containers

# Scan a specific directory
vulnetix containers --path /path/to/project

# Break the build on any container finding
vulnetix containers --severity low

# Emit SARIF JSON to stdout
vulnetix containers --output json-sarif

# Write SARIF to a file
vulnetix containers --output containers.sarif

# Silent when no issues found
vulnetix containers --results-only

# Inspect an unpacked container rootfs
vulnetix containers --container-rootfs ./rootfs

# Inspect a saved image tar without using Docker
vulnetix containers --container-archive ./image.tar
```

## Output Files

| Path | Description |
|------|-------------|
| `.vulnetix/sast.sarif` | SARIF 2.1.0 report from container analysis |
| `.vulnetix/memory.yaml` | Scan state record (timestamp, finding counts, git context) |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully (no threshold breach) |
| `1` | A gate was breached (`--severity`), or a fatal error occurred |

## Known false negatives

Detection is deliberately conservative — a missed detection is preferred over a wrong one. Not detected, by design:

- Images mirrored to private or organisation-local registries when matching official-image heuristics (base-image analysis follows the reference as written).
- Build-arg (`$VAR`) and Helm-templated (`{{ ... }}`) image references — placeholders are dropped, never guessed.
- Packages installed by scripts fetched at build time (`curl | sh`) rather than by a recognised package manager invocation.
- A malformed image digest is dropped rather than reported as a version — it never becomes a fabricated value.

Absence of a finding is not verified absence of container risk.

## Related Commands

- [`vulnetix scan`](scan/) — Full scan with all features enabled
- [`vulnetix sca`](sca/) — SCA-only scan
- [`vulnetix sast`](sast/) — General SAST-only scan
- [`vulnetix secrets`](secrets/) — Secret detection only
- [`vulnetix iac`](iac/) — IaC file analysis only
- [Docker Rules Reference](../sast-rules/#docker) — All 8 built-in container rules
