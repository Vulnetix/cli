---
title: "CDX Command Reference"
weight: 5
description: "Generate a standalone CycloneDX SBOM containing package, AIBOM and CBOM inventory."
---

The `cdx` command generates one local CycloneDX JSON document without VDB lookup,
uploads, memory updates, quality gates, image pulls, or a Docker/Podman daemon.

It combines:

- Package manifests and lock files
- Installed package directories such as `node_modules`, Python virtualenvs, Go module cache, Composer vendor trees, Ruby gems and NuGet packages
- Dockerfile/containerfile package installs and container image references
- CI/CD pipeline install commands, including GitHub Actions, GitLab CI, CircleCI, Buildkite, Azure Pipelines, Bitbucket Pipelines, Cloud Build, CodeBuild, Codefresh, Semaphore, Drone/Woodpecker, AppVeyor, Travis CI and Jenkinsfiles
- Shell-script package installs
- Container root filesystem package databases such as `dpkg`, `apk` and `pacman`
- ELF binaries discovered locally or in supplied container rootfs/archive inputs
- AIBOM and CBOM components in the same CycloneDX file
- Checksums, local signature sidecars and offline transparency-log metadata where present

## Usage

```bash
vulnetix cdx [path] [flags]
```

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--path` | string | `.` | Directory to scan; positional `[path]` overrides |
| `--depth` | int | `25` | Maximum recursion depth for file discovery |
| `--exclude` | stringArray | - | Exclude paths matching glob pattern during manifest discovery |
| `--ignore` | stringArray | - | Exclude paths matching glob pattern during local inventory discovery |
| `-o, --output` | string | `pretty` | Terminal output: `pretty`, `json`, `cyclonedx-json` |
| `--output-file` | string | `<path>/.vulnetix/sbom.cdx.json` | CycloneDX output path |
| `--spec-version` | string | `1.7` | CycloneDX spec version: `1.6` or `1.7` |
| `--no-manifests` | bool | `false` | Skip package manifest and lockfile parsing |
| `--no-filesystem` | bool | `false` | Skip installed-package filesystem discovery |
| `--no-containerfiles` | bool | `false` | Skip Dockerfile, compose, Kubernetes and Helm package discovery |
| `--no-ci` | bool | `false` | Skip CI/CD pipeline package discovery |
| `--no-shell` | bool | `false` | Skip shell-script package discovery |
| `--no-binary-analysis` | bool | `false` | Skip ELF binary analysis |
| `--no-aibom` | bool | `false` | Omit AIBOM detection/components |
| `--no-cbom` | bool | `false` | Omit CBOM detection/components |
| `--no-signatures` | bool | `false` | Skip signature, attestation and transparency-log sidecar discovery |
| `--include-home` | bool | `false` | Include user-scoped package caches |
| `--cdx-include-ignored` | bool | `false` | Include files matched by `.gitignore` |
| `--container-rootfs` | stringArray | - | Container rootfs directory to inspect |
| `--container-archive` | stringArray | - | Docker/OCI/rootfs tar archive to inspect |

## Examples

```bash
# Generate .vulnetix/sbom.cdx.json
vulnetix cdx

# Print CycloneDX JSON to stdout and still write the file
vulnetix cdx -o cyclonedx-json

# Inspect an unpacked container filesystem
vulnetix cdx --container-rootfs ./rootfs

# Inspect a saved image tar without using Docker
vulnetix cdx --container-archive ./image.tar --output-file build/image.cdx.json

# Package SBOM only
vulnetix cdx --no-aibom --no-cbom
```

## Signature And Transparency Log Metadata

`cdx` looks for local signature and attestation sidecars next to discovered
manifest, package, and binary files: `.sig`, `.asc`, `.minisig`, `.sigstore`,
`.bundle`, `.bundle.json`, `.intoto.jsonl`, `.att`, `.attestation` and
`.attestation.json`.

When a Sigstore-style bundle carries Rekor transparency-log entries, `cdx` adds
the offline inclusion metadata to the component as CycloneDX properties under
`vulnetix:tlog/*`. It does not perform live Rekor lookups.
