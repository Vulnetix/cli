---
title: "Image Command Reference"
weight: 9
description: "Inventory a container image layer by layer and record it for Container curation, which compares its base image with the equivalent images on other registries."
---

`vulnetix image` reads one container image, inventories its packages layer by
layer, and records it so the **Container curation** page in Resolve can compare
the base image it was built FROM with the equivalent base on other registries
(Chainguard, Docker Hardened Images, Red Hat UBI, distroless and more) and
write a migration guide.

```bash
vulnetix image node:20.11.1-alpine3.19
vulnetix image ghcr.io/acme/api:2026.10.27 --platform linux/arm64
vulnetix image ./api.tar --output api.cdx.json --no-upload
```

## Where the image is read from

| `--source` | Reads |
|---|---|
| `auto` (default) | an archive when the argument is a file; else a local docker or podman image store that holds the reference; else the registry |
| `registry` | the registry, with your own credentials |
| `docker`, `podman` | the local engine, exported with its own `save` command |
| `archive` | a tarball made by `docker save` or `podman save` |

Registry access uses your docker configuration and credential helpers, the
same ones `docker pull` uses (`docker login`, `credHelpers` for ECR, GCR and
others). Your credentials are never sent to Vulnetix; only the inventory is.

For a multi-platform image, `--platform` picks the build (default: this
machine's architecture on linux).

## What it records

- **Identity**: the platform manifest digest, the manifest list digest it was
  reached through, the platform, and the reference.
- **Layer chain**: the image config's `diff_ids`. An image built FROM a base
  starts with the base's layers, which is how the base is recognised.
- **Packages and the layer that installed each**: the OS package databases
  (`dpkg`, `apk`, `rpm`, `pacman`) are read after every layer that wrote one,
  so each OS package carries the layer it first appeared in. That tells the
  base image's packages from the ones the image's own `RUN` lines added.
  Language packages installed in the image (npm, pip, gems, Go modules, NuGet,
  Composer) are inventoried too; skip them with `--no-language-packages`.
- **Traits a base swap keeps or changes**: the distribution release (as the
  purl `distro=` qualifier, e.g. `alpine-3.19`), libc, whether a shell is
  present, the package manager, the default user, and the runtime and its
  version from the image's environment (`NODE_VERSION`, `PYTHON_VERSION` ...).
- **Source**: the repository named by the `org.opencontainers.image.source`
  label, which links the image to its Dockerfile.

The server resolves the base when the image is recorded, and links any cloud
workloads (EKS, ECS, ECR, Lambda, EMR) your cloud scans found running the same
digest.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--source` | `auto` | where to read the image (above) |
| `--platform` | this machine | `os/arch[/variant]` to read from a multi-platform image |
| `--output`, `-o` | | also write the image's CycloneDX SBOM to this file |
| `--max-size-mb` | `8192` | refuse to unpack more than this |
| `--no-upload` | false | inventory locally only; record nothing |
| `--no-language-packages` | false | skip language package inventory |

## Safety

The image is unpacked into a temporary directory as a container runtime would
apply it: whiteouts delete what lower layers wrote, opaque whiteouts empty a
directory. Entries whose path climbs out of the root, hard links pointing out
of it, and writes through a symlink that resolves outside it are refused.
Device nodes are skipped. The directory is removed when the command ends.

## See also

- [`vulnetix containers`](../containers/) records each Dockerfile's FROM lines
  and package install lines, which the migration guide uses to name the line
  to change.
- [`vulnetix cdx`](../cdx/) builds an SBOM of a directory, rootfs or archive.
