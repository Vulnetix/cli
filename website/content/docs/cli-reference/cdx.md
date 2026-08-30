---
title: "CDX Command Reference"
weight: 5
description: "Generate a standalone CycloneDX SBOM from manifests, installed packages, containers, CI/CD files, shell scripts and compiled binaries."
aliases:
  - /docs/cli-reference/sbom/
---

The `cdx` command generates one local CycloneDX JSON document without VDB lookup,
uploads, memory updates, quality gates, image pulls, or a Docker/Podman daemon.

`vulnetix sbom` is an **alias** for `vulnetix cdx`, not the other way round.
CycloneDX is the format this tool produces natively everywhere else — the SBOM in
`.vulnetix/sbom.cdx.json`, VEX attestations, the AIBOM and the CBOM — so "sbom"
resolves to CycloneDX by preference. An SPDX generator will land as its own
command (`vulnetix spdx`) rather than changing what `sbom` means.

It combines:

- Package manifests and lock files
- Installed package directories such as `node_modules`, Python virtualenvs, Go module cache, Composer vendor trees, Ruby gems and NuGet packages
- Dockerfile/containerfile package installs and container image references
- CI/CD pipeline install commands (see [CI/CD coverage](#cicd-coverage))
- Shell-script, Makefile and task-recipe package installs
- Container root filesystem package databases such as `dpkg`, `apk` and `pacman`
- Packages compiled into binaries: Go build info, Rust `cargo auditable` data and JVM archive coordinates (see [Binary package discovery](#binary-package-discovery))
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
| `--no-ci` | bool | `false` | Skip CI/CD pipeline package discovery (including GitHub Actions workflows) |
| `--no-shell` | bool | `false` | Skip shell-script, Makefile and task-recipe package discovery |
| `--no-binary-analysis` | bool | `false` | Skip binary analysis entirely (file components and embedded package metadata) |
| `--no-binary-packages` | bool | `false` | Analyse binaries but omit the packages embedded in them |
| `--no-licenses` | bool | `false` | Skip license detection for discovered packages |
| `--no-aibom` | bool | `false` | Omit AIBOM detection/components |
| `--no-cbom` | bool | `false` | Omit CBOM detection/components |
| `--no-signatures` | bool | `false` | Skip signature, attestation and transparency-log sidecar discovery |
| `--include-home` | bool | `false` | Include user-scoped package caches |
| `--cdx-include-ignored` | bool | `false` | Include files matched by `.gitignore` (`--sbom-include-ignored` is accepted too) |
| `--container-rootfs` | stringArray | - | Container rootfs directory to inspect |
| `--container-archive` | stringArray | - | Docker/OCI/rootfs tar archive to inspect |
| `--aibom-catalog` | string | - | AIBOM catalog to merge over (or replace) the builtin catalog |
| `--cbom-catalog` | string | - | CBOM catalog to merge over (or replace) the builtin catalog |
| `--no-builtin-aibom-catalog` | bool | `false` | Use only `--aibom-catalog` |
| `--no-builtin-cbom-catalog` | bool | `false` | Use only `--cbom-catalog` |
| `--sign` | bool | `false` | Sign the document with this machine's own OIDC identity; writes `.sig`, `.pem` and `.intoto.jsonl` beside it |
| `--project` | string | inferred | What this artefact is / who owns it — see [Deployment context](../scan/#deployment-context) |
| `--cluster` | string | inferred | Where it is deployed |
| `--namespace` | string | inferred | Namespace within the cluster |
| `--environment` | string | inferred | Deployment stage, e.g. `production` |
| `--tag` | stringArray | - | Additional `key=value` deployment label (repeatable) |
| `--bom-manufacturer` | string | repo owner | Organization that created the BOM — see [BOM authoring identity](../scan/#bom-authoring-identity) |
| `--lifecycle` | string | derived | Lifecycle stage(s) the BOM data was captured at, comma-separated |

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

# Manifests and installed packages only — no inference from pipelines or scripts
vulnetix cdx --no-ci --no-shell --no-containerfiles
```

## Recorded Metadata

Every component carries the same metadata `vulnetix sca` records, so an offline
SBOM and a scanned one describe packages identically:

| Field | Where it lands |
|-------|----------------|
| Package identity | `name`, `version`, `purl`, `bom-ref` |
| Ecosystem and scope | `vulnetix:ecosystem`, `vulnetix:scope`, `vulnetix:environment`, CycloneDX `scope` |
| Direct vs transitive | `vulnetix:direct`, plus `urn:project` → direct dependency edges |
| Provenance | `vulnetix:source-file`, `vulnetix:source-type`, `vulnetix:installed-path`, `vulnetix:version-spec` |
| Registry provenance | `vulnetix:oci:registryType`, `vulnetix:oci:private` |
| Integrity | CycloneDX `hashes`, `vulnetix:integrity`, `vulnetix:gosum-h1` |
| Licenses | CycloneDX `licenses` — an SPDX id when recognised, otherwise a free-text name or expression |
| Discovery evidence | `vulnetix:sbom/evidence-count`, `vulnetix:sbom/evidence` (method, confidence, locator) |
| Signatures | `vulnetix:signature/*`, `vulnetix:tlog/*` |
| Dependency graph | CycloneDX `dependencies`, resolved from lockfile and installed-tree edges |
| Repository and host context | `metadata.component` git properties and `metadata.properties` host properties |
| Who made the document | `metadata.manufacturer`, `metadata.tools`, `metadata.lifecycles` — see [BOM authoring identity](../scan/#bom-authoring-identity) |

`source-type` values are `manifest` (declared in a manifest or lockfile),
`installed` (found in an installed package tree), `container-db` (an OS package
database inside a container root filesystem), `command` (inferred from a package
manager install command in a Dockerfile, CI file or script) and `binary`
(recovered from a compiled artefact).

Evidence confidence reflects how the package was found: `high` for a declared or
installed package and for build-tool-recorded binary metadata, `medium` for a
pinned install command or archive manifest attributes, `low` for an unpinned
install command or a version read off a filename. A command-derived component is
an inference — the command may be conditional or never executed — and is graded
accordingly.

### Authoring identity

The document names its producer as `vulnetix-cdx`, at the version that ran, and
records the organization running the scan as `metadata.manufacturer` — omitted
rather than guessed when nothing resolves it.

Because `cdx` reads several kinds of source in one pass, it usually claims
several lifecycle phases at once: `pre-build` for the manifests, `build` for an
installed tree, `post-build` for a container rootfs or compiled artefacts, and
`discovery` for the AIBOM and CBOM passes. Skipping a pass drops its phase, so
`--no-aibom --no-cbom` removes `discovery`. Override the whole set with
`--lifecycle`. The rules are the same for every command that writes a document
and are described once under
[BOM authoring identity](../scan/#bom-authoring-identity).

### Existing findings are preserved

The default output path is the same file `scan` and `sca` use as scan memory. When
that file already carries `vulnerabilities` (including VEX analysis), `cdx`
carries those entries — and any component they reference but this run did not
rediscover, marked `vulnetix:sbom/carried-over` — into the document it writes. An
inventory run never deletes finding history.

## CI/CD Coverage

Pipeline-as-code files are parsed for package-manager install commands, and
GitHub-Actions-family workflows additionally contribute their `uses:` pins as
`github-actions` packages.

| Detected by | Files |
|-------------|-------|
| Exact name | `.gitlab-ci.yml`/`.yaml`, `.travis.yml`/`.yaml`, `azure-pipelines.yml`/`.yaml`, `bitbucket-pipelines.yml`/`.yaml`, `buildspec.yml`/`.yaml` (AWS CodeBuild), `cloudbuild.yml`/`.yaml` (Google Cloud Build), `codefresh.yml`/`.yaml`, `appveyor.yml`/`.yaml`, `semaphore.yml`/`.yaml`, `.semaphore.yml`, `.drone.yml`/`.yaml`, `.woodpecker.yml`/`.yaml`, `.cirrus.yml`/`.yaml`, `.buddy.yml`/`.yaml`, `wercker.yml`/`.yaml`, `shippable.yml`, `bitrise.yml`, `codemagic.yaml`, `codeship-steps.yml`, `screwdriver.yaml`/`.yml`, `zuul.yaml`/`.zuul.yaml`, `.prow.yaml`, `harness.yaml`, `skaffold.yaml`/`.yml`, `garden.yml`, `render.yaml`, `heroku.yml`, `vercel.json`, `netlify.toml`, `cloud-init.yaml`, `user-data.yaml`, `.gitpod.yml`/`.yaml`, `devcontainer.json`/`.devcontainer.json`, `Taskfile.yml`/`.yaml`, `.build.yml`/`.yaml` (SourceHut), `.space.kts` (JetBrains Space), `Jenkinsfile`, `Jenkinsfile.groovy`, `Jenkinsfile.declarative`, `Earthfile` |
| Directory | `.circleci/`, `.buildkite/`, `.semaphore/`, `.teamcity/`, `.woodpecker/`, `.drone/`, `.azure/`, `.azure-pipelines/`, `.pipelines/`, `.ci/`, `ci/`, `.gitlab/ci/`, `.gitlab-ci/`, `.tekton/`, `tekton/`, `.argo/`, `.argo-workflows/`, `.concourse/`, `concourse/`, `.harness/`, `bamboo-specs/`, `.cirrus/`, `.codefresh/`, `.buddy/`, `.zuul.d/`, `.prow/`, `prow/`, `.builds/`, `.dagger/`, `.jenkins/`, `.spinnaker/`, `.screwdriver/`, `.bitbucket/`, `.codeship/`, `.devcontainer/`, `.earthly/`, `.garden/`, `.skaffold/`, `.gocd/`, `.appveyor/`, `.bitrise/`, `.codemagic/`, `.travis/`, `.nomad/`, `.gitpod/` — matching `.yml`, `.yaml`, `.json`, `.kts`, `.groovy` or an extensionless `config` inside them |
| Name suffix | `*-pipeline.yml`/`.yaml`, `*-pipelines.yml`/`.yaml`, `*.gitlab-ci.yml`/`.yaml`, `pipeline.yml`/`.yaml`, `ci.yml`/`.yaml`, `workflow.yml`/`.yaml`, `*-workflow.yml`/`.yaml` |
| Actions family | `.github/workflows/`, `.github/actions/`, `.gitea/workflows/`, `.forgejo/workflows/`, any `action.yml`/`action.yaml` |

Multi-document YAML streams are parsed in full, so a Tekton `Task` or an Argo
`Workflow` that is not the first document in the file is still read. Per-vendor
command keys are recognised — `run`, `script`, `commands`, `cmds`, `steps`,
`entrypoint`, `content`, `args`, `before_install`, `build_script`, `runcmd`,
`installCommand`, `postCreateCommand` and others — because a missed key silently
drops every package the pipeline installs.

A line-oriented shell pass also runs over every pipeline file, not only as a
fallback. Kotlin (TeamCity, JetBrains Space), Groovy (Jenkins shared libraries) and
TOML (`netlify.toml`) files happen to parse as YAML scalars without error, so a
"did it parse as YAML" test would silently skip them; the extra pass also catches
commands sitting under a key no vendor list knows about.

A compose file or Kubernetes manifest that happens to live in a CI directory keeps
its own, more specific classification.

## Shell And Recipe Coverage

| Detected by | Files |
|-------------|-------|
| Extension | `.sh`, `.bash`, `.zsh`, `.ksh`, `.ash`, `.dash`, `.fish`, `.bats`, `.command`, `.mk`, `.ps1`, `.psm1`, `.cmd`, `.bat` |
| Exact name | `Makefile`, `makefile`, `GNUmakefile`, `justfile`/`Justfile`/`.justfile`, `Vagrantfile` |
| Shebang | Any extensionless file starting with a `sh`, `bash` or `zsh` shebang |

Line continuations are joined before parsing, so a multi-line
`apt-get install \` block is read as one command. Linux distro managers (apk, apt,
dpkg, yum/dnf/zypper, rpm, pacman), language managers (npm/yarn/pnpm/bun, pip/uv/
poetry/pipenv, gem, composer, cargo, go, nuget/dotnet, mvn/gradle, conda) and the
Windows managers used in CI (choco, scoop, winget) are all recognised.

## Binary Package Discovery

Compiled artefacts are read for the package metadata their build tool embedded.
Nothing is executed, and no bytes beyond those metadata sections are interpreted.

| Source | What is recovered |
|--------|-------------------|
| Go build info (ELF, PE, Mach-O, XCOFF) | Main module, every linked dependency module with its `go.sum` H1 hash, replacement modules, the toolchain (as `stdlib` in the Go ecosystem — how Go advisories are indexed), and build settings including `vcs.revision` |
| Rust `cargo auditable` (`.dep-v0` ELF section) | Every crate with its version and source, build/dev crates scoped as development, plus the crate-level dependency graph |
| JVM archives (`.jar`, `.war`, `.ear`, `.hpi`, `.jpi`) | Maven coordinates from `META-INF/maven/**/pom.properties`, then `MANIFEST.MF` attributes, then the archive filename; jars nested one level inside a fat/Spring-Boot jar are read too |

In a container root filesystem the file lists of the package databases
(`dpkg`, `apk`, `pacman`) are read as well, so each binary is attributed to the
package that installed it:

- the owning package component becomes the parent of the file component in the dependency graph
- the file component records `vulnetix:binary/owner-package` and `vulnetix:binary/owner-ecosystem`
- a binary that no package claims is flagged `vulnetix:binary/unpackaged` — a file that arrived outside the package manager

RPM databases are Berkeley DB or SQLite files that cannot be read without a native
library, so rpm-based images get package components from the package-database pass
but no per-file attribution; binaries in those images are not flagged unpackaged.

The same discovery runs during `vulnetix containers`, which prints what it found
and merges the packages into `.vulnetix/sbom.cdx.json`; disable it there with
`--no-binary-package-analysis`.

## Signature And Transparency Log Metadata

`cdx` looks for local signature and attestation sidecars next to discovered
manifest, package, and binary files: `.sig`, `.asc`, `.minisig`, `.sigstore`,
`.bundle`, `.bundle.json`, `.intoto.jsonl`, `.att`, `.attestation` and
`.attestation.json`.

When a Sigstore-style bundle carries Rekor transparency-log entries, `cdx` adds
the offline inclusion metadata to the component as CycloneDX properties under
`vulnetix:tlog/*`. It does not perform live Rekor lookups.

### Signing the document itself

`--sign` signs the document `cdx` just produced, using the machine's **own**
ambient OIDC identity — a workflow reference in CI, a SPIFFE ID for a workload.
Deliberately not a Vulnetix credential: a scan run in your pipeline is more
usefully attested by you than by the tool vendor, and the result verifies with
stock `cosign verify-blob` against no Vulnetix trust root.

```bash
vulnetix cdx --sign
```

Writes three sidecars beside the document — `.sig`, `.pem` and `.intoto.jsonl` —
plus an embedded JSF signature. On a laptop there is no ambient identity, and
that is not an error: signing is skipped with a reason and the scan completes,
because losing scan results over a missing signature would be the worse outcome.

Verify with [`attest verify`](../attest/):

```bash
vulnetix attest verify .vulnetix/sbom.cdx.json
```

## Reading documents back

`cdx` writes. [`bom`](../bom/) reads — CycloneDX 1.0–1.7, SPDX 2.2/2.3, and
in-toto attestation envelopes, whether this CLI produced them or not.

```bash
vulnetix bom diff before.cdx.json after.cdx.json   # what changed
vulnetix bom tree sbom.cdx.json --invert           # what pulls this in
vulnetix bom skew --from ./sboms/                  # inconsistent versions
```
