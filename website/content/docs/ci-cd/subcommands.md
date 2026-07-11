---
title: "Subcommand Reference for CI"
weight: 5
description: "What each scan subcommand writes, which output flag it takes, and when it exits non-zero. Shared by every CI/CD platform page."
---

Every platform page links here rather than restating this. Read it once.

{{< callout type="warning" >}}
**Current as of writing** (Vulnetix CLI `v3.59.3`). Flags and default output paths change between releases. Check `vulnetix <command> --help`, and [open an issue](https://github.com/Vulnetix/cli/issues/new) if a page here is stale.
{{< /callout >}}

## Installing in CI

One command, on every platform that has a shell:

```sh
curl -fsSL https://cli.vulnetix.com/install.sh | sh
```

It installs to `/usr/local/bin`, falling back to `$HOME/.local/bin` when that is not writable. Pin a release in CI:

```sh
curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --version v3.59.3
```

On minimal images, install the script's dependencies first — `alpine` ships without `curl`, `bash`, `tar`, or CA certificates:

```sh
apk add --no-cache bash ca-certificates curl tar
```

Via Go, note the `/v3` module suffix; the module cannot be fetched without it:

```sh
go install github.com/vulnetix/cli/v3@latest
```

{{< callout type="info" >}}
**There is no published Vulnetix container image.** The repository has a `Dockerfile` for local builds, but nothing is pushed to a registry. Install the CLI into a standard base image, or bake your own image once and reuse it.
{{< /callout >}}

## Authenticating in CI

Set two environment variables from your platform's secret store. That is the whole setup.

| Variable | Value |
|----------|-------|
| `VULNETIX_ORG_ID` | Organization UUID |
| `VULNETIX_API_KEY` | ApiKey hex digest |

Then, as the first step of the job:

```sh
vulnetix auth verify
```

It reads the credential, calls the API, exits non-zero on failure, and **writes nothing**.

Do **not** run `vulnetix auth login` on an ephemeral runner. Environment variables sit at the top of the [credential precedence chain](/docs/authentication/precedence/), persist nothing, and disappear with the job; a login step writes a plaintext credentials file into the workspace for no benefit.

Do **not** store an ApiKey in `VULNETIX_API_TOKEN`. That variable holds a **Bearer token**, outranks everything else, and an ApiKey sent as a bearer credential is rejected. See [Authentication in CI/CD](/docs/authentication/ci-cd/).

## What Each Subcommand Writes

Results land under `.vulnetix/` in the scanned directory whether or not you ask for a copy elsewhere. Each command uploads its own findings to Vulnetix automatically when authenticated.

| Command | Default result file | Format | Exits `1` when |
|---------|--------------------|--------|----------------|
| `vulnetix sca` | `.vulnetix/sbom.cdx.json` | CycloneDX | a gate flag is passed and breached |
| `vulnetix sast` | `.vulnetix/sast.sarif` | SARIF | `--severity` is met or exceeded |
| `vulnetix secrets` | `.vulnetix/sast.sarif` | SARIF | `--severity` is met or exceeded |
| `vulnetix containers` | `.vulnetix/containers.sarif` | SARIF | `--severity` is met or exceeded |
| `vulnetix iac` | `.vulnetix/sast.sarif` | SARIF | `--severity` is met or exceeded |
| `vulnetix license` | `.vulnetix/sbom.cdx.json` | CycloneDX | `--severity` is met or exceeded |
| `vulnetix cbom` | `.vulnetix/cbom.cdx.json` | CycloneDX (CBOM) | `--fail-on` status is found |
| `vulnetix aibom` | `.vulnetix/ai-bom.cdx.json` | CycloneDX (AIBOM) | never |
| `vulnetix malscan` | `.vulnetix/malscan.sarif` | SARIF | any malware finding |
| `vulnetix scan` | `.vulnetix/sbom.cdx.json` + `.vulnetix/sast.sarif` | both | any passed gate is breached |

{{< callout type="info" >}}
The SARIF-producing scans write their file **only when there are findings**. A clean scan deliberately leaves no empty artifact behind, so an artifact-upload step must tolerate a missing file.
{{< /callout >}}

## Choosing the Output Flag

Three different behaviours. Getting this wrong is the most common mistake in a CI config.

| Flag | Commands | Behaviour |
|------|----------|-----------|
| `-o` / `--output` | `scan`, `sca`, `sast`, `secrets`, `containers`, `iac` | Repeatable. Takes a path ending `.cdx.json` or `.sarif`, or the literals `json-cyclonedx` / `json-sarif` for stdout |
| `--output-file` | `cbom`, `aibom`, `malscan` | Single path. On these commands `-o` selects the **terminal** format only (`pretty`, `json`, …) |
| *(neither)* | `license` | Writes `.vulnetix/sbom.cdx.json`. `-o json-spdx` prints SPDX 2.3 to stdout. Copy the file out to publish it |

```sh
# Two artifacts from one pass
vulnetix scan -o dist/results.sarif -o dist/sbom.cdx.json

# CBOM and AIBOM take a different flag
vulnetix cbom --output-file dist/cbom.cdx.json

# license takes neither
vulnetix license && cp .vulnetix/sbom.cdx.json dist/licenses.cdx.json
```

`--format` / `-f` on the scan family is **deprecated**; use `--output`.

## Quality Gates

Gates are opt-in. Without a gate flag the command reports findings and exits `0`.

| Flag | Fails the build when |
|------|----------------------|
| `--severity low\|medium\|high\|critical` | any finding meets or exceeds the threshold |
| `--block-malware` | a dependency is a known malicious package, or malscan finds malware in the installed bytes |
| `--block-eol` | a runtime or package dependency is end-of-life |
| `--block-unpinned` | a direct dependency uses a version range instead of an exact pin |
| `--exploits poc\|active\|weaponized` | exploit maturity reaches the threshold |
| `--version-lag N` | a dependency is within the N most recently published versions |
| `--cooldown N` | a dependency version was published within the last N days |

```sh
vulnetix scan --severity high --block-malware --block-eol --exploits active
```

Most CI systems have a way to report a breach without blocking the merge — GitLab's `allow_failure: true`, Jenkins' `catchError`, GitHub's `continue-on-error`. Prefer that to lowering the gate.

## Uploading Third-Party Artifacts

The scan subcommands upload themselves. `upload` exists for reports produced by *other* tools.

```sh
vulnetix upload --file reports/semgrep.sarif --format sarif
vulnetix upload --file reports/syft.spdx.json --format spdx
```

| Flag | Purpose |
|------|---------|
| `--file` | Path to one artifact. Optional — without it, `.vulnetix/` is auto-discovered |
| `--dir` | Directory to scan for artifacts |
| `--format` | Override auto-detection: `cyclonedx`, `spdx`, `sarif`, `openvex`, `csaf_vex` |
| `--org-id` | Organization UUID, when not using stored or environment credentials |
| `--json` | Machine-readable result, for parsing a pipeline ID out of the output |

A format the CLI does not recognise cannot be uploaded. `govulncheck -json` output, for instance, is not one of the five — emit SARIF instead (`govulncheck -format sarif`).

## Pipeline Context Is Automatic

The CLI detects GitHub Actions and GitLab CI from their environment variables and attributes findings to the right repository, commit, branch, and merge/pull request without any flags. On other platforms it falls back to reading the local git checkout.

You never pass `--org-id` on a machine where the environment credentials are set.
