---
title: "Semaphore CI"
weight: 27
description: "Integrate Vulnetix CLI into Semaphore CI pipelines for automated vulnerability scanning."
---

Security scanning in Semaphore CI.

{{< callout type="warning" >}}
**Current as of writing** (Vulnetix CLI `v3.59.3`). If a snippet no longer works, [open an issue](https://github.com/Vulnetix/cli/issues/new) with the CLI version you are on.
{{< /callout >}}

## Before You Start

Credentials come from A Semaphore secret, attached to the block.

| Variable | Value |
|----------|-------|
| `VULNETIX_ORG_ID` | Organization UUID |
| `VULNETIX_API_KEY` | ApiKey hex digest |

Environment variables authenticate on their own. Do not run `vulnetix auth login` on an ephemeral runner — see [Authentication in CI/CD](/docs/authentication/ci-cd/).

## Quick Start

`.semaphore/semaphore.yml`:

```yaml
version: v1.0
name: Vulnetix Security
agent:
  machine:
    type: e1-standard-2
    os_image: ubuntu2004
blocks:
  - name: Security Scan
    task:
      secrets:
        - name: vulnetix
      jobs:
        - name: Vulnetix
          commands:
            - curl -fsSL https://cli.vulnetix.com/install.sh | sh
            - export PATH=$PATH:$HOME/.local/bin
            - vulnetix auth verify
            - vulnetix scan --severity high
```

`vulnetix auth verify` on the first line fails the build immediately when the credential is missing or revoked, rather than halfway through a scan.

{{< callout type="info" >}}
Secrets attach at the block level; a job in a different block does not see them.
{{< /callout >}}

## Running Individual Scans

Each subcommand runs standalone and uploads its own findings. Swap `vulnetix scan` for any of them:

```sh
vulnetix sca --severity high -o dist/sbom.cdx.json     # dependencies
vulnetix sast --severity high -o dist/sast.sarif       # source code
vulnetix secrets -o dist/secrets.sarif                 # hardcoded credentials
vulnetix license --allow MIT,Apache-2.0                # SPDX policy
vulnetix cbom --output-file dist/cbom.cdx.json         # cryptography, PQC posture
vulnetix aibom --output-file dist/aibom.cdx.json       # AI agents, SDKs, models
```

Note the flag split: the scan family takes `-o <path>`, while `cbom`, `aibom`, and `malscan` take `--output-file`. `license` takes neither. The full table is in the [Subcommand Reference]({{< relref "subcommands" >}}).

## Keeping the Report

`artifact push workflow dist/`

The SARIF-producing scans write their file **only when there are findings**, so a clean run leaves nothing behind. Tolerate the missing path rather than failing on it.

## Quality Gates

Gates are opt-in; without a gate flag the command reports and exits `0`.

```sh
vulnetix scan --severity high --block-malware --block-eol --exploits active
```

To surface a breach without blocking the merge: `|| true` on the command, or a `fail_fast` policy on the pipeline.

Full gate list in the [Subcommand Reference]({{< relref "subcommands" >}}#quality-gates).

## Uploading Third-Party Artifacts

The scans upload themselves. `upload` is for reports produced by other tools:

```sh
vulnetix upload --file reports/semgrep.sarif --format sarif
```

Accepted formats: `cyclonedx`, `spdx`, `sarif`, `openvex`, `csaf_vex`.

## See Also

- [Subcommand Reference for CI]({{< relref "subcommands" >}}) — what each command writes, which output flag it takes
- [Authentication in CI/CD](/docs/authentication/ci-cd/) — credential choice, masking, rotation
- [Scan Command Reference]({{< relref "scan" >}}) — every flag
