---
title: "Argo Workflows"
weight: 22
description: "Run Vulnetix CLI as Argo Workflow steps for Kubernetes-native vulnerability scanning."
---

Security scanning with Argo Workflows.

{{< callout type="warning" >}}
**Current as of writing** (Vulnetix CLI `v3.59.3`). If a snippet no longer works, [open an issue](https://github.com/Vulnetix/cli/issues/new) with the CLI version you are on.
{{< /callout >}}

## Before You Start

Credentials come from A `Secret` consumed with `secretKeyRef` in the template's container spec.

| Variable | Value |
|----------|-------|
| `VULNETIX_ORG_ID` | Organization UUID |
| `VULNETIX_API_KEY` | ApiKey hex digest |

Environment variables authenticate on their own. Do not run `vulnetix auth login` on an ephemeral runner — see [Authentication in CI/CD](/docs/authentication/ci-cd/).

## Quick Start

`vulnetix-workflow.yaml`:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: vulnetix-scan
spec:
  entrypoint: scan
  templates:
  - name: scan
    container:
      image: golang:1.21
      command: [bash, -c]
      args:
      - |
        go install github.com/vulnetix/cli/v3@latest
        vulnetix auth verify
        vulnetix scan --severity high
      env:
      - name: VULNETIX_ORG_ID
        valueFrom:
          secretKeyRef:
            name: vulnetix-secrets
            key: org-id
```

`vulnetix auth verify` on the first line fails the build immediately when the credential is missing or revoked, rather than halfway through a scan.

{{< callout type="info" >}}
Argo Workflows runs each template in its own Pod. Install the CLI in an init container or bake it into the image you already use.
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

An `outputs.artifacts` entry, pushed to the configured artifact repository.

The SARIF-producing scans write their file **only when there are findings**, so a clean run leaves nothing behind. Tolerate the missing path rather than failing on it.

## Quality Gates

Gates are opt-in; without a gate flag the command reports and exits `0`.

```sh
vulnetix scan --severity high --block-malware --block-eol --exploits active
```

To surface a breach without blocking the merge: `continueOn: { failed: true }` on the step.

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
