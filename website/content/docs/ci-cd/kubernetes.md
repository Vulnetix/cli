---
title: "Kubernetes"
weight: 9
description: "Run Vulnetix CLI as Kubernetes Jobs with secret management, persistent volumes, and cloud-native security scanning workflows."
---

Deploy security scanning as Kubernetes Jobs.

{{< callout type="warning" >}}
**Current as of writing** (Vulnetix CLI `v3.59.4`). If a snippet no longer works, [open an issue](https://github.com/Vulnetix/cli/issues/new) with the CLI version you are on.
{{< /callout >}}

## Before You Start

Credentials come from A `Secret` consumed with `secretKeyRef`, never a mounted file, so the value stays out of the container filesystem.

| Variable | Value |
|----------|-------|
| `VULNETIX_ORG_ID` | Organization UUID |
| `VULNETIX_API_KEY` | ApiKey hex digest |

Environment variables authenticate on their own. Do not run `vulnetix auth login` on an ephemeral runner — see [Authentication in CI/CD](/docs/authentication/ci-cd/).

## Quick Start

`vulnetix-job.yaml`:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: vulnetix-scan
spec:
  template:
    spec:
      restartPolicy: Never
      initContainers:
      # No published Vulnetix image; stage the binary on a shared volume.
      - name: install-vulnetix
        image: alpine:3.20
        command: ["/bin/sh", "-c"]
        args:
          - |
            apk add --no-cache ca-certificates curl tar
            curl -fsSL https://cli.vulnetix.com/install.sh | sh -s -- --install-dir /opt/vulnetix/bin
        volumeMounts:
        - name: cli
          mountPath: /opt/vulnetix/bin
      containers:
      - name: vulnetix
        image: alpine:3.20
        env:
        - name: VULNETIX_ORG_ID
          valueFrom:
            secretKeyRef:
              name: vulnetix-secrets
              key: org-id
        - name: VULNETIX_API_KEY
          valueFrom:
            secretKeyRef:
              name: vulnetix-secrets
              key: api-key
        command: ["/opt/vulnetix/bin/vulnetix"]
        args: ["scan", "--severity", "high"]
        volumeMounts:
        - name: cli
          mountPath: /opt/vulnetix/bin
        - name: workspace
          mountPath: /workspace
      volumes:
      - name: cli
        emptyDir: {}
      - name: workspace
        hostPath:
          path: /path/to/project
```

`vulnetix auth verify` on the first line fails the build immediately when the credential is missing or revoked, rather than halfway through a scan.

{{< callout type="info" >}}
No Vulnetix image exists, so an initContainer stages the binary into an `emptyDir` that the scan container mounts. That also lets the scan container keep `readOnlyRootFilesystem: true`.
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

A `PersistentVolumeClaim`, or ship the SARIF straight to Vulnetix (the scans upload themselves).

The SARIF-producing scans write their file **only when there are findings**, so a clean run leaves nothing behind. Tolerate the missing path rather than failing on it.

## Quality Gates

Gates are opt-in; without a gate flag the command reports and exits `0`.

```sh
vulnetix scan --severity high --block-malware --block-eol --exploits active
```

To surface a breach without blocking the merge: `backoffLimit: 0` and inspect the Job status.

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
