# GitHub Actions

This documentation has moved to **[docs.cli.vulnetix.com/docs/ci-cd/github-actions](https://docs.cli.vulnetix.com/docs/ci-cd/github-actions/)**.

## Quick Start

```yaml
name: Vulnetix
on: [push, pull_request]
jobs:
  vulnetix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: stable
      - uses: Vulnetix/cli@v1
        with:
          org-id: ${{ secrets.VULNETIX_ORG_ID }}
```

## Action Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `org-id` | Organization ID (UUID) | Yes | - |
| `task` | Task to perform: `info`, `upload`, `gha` | No | `info` |
| `version` | CLI version to use | No | `latest` |
| `api-key` | Direct API Key for authentication | No | - |
| `upload-file` | Artifact file path (with `task: upload`) | No | - |
| `upload-format` | Override format (`cyclonedx`, `spdx`, `sarif`, `openvex`, `csaf_vex`) | No | - |

## Action Outputs

| Output | Description |
|--------|-------------|
| `result` | Result of the CLI execution |
| `summary` | Summary of vulnerabilities processed |
| `upload-uuid` | Pipeline UUID of uploaded artifact (with `task: upload`) |

See the [full documentation](https://docs.cli.vulnetix.com/docs/ci-cd/github-actions/) for advanced configuration, matrix strategies, and troubleshooting.
