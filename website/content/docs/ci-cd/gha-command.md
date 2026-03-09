---
title: "GHA Command"
weight: 5
description: "GitHub Actions artifact upload command reference for Vulnetix CLI."
---

The `gha` subcommand provides seamless integration with GitHub Actions workflows for uploading artifacts to Vulnetix. It automatically collects all workflow artifacts, gathers GitHub Actions metadata, and uploads them to the Vulnetix platform for vulnerability analysis.

## Features

- **Automatic Artifact Collection**: Discovers and collects all artifacts from the current GitHub Actions workflow run
- **Metadata Capture**: Automatically captures GitHub Actions environment variables for context
- **Pipeline Tracking**: Reports pipeline UUIDs for each uploaded file
- **Status Tracking**: Check upload status using transaction ID or individual artifact UUID
- **JSON Output**: Optional JSON output for integration with other tools

## Commands

### `vulnetix gha upload`

Upload all artifacts from the current GitHub Actions workflow run to Vulnetix.

#### Usage

```bash
vulnetix gha upload [flags]
```

#### Flags

- `--org-id`: Organization UUID (optional — uses stored credentials if not set)
- `--base-url`: Base URL for Vulnetix API (default: `https://app.vulnetix.com/api`)
- `--json`: Output results as JSON

#### Environment Variables Required

The following GitHub Actions environment variables must be set (automatically available in GitHub Actions):

- `GITHUB_TOKEN`: GitHub token for API access
- `GITHUB_REPOSITORY`: Repository name (e.g., `owner/repo`)
- `GITHUB_RUN_ID`: Workflow run ID
- `GITHUB_API_URL`: GitHub API URL (defaults to `https://api.github.com`)

Additional metadata is collected from these variables if available:
- `GITHUB_REPOSITORY_OWNER`
- `GITHUB_RUN_NUMBER`
- `GITHUB_WORKFLOW`
- `GITHUB_JOB`
- `GITHUB_SHA`
- `GITHUB_REF_NAME`
- `GITHUB_REF_TYPE`
- `GITHUB_EVENT_NAME`
- `GITHUB_ACTOR`
- `GITHUB_SERVER_URL`
- `GITHUB_HEAD_REF`
- `GITHUB_BASE_REF`
- `RUNNER_OS`
- `RUNNER_ARCH`

#### Example

```bash
vulnetix gha upload --org-id 123e4567-e89b-12d3-a456-426614174000
```

#### Output

```
Starting GitHub Actions artifact upload
   Organization: 123e4567-e89b-12d3-a456-426614174000
   Repository: myorg/myrepo
   Run ID: 123456789

Fetching workflow artifacts...
Found 3 artifact(s)
   1. sarif-results (1234 bytes)
   2. sbom-report (5678 bytes)
   3. test-coverage (9012 bytes)

Uploading artifacts...
   [1/3] Processing sarif-results...
      Uploading results.sarif...
      Uploaded results.sarif (pipeline: a1b2c3d4-e5f6-7890-abcd-ef1234567890)
   [2/3] Processing sbom-report...
      Uploading sbom.json...
      Uploaded sbom.json (pipeline: b2c3d4e5-f6a7-8901-bcde-f12345678901)
   [3/3] Processing test-coverage...
      Uploading coverage.xml...
      Uploaded coverage.xml (pipeline: c3d4e5f6-a7b8-9012-cdef-123456789012)

Upload complete: 3/3 files uploaded successfully
```

#### JSON Output (`--json`)

```json
{
  "artifacts": [
    {
      "name": "sarif-results",
      "file": "results.sarif",
      "pipelineId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "status": "uploaded"
    },
    {
      "name": "sbom-report",
      "file": "sbom.json",
      "pipelineId": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
      "status": "uploaded"
    },
    {
      "name": "test-coverage",
      "file": "coverage.xml",
      "pipelineId": "c3d4e5f6-a7b8-9012-cdef-123456789012",
      "status": "uploaded"
    }
  ],
  "total": 3,
  "success": 3
}
```

### `vulnetix gha status`

Check the status of artifact uploads using transaction ID or artifact UUID.

#### Usage

```bash
# Check status by transaction ID
vulnetix gha status --txnid <transaction-id>

# Check status by artifact UUID
vulnetix gha status --uuid <artifact-uuid>
```

#### Flags

- `--org-id`: Organization UUID (optional — uses stored credentials if not set)
- `--txnid`: Transaction ID to check status (mutually exclusive with `--uuid`)
- `--uuid`: Artifact UUID to check status (mutually exclusive with `--txnid`)
- `--base-url`: Base URL for Vulnetix API (default: `https://app.vulnetix.com/api`)
- `--json`: Output results as JSON

#### Examples

**Check transaction status:**
```bash
vulnetix gha status --txnid txn_abc123def456
```

**Check individual artifact status:**
```bash
vulnetix gha status --uuid a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**Get JSON output:**
```bash
vulnetix gha status --txnid txn_abc123def456 --json
```

## GitHub Actions Workflow Integration

### Basic Workflow Example

```yaml
name: Security Assessment
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run SAST Scanner
        run: |
          # Your scanner command that produces SARIF
          scanner --output results.sarif

      - name: Upload SARIF as artifact
        uses: actions/upload-artifact@v4
        with:
          name: sarif-results
          path: results.sarif

  upload-to-vulnetix:
    needs: security-scan
    runs-on: ubuntu-latest
    permissions:
      actions: read  # Required to read artifacts
    steps:
      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: stable

      - name: Checkout Vulnetix CLI
        uses: actions/checkout@v4
        with:
          repository: vulnetix/cli
          path: vulnetix-cli

      - name: Install Vulnetix CLI
        run: |
          cd vulnetix-cli
          go build -o /usr/local/bin/vulnetix .

      - name: Upload Artifacts to Vulnetix
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          vulnetix gha upload --org-id ${{ secrets.VULNETIX_ORG_ID }}
```

### Advanced Workflow with Multiple Scanners

```yaml
name: Comprehensive Security Assessment
on: [push, pull_request]

jobs:
  sast-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run SAST
        run: sast-tool --output sast-results.sarif
      - uses: actions/upload-artifact@v4
        with:
          name: sast-results
          path: sast-results.sarif

  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate SBOM
        run: sbom-tool --output sbom.json
      - uses: actions/upload-artifact@v4
        with:
          name: sbom-report
          path: sbom.json

  container-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan Container
        run: container-scanner --output container-scan.sarif
      - uses: actions/upload-artifact@v4
        with:
          name: container-scan
          path: container-scan.sarif

  upload-to-vulnetix:
    needs: [sast-scan, dependency-scan, container-scan]
    runs-on: ubuntu-latest
    permissions:
      actions: read
    steps:
      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: stable

      - uses: actions/checkout@v4
        with:
          repository: vulnetix/cli
          path: vulnetix-cli

      - name: Install Vulnetix CLI
        run: cd vulnetix-cli && go build -o /usr/local/bin/vulnetix .

      - name: Upload All Artifacts
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          vulnetix gha upload \
            --org-id ${{ secrets.VULNETIX_ORG_ID }} \
            --json > upload-result.json

          # Show summary
          cat upload-result.json | jq '.success'
```

## Troubleshooting

### Error: "GITHUB_TOKEN environment variable is required"

**Solution:** Ensure the `GITHUB_TOKEN` is set in your workflow:
```yaml
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Warning: "Not running in GitHub Actions environment"

This warning appears when running outside GitHub Actions. The command will still attempt to run but may fail if required environment variables are missing.

### Error: "No artifacts found in this workflow run"

**Possible causes:**
1. Artifacts haven't been uploaded yet (ensure `needs:` dependencies are correct)
2. Artifacts were uploaded in a different workflow run
3. Artifacts have expired (GitHub Actions artifacts expire after 90 days by default)

**Solution:** Ensure artifacts are uploaded before the `gha upload` step runs.

### Error: "Failed to list artifacts: GitHub API returned status 403"

**Solution:** Check that the workflow has proper permissions:
```yaml
permissions:
  actions: read  # Required to read workflow artifacts
```

## Best Practices

1. **Use Workflow Dependencies**: Ensure artifact upload jobs depend on scanner jobs using `needs:`
2. **Set Proper Permissions**: Grant `actions: read` permission for artifact access
3. **Store Org ID Securely**: Use GitHub Secrets for the organization ID
4. **Check Upload Status**: Verify successful uploads using the status command
5. **Use JSON Output**: For automation, use `--json` flag to parse results programmatically
