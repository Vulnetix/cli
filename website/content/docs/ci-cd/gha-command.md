---
title: "GHA Command"
weight: 5
description: "GitHub Actions artifact upload command reference for Vulnetix CLI."
---

The `gha` subcommand provides seamless integration with GitHub Actions workflows for uploading artifacts to Vulnetix. It automatically collects all workflow artifacts, gathers GitHub Actions metadata, and uploads them to the Vulnetix platform for vulnerability analysis.

## Features

- **Automatic Artifact Collection**: Discovers and collects all artifacts from the current GitHub Actions workflow run
- **Metadata Capture**: Automatically captures GitHub Actions environment variables for context
- **Transaction-based Upload**: Creates a transaction for tracking multiple artifact uploads
- **Status Tracking**: Check upload status using transaction ID or individual artifact UUID
- **JSON Output**: Optional JSON output for integration with other tools

## Commands

### `vulnetix gha upload`

Upload all artifacts from the current GitHub Actions workflow run to Vulnetix.

#### Usage

```bash
vulnetix gha upload --org-id <uuid> [flags]
```

#### Flags

- `--org-id` (required): Organization UUID for Vulnetix operations
- `--base-url`: Base URL for Vulnetix API (default: `https://api.vulnetix.com`)
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

Initiating upload transaction...
Transaction initiated
   Transaction ID: txn_abc123def456

Uploading artifacts...
   [1/3] Uploading sarif-results...
      Uploaded successfully
         UUID: art_111222333
         Queue Path: /queue/2024/01/art_111222333
   [2/3] Uploading sbom-report...
      Uploaded successfully
         UUID: art_444555666
         Queue Path: /queue/2024/01/art_444555666
   [3/3] Uploading test-coverage...
      Uploaded successfully
         UUID: art_777888999
         Queue Path: /queue/2024/01/art_777888999

Upload complete!
   Transaction ID: txn_abc123def456
   Uploaded: 3/3 artifacts

Check status with: vulnetix gha status --org-id 123e4567-e89b-12d3-a456-426614174000 --txnid txn_abc123def456
View at: https://dashboard.vulnetix.com/org/123e4567-e89b-12d3-a456-426614174000/artifacts
```

### `vulnetix gha status`

Check the status of artifact uploads using transaction ID or artifact UUID.

#### Usage

```bash
# Check status by transaction ID
vulnetix gha status --org-id <uuid> --txnid <transaction-id>

# Check status by artifact UUID
vulnetix gha status --org-id <uuid> --uuid <artifact-uuid>
```

#### Flags

- `--org-id` (required): Organization UUID for Vulnetix operations
- `--txnid`: Transaction ID to check status (mutually exclusive with `--uuid`)
- `--uuid`: Artifact UUID to check status (mutually exclusive with `--txnid`)
- `--base-url`: Base URL for Vulnetix API (default: `https://api.vulnetix.com`)
- `--json`: Output results as JSON

#### Examples

**Check transaction status:**
```bash
vulnetix gha status --org-id 123e4567-e89b-12d3-a456-426614174000 --txnid txn_abc123def456
```

**Check individual artifact status:**
```bash
vulnetix gha status --org-id 123e4567-e89b-12d3-a456-426614174000 --uuid art_111222333
```

**Get JSON output:**
```bash
vulnetix gha status --org-id 123e4567-e89b-12d3-a456-426614174000 --txnid txn_abc123def456 --json
```

#### Output

```
Checking transaction status: txn_abc123def456

Status: completed
   Transaction ID: txn_abc123def456
   Message: All artifacts processed successfully

Artifacts (3):
   1. sarif-results
      UUID: art_111222333
      Status: processed
      Queue Path: /queue/2024/01/art_111222333
   2. sbom-report
      UUID: art_444555666
      Status: processed
      Queue Path: /queue/2024/01/art_444555666
   3. test-coverage
      UUID: art_777888999
      Status: processing
      Queue Path: /queue/2024/01/art_777888999

View at: https://dashboard.vulnetix.com/org/123e4567-e89b-12d3-a456-426614174000/artifacts
```

## GitHub Actions Workflow Integration

### Basic Workflow Example

```yaml
name: Security Scan
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
      - name: Install Vulnetix CLI
        run: |
          curl -sSL https://install.vulnetix.com/cli | bash

      - name: Upload Artifacts to Vulnetix
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          vulnetix gha upload --org-id ${{ secrets.VULNETIX_ORG_ID }}
```

### Advanced Workflow with Multiple Scanners

```yaml
name: Comprehensive Security Scan
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
      - name: Install Vulnetix CLI
        run: curl -sSL https://install.vulnetix.com/cli | bash

      - name: Upload All Artifacts
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          vulnetix gha upload \
            --org-id ${{ secrets.VULNETIX_ORG_ID }} \
            --json > upload-result.json

          # Extract transaction ID for status checking
          TXNID=$(jq -r '.txnid' upload-result.json)
          echo "Transaction ID: $TXNID"

          # Optionally check status
          vulnetix gha status \
            --org-id ${{ secrets.VULNETIX_ORG_ID }} \
            --txnid $TXNID
```

## API Endpoints

The `gha` command interacts with the following Vulnetix API endpoints:

### 1. Initiate Transaction
**POST** `https://api.vulnetix.com/:org-id/github/artifact-upload`

**Request Body:**
```json
{
  "_meta": {
    "repository": "owner/repo",
    "repository_owner": "owner",
    "run_id": "123456789",
    "run_number": "42",
    "workflow_name": "Security Scan",
    "job": "upload-artifacts",
    "sha": "abc123...",
    "ref_name": "main",
    "ref_type": "branch",
    "event_name": "push",
    "actor": "username",
    "server_url": "https://github.com",
    "api_url": "https://api.github.com",
    "artifacts": ["sarif-results", "sbom-report"],
    "extra_env_vars": {
      "RUNNER_OS": "Linux",
      "RUNNER_ARCH": "X64"
    }
  },
  "artifacts": ["sarif-results", "sbom-report"]
}
```

**Response:**
```json
{
  "txnid": "txn_abc123def456",
  "success": true
}
```

### 2. Upload Artifact
**POST** `https://api.vulnetix.com/:org-id/github/artifact-upload/:txnid`

**Request:** Multipart form data with files

**Response:**
```json
{
  "uuid": "art_111222333",
  "queue_path": "/queue/2024/01/art_111222333",
  "success": true
}
```

### 3. Check Transaction Status
**GET** `https://api.vulnetix.com/:org-id/github/artifact-upload/:txnid/status`

**Response:**
```json
{
  "status": "completed",
  "txnid": "txn_abc123def456",
  "artifacts": [
    {
      "uuid": "art_111222333",
      "name": "sarif-results",
      "status": "processed",
      "queue_path": "/queue/2024/01/art_111222333"
    }
  ]
}
```

### 4. Check Artifact Status
**GET** `https://api.vulnetix.com/:org-id/github/artifact/:uuid/status`

**Response:**
```json
{
  "status": "processed",
  "uuid": "art_111222333",
  "name": "sarif-results",
  "queue_path": "/queue/2024/01/art_111222333"
}
```

## Troubleshooting

### Error: "GITHUB_TOKEN environment variable is required"

**Solution:** Ensure the `GITHUB_TOKEN` is set in your workflow:
```yaml
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Error: "Not running in GitHub Actions environment"

This is a warning that appears when running outside GitHub Actions. The command will still attempt to run but may fail if required environment variables are missing.

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
