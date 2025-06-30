# Vulnetix GitHub Action

<img align="right" height="300" src="./.repo/Pix-512.png">

<br>

### Automate vulnerability triage which prioritizes remediation over discovery

This GitHub Action provides the Vulnetix CLI for your workflows, enabling automated vulnerability management directly in your CI/CD pipeline.

Please also check out our [GitHub App](https://github.com/marketplace/vulnetix) for additional integrations.

## Quick Start

### Basic Vulnerability Scanning

```yaml
- name: Run Vulnetix scan
  uses: vulnetix/vulnetix@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
```

### Release Readiness Assessment

For assessing release readiness by collecting artifacts from multiple security tools:

```yaml
# In a Pull Request workflow
- name: Vulnetix Release Assessment
  uses: vulnetix/vulnetix@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
    task: release
    tools: |
      - category: "SAST"
        artifact_name: "sarif-results"
        format: "SARIF"
        customer_identifier: "team-backend"
      - category: "SCA" 
        artifact_name: "sbom-report"
        format: "SBOM"
        customer_identifier: "team-backend"
      - category: "SECRETS"
        artifact_name: "secrets-scan"
        format: "SARIF"
        customer_identifier: "team-backend"

# In a workflow outside PR context
- name: Vulnetix Release Assessment
  uses: vulnetix/vulnetix@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
    task: release
    production-branch: "main"
    release-branch: "release/v2.1.0"
    workflow-run-timeout: "45"
```

### Other Available Tasks

```yaml
# Generate vulnerability reports
- name: Generate Reports
  uses: vulnetix/vulnetix@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
    task: report

# Automated vulnerability triage
- name: Auto Triage
  uses: vulnetix/vulnetix@v1
  with:
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
    task: triage
```

[📖 **View detailed usage examples →**](./USAGE.md)

### Required Permissions

When using release mode, ensure your GitHub Action has the following permissions:

```yaml
permissions:
  # Required for accessing workflow run artifacts
  actions: read
  # Required for accessing repository context
  contents: read
  # Required if fetching artifacts from other jobs
  id-token: read
```

## Available Tasks

Vulnetix supports multiple task types to cover different aspects of vulnerability management:

### Task Types

| Task | Description | Use Case |
|------|-------------|----------|
| `scan` | Default vulnerability scanning and analysis | Continuous vulnerability monitoring |
| `release` | Release readiness assessment | Pre-release security validation |
| `report` | Generate comprehensive vulnerability reports | Compliance and stakeholder reporting |
| `triage` | Automated vulnerability triage and prioritization | Streamline manual review processes |

### Task-Specific Configuration

#### Release Task
When using `task: release`, additional configuration options are available:

- **Branch Configuration**: Specify production and release branches
- **Artifact Collection**: Define tools and artifact formats to collect
- **Timeout Management**: Configure wait times for sibling job completion
- **PR Context Detection**: Automatically detect branch context in pull requests

#### Scan Task (Default)
Standard vulnerability scanning with configurable:

- **Tool Integration**: Specify security tools to integrate with
- **Tag-based Organization**: Categorize scans with custom tags
- **Project Metadata**: Include project, product, team, and group information
