# Azure DevOps

This documentation has moved to **[docs.cli.vulnetix.com/docs/ci-cd/azure-devops](https://docs.cli.vulnetix.com/docs/ci-cd/azure-devops/)**.

## Quick Start

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: GoTool@0
    inputs:
      version: '1.21'
  - script: |
      go install github.com/vulnetix/cli@latest
      vulnetix auth login --method apikey --org-id "$(VULNETIX_ORG_ID)" --secret "$(VULNETIX_API_KEY)" --store project
      vulnetix
    env:
      VULNETIX_ORG_ID: $(VULNETIX_ORG_ID)
      VULNETIX_API_KEY: $(VULNETIX_API_KEY)
```

See the [full documentation](https://docs.cli.vulnetix.com/docs/ci-cd/azure-devops/) for pipeline templates and advanced configuration.
