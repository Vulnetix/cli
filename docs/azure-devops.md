# Azure DevOps

This documentation has moved to **[docs.vulnetix.com/cli/ci-cd/azure-devops](https://docs.vulnetix.com/cli/ci-cd/azure-devops/)**.

## Quick Start

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: GoTool@0
    inputs:
      version: '1.25'
  - script: |
      go install github.com/vulnetix/cli/v3@latest
      vulnetix auth login --api-key "$(VULNETIX_API_KEY)" --org-id "$(VULNETIX_ORG_ID)" --store project
      vulnetix
    env:
      VULNETIX_ORG_ID: $(VULNETIX_ORG_ID)
      VULNETIX_API_KEY: $(VULNETIX_API_KEY)
```

See the [full documentation](https://docs.vulnetix.com/cli/ci-cd/azure-devops/) for pipeline templates and advanced configuration.
