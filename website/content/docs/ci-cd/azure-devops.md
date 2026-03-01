---
title: "Azure DevOps"
weight: 4
description: "Integrate Vulnetix CLI into Azure DevOps Pipelines."
---

Azure DevOps provides comprehensive CI/CD capabilities with Azure Pipelines supporting both YAML and classic release pipelines.

## Quick Start

### Basic YAML Pipeline

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
    - main
    - develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  VULNETIX_ORG_ID: $(vulnetix-org-id)

steps:
- task: Bash@3
  displayName: 'Install Vulnetix'
  inputs:
    targetType: 'inline'
    script: |
      curl -fsSL https://raw.githubusercontent.com/vulnetix/cli/main/install.sh | sh
      export PATH=$PATH:$HOME/.local/bin
      vulnetix --version

- task: Bash@3
  displayName: 'Run Vulnetix'
  inputs:
    targetType: 'inline'
    script: |
      export PATH=$PATH:$HOME/.local/bin
      vulnetix upload --org-id "$VULNETIX_ORG_ID" --file <artifact-path>
  env:
    VULNETIX_ORG_ID: $(VULNETIX_ORG_ID)
```

## Advanced Pipeline Configurations

### Multi-Stage Security Pipeline

```yaml
# azure-pipelines-multistage.yml
trigger:
  branches:
    include:
    - main
    - develop

variables:
  VULNETIX_ORG_ID: $(vulnetix-org-id)

stages:
- stage: SecurityScan
  displayName: 'Security Analysis'
  jobs:
  - job: StaticAnalysis
    displayName: 'Static Security Analysis'
    pool:
      vmImage: 'ubuntu-latest'
    steps:
    - template: templates/install-security-tools.yml

    - task: Bash@3
      displayName: 'SAST Scan'
      inputs:
        targetType: 'inline'
        script: |
          semgrep --config=auto --sarif --output=sast-results.sarif $(Build.SourcesDirectory)

    - task: Bash@3
      displayName: 'Dependency Scan'
      inputs:
        targetType: 'inline'
        script: |
          trivy fs $(Build.SourcesDirectory) --format sarif --output dependency-scan.sarif

    - task: Bash@3
      displayName: 'Secrets Scan'
      inputs:
        targetType: 'inline'
        script: |
          trufflehog filesystem $(Build.SourcesDirectory) --json > secrets-results.json

    - task: PublishBuildArtifacts@1
      displayName: 'Publish Scan Artifacts'
      inputs:
        pathToPublish: '$(Build.SourcesDirectory)'
        artifactName: 'security-scans'
        publishLocation: 'Container'
      condition: always()

  - job: VulnetixAssessment
    displayName: 'Vulnetix Security Assessment'
    dependsOn: StaticAnalysis
    pool:
      vmImage: 'ubuntu-latest'
    steps:
    - task: DownloadBuildArtifacts@0
      displayName: 'Download Security Artifacts'
      inputs:
        buildType: 'current'
        downloadType: 'single'
        artifactName: 'security-scans'
        downloadPath: '$(Build.SourcesDirectory)'

    - task: Bash@3
      displayName: 'Install Vulnetix'
      inputs:
        targetType: 'inline'
        script: |
          curl -fsSL https://raw.githubusercontent.com/vulnetix/cli/main/install.sh | sh
          export PATH=$PATH:$HOME/.local/bin
          vulnetix --version

    - task: Bash@3
      displayName: 'Security Assessment'
      inputs:
        targetType: 'inline'
        script: |
          export PATH=$PATH:$HOME/.local/bin
          vulnetix upload --org-id "$VULNETIX_ORG_ID" --file <artifact-path>
      env:
        VULNETIX_ORG_ID: $(VULNETIX_ORG_ID)

    - task: PublishBuildArtifacts@1
      displayName: 'Publish Assessment Results'
      inputs:
        pathToPublish: '$(Build.SourcesDirectory)'
        artifactName: 'vulnetix-assessment'
        publishLocation: 'Container'

- stage: SecurityGate
  displayName: 'Security Gate'
  dependsOn: SecurityScan
  condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
  jobs:
  - deployment: SecurityApproval
    displayName: 'Security Gate Approval'
    environment: 'security-approval'
    strategy:
      runOnce:
        deploy:
          steps:
          - task: DownloadBuildArtifacts@0
            displayName: 'Download Assessment'
            inputs:
              buildType: 'current'
              downloadType: 'single'
              artifactName: 'vulnetix-assessment'
              downloadPath: '$(Pipeline.Workspace)'

          - task: Bash@3
            displayName: 'Validate Security Gate'
            inputs:
              targetType: 'inline'
              script: |
                # Security gate validation based on Vulnetix assessment
                echo "Security assessment validation completed"
                # Custom validation logic can be added here
                echo "Security gate validation passed"
```

### Template for Reusable Components

```yaml
# templates/install-security-tools.yml
steps:
- task: Bash@3
  displayName: 'Install Security Tools'
  inputs:
    targetType: 'inline'
    script: |
      # Install Vulnetix
      curl -fsSL https://raw.githubusercontent.com/vulnetix/cli/main/install.sh | sh
      export PATH=$PATH:$HOME/.local/bin

      # Install Semgrep
      pip install semgrep

      # Install Trivy
      curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

      # Install TruffleHog
      curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

      # Verify installations
      vulnetix --version
      semgrep --version
      trivy --version
      trufflehog --version
```

```yaml
# templates/vulnetix.yml
steps:
- task: Bash@3
  displayName: 'Vulnetix'
  inputs:
    targetType: 'inline'
    script: |
      export PATH=$PATH:$HOME/.local/bin
      vulnetix upload --org-id "$VULNETIX_ORG_ID" --file <artifact-path>
  env:
    VULNETIX_ORG_ID: $(VULNETIX_ORG_ID)
```

## Variable Groups and Secrets

### Variable Group Configuration

```yaml
# In Azure DevOps Library, create a variable group named "vulnetix-config"
variables:
- group: vulnetix-config

# The variable group should contain:
# - vulnetix-org-id: Your organization ID
# - vulnetix-api-endpoint: Custom API endpoint (optional)
```

### Using Azure Key Vault

```yaml
# azure-pipelines-keyvault.yml
variables:
- group: vulnetix-secrets  # Links to Azure Key Vault

steps:
- task: AzureKeyVault@2
  displayName: 'Get secrets from Key Vault'
  inputs:
    azureSubscription: 'Azure-Service-Connection'
    KeyVaultName: 'your-keyvault'
    SecretsFilter: 'vulnetix-org-id,vulnetix-api-token'
    RunAsPreJob: true

- task: Bash@3
  displayName: 'Run Vulnetix with Secrets'
  inputs:
    targetType: 'inline'
    script: |
      export PATH=$PATH:$HOME/.local/bin
      curl -fsSL https://raw.githubusercontent.com/vulnetix/cli/main/install.sh | sh
      vulnetix upload --org-id "$VULNETIX_ORG_ID" --file <artifact-path>
  env:
    VULNETIX_ORG_ID: $(vulnetix-org-id)
```

## Environment-Specific Configurations

### Development Environment

```yaml
# azure-pipelines-dev.yml
trigger:
  branches:
    include:
    - develop
    - feature/*

variables:
  VULNETIX_ENVIRONMENT: 'development'
  VULNETIX_SEVERITY_THRESHOLD: 'medium'

steps:
- template: templates/install-security-tools.yml

- task: Bash@3
  displayName: 'Development Security Assessment'
  inputs:
    targetType: 'inline'
    script: |
      export PATH=$PATH:$HOME/.local/bin
      vulnetix upload --org-id "$VULNETIX_ORG_ID" --file <artifact-path>
  env:
    VULNETIX_ORG_ID: $(vulnetix-org-id)
```

### Production Release Pipeline

```yaml
# azure-pipelines-release.yml
trigger:
  branches:
    include:
    - main

variables:
  VULNETIX_ENVIRONMENT: 'production'
  VULNETIX_FAIL_ON_HIGH: 'true'

stages:
- stage: ReleaseSecurityAssessment
  displayName: 'Production Security Assessment'
  jobs:
  - job: ComprehensiveScan
    displayName: 'Comprehensive Security Assessment'
    pool:
      vmImage: 'ubuntu-latest'
    timeoutInMinutes: 60
    steps:
    - template: templates/install-security-tools.yml

    - task: Bash@3
      displayName: 'Multi-Tool Security Assessment'
      inputs:
        targetType: 'inline'
        script: |
          # Create scan results directory
          mkdir -p scan-results

          # SAST Scan
          semgrep --config=auto --sarif --output=scan-results/sast.sarif $(Build.SourcesDirectory)

          # Dependency Scan
          trivy fs $(Build.SourcesDirectory) --format sarif --output scan-results/deps.sarif

          # Container Scan (if Dockerfile exists)
          if [ -f "Dockerfile" ]; then
            trivy config Dockerfile --format sarif --output scan-results/container.sarif
          fi

          # Secrets Scan
          trufflehog filesystem $(Build.SourcesDirectory) --json > scan-results/secrets.json

    - task: Bash@3
      displayName: 'Vulnetix Security Assessment'
      inputs:
        targetType: 'inline'
        script: |
          export PATH=$PATH:$HOME/.local/bin
          vulnetix upload --org-id "$VULNETIX_ORG_ID" --file scan-results/sast.sarif
          vulnetix upload --org-id "$VULNETIX_ORG_ID" --file scan-results/deps.sarif
      env:
        VULNETIX_ORG_ID: $(vulnetix-org-id)

    - task: PublishBuildArtifacts@1
      displayName: 'Publish Security Assessment'
      inputs:
        pathToPublish: '$(Build.SourcesDirectory)'
        artifactName: 'release-assessment'
        publishLocation: 'Container'
      condition: always()
```

## Integration with Azure DevOps Features

### SARIF Upload Integration

```yaml
# Upload SARIF files to Vulnetix
steps:
- task: Bash@3
  displayName: 'Upload SARIF to Vulnetix'
  inputs:
    targetType: 'inline'
    script: |
      export PATH=$PATH:$HOME/.local/bin
      vulnetix upload --file scan-results.sarif --org-id "$VULNETIX_ORG_ID"
  env:
    VULNETIX_ORG_ID: $(vulnetix-org-id)
```

## Multi-Platform Builds

### Cross-Platform Security Assessment

```yaml
# azure-pipelines-multiplatform.yml
strategy:
  matrix:
    Linux:
      vmImage: 'ubuntu-latest'
      platform: 'linux'
    Windows:
      vmImage: 'windows-latest'
      platform: 'windows'
    macOS:
      vmImage: 'macOS-latest'
      platform: 'darwin'

pool:
  vmImage: $(vmImage)

steps:
- task: Bash@3
  displayName: 'Install Vulnetix (Unix)'
  inputs:
    targetType: 'inline'
    script: |
      curl -fsSL https://raw.githubusercontent.com/vulnetix/cli/main/install.sh | sh
      export PATH=$PATH:$HOME/.local/bin
      vulnetix --version
  condition: ne(variables['platform'], 'windows')

- task: PowerShell@2
  displayName: 'Install Vulnetix (Windows)'
  inputs:
    targetType: 'inline'
    script: |
      Invoke-WebRequest -Uri "https://github.com/vulnetix/cli/releases/latest/download/vulnetix-windows-amd64.zip" -OutFile "vulnetix.zip"
      Expand-Archive vulnetix.zip -DestinationPath "C:\Tools\Vulnetix"
      $env:PATH += ";C:\Tools\Vulnetix"
      vulnetix --version
  condition: eq(variables['platform'], 'windows')

- task: Bash@3
  displayName: 'Run Vulnetix (Unix)'
  inputs:
    targetType: 'inline'
    script: |
      export PATH=$PATH:$HOME/.local/bin
      vulnetix upload --org-id "$VULNETIX_ORG_ID" --file <artifact-path>
  condition: ne(variables['platform'], 'windows')

- task: PowerShell@2
  displayName: 'Run Vulnetix (Windows)'
  inputs:
    targetType: 'inline'
    script: |
      $env:PATH += ";C:\Tools\Vulnetix"
      vulnetix upload --org-id "$env:VULNETIX_ORG_ID" --file <artifact-path>
  condition: eq(variables['platform'], 'windows')
```

## Advanced Features

### Conditional Security Assessments

```yaml
# Only run security assessments on specific file changes
trigger:
  branches:
    include:
    - main
  paths:
    include:
    - src/*
    - Dockerfile
    - requirements.txt
    - package.json
    - go.mod

steps:
- task: Bash@3
  displayName: 'Conditional Security Assessment'
  inputs:
    targetType: 'inline'
    script: |
      # Check for security-relevant changes
      CHANGED_FILES=$(git diff --name-only HEAD~1)
      SECURITY_RELEVANT_CHANGES=false

      for file in $CHANGED_FILES; do
        case $file in
          *.go|*.py|*.js|*.ts|*.java|*.c|*.cpp|Dockerfile|requirements.txt|package.json|go.mod)
            SECURITY_RELEVANT_CHANGES=true
            break
            ;;
        esac
      done

      if [ "$SECURITY_RELEVANT_CHANGES" = "true" ]; then
        echo "Security-relevant changes detected, running assessment..."
        export PATH=$PATH:$HOME/.local/bin
        vulnetix upload --org-id "$VULNETIX_ORG_ID" --file <artifact-path>
      else
        echo "No security-relevant changes detected, skipping assessment"
      fi
```

### Parallel Security Tools

```yaml
# Run multiple security tools in parallel
jobs:
- job: ParallelSecurityAssessments
  displayName: 'Parallel Security Analysis'
  strategy:
    parallel: 4
  pool:
    vmImage: 'ubuntu-latest'
  steps:
  - task: Bash@3
    displayName: 'SAST Scan'
    inputs:
      targetType: 'inline'
      script: |
        if [ "$(System.JobPositionInPhase)" = "1" ]; then
          semgrep --config=auto --sarif --output=sast.sarif $(Build.SourcesDirectory)
        fi
    condition: eq(variables['System.JobPositionInPhase'], '1')

  - task: Bash@3
    displayName: 'Dependency Scan'
    inputs:
      targetType: 'inline'
      script: |
        if [ "$(System.JobPositionInPhase)" = "2" ]; then
          trivy fs $(Build.SourcesDirectory) --format sarif --output deps.sarif
        fi
    condition: eq(variables['System.JobPositionInPhase'], '2')

  - task: Bash@3
    displayName: 'Secrets Scan'
    inputs:
      targetType: 'inline'
      script: |
        if [ "$(System.JobPositionInPhase)" = "3" ]; then
          trufflehog filesystem $(Build.SourcesDirectory) --json > secrets.json
        fi
    condition: eq(variables['System.JobPositionInPhase'], '3')

  - task: Bash@3
    displayName: 'Vulnetix Assessment'
    inputs:
      targetType: 'inline'
      script: |
        if [ "$(System.JobPositionInPhase)" = "4" ]; then
          export PATH=$PATH:$HOME/.local/bin
          curl -fsSL https://raw.githubusercontent.com/vulnetix/cli/main/install.sh | sh
          vulnetix upload --org-id "$VULNETIX_ORG_ID" --file <artifact-path>
        fi
    condition: eq(variables['System.JobPositionInPhase'], '4')
```

## Troubleshooting

### Common Issues

#### Permission Errors
```yaml
# Fix common permission issues
steps:
- task: Bash@3
  displayName: 'Fix Permissions'
  inputs:
    targetType: 'inline'
    script: |
      # Ensure user has proper permissions
      sudo chown -R $(whoami) $HOME/.local
      mkdir -p $HOME/.local/bin
      chmod +x $HOME/.local/bin/*
```

#### Path Issues
```yaml
# Ensure tools are in PATH
steps:
- task: Bash@3
  displayName: 'Setup PATH'
  inputs:
    targetType: 'inline'
    script: |
      echo "Current PATH: $PATH"
      export PATH=$HOME/.local/bin:/usr/local/bin:$PATH
      echo "Updated PATH: $PATH"
      which vulnetix || echo "Vulnetix not found in PATH"
```

#### Network Connectivity
```yaml
# Debug network issues
steps:
- task: Bash@3
  displayName: 'Test Connectivity'
  inputs:
    targetType: 'inline'
    script: |
      # Test GitHub connectivity
      curl -I https://github.com/vulnetix/cli/releases/latest

      # Test Vulnetix API connectivity
      curl -I https://app.vulnetix.com/api/check

      # Check proxy settings
      echo "HTTP_PROXY: $HTTP_PROXY"
      echo "HTTPS_PROXY: $HTTPS_PROXY"
```

### Debug Mode

```yaml
# Enable debug logging
variables:
  VULNETIX_DEBUG: 'true'
  SYSTEM_DEBUG: 'true'

steps:
- task: Bash@3
  displayName: 'Debug Security Assessment'
  inputs:
    targetType: 'inline'
    script: |
      export PATH=$PATH:$HOME/.local/bin
      vulnetix upload --org-id "$VULNETIX_ORG_ID" --file <artifact-path>
  env:
    VULNETIX_DEBUG: $(VULNETIX_DEBUG)
```
