---
title: "Chocolatey"
weight: 4
description: "Install Vulnetix CLI on Windows using the Chocolatey package manager."
---

Chocolatey is a popular package manager for Windows that simplifies software installation and management.

## Quick Start

### Installation

```powershell
# Install Chocolatey (if not already installed)
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install Vulnetix
choco install vulnetix

# Verify installation
vulnetix --version
```

### Basic Usage

```powershell
# Basic vulnerability scan
$env:VULNETIX_ORG_ID = "your-org-id"
vulnetix --task release --project-name "My Project"

# Release security assessment
$env:VULNETIX_ORG_ID = "your-org-id"
vulnetix --task release --project-name "My Project"
```

## Installation Options

### Standard Installation

```powershell
# Install latest stable version
choco install vulnetix

# Install specific version
choco install vulnetix --version 1.2.3

# Install with confirmation prompts disabled
choco install vulnetix -y
```

### Pre-release Versions

```powershell
# Install pre-release version
choco install vulnetix --pre

# Install specific pre-release
choco install vulnetix --version 1.3.0-beta.1 --pre
```

### Custom Installation Directory

```powershell
# Install to custom directory
choco install vulnetix --install-directory="C:\Tools\Vulnetix"

# Install with custom parameters
choco install vulnetix --params "'/InstallDir:C:\MyTools\Vulnetix /AddToPath:true'"
```

## Package Management

### Upgrading

```powershell
# Upgrade to latest version
choco upgrade vulnetix

# Upgrade all packages
choco upgrade all

# Upgrade with confirmation disabled
choco upgrade vulnetix -y
```

### Uninstalling

```powershell
# Uninstall Vulnetix
choco uninstall vulnetix

# Uninstall with cleanup
choco uninstall vulnetix --remove-dependencies
```

### Package Information

```powershell
# Show package information
choco info vulnetix

# List installed packages
choco list --local-only

# Show outdated packages
choco outdated
```

## Configuration

### Chocolatey Configuration

```powershell
# Configure proxy settings
choco config set proxy http://proxy.company.com:8080
choco config set proxyUser domain\username
choco config set proxyPassword encrypted_password

# Configure package source
choco source add -n=private-repo -s="https://chocolatey.company.com/nuget" --priority=1

# Disable default public repository (enterprise environments)
choco source disable -n=chocolatey
```

### Environment Variables

```powershell
# Set Vulnetix environment variables
$env:VULNETIX_ORG_ID = "123e4567-e89b-12d3-a456-426614174000"
$env:VULNETIX_API_TOKEN = "your-api-token"
$env:VULNETIX_CONFIG_PATH = "C:\Config\vulnetix-config.yaml"

# Make permanent (requires elevated prompt)
[Environment]::SetEnvironmentVariable("VULNETIX_ORG_ID", "123e4567-e89b-12d3-a456-426614174000", "Machine")
```

## Enterprise Integration

### Group Policy Installation

Create a PowerShell script for domain deployment:

```powershell
# deploy-vulnetix.ps1 - Group Policy deployment script

# Check if Chocolatey is installed
if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

# Configure enterprise source
choco source add -n=enterprise-repo -s="https://packages.company.com/nuget" --priority=1
choco source disable -n=chocolatey

# Install Vulnetix
choco install vulnetix -y --source=enterprise-repo

# Configure enterprise defaults
$configPath = "C:\ProgramData\Vulnetix\config.yaml"
New-Item -ItemType Directory -Force -Path (Split-Path $configPath)

@"
org_id: 123e4567-e89b-12d3-a456-426614174000
api_endpoint: https://app.vulnetix.com/api/
default_team: security-team
proxy:
  http_proxy: http://proxy.company.com:8080
  https_proxy: http://proxy.company.com:8080
  no_proxy: localhost,127.0.0.1,.company.com
"@ | Out-File -FilePath $configPath -Encoding UTF8

Write-Host "Vulnetix installed and configured successfully"
```

### SCCM Package Deployment

For System Center Configuration Manager deployment:

```powershell
# sccm-install.ps1 - SCCM deployment script

param(
    [Parameter(Mandatory=$false)]
    [string]$Version = "latest",

    [Parameter(Mandatory=$false)]
    [string]$InstallPath = "$env:ProgramFiles\Vulnetix"
)

try {
    # Ensure Chocolatey is available
    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
        throw "Chocolatey is not installed. Install Chocolatey first."
    }

    # Install Vulnetix
    if ($Version -eq "latest") {
        $result = choco install vulnetix -y --install-directory="$InstallPath"
    } else {
        $result = choco install vulnetix --version=$Version -y --install-directory="$InstallPath"
    }

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Vulnetix installed successfully to $InstallPath"
        exit 0
    } else {
        throw "Installation failed with exit code $LASTEXITCODE"
    }
} catch {
    Write-Error "Installation failed: $_"
    exit 1
}
```

## CI/CD Integration

### Azure DevOps Pipelines

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
    - main
    - develop

pool:
  vmImage: 'windows-latest'

steps:
- task: PowerShell@2
  displayName: 'Install Vulnetix'
  inputs:
    targetType: 'inline'
    script: |
      choco install vulnetix -y
      vulnetix --version

- task: PowerShell@2
  displayName: 'Run Security Scan'
  inputs:
    targetType: 'inline'
    script: |
      $env:VULNETIX_ORG_ID = "$(VULNETIX_ORG_ID)"
      vulnetix --task release --project-name "$(Build.Repository.Name)"
  env:
    VULNETIX_ORG_ID: $(VULNETIX_ORG_ID)

- task: PublishTestResults@2
  displayName: 'Publish Security Results'
  inputs:
    testResultsFormat: 'JUnit'
    testResultsFiles: 'scan-results.json'
    testRunTitle: 'Vulnetix Security Scan'
```

### GitHub Actions (Windows Runner)

```yaml
name: Security Scan (Windows)

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: windows-latest

    steps:
    - uses: actions/checkout@v4

    - name: Install Vulnetix via Chocolatey
      run: |
        choco install vulnetix -y
        vulnetix --version

    - name: Run Security Assessment
      env:
        VULNETIX_ORG_ID: ${{ secrets.VULNETIX_ORG_ID }}
      run: |
        vulnetix --task release --project-name "${GITHUB_REPOSITORY##*/}"

    - name: Upload SARIF results
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: security-results.sarif
```

## Edge Cases and Advanced Configuration

### Corporate Firewall/Proxy

```powershell
# Configure Chocolatey for corporate proxy
choco config set proxy http://proxy.company.com:8080
choco config set proxyUser domain\username

# For NTLM authentication
choco config set proxyBypassOnLocal true
choco config set proxyBypassList "*.company.com,localhost,127.0.0.1"

# Install through proxy
choco install vulnetix --proxy="http://proxy.company.com:8080" --proxy-user="domain\username"
```

### Air-Gapped Environment

```powershell
# Download package for offline installation
choco download vulnetix --output-directory="C:\ChocolateyPackages"

# On air-gapped machine, install from local package
choco install vulnetix --source="C:\ChocolateyPackages" --local-only
```

### Custom Package Source

```powershell
# Add internal package repository
choco source add -n=internal-repo -s="https://nuget.company.com/api/v2" --priority=1 --user="domain\serviceaccount" --password="encrypted_password"

# Install from internal repository
choco install vulnetix --source=internal-repo
```

### PowerShell Module Integration

```powershell
# Create PowerShell wrapper module
$modulePath = "$env:USERPROFILE\Documents\PowerShell\Modules\VulnetixPS"
New-Item -ItemType Directory -Force -Path $modulePath

@"
function Invoke-VulnetixScan {
    param(
        [Parameter(Mandatory=`$true)]
        [string]`$ProjectPath,

        [Parameter(Mandatory=`$false)]
        [string]`$OutputFormat = "json",

        [Parameter(Mandatory=$false)]
        [string]$ConfigPath
    )

    $params = @("--task", "scan", "--project-name", $ProjectPath)

    if (`$ConfigPath) {
        `$params += @("--config", `$ConfigPath)
    }

    & vulnetix @params
}

Export-ModuleMember -Function Invoke-VulnetixScan
"@ | Out-File -FilePath "$modulePath\VulnetixPS.psm1" -Encoding UTF8

# Use the module
Import-Module VulnetixPS
Invoke-VulnetixScan -ProjectPath "C:\MyProject" -OutputFormat "sarif"
```

## Troubleshooting

### Common Issues

#### Installation Fails

```powershell
# Check Chocolatey installation
choco --version

# Verify execution policy
Get-ExecutionPolicy
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# Check for conflicting installations
where vulnetix
choco list vulnetix
```

#### Proxy Issues

```powershell
# Test proxy connectivity
Test-NetConnection proxy.company.com -Port 8080

# Check Chocolatey proxy configuration
choco config list

# Test installation with explicit proxy
choco install vulnetix --proxy="http://proxy.company.com:8080" --proxy-user="domain\username" --proxy-password="password"
```

#### Permission Errors

```powershell
# Run as administrator
Start-Process PowerShell -Verb RunAs

# Check folder permissions
icacls "C:\ProgramData\chocolatey"

# Install to user directory
choco install vulnetix --user
```

### Debug Mode

```powershell
# Enable Chocolatey debug output
choco install vulnetix --debug --verbose

# Enable Vulnetix debug mode
$env:VULNETIX_DEBUG = "true"
vulnetix --task release --project-name "My Project"
```

### Performance Optimization

```powershell
# Disable progress bar for scripting
$ProgressPreference = 'SilentlyContinue'

# Use parallel installation for multiple packages
choco install vulnetix dependency1 dependency2 -y

# Clear Chocolatey cache periodically
choco cache clean
```

### Getting Help

```powershell
# Chocolatey help
choco help install
choco help upgrade

# Vulnetix help
vulnetix --help

# Check package information
choco info vulnetix
choco search vulnetix
```

## Package Maintenance

### Creating Custom Package

For organizations that need to customize the Vulnetix package:

```powershell
# chocolateyinstall.ps1 - Custom package install script
$ErrorActionPreference = 'Stop'

$packageName = 'vulnetix'
$url64 = 'https://github.com/vulnetix/vulnetix/releases/download/v1.2.3/vulnetix-windows-amd64.exe'
$checksum64 = 'SHA256_CHECKSUM_HERE'

$packageArgs = @{
  packageName   = $packageName
  fileType      = 'exe'
  url64bit      = $url64
  checksum64    = $checksum64
  checksumType64 = 'sha256'
  silentArgs    = '/S'
  validExitCodes = @(0)
}

Install-ChocolateyPackage @packageArgs

# Custom configuration
$configPath = "$env:ProgramData\Vulnetix\config.yaml"
New-Item -ItemType Directory -Force -Path (Split-Path $configPath)

@"
org_id: YOUR_ORG_ID
api_endpoint: https://app.vulnetix.com/api
"@ | Out-File -FilePath $configPath -Encoding UTF8
```

---

**Next Steps:**
- See [Windows](windows.md) for comprehensive Windows-specific configuration
- See [Corporate Proxy](corporate-proxy.md) for enterprise proxy configuration
- See [Azure DevOps](azure-devops.md) for complete Azure DevOps integration
