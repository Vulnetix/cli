---
title: "Bitbucket Pipelines"
weight: 3
description: "Integrate Vulnetix CLI into Bitbucket Pipelines."
---

Bitbucket Pipelines is Atlassian's integrated CI/CD service that builds, tests, and deploys code from Bitbucket repositories.

## Quick Start

### Basic Configuration

```yaml
# bitbucket-pipelines.yml
image: alpine:latest

pipelines:
  default:
    - step:
        name: Security Scan
        script:
          - apk add --no-cache curl
          - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
          - export PATH=$PATH:$HOME/.local/bin
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
        artifacts:
          - security-results.sarif

  branches:
    main:
      - step:
          name: Release Security Assessment
          script:
            - apk add --no-cache curl
            - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
            - export PATH=$PATH:$HOME/.local/bin
            - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
          artifacts:
            - vulnetix-assessment.json
```

### Docker-based Pipeline

```yaml
# bitbucket-pipelines.yml - Using Docker
image: vulnetix/vulnetix:latest

pipelines:
  default:
    - step:
        name: Vulnerability Assessment
        script:
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
        artifacts:
          - scan-results.json

  pull-requests:
    '**':
      - step:
          name: PR Security Check
          script:
            - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
          artifacts:
            - security-results.sarif

  branches:
    main:
      - step:
          name: Release Assessment
          script:
            - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
    develop:
      - step:
          name: Development Scan
          script:
            - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
```

## Advanced Configuration

### Multi-Step Security Pipeline

```yaml
# bitbucket-pipelines.yml - Complete security pipeline
image: alpine:latest

definitions:
  steps:
    - step: &install-vulnetix
        name: Install Vulnetix
        script:
          - apk add --no-cache curl bash
          - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
          - export PATH=$PATH:$HOME/.local/bin
          - vulnetix --version
        caches:
          - vulnetix-cache

    - step: &security-scan
        name: Security Scan
        script:
          - export PATH=$PATH:$HOME/.local/bin
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
        caches:
          - vulnetix-cache

    - step: &sast-analysis
        name: SAST Analysis
        image: returntocorp/semgrep:latest
        script:
          - semgrep --config=auto --sarif --output=sast-results.sarif .
        artifacts:
          - sast-results.sarif

    - step: &dependency-scan
        name: Dependency Scan
        script:
          - apk add --no-cache curl
          - curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
          - trivy fs . --format sarif --output dependency-scan.sarif
        artifacts:
          - dependency-scan.sarif

    - step: &release-assessment
        name: Release Assessment
        script:
          - export PATH=$PATH:$HOME/.local/bin
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
        caches:
          - vulnetix-cache

  caches:
    vulnetix-cache: ~/.local/bin

pipelines:
  default:
    - step: *install-vulnetix
    - parallel:
        - step: *security-scan
        - step: *sast-analysis
        - step: *dependency-scan
    - step: *release-assessment

  pull-requests:
    '**':
      - step: *install-vulnetix
      - step: *security-scan
      - step:
          name: PR Security Report
          script:
            - export PATH=$PATH:$HOME/.local/bin
            - vulnetix --org-id "$VULNETIX_ORG_ID" --task report --project-name "$BITBUCKET_REPO_SLUG"

  branches:
    main:
      - step: *install-vulnetix
      - parallel:
          - step: *security-scan
          - step: *sast-analysis
          - step: *dependency-scan
      - step: *release-assessment
      - step:
          name: Deploy Security Report
          deployment: production
          script:
            - echo "Deploying security assessment results..."
            # Deploy to security dashboard or artifact repository

    develop:
      - step: *install-vulnetix
      - step: *security-scan
```

### Custom Docker Image Pipeline

```yaml
# bitbucket-pipelines.yml - Custom security image
image: your-registry.com/security-tools:latest

pipelines:
  default:
    - step:
        name: Comprehensive Security Assessment
        script:
          # All tools pre-installed in custom image
          - semgrep --config=auto --sarif --output=sast.sarif .
          - trivy fs . --format sarif --output=deps.sarif
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
        artifacts:
          - "*.sarif"
        services:
          - docker
        caches:
          - docker
```

## Environment Configuration

### Repository Variables

Configure in Bitbucket repository settings:

```bash
# Repository Variables (Bitbucket Settings > Repository variables)
VULNETIX_ORG_ID=123e4567-e89b-12d3-a456-426614174000
VULNETIX_API_TOKEN=$VULNETIX_API_TOKEN  # Use secured variable
VULNETIX_ENVIRONMENT=production
VULNETIX_TEAM_NAME=security-team
```

### Secured Variables

For sensitive configuration:

```yaml
# bitbucket-pipelines.yml - Using secured variables
pipelines:
  default:
    - step:
        name: Secure Assessment
        script:
          - export VULNETIX_ORG_ID=$VULNETIX_ORG_ID
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG" --team-name "$VULNETIX_TEAM_NAME"
```

### Configuration Files

```yaml
# vulnetix-tools.yaml - Tool configuration
tools:
  - category: "SAST"
    artifact_name: "./sast-results.sarif"
    format: "SARIF"
    tool_name: "semgrep"

  - category: "SCA"
    artifact_name: "./dependency-scan.sarif"
    format: "SARIF"
    tool_name: "trivy"

assessment:
  fail_on_high_severity: true
  generate_report: true
  output_formats: ["json", "sarif", "html"]
```

## Integration Patterns

### Parallel Execution

```yaml
# bitbucket-pipelines.yml - Parallel security scans
pipelines:
  default:
    - step:
        name: Setup
        script:
          - apk add --no-cache curl
          - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
        caches:
          - vulnetix-cache

    - parallel:
        - step:
            name: SAST Scan
            image: returntocorp/semgrep:latest
            script:
              - semgrep --config=auto --sarif --output=sast.sarif .
            artifacts:
              - sast.sarif

        - step:
            name: Dependency Scan
            script:
              - apk add --no-cache curl
              - curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
              - trivy fs . --format sarif --output=deps.sarif
            artifacts:
              - deps.sarif

        - step:
            name: Secrets Scan
            image: trufflesecurity/trufflehog:latest
            script:
              - trufflehog filesystem . --json > secrets.json
            artifacts:
              - secrets.json

    - step:
        name: Aggregate Assessment
        script:
          - export PATH=$PATH:$HOME/.local/bin
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
        caches:
          - vulnetix-cache
```

### Conditional Execution

```yaml
# bitbucket-pipelines.yml - Conditional security steps
pipelines:
  default:
    - step:
        name: Security Scan
        script:
          - export PATH=$PATH:$HOME/.local/bin
          - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
        condition:
          changesets:
            includePaths:
              - "src/**"
              - "*.go"
              - "*.py"
              - "*.js"
              - "*.ts"
              - "Dockerfile"
              - "requirements.txt"
              - "package.json"
              - "go.mod"

  branches:
    main:
      - step:
          name: Production Security Assessment
          script:
            - export PATH=$PATH:$HOME/.local/bin
            - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
            - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
```

### Deployment Integration

```yaml
# bitbucket-pipelines.yml - Security gates for deployment
pipelines:
  branches:
    main:
      - step:
          name: Security Gate
          script:
            - export PATH=$PATH:$HOME/.local/bin
            - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
            - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"

      - step:
          name: Deploy to Staging
          deployment: staging
          script:
            - echo "Deploying to staging environment..."
            # Deployment logic here

      - step:
          name: Staging Security Validation
          script:
            - export PATH=$PATH:$HOME/.local/bin
            - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
          after-script:
            - echo "Staging validation completed"

      - step:
          name: Deploy to Production
          deployment: production
          trigger: manual
          script:
            - echo "Deploying to production environment..."
            # Production deployment logic
```

## Artifact Management

### Security Report Generation

```yaml
# bitbucket-pipelines.yml - Comprehensive reporting
pipelines:
  default:
    - step:
        name: Security Assessment with Reports
        script:
          - export PATH=$PATH:$HOME/.local/bin
          - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task report --project-name "$BITBUCKET_REPO_SLUG"
```

### Artifact Retention

```yaml
# bitbucket-pipelines.yml - Long-term artifact retention
pipelines:
  default:
    - step:
        name: Security Scan with Retention
        script:
          - export PATH=$PATH:$HOME/.local/bin
          - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
        # Build retained for 365 days
```

## Edge Cases and Troubleshooting

### Corporate Firewall/Proxy

```yaml
# bitbucket-pipelines.yml - Corporate proxy configuration
pipelines:
  default:
    - step:
        name: Security Scan (Corporate Network)
        script:
          - export HTTP_PROXY=http://proxy.company.com:8080
          - export HTTPS_PROXY=http://proxy.company.com:8080
          - export NO_PROXY=localhost,127.0.0.1,.company.com
          - apk add --no-cache curl
          - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
          - export PATH=$PATH:$HOME/.local/bin
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
```

### Large Repository Handling

```yaml
# bitbucket-pipelines.yml - Large repository optimization
pipelines:
  default:
    - step:
        name: Optimized Security Scan
        size: 2x  # Use larger build container
        script:
          - export PATH=$PATH:$HOME/.local/bin
          - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
        max-time: 30  # Extended timeout for large repos
```

### Custom SSL Certificates

```yaml
# bitbucket-pipelines.yml - Custom CA certificates
pipelines:
  default:
    - step:
        name: Security Scan (Custom CA)
        script:
          - apk add --no-cache ca-certificates curl
          - cp company-ca.crt /usr/local/share/ca-certificates/
          - update-ca-certificates
          - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
          - export PATH=$PATH:$HOME/.local/bin
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
```

### Memory and Resource Optimization

```yaml
# bitbucket-pipelines.yml - Resource optimization
pipelines:
  default:
    - step:
        name: Memory-Optimized Scan
        memory: 1024  # Allocate more memory
        script:
          - export PATH=$PATH:$HOME/.local/bin
          - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
```

## Integration with Bitbucket Features

### SARIF Upload Integration

```yaml
# bitbucket-pipelines.yml - SARIF upload to Vulnetix
pipelines:
  pull-requests:
    '**':
      - step:
          name: Security Review
          script:
            - export PATH=$PATH:$HOME/.local/bin
            - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
            - |
              if [ -f "security-results.sarif" ]; then
                vulnetix --task sarif --org-id "$VULNETIX_ORG_ID" --project-name "$BITBUCKET_REPO_SLUG" --file security-results.sarif
              fi
```

## Performance Optimization

### Caching Strategies

```yaml
# bitbucket-pipelines.yml - Advanced caching
definitions:
  caches:
    vulnetix-cache: ~/.local/bin/vulnetix
    security-tools: ~/.local/bin
    scan-cache: ~/.vulnetix/cache

pipelines:
  default:
    - step:
        name: Cached Security Scan
        script:
          - export PATH=$PATH:$HOME/.local/bin
          - |
            if [ ! -f ~/.local/bin/vulnetix ]; then
              curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
            fi
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
        caches:
          - vulnetix-cache
          - security-tools
          - scan-cache
```

### Build Matrix

```yaml
# bitbucket-pipelines.yml - Multi-environment testing
pipelines:
  default:
    - parallel:
        - step:
            name: Security Scan (Go)
            image: golang:1.21-alpine
            script:
              - apk add --no-cache curl
              - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
              - export PATH=$PATH:$HOME/.local/bin
              - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"

        - step:
            name: Security Scan (Node.js)
            image: node:18-alpine
            script:
              - apk add --no-cache curl
              - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
              - export PATH=$PATH:$HOME/.local/bin
              - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"

        - step:
            name: Security Scan (Python)
            image: python:3.11-alpine
            script:
              - apk add --no-cache curl
              - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
              - export PATH=$PATH:$HOME/.local/bin
              - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"

    - step:
        name: Aggregate Multi-Language Results
        script:
          - export PATH=$PATH:$HOME/.local/bin
          - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task report --project-name "$BITBUCKET_REPO_SLUG"
```

## Troubleshooting

### Common Issues

#### Installation Problems
```bash
# Debug installation
apk add --no-cache curl bash
curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | bash -x

# Manual installation
wget https://github.com/vulnetix/vulnetix/releases/latest/download/vulnetix-linux-amd64.tar.gz
tar -xzf vulnetix-linux-amd64.tar.gz
mv vulnetix /usr/local/bin/
chmod +x /usr/local/bin/vulnetix
```

#### Network Connectivity
```bash
# Test connectivity
curl -I https://app.vulnetix.com/api/check
curl -I https://github.com/vulnetix/vulnetix/releases/latest

# Debug with Vulnetix
export VULNETIX_DEBUG=true
vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "test-project"
```

#### Memory Issues
```yaml
# Use larger container
size: 2x
memory: 2048
```

### Debug Mode

```yaml
# bitbucket-pipelines.yml - Debug configuration
pipelines:
  default:
    - step:
        name: Debug Security Scan
        script:
          - export VULNETIX_DEBUG=true
          - export PATH=$PATH:$HOME/.local/bin
          - curl -fsSL https://raw.githubusercontent.com/vulnetix/vulnetix/main/install.sh | sh
          - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$BITBUCKET_REPO_SLUG"
```
