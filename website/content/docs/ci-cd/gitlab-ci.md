---
title: "GitLab CI"
weight: 2
description: "Integrate Vulnetix CLI into GitLab CI/CD pipelines."
---

Comprehensive guide for integrating Vulnetix CLI in GitLab CI/CD pipelines.

## Quick Start

```yaml
# .gitlab-ci.yml
stages:
  - security

vulnetix:
  stage: security
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest
  script:
    - vulnetix --org-id "$VULNETIX_ORG_ID" --task release
  variables:
    VULNETIX_ORG_ID: $VULNETIX_ORG_ID
```

## Installation Methods

### Using Go Install

```yaml
vulnetix:
  image: golang:1.21
  stage: security
  before_script:
    - go install github.com/vulnetix/cli@latest
  script:
    - vulnetix --org-id "$VULNETIX_ORG_ID" --task release
```

### Using Binary Download

```yaml
vulnetix:
  image: alpine:latest
  stage: security
  before_script:
    - apk add --no-cache curl
    - curl -L https://github.com/vulnetix/cli/releases/latest/download/vulnetix-linux-amd64 -o vulnetix
    - chmod +x vulnetix
  script:
    - ./vulnetix --org-id "$VULNETIX_ORG_ID" --task release
```

## Configuration

### Variables

Configure in GitLab UI: Settings > CI/CD > Variables

| Variable | Description | Protected | Masked |
|----------|-------------|-----------|---------|
| `VULNETIX_ORG_ID` | Organization ID (UUID) | Yes | Yes |
| `VULNETIX_API_TOKEN` | API token for authentication | Yes | Yes |
| `VULNETIX_API_URL` | Custom API endpoint | No | No |

### Environment-Specific Variables

```yaml
variables:
  VULNETIX_ORG_ID: $VULNETIX_ORG_ID
  VULNETIX_LOG_LEVEL: "info"

# Development environment
vulnetix-dev:
  stage: security
  environment: development
  variables:
    VULNETIX_TAGS: '["Public", "Crown Jewels"]'
  script:
    - vulnetix --task release --tags "$VULNETIX_TAGS"
  only:
    - develop

# Production environment
vulnetix-prod:
  stage: security
  environment: production
  variables:
    VULNETIX_TAGS: '["Public", "Crown Jewels"]'
  script:
    - vulnetix --task release --tags "$VULNETIX_TAGS"
  only:
    - main
```

## Usage Examples

### Basic Security Pipeline

```yaml
# .gitlab-ci.yml
stages:
  - build
  - test
  - security
  - deploy

variables:
  VULNETIX_ORG_ID: $VULNETIX_ORG_ID
  PROJECT_NAME: $CI_PROJECT_NAME
  TEAM_NAME: "DevSecOps"

# Security assessment stage
vulnetix:
  stage: security
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest
  script:
    - vulnetix --task release
        --project-name "$PROJECT_NAME"
        --team-name "$TEAM_NAME"
        --build-id "$CI_PIPELINE_ID"
  artifacts:
    reports:
      sast: vulnetix-output/sast.json
    paths:
      - vulnetix-output/
    expire_in: 7 days
  only:
    - main
    - merge_requests
```

### Comprehensive Release Assessment

```yaml
stages:
  - build
  - security-scans
  - security-assessment
  - deploy

variables:
  VULNETIX_ORG_ID: $VULNETIX_ORG_ID
  REPORTS_DIR: "security-reports"

# SAST scanning
sast-scan:
  stage: security-scans
  image: returntocorp/semgrep
  script:
    - mkdir -p $REPORTS_DIR
    - semgrep --config=auto --sarif --output=$REPORTS_DIR/sast-semgrep.sarif .
  artifacts:
    paths:
      - $REPORTS_DIR/sast-semgrep.sarif
    expire_in: 1 day

# SCA scanning
sca-scan:
  stage: security-scans
  image: anchore/syft
  script:
    - mkdir -p $REPORTS_DIR
    - syft dir:. -o spdx-json=$REPORTS_DIR/sbom.json
  artifacts:
    paths:
      - $REPORTS_DIR/sbom.json
    expire_in: 1 day

# Secrets scanning
secrets-scan:
  stage: security-scans
  image: alpine/git
  before_script:
    - apk add --no-cache curl tar
    - curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.18.0_linux_x64.tar.gz | tar -xz
  script:
    - mkdir -p $REPORTS_DIR
    - ./gitleaks detect --source=. --report-format=sarif --report-path=$REPORTS_DIR/secrets-gitleaks.sarif
  artifacts:
    paths:
      - $REPORTS_DIR/secrets-gitleaks.sarif
    expire_in: 1 day

# Container scanning (if Dockerfile exists)
container-scan:
  stage: security-scans
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - apk add --no-cache curl
    - curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
  script:
    - mkdir -p $REPORTS_DIR
    - |
      if [ -f "Dockerfile" ]; then
        docker build -t $CI_PROJECT_NAME:$CI_COMMIT_SHA .
        grype $CI_PROJECT_NAME:$CI_COMMIT_SHA -o sarif=$REPORTS_DIR/container-grype.sarif
      else
        echo "No Dockerfile found, skipping container scan"
        touch $REPORTS_DIR/container-grype.sarif
      fi
  artifacts:
    paths:
      - $REPORTS_DIR/container-grype.sarif
    expire_in: 1 day
  only:
    changes:
      - Dockerfile
      - docker-compose.yml

# Vulnetix release assessment
vulnetix-assessment:
  stage: security-assessment
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest
  dependencies:
    - sast-scan
    - sca-scan
    - secrets-scan
    - container-scan
  script:
    - |
      vulnetix --task release \
        --production-branch "main" \
        --release-branch "$CI_COMMIT_REF_NAME" \
        --project-name "$CI_PROJECT_NAME" \
        --team-name "Security Engineering" \
        --tools '[
          {
            "category": "SAST",
            "tool_name": "semgrep",
            "artifact_name": "./'$REPORTS_DIR'/sast-semgrep.sarif",
            "format": "SARIF"
          },
          {
            "category": "SCA",
            "tool_name": "sca-tool",
            "artifact_name": "./'$REPORTS_DIR'/sbom.json",
            "format": "JSON"
          },
          {
            "category": "SECRETS",
            "tool_name": "gitleaks",
            "artifact_name": "./'$REPORTS_DIR'/secrets-gitleaks.sarif",
            "format": "SARIF"
          },
          {
            "category": "CONTAINER",
            "tool_name": "grype",
            "artifact_name": "./'$REPORTS_DIR'/container-grype.sarif",
            "format": "SARIF"
          }
        ]'
  artifacts:
    reports:
      sast: vulnetix-output/aggregated-sast.json
    paths:
      - vulnetix-output/
      - $REPORTS_DIR/
    expire_in: 30 days
  only:
    - merge_requests
    - main
```

### Language-Specific Pipelines

#### Go Projects

```yaml
# Go-specific security pipeline
go-security-assessment:
  stage: security
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest
    - go install golang.org/x/vuln/cmd/govulncheck@latest
    - go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
  script:
    - mkdir -p security-reports

    # Go vulnerability check
    - govulncheck -json ./... > security-reports/govulncheck.json

    # Go security analysis
    - gosec -fmt sarif -out security-reports/gosec.sarif ./...

    # Generate Go module SBOM
    - go list -json -deps ./... > security-reports/go-deps.json

    # Run Vulnetix assessment
    - vulnetix --task release
        --production-branch "main"
        --release-branch "$CI_COMMIT_REF_NAME"
        --tools '[
          {
            "category": "SCA",
            "tool_name": "govulncheck",
            "artifact_name": "./security-reports/govulncheck.json",
            "format": "JSON"
          },
          {
            "category": "SAST",
            "tool_name": "gosec",
            "artifact_name": "./security-reports/gosec.sarif",
            "format": "SARIF"
          }
        ]'
  artifacts:
    paths:
      - security-reports/
    expire_in: 7 days
  only:
    changes:
      - "*.go"
      - "go.mod"
      - "go.sum"
```

#### Node.js Projects

```yaml
nodejs-security-assessment:
  stage: security
  image: node:18
  before_script:
    - apk add --no-cache curl
    - curl -L https://github.com/vulnetix/cli/releases/latest/download/vulnetix-linux-amd64 -o /usr/local/bin/vulnetix
    - chmod +x /usr/local/bin/vulnetix
    - npm install -g audit-ci
  script:
    - mkdir -p security-reports

    # NPM audit
    - npm audit --audit-level=moderate --json > security-reports/npm-audit.json || true

    # Generate package lock analysis
    - npm list --json --all > security-reports/npm-deps.json

    # Run Vulnetix assessment
    - vulnetix --task release
        --project-name "$CI_PROJECT_NAME"
        --team-name "Frontend Team"
  artifacts:
    paths:
      - security-reports/
    expire_in: 7 days
  only:
    changes:
      - "package.json"
      - "package-lock.json"
      - "*.js"
      - "*.ts"
```

#### Python Projects

```yaml
python-security-assessment:
  stage: security
  image: python:3.9
  before_script:
    - pip install safety bandit
    - curl -L https://github.com/vulnetix/cli/releases/latest/download/vulnetix-linux-amd64 -o /usr/local/bin/vulnetix
    - chmod +x /usr/local/bin/vulnetix
  script:
    - mkdir -p security-reports

    # Python safety check
    - safety check --json --output security-reports/safety.json || true

    # Bandit SAST
    - bandit -r . -f sarif -o security-reports/bandit.sarif || true

    # Generate requirements analysis
    - pip freeze > security-reports/requirements-freeze.txt

    # Run Vulnetix assessment
    - vulnetix --task release
        --project-name "$CI_PROJECT_NAME"
        --team-name "Backend Team"
  artifacts:
    paths:
      - security-reports/
    expire_in: 7 days
  only:
    changes:
      - "*.py"
      - "requirements.txt"
      - "setup.py"
      - "pyproject.toml"
```

## Edge Cases & Advanced Configuration

### Corporate Proxy Support

```yaml
variables:
  HTTP_PROXY: "http://proxy.company.com:8080"
  HTTPS_PROXY: "http://proxy.company.com:8080"
  NO_PROXY: "localhost,127.0.0.1,.company.com"

vulnetix-proxy:
  stage: security
  image: golang:1.21
  before_script:
    # Configure proxy for package managers
    - export http_proxy=$HTTP_PROXY
    - export https_proxy=$HTTPS_PROXY
    - export no_proxy=$NO_PROXY
    - go install github.com/vulnetix/cli@latest
  script:
    - vulnetix --org-id "$VULNETIX_ORG_ID" --task release
```

### Self-Hosted GitLab Runners

```yaml
vulnetix-self-hosted:
  stage: security
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest
    - df -h  # Check disk space
    - curl -I https://app.vulnetix.com/api/  # Test connectivity
  script:
    - vulnetix --org-id "$VULNETIX_ORG_ID" --task release
  after_script:
    # Cleanup
    - rm -rf vulnetix-output/cache/
```

### Air-Gapped Environments

```yaml
vulnetix-airgapped:
  stage: security
  image: alpine:latest
  variables:
    VULNETIX_API_URL: "https://vulnetix.company.com/api"
  before_script:
    # Use internal certificate authority
    - cp /etc/ssl/company-ca.crt /usr/local/share/ca-certificates/
    - update-ca-certificates
    # Install from internal binary mirror
    - apk add --no-cache curl
    - curl -L https://packages.company.com/vulnetix/vulnetix-linux-amd64 -o /usr/local/bin/vulnetix
    - chmod +x /usr/local/bin/vulnetix
  script:
    - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --offline-mode
```

### Multi-Environment Deployment

```yaml
# Development environment
.vulnetix-dev: &vulnetix-dev
  stage: security
  variables:
    VULNETIX_TAGS: '["Public", "Crown Jewels"]'
  script:
    - vulnetix --task release --tags "$VULNETIX_TAGS"
  only:
    - develop
    - feature/*

# Staging environment
.vulnetix-staging: &vulnetix-staging
  stage: security
  variables:
    VULNETIX_TAGS: '["Public", "Crown Jewels"]'
    VULNETIX_PRIORITY: "high"
  script:
    - vulnetix --task release --tags "$VULNETIX_TAGS"
  only:
    - staging

# Production environment
.vulnetix-prod: &vulnetix-prod
  stage: security
  variables:
    VULNETIX_TAGS: '["Public", "Crown Jewels"]'
    VULNETIX_PRIORITY: "critical"
  script:
    - vulnetix --task release --tags "$VULNETIX_TAGS"
  only:
    - main

vulnetix-dev:
  <<: *vulnetix-dev
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest

vulnetix-staging:
  <<: *vulnetix-staging
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest

vulnetix-prod:
  <<: *vulnetix-prod
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest
```

### Parallel Security Assessments

```yaml
# Parallel execution for faster assessments
.parallel-security: &parallel-security
  stage: security
  parallel:
    matrix:
      - SCAN_TYPE: [sast, sca, secrets, container]

parallel-security-assessment:
  <<: *parallel-security
  image: alpine:latest
  before_script:
    - apk add --no-cache curl docker git
  script:
    - mkdir -p security-reports
    - |
      case $SCAN_TYPE in
        sast)
          # SAST scanning logic
          curl -sSfL https://github.com/semgrep/semgrep/releases/latest/download/semgrep-linux-x86_64 -o semgrep
          chmod +x semgrep
          ./semgrep --config=auto --sarif --output=security-reports/sast.sarif .
          ;;
        sca)
          # SCA scanning logic
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          syft dir:. -o spdx-json=security-reports/sbom.json
          ;;
        secrets)
          # Secrets scanning logic
          curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.18.0_linux_x64.tar.gz | tar -xz
          ./gitleaks detect --source=. --report-format=sarif --report-path=security-reports/secrets.sarif
          ;;
        container)
          # Container scanning logic
          if [ -f "Dockerfile" ]; then
            docker build -t scan-target .
            curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
            grype scan-target -o sarif=security-reports/container.sarif
          fi
          ;;
      esac
  artifacts:
    paths:
      - security-reports/
    expire_in: 1 hour
```

### Custom Security Rules

```yaml
vulnetix-custom-rules:
  stage: security
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest
    # Download custom security rules
    - curl -sSfL "$CUSTOM_RULES_URL" -o custom-rules.yaml
  script:
    - vulnetix --task release
        --config-file custom-rules.yaml
        --custom-rules-enabled
        --severity-threshold high
  artifacts:
    when: always
    paths:
      - vulnetix-output/
    reports:
      sast: vulnetix-output/custom-sast.json
```

## Integration with GitLab Features

### Security Dashboard Integration

```yaml
vulnetix-security-dashboard:
  stage: security
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest
  script:
    - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --project-name "$CI_PROJECT_NAME"
  artifacts:
    reports:
      sast: vulnetix-output/gl-sast-report.json
      dependency_scanning: vulnetix-output/gl-dependency-scanning-report.json
      container_scanning: vulnetix-output/gl-container-scanning-report.json
    expire_in: 1 week
```

### Merge Request Integration

```yaml
vulnetix-mr-security:
  stage: security
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest
  script:
    - vulnetix --org-id "$VULNETIX_ORG_ID" --task release
    - |
      # Comment on MR with results
      if [ -n "$CI_MERGE_REQUEST_IID" ]; then
        SCAN_RESULTS=$(cat vulnetix-output/summary.json)
        curl -X POST \
          -H "PRIVATE-TOKEN: $GITLAB_TOKEN" \
          -H "Content-Type: application/json" \
          -d "{\"body\": \"## Security Assessment Results\n\`\`\`json\n$SCAN_RESULTS\n\`\`\`\"}" \
          "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes"
      fi
  only:
    - merge_requests
```

### GitLab Pages Integration

```yaml
vulnetix-pages:
  stage: deploy
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest
  script:
    - vulnetix --org-id "$VULNETIX_ORG_ID" --task report --format html
    - mkdir public
    - cp -r vulnetix-output/reports/* public/
  artifacts:
    paths:
      - public
  only:
    - main
```

## Troubleshooting

### Common Issues

#### Variable Not Set

```yaml
# Issue: VULNETIX_ORG_ID not set
# Solution: Add default and validation

vulnetix-with-validation:
  stage: security
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest
    - |
      if [ -z "$VULNETIX_ORG_ID" ]; then
        echo "ERROR: VULNETIX_ORG_ID not set"
        echo "Please set this variable in GitLab CI/CD settings"
        exit 1
      fi
  script:
    - vulnetix --org-id "$VULNETIX_ORG_ID" --task release
```

#### Network Connectivity

```yaml
# Issue: Cannot connect to Vulnetix API
# Solution: Debug network connectivity

vulnetix-debug-network:
  stage: security
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest
    - apt-get update && apt-get install -y curl dnsutils
    - echo "Testing connectivity..."
    - curl -I https://app.vulnetix.com/api/ || echo "API unreachable"
    - nslookup app.vulnetix.com || echo "DNS resolution failed"
  script:
    - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --verbose
```

#### Artifact Upload Failures

```yaml
# Issue: Artifacts not uploading
# Solution: Debug and fix paths

vulnetix-debug-artifacts:
  stage: security
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest
  script:
    - vulnetix --org-id "$VULNETIX_ORG_ID" --task release
    - ls -la vulnetix-output/
    - find . -name "*.sarif" -o -name "*.json" | head -20
  artifacts:
    when: always  # Upload even on failure
    paths:
      - vulnetix-output/
      - "**/*.sarif"
      - "**/*.json"
    expire_in: 1 day
```

### Performance Issues

#### Large Repository Optimization

```yaml
vulnetix-optimized:
  stage: security
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest
  variables:
    GIT_DEPTH: 10  # Shallow clone
    GIT_STRATEGY: clone
  cache:
    key: vulnetix-cache-$CI_PROJECT_ID
    paths:
      - .vulnetix-cache/
  script:
    - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --cache-dir .vulnetix-cache/
```

#### Parallel Job Optimization

```yaml
vulnetix-parallel-opt:
  stage: security
  image: golang:1.21
  before_script:
    - go install github.com/vulnetix/cli@latest
  parallel: 3
  script:
    - vulnetix --org-id "$VULNETIX_ORG_ID" --task release --parallel-jobs $CI_NODE_TOTAL --node-index $CI_NODE_INDEX
```
