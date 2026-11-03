# Bitbucket Pipelines

This documentation has moved to **[docs.vulnetix.com/cli/ci-cd/bitbucket](https://docs.vulnetix.com/cli/ci-cd/bitbucket/)**.

## Quick Start

```yaml
pipelines:
  default:
    - step:
        name: Vulnetix Security Scan
        image: golang:1.25
        script:
          - go install github.com/vulnetix/cli/v4@latest
          - vulnetix auth login --api-key "$VULNETIX_API_KEY" --org-id "$VULNETIX_ORG_ID" --store project
          - vulnetix
```

See the [full documentation](https://docs.vulnetix.com/cli/ci-cd/bitbucket/) for pipeline templates and advanced configuration.
