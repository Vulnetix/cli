# Bitbucket Pipelines

This documentation has moved to **[docs.cli.vulnetix.com/docs/ci-cd/bitbucket](https://docs.cli.vulnetix.com/docs/ci-cd/bitbucket/)**.

## Quick Start

```yaml
pipelines:
  default:
    - step:
        name: Vulnetix Security Scan
        image: golang:1.25
        script:
          - go install github.com/vulnetix/cli/v3@latest
          - vulnetix auth login --api-key "$VULNETIX_API_KEY" --org-id "$VULNETIX_ORG_ID" --store project
          - vulnetix
```

See the [full documentation](https://docs.cli.vulnetix.com/docs/ci-cd/bitbucket/) for pipeline templates and advanced configuration.
