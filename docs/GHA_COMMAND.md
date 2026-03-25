# GHA Command Reference

This documentation has moved to **[docs.cli.vulnetix.com/docs/ci-cd/gha-command](https://docs.cli.vulnetix.com/docs/ci-cd/gha-command/)**.

## Overview

The `vulnetix gha` subcommand provides seamless integration with GitHub Actions workflows for uploading artifacts to Vulnetix.

### Upload all workflow artifacts

```bash
vulnetix gha upload --org-id "$VULNETIX_ORG_ID" --json
```

### Check upload status

```bash
vulnetix gha status --txnid <transaction-id>
vulnetix gha status --uuid <artifact-uuid>
```

### Workflow example

```yaml
- name: Upload artifacts to Vulnetix
  uses: Vulnetix/cli@v1
  with:
    task: gha
    org-id: ${{ secrets.VULNETIX_ORG_ID }}
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

See the [full documentation](https://docs.cli.vulnetix.com/docs/ci-cd/gha-command/) for detailed usage and examples.
