---
title: "VNX-SEC-041 – Atlassian API Token"
description: "Detects Atlassian Cloud API tokens (ATATT3 prefix) hardcoded in source code."
---

## Overview

This rule detects Atlassian Cloud API tokens matching the `ATATT3[A-Za-z0-9_\-=]{186}` pattern. These tokens grant API access to Jira, Confluence, Bitbucket Cloud, and other Atlassian Cloud products using the account of the issuing user.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

A leaked Atlassian API token can be used to read confidential Jira issues, exfiltrate Confluence spaces (which often hold architecture diagrams, credentials, and runbooks), and pull private Bitbucket repositories. Because Atlassian Cloud has no IP allow-listing by default, the token works from any host on the public internet.

## Remediation

1. **Revoke the API token in id.atlassian.com/manage-profile/security/api-tokens**.
2. **Use OAuth 2.0 (3LO) authorization** for any integration that needs user-context access.
3. **Audit the Atlassian audit log** for API calls you did not initiate.
4. **Purge from git history** with `git filter-repo`.

## References

- [Atlassian API Tokens](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/)
- [Atlassian OAuth 2.0](https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [gitleaks `atlassian-api-token`](https://github.com/gitleaks/gitleaks)
- [MITRE ATT&CK T1552.001](https://attack.mitre.org/techniques/T1552/001/)
