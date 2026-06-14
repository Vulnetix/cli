---
title: "VNX-SEC-039 – GitLab Personal Access Token (Legacy)"
description: "Detects legacy GitLab personal access tokens (glpat- prefix) hardcoded in source code."
---

## Overview

This rule detects GitLab personal access tokens matching the `glpat-[\w-]{20}` pattern. These tokens grant API access to the user's GitLab account including the ability to clone private repos, push code, read the container registry, and access package registries.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

A leaked GitLab PAT can be used to exfiltrate source code, push malicious commits to private repos, and access the GitLab container and package registries, which often hold production Docker images. GitLab Enterprise audit logs will show the token's IP and user-agent for every API call.

## Remediation

1. **Revoke the token in GitLab user settings** → Access Tokens.
2. **Audit the GitLab audit log** for API calls you did not initiate.
3. **Use a project access token or deploy key** with the minimum required scopes instead of a personal token.
4. **For CI, use GitLab CI/CD job tokens** which are short-lived and bound to a single pipeline.
5. **Purge from git history** with `git filter-repo`.

## References

- [GitLab Personal Access Tokens](https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [gitleaks `gitlab-pat`](https://github.com/gitleaks/gitleaks)
- [MITRE ATT&CK T1552.001](https://attack.mitre.org/techniques/T1552/001/)
