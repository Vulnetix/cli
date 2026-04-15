---
title: "VNX-SEC-004 – GitHub or GitLab Token"
description: "Detects hardcoded GitHub personal access tokens (ghp_/ghs_ prefix) and GitLab personal access tokens (glpat- prefix) in source code."
---

## Overview

This rule detects GitHub personal access tokens with the `ghp_` or `ghs_` prefix and GitLab personal access tokens with the `glpat-` prefix hardcoded in source files. These tokens authenticate API requests to GitHub and GitLab on behalf of a user and carry the full scope of permissions granted at token creation. Because they are long-lived and reusable, a single leaked token can be used to read private repositories, push malicious code, modify CI/CD pipelines, or enumerate organization members.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

GitHub personal access tokens with `repo` scope grant read and write access to every repository the user owns. `admin:org` scope grants control over organization settings, membership, and webhooks. A leaked token enables a supply chain attack: an attacker can push commits or modify GitHub Actions workflows to inject malicious code into your release pipeline without triggering any authentication alerts.

GitLab personal access tokens (`glpat-`) similarly carry whatever scopes were granted — including `api` (full API access), `write_repository`, and `sudo` (admin-level impersonation on self-managed instances). GitHub introduced fine-grained tokens and `ghs_` (installation tokens) as safer alternatives, but classic `ghp_` tokens remain widely used and are not automatically scoped.

GitHub has built-in secret scanning that detects `ghp_` and `glpat-` prefixes and can notify you or block pushes. Even so, once a token is in history it must be revoked.

## What Gets Flagged

Any source line containing a string matching `ghp_[A-Za-z0-9_]{36,}`, `ghs_[A-Za-z0-9_]{36,}`, or `glpat-[A-Za-z0-9_-]{20,}`.

```python
# FLAGGED: GitHub PAT hardcoded
import requests

headers = {
    'Authorization': 'token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'Accept': 'application/vnd.github.v3+json'
}
response = requests.get('https://api.github.com/user/repos', headers=headers)
```

```bash
# FLAGGED: GitLab token in script
curl --header "PRIVATE-TOKEN: glpat-xxxxxxxxxxxxxxxxxxxx" \
  "https://gitlab.com/api/v4/projects"
```

## Remediation

1. **Revoke the token immediately.** For GitHub: go to Settings → Developer settings → Personal access tokens → find the token → Delete. For GitLab: go to User Settings → Access Tokens → Revoke.

2. **Remove from source code.** Replace the hardcoded token with an environment variable:

```python
# SAFE: load GitHub token from environment
import os
import requests

token = os.environ['GITHUB_TOKEN']
headers = {'Authorization': f'token {token}'}
response = requests.get('https://api.github.com/user/repos', headers=headers)
```

3. **For GitHub Actions, use the built-in `GITHUB_TOKEN`.** This token is automatically created for each workflow run, is scoped to the repository, and expires when the job completes — far safer than a personal access token:

```yaml
# SAFE: use the built-in token in GitHub Actions
- name: Call GitHub API
  run: |
    curl -H "Authorization: token ${{ secrets.GITHUB_TOKEN }}" \
         https://api.github.com/repos/${{ github.repository }}
```

4. **For long-lived automation, use a GitHub App installation token or a fine-grained PAT** scoped to only the repositories and permissions the automation needs. Store these in GitHub Actions secrets or your secrets manager.

5. **Scan git history** and rewrite if the token appears in old commits:

```bash
git filter-repo --replace-text <(echo 'ghp_xxxx==>REDACTED_GITHUB_TOKEN')
gitleaks detect --source . --verbose
```

6. **Enable GitHub push protection** to block future commits containing token patterns before they reach the remote.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [GitHub: Managing personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
- [GitHub: Automatic token authentication (GITHUB_TOKEN)](https://docs.github.com/en/actions/security-guides/automatic-token-authentication)
- [GitLab: Personal access tokens](https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
