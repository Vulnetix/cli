---
title: "VNX-SEC-020 – GitLab Access Token"
description: "Detects hardcoded GitLab personal, project, and group access tokens (glpat- prefix) in source code, which grant API access to GitLab resources."
---

## Overview

This rule specifically targets GitLab personal access tokens (PATs), project access tokens, and group access tokens with the `glpat-` prefix pattern `glpat-[A-Za-z0-9\-_]{20,}`. While VNX-SEC-004 detects both GitHub and GitLab tokens, this rule focuses exclusively on the GitLab PAT format and provides more targeted guidance. GitLab tokens with broad scopes (`api`, `write_repository`, `sudo`) grant extensive control over repositories, CI/CD pipelines, group settings, and on self-managed instances, potentially the entire GitLab installation.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

GitLab access tokens can carry any combination of the following scopes: `api` (full API access), `read_api`, `read_user`, `read_repository`, `write_repository`, `read_registry`, `write_registry`, `sudo` (admin impersonation), and `create_runner`. A token with `api` scope is effectively a complete set of the token owner's permissions — including access to every project, group, and organization-level setting they can reach.

GitLab project access tokens and group access tokens can be configured with maintainer or owner roles, meaning they can be used to modify CI/CD pipeline definitions — a direct path to supply chain compromise. On self-managed GitLab instances with the `sudo` scope, a leaked admin token grants complete control over all users, projects, and system settings.

GitLab has built-in token detection but detection alone is insufficient — the token must be revoked and replaced.

## What Gets Flagged

```python
# FLAGGED: GitLab PAT hardcoded
import gitlab

gl = gitlab.Gitlab('https://gitlab.com', private_token='glpat-xxxxxxxxxxxxxxxxxxxx')
projects = gl.projects.list()
```

```bash
# FLAGGED: token in curl command for CI script
curl --header "PRIVATE-TOKEN: glpat-xxxxxxxxxxxxxxxxxxxx" \
  "https://gitlab.com/api/v4/projects/123/pipelines"
```

```yaml
# FLAGGED: token in .gitlab-ci.yml
variables:
  DEPLOY_TOKEN: "glpat-xxxxxxxxxxxxxxxxxxxx"
```

## Remediation

1. **Revoke the token immediately.** In GitLab go to User Settings → Access Tokens → find the token → Revoke. For project tokens: Project → Settings → Access Tokens → Revoke. For group tokens: Group → Settings → Access Tokens → Revoke.

2. **Review GitLab audit events** for API activity during the exposure period. Admins can access this at Admin Area → Monitoring → Audit Events. Project maintainers can view project-level audit events at Project → Security & Compliance → Audit events.

3. **For CI/CD pipelines, use the built-in `CI_JOB_TOKEN`** instead of a personal access token. `CI_JOB_TOKEN` is automatically injected into each job, scoped to the current project, and expires when the job completes:

```yaml
# SAFE: use CI_JOB_TOKEN in .gitlab-ci.yml
deploy:
  script:
    - curl --header "JOB-TOKEN: $CI_JOB_TOKEN" \
        "https://gitlab.com/api/v4/projects/123/packages/npm/"
```

4. **For cross-project access in CI**, configure CI_JOB_TOKEN allowlists rather than sharing a PAT:

```yaml
# SAFE: trigger downstream pipeline with CI_JOB_TOKEN
trigger:
  project: group/downstream-project
  strategy: depend
```

5. **For automation outside CI**, create a dedicated project access token** or group access token with the minimum required scope and expiration date, then store it in GitLab CI/CD variables (masked and protected) or your secrets manager:

```python
# SAFE: load GitLab token from environment
import gitlab
import os

gl = gitlab.Gitlab('https://gitlab.com', private_token=os.environ['GITLAB_TOKEN'])
```

6. **Configure token expiration.** GitLab now requires expiration dates on PATs. Set the shortest expiration that is operationally feasible and implement automated rotation.

7. **Scan git history** for any exposed tokens:

```bash
gitleaks detect --source . --verbose
git filter-repo --replace-text <(echo 'glpat-xxxx==>REDACTED_GITLAB_TOKEN')
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [GitLab: Personal access tokens](https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html)
- [GitLab: CI/CD job token](https://docs.gitlab.com/ee/ci/jobs/ci_job_token.html)
- [GitLab: Project access tokens](https://docs.gitlab.com/ee/user/project/settings/project_access_tokens.html)
- [GitLab: Push rules for secret detection](https://docs.gitlab.com/ee/user/project/repository/push_rules.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
