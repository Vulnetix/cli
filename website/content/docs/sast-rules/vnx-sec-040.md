---
title: "VNX-SEC-040 – GitLab Pipeline / Deploy / Runner / Agent Token"
description: "Reports a GitLab infrastructure token by its documented prefix and body shape: pipeline trigger (glptt- + 40 hex), deploy (gldt-), runner authentication (glrt-), runner registration (GR1348941), Kubernetes agent (glagent-), CI job (glcbt-), OAuth application secret (gloas-), incoming mail (glimt-), feature-flag client (glffct-), feed (glft-) and SCIM (glsoat-) tokens. A prefix without a token body of the right length, placeholders and test or fixture paths are not reported; glpat- access tokens are VNX-SEC-039."
---

## Overview

This rule detects GitLab infrastructure tokens for pipeline triggers, deploy tokens, runner authentication, Kubernetes agents, CI/CD jobs, OAuth applications, incoming mail, feature flags, feeds, SCIM provisioning, and runner registration.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Each of these tokens grants a specific kind of automated access. A leaked runner authentication token (glrt-) lets the attacker register their own runner and execute arbitrary code inside your CI jobs. A leaked Kubernetes agent token (glagent-) gives the attacker a foothold in your cluster.

## What Gets Flagged

Flagged (prefix plus a token body of the documented shape):

```yaml
script:
  - curl -X POST -F token=glptt-<40 hex> -F ref=main https://gitlab.com/api/v4/projects/42/trigger/pipeline
```

```toml
[[runners]]
  token = "glrt-<20+ characters>"
```

Also `gldt-` deploy, `GR1348941` runner registration, `glagent-` agent, `glcbt-` CI job, `gloas-` OAuth secret, `glimt-` incoming mail, `glffct-` feature-flag, `glft-` feed and `glsoat-` SCIM tokens.

Not flagged: a prefix named in prose, a CSS class such as `.glft-icon-container-wrapper`, `$CI_JOB_TOKEN`, placeholders, and test or fixture files.

## Remediation

1. **Revoke the token in GitLab** in the corresponding settings page (Project → Settings → CI/CD for runners, Admin → Tokens for runners, etc.).
2. **Use a CI/CD variable** (Settings → CI/CD → Variables, masked + protected) to inject the token at job time.
3. **Audit the GitLab audit log** for any pipeline / deploy / runner activity you did not initiate.
4. **Purge from git history** with `git filter-repo`.

## References

- [GitLab CI/CD Variables](https://docs.gitlab.com/ee/ci/variables/)
- [GitLab Runner Registration](https://docs.gitlab.com/runner/register/)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [GitLab Secret Detection](https://docs.gitlab.com/ee/user/application_security/secret_detection/)
- [MITRE ATT&CK T1552.001](https://attack.mitre.org/techniques/T1552/001/)
