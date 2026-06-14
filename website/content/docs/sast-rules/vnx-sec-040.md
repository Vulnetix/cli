---
title: "VNX-SEC-040 – GitLab Pipeline / Deploy / Runner / Agent Token"
description: "Detects GitLab infrastructure tokens (glptt-, gldt-, glrt-, glagent-, glcbt-, gloas-, glimt-, glffct-, glft-, glsoat-, GR1348941) hardcoded in source code."
---

## Overview

This rule detects GitLab infrastructure tokens for pipeline triggers, deploy tokens, runner authentication, Kubernetes agents, CI/CD jobs, OAuth applications, incoming mail, feature flags, feeds, SCIM provisioning, and runner registration.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Each of these tokens grants a specific kind of automated access. A leaked runner authentication token (glrt-) lets the attacker register their own runner and execute arbitrary code inside your CI jobs. A leaked Kubernetes agent token (glagent-) gives the attacker a foothold in your cluster.

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
