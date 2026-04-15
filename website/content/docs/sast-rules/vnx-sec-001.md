---
title: "VNX-SEC-001 – AWS Access Key ID"
description: "Detects hardcoded AWS access key IDs (AKIA prefix) in source code, which enable account takeover and unauthorized resource access if exposed."
---

## Overview

This rule detects AWS access key IDs matching the `AKIA[0-9A-Z]{16}` pattern hardcoded anywhere in source files. AWS access key IDs are one half of the credential pair used for programmatic access to AWS services; combined with the corresponding secret access key (detected by VNX-SEC-003), they grant full API access to whatever IAM permissions the key owner holds. Hardcoding them in source code puts them at risk of exposure through public repositories, code review tools, or log files.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

AWS access key IDs committed to a repository have been the root cause of some of the largest cloud breaches on record. Automated bots continuously scan GitHub, GitLab, and Bitbucket for `AKIA` prefixes; a key can be found and abused within minutes of a public push. A compromised key can be used to spin up EC2 instances for crypto mining, exfiltrate data from S3 buckets, pivot through IAM roles, or destroy an entire AWS environment. The 2019 Capital One breach and numerous smaller incidents traced back to exposed AWS credentials.

Even in private repositories, keys exposed in git history persist indefinitely. Any developer or CI system with read access to the repo can extract credentials from old commits. GitHub Secret Scanning automatically detects `AKIA` prefixes and will alert you — but remediation is still required.

## What Gets Flagged

Any source file line containing a 20-character string starting with `AKIA` followed by uppercase letters and digits.

```python
# FLAGGED: hardcoded AWS access key ID
import boto3

client = boto3.client(
    's3',
    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
)
```

```yaml
# FLAGGED: key in a config file
aws:
  access_key_id: AKIAIOSFODNN7EXAMPLE
  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

## Remediation

1. **Rotate the key immediately.** Log into the AWS Console, go to IAM → Users → Security credentials, and create a new access key. Do not delete the old key yet — confirm the new key works first, then delete the compromised one. Alternatively use the CLI: `aws iam create-access-key --user-name <username>`.

2. **Verify exposure.** Run `aws sts get-caller-identity --profile <compromised-profile>` to confirm the key is still active. Check CloudTrail for any API calls made using the key since it was committed.

3. **Remove from source code.** Replace the hardcoded value with an environment variable read:

```python
# SAFE: load credentials from environment
import boto3
import os

client = boto3.client(
    's3',
    aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
    aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY']
)
```

For production workloads running on AWS, eliminate static keys entirely by using IAM roles attached to EC2 instances, ECS tasks, or Lambda functions — boto3 will automatically pick up instance profile credentials.

4. **Store the new key securely.** Use AWS Secrets Manager, AWS Systems Manager Parameter Store (SecureString), GitHub Actions secrets, or HashiCorp Vault. Never write the value to a file that is tracked by git.

5. **Scan git history.** Even after removing the key from the current code, it persists in history. Use `git-filter-repo` or BFG Repo Cleaner to purge it:

```bash
# Using git-filter-repo
pip install git-filter-repo
git filter-repo --replace-text <(echo 'AKIAIOSFODNN7EXAMPLE==>REDACTED')
```

Run truffleHog or gitleaks on the cleaned history to confirm no other secrets remain:

```bash
gitleaks detect --source . --verbose
trufflehog git file://. --since-commit HEAD~50
```

6. **Enable GitHub Secret Scanning and push protection** in your repository settings so future commits containing `AKIA` patterns are blocked before they reach the remote.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP: Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [git-filter-repo](https://github.com/newren/git-filter-repo)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [CAPEC-191: Read Sensitive Constants Within an Executable](https://capec.mitre.org/data/definitions/191.html)
