---
title: "VNX-SEC-001 – AWS Access Key ID"
description: "Detects hardcoded AWS access key IDs (AKIA prefix) in source code, which enable account takeover and unauthorized resource access if exposed."
---

## Overview

This rule detects AWS access key IDs matching the `AKIA[0-9A-Z]{16}` pattern hardcoded anywhere in source files. AWS access key IDs are one half of the credential pair used for programmatic access to AWS services; combined with the corresponding secret access key (detected by VNX-SEC-003), they grant full API access to whatever IAM permissions the key owner holds. Hardcoding them in source code puts them at risk of exposure through public repositories, code review tools, or log files.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) | **OWASP ASVS v4:** V2.10.1, V2.10.4

## Why This Matters

AWS access key IDs committed to a repository have been the root cause of some of the largest cloud breaches on record. Automated bots continuously scan GitHub, GitLab, and Bitbucket for `AKIA` prefixes; a key can be found and abused within minutes of a public push. A compromised key can be used to spin up EC2 instances for crypto mining, exfiltrate data from S3 buckets, pivot through IAM roles, or destroy an entire AWS environment. The 2019 Capital One breach and numerous smaller incidents traced back to exposed AWS credentials.

Even in private repositories, keys exposed in git history persist indefinitely. Any developer or CI system with read access to the repo can extract credentials from old commits. GitHub Secret Scanning automatically detects `AKIA` prefixes and will alert you — but remediation is still required.

Hardcoded secrets are never secure — there is no "safe" value to use as a placeholder or default. Any `AKIA` pattern in source code must be treated as compromised.

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

## Detecting a Compromise

Before rotating, determine whether the key was actually used by an attacker:

```bash
# Check CloudTrail for API calls using the compromised key
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAIOSFODNN7EXAMPLE \
  --start-time 2024-01-01T00:00:00Z

# Check for unauthorized IAM changes
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser

# Use AWS Access Advisor to see what services the key accessed
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d
```

Look especially for `iam:CreateUser`, `iam:CreateAccessKey`, `ec2:RunInstances`, `s3:GetObject`, and `sts:AssumeRole` calls you did not initiate. The AWS GuardDuty service will generate `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` or similar findings if the key was misused.

## Remediation

1. **Rotate the key immediately.** Log into the AWS Console, go to IAM → Users → Security credentials, and create a new access key. Do not delete the old key yet — confirm the new key works first, then delete the compromised one. Alternatively use the CLI: `aws iam create-access-key --user-name <username>`.

2. **Remove from source code.** Replace the hardcoded value with an environment variable read:

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

3. **Store the new key securely.** Use AWS Secrets Manager, AWS Systems Manager Parameter Store (SecureString), GitHub Actions secrets, or HashiCorp Vault. Never write the value to a file that is tracked by git.

```bash
# Store in AWS Secrets Manager
aws secretsmanager create-secret \
  --name prod/app/aws-credentials \
  --secret-string '{"aws_access_key_id":"AKIA...","aws_secret_access_key":"..."}'
```

4. **Scan git history.** Even after removing the key from the current code, it persists in history. Use `git-filter-repo` or BFG Repo Cleaner to purge it:

```bash
# Using git-filter-repo
pip install git-filter-repo
git filter-repo --replace-text <(echo 'AKIAIOSFODNN7EXAMPLE==>REDACTED')
```

Run truffleHog, gitleaks, or detect-secrets on the cleaned history to confirm no other secrets remain:

```bash
# gitleaks
gitleaks detect --source . --verbose

# truffleHog
trufflehog git file://. --since-commit HEAD~50

# detect-secrets
pip install detect-secrets
detect-secrets scan . > .secrets.baseline
detect-secrets audit .secrets.baseline
```

5. **Enable GitHub Secret Scanning and push protection** in your repository settings so future commits containing `AKIA` patterns are blocked before they reach the remote.

6. **Prefer IAM roles over long-term access keys.** For CI/CD pipelines, use OIDC federation to assume IAM roles without any static credentials:

```yaml
# GitHub Actions OIDC federation — no stored AWS keys needed
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
    aws-region: us-east-1
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP ASVS v4 – V2.10: Service Authentication Requirements](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP: Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS: Using IAM roles instead of long-term access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [truffleHog](https://github.com/trufflesecurity/trufflehog)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [git-filter-repo](https://github.com/newren/git-filter-repo)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [CAPEC-191: Read Sensitive Constants Within an Executable](https://capec.mitre.org/data/definitions/191.html)
