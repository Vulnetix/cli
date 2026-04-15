---
title: "VNX-SEC-003 – AWS Secret Access Key"
description: "Detects hardcoded AWS secret access keys in source code, which combined with an access key ID grant full programmatic access to AWS services."
kind: secrets
---

## Overview

This rule detects AWS secret access keys embedded in source files by matching variable names such as `aws_secret`, `secret_access_key`, or `aws_secret_access_key` assigned to a 40-character base64 string. The AWS secret access key is the second half of the AWS credential pair; alone it is insufficient for authentication, but when combined with an access key ID (detected by VNX-SEC-001) it provides complete programmatic access to AWS APIs. These two values almost always appear together in the same file or nearby.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

AWS credentials are one of the most targeted secrets in automated scanning operations. Malicious bots continuously crawl public repositories for patterns matching AWS secret keys; a key can be abused for crypto mining, data exfiltration, or infrastructure destruction within minutes of exposure. Secret access keys are 40 characters of base64 and do not have a distinctive prefix like access key IDs, making them harder to detect visually — but the rule matches them by context (the surrounding variable name).

Unlike a password that might be rotated periodically, AWS keys remain valid until explicitly rotated or deleted. Every git clone, CI/CD artifact, or log containing the key becomes a potential leak vector. VNX-SEC-001 and VNX-SEC-003 are designed to be used together since these two values always travel as a pair.

## What Gets Flagged

Variable assignments where the key name indicates an AWS secret and the value is a 40-character alphanumeric string.

```python
# FLAGGED: hardcoded AWS secret access key
import boto3

session = boto3.Session(
    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
)
```

```ini
# FLAGGED: in a config file
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

## Remediation

1. **Rotate the access key immediately.** In the AWS Console go to IAM → Users → your user → Security credentials → Create access key. Delete the old key once the new one is confirmed working.

2. **Verify whether the key was used maliciously.** Check AWS CloudTrail for API calls from the compromised key. Look especially for `iam:CreateUser`, `ec2:RunInstances`, `s3:GetObject`, and `sts:AssumeRole` calls that you did not make.

3. **Remove from source code.** Replace hardcoded values with environment variable lookups:

```python
# SAFE: load from environment
import boto3
import os

session = boto3.Session(
    aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
    aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY']
)
```

For services running on AWS (EC2, ECS, Lambda), use IAM instance roles or task roles — no static keys are needed at all. The SDK picks up credentials automatically from instance metadata.

4. **Use AWS Secrets Manager for non-AWS-hosted workloads:**

```python
# SAFE: fetch from AWS Secrets Manager at runtime
import boto3
import json

def get_aws_credentials():
    client = boto3.client('secretsmanager', region_name='us-east-1')
    secret = client.get_secret_value(SecretId='prod/app/aws-credentials')
    return json.loads(secret['SecretString'])
```

5. **Scan git history** for any traces of the key, then rewrite history with `git-filter-repo` if found:

```bash
git filter-repo --replace-text <(echo 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY==>REDACTED')
gitleaks detect --source . --verbose
```

6. **Set environment variables in CI/CD.** Use GitHub Actions secrets, GitLab CI/CD variables, or your pipeline's secrets management — never hardcode in workflow files either.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP: Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [AWS IAM Best Practices – Use roles instead of long-term access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS Secrets Manager documentation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
