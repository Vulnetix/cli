---
title: "VNX-TF-008 – Terraform AWS Provider with Hardcoded Static Credentials"
description: "Detect hardcoded AWS access_key and secret_key values in Terraform provider blocks, which expose long-lived IAM credentials to anyone who can read the source code or its git history."
---

## Overview

This rule flags Terraform `.tf` files where an AWS provider block contains `access_key` or `secret_key` attributes set to literal string values (non-empty strings that do not use variable references or Terraform expressions). AWS provider credentials hardcoded directly in Terraform files are committed to version control and exposed to everyone who has read access to the repository.

Unlike environment-injected credentials or IAM instance roles, hardcoded credentials in `.tf` files are static: they do not rotate, they do not expire automatically, and they persist in git history indefinitely. An attacker who obtains these credentials can authenticate to AWS from anywhere on the internet, using the full permissions of the associated IAM user.

This rule corresponds to [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html).

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

AWS access keys for IAM users are long-lived credentials that provide persistent, programmatic access to AWS resources. Unlike temporary credentials issued by IAM roles (which expire after hours), IAM user access keys remain valid until explicitly rotated or deleted. An attacker who extracts an access key from a Terraform file can use it indefinitely unless the key is revoked.

Terraform state files and configuration files are frequently stored in version control systems, CI/CD platform logs, and artifact stores — all of which may have weaker access controls than the production infrastructure they manage. A single compromised developer laptop or CI system that has access to the repository is sufficient to expose hardcoded credentials to an attacker.

Compromised Terraform provider credentials are particularly high-value because they typically have broad permissions: Terraform needs to create, modify, and delete infrastructure resources, so the associated IAM user or role often has significant access. An attacker using these credentials can provision additional infrastructure (for cryptomining), exfiltrate data from S3 and databases, modify security group rules to create backdoors, and cover their tracks by modifying CloudTrail settings.

## What Gets Flagged

The rule matches `.tf` files where `access_key` or `secret_key` attributes are set to literal string values (not Terraform variables or local references).

```hcl
# FLAGGED: hardcoded static credentials in provider block
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
```

## Remediation

1. **Use IAM instance roles or task roles.** When Terraform runs on an EC2 instance, ECS task, Lambda function, or CodeBuild project, the AWS provider automatically discovers credentials from the instance metadata service. No credentials need to be specified in the provider block:

```hcl
# SAFE: no credentials in provider — discovered from instance role
provider "aws" {
  region = "us-east-1"
  # credentials loaded from IAM role via instance metadata
}
```

2. **Use environment variables for local development and CI/CD.** The AWS provider reads `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` from the environment automatically:

```bash
# SAFE: inject credentials from environment — not committed to source
export AWS_ACCESS_KEY_ID="$(vault read -field=access_key aws/creds/deploy)"
export AWS_SECRET_ACCESS_KEY="$(vault read -field=secret_key aws/creds/deploy)"
terraform apply
```

3. **Use short-lived credentials from AWS IAM Identity Center (SSO) or Vault's AWS secrets engine** to ensure credentials rotate automatically and are never long-lived static keys.

4. **Revoke the hardcoded credentials immediately** in the AWS IAM console, then rewrite git history to remove them using `git filter-repo` or BFG Repo-Cleaner.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [Terraform AWS Provider – Authentication](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#authentication-and-configuration)
- [AWS IAM – Best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS IAM Identity Center documentation](https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html)
- [OWASP Infrastructure as Code Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
