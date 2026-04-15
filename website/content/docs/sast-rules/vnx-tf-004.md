---
title: "VNX-TF-004 – Terraform IAM Policy with Wildcard Action (*)"
description: "Detect AWS IAM policies in Terraform that grant wildcard actions (*) without a corresponding Deny statement, violating the principle of least privilege and enabling privilege escalation."
---

## Overview

This rule flags Terraform `.tf` files where an IAM policy resource — `aws_iam_role_policy`, `aws_iam_policy`, `aws_iam_user_policy`, `aws_iam_group_policy`, or `aws_iam_policy_document` — grants `Action = "*"` or `actions = ["*"]` without a corresponding `Effect = "Deny"` statement. A wildcard action in an Allow statement grants the principal permission to perform every AWS API action across all services.

Least-privilege IAM policies are the foundational access control mechanism in AWS. When a policy grants `Action = "*"`, the associated role, user, or group can perform any operation on any resource in the account that is not blocked by a Service Control Policy (SCP) — including creating new IAM users, modifying security group rules, exfiltrating data from S3, or deleting production resources.

This rule corresponds to [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html).

**Severity:** High | **CWE:** [CWE-269 – Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

## Why This Matters

Overly permissive IAM policies are one of the most common misconfigurations in AWS environments and a primary vector for privilege escalation. An attacker who compromises a workload running with an overly permissive role — through application-level vulnerabilities, container escape, SSRF, or credential theft — inherits all the permissions of that role.

A wildcard `Action = "*"` policy effectively grants administrative access. Even if the resource scope is limited (e.g., `Resource = "arn:aws:s3:::my-bucket/*"`), combined with a broad resource or `Resource = "*"`, it grants full administrative control over the account. This means a compromised Lambda function, EC2 instance, or ECS task can create new IAM users with console access, modify CloudTrail settings to disable audit logging, exfiltrate secrets from Secrets Manager, and pivot to any other AWS service.

The risk extends beyond direct exploitation: over-permissive roles make the blast radius of any compromise much larger and make incident response much harder, since you cannot determine what an attacker did or did not access.

## What Gets Flagged

The rule matches `.tf` files where `Action = "*"` or `actions = ["*"]` appears in an IAM policy context without a Deny effect.

```hcl
# FLAGGED: wildcard Action grants all AWS API permissions
resource "aws_iam_role_policy" "app_policy" {
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# FLAGGED: wildcard in policy document data source
data "aws_iam_policy_document" "lambda" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}
```

## Remediation

1. **Enumerate only the specific actions required by the workload.** Review what the application actually does and grant only those actions. Use AWS IAM Access Analyzer to identify the minimum permissions from CloudTrail logs:

```hcl
# SAFE: minimal permissions for a specific task
resource "aws_iam_role_policy" "app_policy" {
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "arn:aws:s3:::${var.bucket_name}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage"]
        Resource = aws_sqs_queue.work_queue.arn
      }
    ]
  })
}
```

2. **Use AWS managed policies with defined scopes as a starting point**, then restrict further. Prefer service-specific managed policies (e.g., `AmazonS3ReadOnlyAccess`) over `AdministratorAccess`.

3. **Use IAM Access Analyzer to generate least-privilege policies** from actual usage. This automatically produces a policy containing only the actions that were observed in CloudTrail logs during a review period.

## References

- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- [AWS IAM – Grant least privilege](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege)
- [AWS IAM Access Analyzer – Policy generation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html)
- [CIS AWS Foundations Benchmark – IAM controls](https://www.cisecurity.org/benchmark/amazon_web_services)
- [OWASP Infrastructure as Code Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
- [Terraform aws_iam_policy_document documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document)
