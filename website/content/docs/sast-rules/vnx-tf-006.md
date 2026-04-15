---
title: "VNX-TF-006 – Terraform AWS EC2 Instance Metadata Service v1 (IMDSv1) Enabled"
description: "Detect EC2 instances in Terraform that allow the legacy IMDSv1, which does not require a session token and is vulnerable to SSRF attacks that can steal IAM credentials from the metadata endpoint."
---

## Overview

This rule flags Terraform `.tf` files where an `aws_instance` resource either explicitly sets `http_tokens = "optional"` in its `metadata_options` block (enabling IMDSv1) or omits the `metadata_options` block entirely (which defaults to IMDSv1-enabled behaviour). IMDSv1 allows any HTTP request to `http://169.254.169.254/latest/meta-data/` — without a session token — to retrieve instance metadata, including IAM role credentials.

IMDSv2 (the more secure version) requires a preliminary PUT request to obtain a session token, which must be included in all subsequent metadata requests. This PUT request cannot be followed by standard HTTP redirect-following behavior, which prevents server-side request forgery (SSRF) attacks from being able to retrieve credentials from the metadata service.

This rule corresponds to [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html).

**Severity:** High | **CWE:** [CWE-918 – Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)

## Why This Matters

SSRF vulnerabilities allow an attacker to cause the server to make HTTP requests to arbitrary URLs. When IMDSv1 is enabled, an SSRF vulnerability in any application running on the EC2 instance can be used to retrieve IAM role credentials from `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>`. These temporary credentials can then be used from outside AWS to authenticate as the instance's IAM role.

This attack vector was used in the well-publicized 2019 Capital One data breach and in numerous other cloud breaches. The attacker exploited an SSRF vulnerability in a web application, retrieved IAM credentials from the metadata service, and used those credentials to exfiltrate data from S3 buckets. The breach affected over 100 million customers.

IMDSv1 credentials theft is particularly insidious because the IAM credentials retrieved are temporary (typically valid for 6 hours) but automatically rotate, giving the attacker ongoing access as long as the SSRF vulnerability persists. The attack does not require any special AWS knowledge — the endpoint is well-documented and the exploitation steps are publicly available.

## What Gets Flagged

The rule matches `.tf` files where `http_tokens = "optional"` is set or where an `aws_instance` resource lacks a `metadata_options` block entirely.

```hcl
# FLAGGED: IMDSv1 explicitly enabled
resource "aws_instance" "web" {
  ami           = var.ami_id
  instance_type = "t3.medium"
  metadata_options {
    http_tokens = "optional"
  }
}

# FLAGGED: missing metadata_options block — defaults to IMDSv1
resource "aws_instance" "web" {
  ami           = var.ami_id
  instance_type = "t3.medium"
  # no metadata_options block
}
```

## Remediation

1. **Add a `metadata_options` block with `http_tokens = "required"` to enforce IMDSv2.** This is the recommended configuration for all new EC2 instances:

```hcl
# SAFE: IMDSv2 enforced
resource "aws_instance" "web" {
  ami           = var.ami_id
  instance_type = "t3.medium"

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    http_endpoint               = "enabled"
  }
}
```

2. **Set `http_put_response_hop_limit = 1`** to prevent metadata service tokens from being accessed by containers on the instance (which would add a network hop, exceeding the limit of 1).

3. **Enforce IMDSv2 at the account level** using an SCP or IAM condition key:

```json
// SCP to deny launching instances without IMDSv2
{
  "Effect": "Deny",
  "Action": "ec2:RunInstances",
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": {
    "StringNotEquals": {
      "ec2:MetadataHttpTokens": "required"
    }
  }
}
```

4. **Update application code to use the IMDSv2 token header** if it makes direct calls to the metadata service (AWS SDKs handle this automatically when using the latest versions).

## References

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [AWS – Add defense in depth against open firewalls, reverse proxies, and SSRF with IMDSv2](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/)
- [AWS EC2 – IMDSv2 documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [CIS AWS Foundations Benchmark – EC2 metadata controls](https://www.cisecurity.org/benchmark/amazon_web_services)
- [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Terraform aws_instance metadata_options documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#metadata_options)
