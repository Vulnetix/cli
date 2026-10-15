---
title: "VNX-TF-006 – Terraform AWS EC2 Instance Metadata Service v1 (IMDSv1) Enabled"
description: "Detect EC2 instances and launch templates in Terraform that leave the token-less IMDSv1 enabled (http_tokens = \"optional\" in resources or the ec2-instance/autoscaling modules, metadata_options without http_tokens, or no metadata_options), which lets SSRF steal IAM credentials from the metadata endpoint."
---

## Overview

This rule flags Terraform `.tf` files where `http_tokens = "optional"` is set in the `metadata_options` of an `aws_instance`, `aws_launch_template` or `aws_launch_configuration`, where an `aws_instance` or `aws_launch_template` has a `metadata_options` block without `http_tokens`, or has no `metadata_options` block at all (both default to IMDSv1 enabled). It does not report `http_tokens = "required"`, a variable value, `http_endpoint = "disabled"`, an instance configured through a `launch_template` block, or any instance in a project that declares `aws_ec2_instance_metadata_defaults` with `http_tokens = "required"`. IMDSv1 allows any HTTP request to `http://169.254.169.254/latest/meta-data/`, without a session token, to retrieve instance metadata, including IAM role credentials.

IMDSv2 (the more secure version) requires a preliminary PUT request to obtain a session token, which must be included in all subsequent metadata requests. This PUT request cannot be followed by standard HTTP redirect-following behavior, which prevents server-side request forgery (SSRF) attacks from being able to retrieve credentials from the metadata service.

This rule corresponds to [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html).

**Severity:** High | **CWE:** [CWE-918 – Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)

## Why This Matters

SSRF vulnerabilities allow an attacker to cause the server to make HTTP requests to arbitrary URLs. When IMDSv1 is enabled, an SSRF vulnerability in any application running on the EC2 instance can be used to retrieve IAM role credentials from `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>`. These temporary credentials can then be used from outside AWS to authenticate as the instance's IAM role.

This attack vector was used in the well-publicized 2019 Capital One data breach and in numerous other cloud breaches. The attacker exploited an SSRF vulnerability in a web application, retrieved IAM credentials from the metadata service, and used those credentials to exfiltrate data from S3 buckets. The breach affected over 100 million customers.

IMDSv1 credentials theft is particularly insidious because the IAM credentials retrieved are temporary (typically valid for 6 hours) but automatically rotate, giving the attacker ongoing access as long as the SSRF vulnerability persists. The attack does not require any special AWS knowledge — the endpoint is well-documented and the exploitation steps are publicly available.

## What Gets Flagged

```hcl
resource "aws_instance" "api" {
  metadata_options {
    http_tokens = "optional"          # FLAGGED: IMDSv1 explicitly enabled
  }
}

resource "aws_instance" "web" {       # FLAGGED: no metadata_options block
  ami           = var.ami_id
  instance_type = "t3.medium"
}

resource "aws_instance" "runner" {
  metadata_options {                  # FLAGGED: http_tokens defaults to optional
    http_put_response_hop_limit = 1
  }
}
```

Not flagged: `http_tokens = "required"`, `http_endpoint = "disabled"`, or an account-level `aws_ec2_instance_metadata_defaults` that requires tokens.

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
