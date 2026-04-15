---
title: "VNX-TF-005 – Terraform AWS EBS Volume Unencrypted"
description: "Detect AWS EBS volumes and launch configurations in Terraform that have encryption disabled or missing, exposing data at rest to anyone who accesses the underlying physical storage or a leaked snapshot."
---

## Overview

This rule flags Terraform `.tf` files where an EBS-related resource — `aws_ebs_volume`, `aws_launch_configuration`, or `aws_launch_template` — either explicitly sets `encrypted = false` or omits the `encrypted` attribute entirely (in the case of `aws_ebs_volume`, where the default is unencrypted).

EBS volumes store the persistent data for EC2 instances: operating system files, application data, database files, and log data. An unencrypted EBS volume stores this data in plaintext on the physical disk. AWS personnel with physical data center access, automated backup and snapshot systems, and anyone who obtains a copy of a leaked or misconfigured snapshot can read the data without any further authentication.

This rule corresponds to [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html).

**Severity:** High | **CWE:** [CWE-311 – Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

## Why This Matters

EBS encryption protects data at rest with no performance overhead on modern instance types (AES-256 via AWS KMS). Its absence means that data is stored in plaintext throughout its lifecycle — including during snapshot creation (which is used for backups, AMI creation, and cross-region replication) and volume sharing.

EBS snapshots are a particularly common exposure vector. Many organizations make snapshots to facilitate cross-account or cross-region copies, and a misconfigured permission allows a snapshot to be made public. AWS's security advisory history contains multiple incidents of public snapshots exposing sensitive data — including database content, source code, and credentials. Unencrypted snapshots that are publicly shared expose the entire volume's contents. Encrypted snapshots shared across accounts require explicit KMS key grants, providing an additional access control layer.

For databases running on EBS (MySQL, PostgreSQL, or other self-managed databases), unencrypted volumes mean that a database dump taken from the raw volume — bypassing all database-level authentication — would expose all data in plaintext.

## What Gets Flagged

The rule matches `.tf` files where an EBS resource has `encrypted = false` explicitly, and also matches `aws_ebs_volume` resources that do not contain the `encrypted` attribute at all.

```hcl
# FLAGGED: explicitly disabled encryption
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

# FLAGGED: missing encrypted attribute on aws_ebs_volume
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  # encrypted attribute absent — defaults to false
}

# FLAGGED: launch template with unencrypted root block device
resource "aws_launch_template" "app" {
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      encrypted = false
    }
  }
}
```

## Remediation

1. **Enable encryption and specify a KMS key.** Using a customer-managed KMS key (CMK) provides additional control over who can access the key, enabling key rotation and access auditing:

```hcl
# SAFE: EBS volume encrypted with a customer-managed KMS key
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs.arn
}

resource "aws_kms_key" "ebs" {
  description             = "KMS key for EBS volume encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}
```

2. **Enable account-level EBS encryption by default.** AWS supports a per-region setting that encrypts all new EBS volumes and snapshots by default. This can also be enforced via Terraform:

```hcl
# SAFE: enable EBS encryption by default for the entire account/region
resource "aws_ebs_encryption_by_default" "default" {
  enabled = true
}
```

3. **For launch templates and configurations**, encrypt root and data block devices explicitly:

```hcl
# SAFE: encrypted root volume in launch template
resource "aws_launch_template" "app" {
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      encrypted  = true
      kms_key_id = aws_kms_key.ebs.arn
    }
  }
}
```

## References

- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
- [AWS EBS – Encryption](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html)
- [AWS EBS – Encryption by default](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/encryption-by-default.html)
- [CIS AWS Foundations Benchmark – EBS encryption controls](https://www.cisecurity.org/benchmark/amazon_web_services)
- [OWASP Infrastructure as Code Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
- [Terraform aws_ebs_volume documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_volume)
