---
title: "VNX-TF-005 – Terraform AWS EBS Volume Unencrypted"
description: "Detect EBS volumes in Terraform created without encryption at rest: encrypted = false on volumes, snapshot copies, instance block devices and launch templates, or an aws_ebs_volume that sets neither encrypted nor snapshot_id, unless the account enables EBS encryption by default."
---

## Overview

This rule flags Terraform `.tf` files where `encrypted = false` is set inside an `aws_ebs_volume`, `aws_ebs_snapshot_copy`, an `aws_instance`/`aws_spot_instance_request`/`aws_launch_configuration` block device, or the `ebs` block of an `aws_launch_template`, and an `aws_ebs_volume` that sets neither `encrypted` nor `snapshot_id` (the default is unencrypted, and a commented-out `encrypted` line does not count). Nothing is reported when the project declares `aws_ebs_encryption_by_default` with `enabled = true`, because AWS then encrypts every new volume; a value from a variable and a volume restored from a snapshot are not reported either.

EBS volumes store the persistent data for EC2 instances: operating system files, application data, database files, and log data. An unencrypted EBS volume stores this data in plaintext on the physical disk. AWS personnel with physical data center access, automated backup and snapshot systems, and anyone who obtains a copy of a leaked or misconfigured snapshot can read the data without any further authentication.

This rule corresponds to [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html).

**Severity:** High | **CWE:** [CWE-311 – Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

## Why This Matters

EBS encryption protects data at rest with no performance overhead on modern instance types (AES-256 via AWS KMS). Its absence means that data is stored in plaintext throughout its lifecycle — including during snapshot creation (which is used for backups, AMI creation, and cross-region replication) and volume sharing.

EBS snapshots are a particularly common exposure vector. Many organizations make snapshots to facilitate cross-account or cross-region copies, and a misconfigured permission allows a snapshot to be made public. AWS's security advisory history contains multiple incidents of public snapshots exposing sensitive data — including database content, source code, and credentials. Unencrypted snapshots that are publicly shared expose the entire volume's contents. Encrypted snapshots shared across accounts require explicit KMS key grants, providing an additional access control layer.

For databases running on EBS (MySQL, PostgreSQL, or other self-managed databases), unencrypted volumes mean that a database dump taken from the raw volume — bypassing all database-level authentication — would expose all data in plaintext.

## What Gets Flagged

```hcl
resource "aws_ebs_volume" "data" {
  availability_zone = "eu-west-1a"
  size              = 100
  encrypted         = false           # FLAGGED
}

resource "aws_ebs_volume" "scratch" {   # FLAGGED: no encrypted attribute
  availability_zone = "eu-west-1b"
  size              = 50
}

resource "aws_instance" "app" {
  root_block_device {
    encrypted = false                 # FLAGGED
  }
}
```

Not flagged: `encrypted = true`, `snapshot_id = aws_ebs_snapshot.encrypted.id`, or `storage_encrypted = false` on a database (a different resource).

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
