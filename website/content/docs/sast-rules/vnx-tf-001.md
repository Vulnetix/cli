---
title: "VNX-TF-001 – Terraform AWS S3 Bucket with Public ACL"
description: "Detect S3 buckets and objects in Terraform whose ACL grants access to everyone: public-read, public-read-write or authenticated-read canned ACLs, or grants to the AllUsers or AuthenticatedUsers groups, unless the bucket's own public access block (in any file) or the module's inputs neutralise them."
---

## Overview

This rule flags Terraform `.tf` files where an `aws_s3_bucket`, `aws_s3_bucket_acl`, `aws_s3_object`, `aws_s3_bucket_object` or `alicloud_oss_bucket` resource, or an S3 bucket module, sets `acl = "public-read"`, `"public-read-write"` or `"authenticated-read"`, or carries a `grant`/`grantee` whose `uri` is the `AllUsers` or `AuthenticatedUsers` group. It does not report private or log-delivery ACLs, ACLs taken from variables, grants to canonical users or the LogDelivery group, a bucket whose own `aws_s3_bucket_public_access_block` (in any file of the project) sets `block_public_acls` or `ignore_public_acls = true`, an S3 module whose own inputs set either, any bucket when an `aws_s3_account_public_access_block` in the project does, or comments.

S3 buckets with public ACLs have been the source of some of the largest data breaches in cloud computing history. Misconfigured buckets containing customer records, application backups, internal documentation, and cryptographic keys have been exposed to the internet, often without the owning organization's knowledge. AWS has introduced multiple safeguards over the years specifically because this misconfiguration is so common and so harmful.

This rule corresponds to [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html).

**Severity:** High | **CWE:** [CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Why This Matters

S3 buckets are used throughout AWS-based applications as the de facto storage layer for user uploads, application logs, static assets, data lake storage, database backups, and deployment artifacts. A bucket that is accidentally made public exposes every object in it to the entire internet, often including objects that were never intended to be public at all — log files, configuration backups, database dumps, and private user content.

An attacker who discovers a public bucket using automated scanning tools (which continuously probe AWS for misconfigured resources) can enumerate all objects in the bucket using the S3 list operation and download any or all of them without authentication. Because S3 access does not generate application-level logs by default (only S3 server access logs, if enabled), many organizations discover breaches months after the data was exfiltrated.

The `public-read-write` ACL is particularly dangerous: it allows anyone on the internet to not only read existing objects but also upload new objects to the bucket, potentially hosting malware, defacement content, or using the bucket's bandwidth for distribution.

## What Gets Flagged

```hcl
resource "aws_s3_bucket" "assets" {
  bucket = "acme-public-assets"
  acl    = "public-read"            # FLAGGED
}

resource "aws_s3_bucket_acl" "partners" {
  bucket = aws_s3_bucket.partners.id
  acl    = "authenticated-read"     # FLAGGED: any AWS account can read
}

resource "aws_s3_bucket" "downloads" {
  grant {
    type        = "Group"
    uri         = "http://acs.amazonaws.com/groups/global/AllUsers"   # FLAGGED
    permissions = ["READ"]
  }
}
```

Not flagged: `acl = "private"`, `acl = var.bucket_acl`, or a public ACL on a bucket whose public access block sets `ignore_public_acls = true`.

## Remediation

1. **Remove the public ACL and use `aws_s3_bucket_public_access_block` to block all public access.** This is the recommended approach for any bucket that should not be publicly accessible:

```hcl
# SAFE: private bucket with all public access blocked
resource "aws_s3_bucket" "uploads" {
  bucket = "my-app-uploads"
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

2. **For static website hosting, use CloudFront with an Origin Access Control instead of a public bucket.** This serves content publicly via CloudFront while keeping the bucket private:

```hcl
# SAFE: serve via CloudFront OAC — bucket remains private
resource "aws_cloudfront_origin_access_control" "default" {
  name                              = "my-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}
```

3. **Use pre-signed URLs for temporary public access to specific objects.** Rather than making a bucket or its objects permanently public, generate short-lived signed URLs for legitimate user downloads.

## References

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [AWS S3 – Blocking public access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [CIS AWS Foundations Benchmark – S3 controls](https://www.cisecurity.org/benchmark/amazon_web_services)
- [OWASP Infrastructure as Code Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
- [Terraform aws_s3_bucket_public_access_block documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block)
