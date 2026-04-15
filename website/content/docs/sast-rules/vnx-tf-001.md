---
title: "VNX-TF-001 – Terraform AWS S3 Bucket with Public ACL"
description: "Detect AWS S3 buckets configured with public-read or public-read-write ACLs in Terraform, which make all bucket contents accessible to the entire internet."
---

## Overview

This rule flags Terraform `.tf` files where an S3 bucket resource is configured with `acl = "public-read"` or `acl = "public-read-write"`. These ACL values instruct AWS to grant read or full access to the bucket and all of its objects to any anonymous internet user, without any authentication required.

S3 buckets with public ACLs have been the source of some of the largest data breaches in cloud computing history. Misconfigured buckets containing customer records, application backups, internal documentation, and cryptographic keys have been exposed to the internet, often without the owning organization's knowledge. AWS has introduced multiple safeguards over the years specifically because this misconfiguration is so common and so harmful.

This rule corresponds to [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html).

**Severity:** High | **CWE:** [CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Why This Matters

S3 buckets are used throughout AWS-based applications as the de facto storage layer for user uploads, application logs, static assets, data lake storage, database backups, and deployment artifacts. A bucket that is accidentally made public exposes every object in it to the entire internet, often including objects that were never intended to be public at all — log files, configuration backups, database dumps, and private user content.

An attacker who discovers a public bucket using automated scanning tools (which continuously probe AWS for misconfigured resources) can enumerate all objects in the bucket using the S3 list operation and download any or all of them without authentication. Because S3 access does not generate application-level logs by default (only S3 server access logs, if enabled), many organizations discover breaches months after the data was exfiltrated.

The `public-read-write` ACL is particularly dangerous: it allows anyone on the internet to not only read existing objects but also upload new objects to the bucket, potentially hosting malware, defacement content, or using the bucket's bandwidth for distribution.

## What Gets Flagged

The rule matches `.tf` files containing `acl = "public-read"` or `acl = "public-read-write"`.

```hcl
# FLAGGED: public-read ACL exposes all objects to the internet
resource "aws_s3_bucket" "uploads" {
  bucket = "my-app-uploads"
  acl    = "public-read"
}

# FLAGGED: public-read-write allows unauthenticated uploads
resource "aws_s3_bucket" "assets" {
  bucket = "my-app-assets"
  acl    = "public-read-write"
}
```

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
