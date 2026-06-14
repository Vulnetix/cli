---
title: "VNX-SEC-034 – Alibaba Cloud Access Key"
description: "Detects hardcoded Alibaba Cloud access key IDs (LTAI prefix) which grant full access to the holder's Alibaba Cloud RAM permissions."
---

## Overview

This rule detects Alibaba Cloud access key IDs matching the `LTAI[a-z0-9]{20}` pattern. Alibaba keys are 24 characters long, always begin with `LTAI`, and grant the holder the RAM permissions of the associated user. They are frequently committed by developers working with Aliyun OSS, ECS, or Function Compute.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) | **OWASP ASVS v4:** V2.10.1, V2.10.4

## Why This Matters

Alibaba Cloud hosts a large share of Asia-Pacific e-commerce workloads. A leaked key allows an attacker to spin up ECS instances for cryptomining, exfiltrate OSS bucket contents, manipulate RDS databases, or pivot through RAM roles. Alibaba's RAM service provides CloudTrail-equivalent audit logs via ActionTrail; review `CreateAccessKey`, `RunInstances`, and `GetObject` calls you did not initiate.

## What Gets Flagged

```python
# FLAGGED
aliyun_client = OssClient(
    access_key_id="LTAI5t7D9cXfK3mZ8nQ2bJ4e",
    access_key_secret="bVc7Yt1QwErTyUiOpAsDfGhJkLzXcVbNm",
)
```

## Remediation

1. **Revoke the key in the Alibaba Cloud RAM console** → Users → AccessKey. Do not delete until you have rotated.
2. **Replace with RAM Role + STS tokens** when running on ECS, ECI, or Function Compute — STS tokens expire in 1 hour by default.
3. **Purge from git history** with `git filter-repo` then re-scan with `gitleaks detect --source .`.
4. **Enable ActionTrail** if not already on, so you can audit any unauthorised use.
5. **Adopt the principle of least privilege**: even the new key should only carry the permissions the workload strictly needs.

## References

- [Alibaba Cloud RAM access keys](https://www.alibabacloud.com/help/en/ram/user-guide/create-an-accesskey-pair)
- [Alibaba Cloud STS](https://www.alibabacloud.com/help/en/ram/user-guide/overview-of-sts)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [gitleaks `alibaba-access-key-id`](https://github.com/gitleaks/gitleaks)
- [MITRE ATT&CK T1552.001](https://attack.mitre.org/techniques/T1552/001/)
