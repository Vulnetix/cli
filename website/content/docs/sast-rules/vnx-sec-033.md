---
title: "VNX-SEC-033 – AWS Bedrock Long-Lived API Key"
description: "Detects hardcoded AWS Bedrock long-lived API keys (ABSK prefix) that grant programmatic access to Anthropic, Cohere, Meta, Mistral and Stability models."
---

## Overview

This rule detects AWS Bedrock long-lived API keys matching the `ABSK[A-Za-z0-9+/]{109,269}={0,2}` pattern hardcoded anywhere in source files. Bedrock long-lived keys are valid until explicitly revoked and grant full programmatic access to every foundation model the IAM principal is allowed to call. Combined with prompt-injection attacks, a leaked Bedrock key can be abused to run up large bills, exfiltrate user data sent to the model, or train downstream attackers on a competitor's prompts.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) | **OWASP ASVS v4:** V2.10.1, V2.10.4

## Why This Matters

Anthropic, Cohere, Meta Llama, Mistral, Stability, and Amazon Titan models are all served through Bedrock. A leaked key lets any attacker who finds it run inference, fine-tune models, and consume provisioned throughput — the cost of which is charged to your AWS account. Unlike `AKIA` access keys, Bedrock keys are not surfaced by GitHub Secret Scanning's partner program, so they often linger in public repos for weeks before revocation.

## What Gets Flagged

Any source file line containing a 100+ character base64 string starting with `ABSK`.

## Remediation

1. **Revoke the key in IAM → Users → Security credentials → API keys.** Treat it as compromised even if you only saw the leak in a private scanner report.
2. **Replace with short-lived credentials.** Bedrock supports IAM Identity Center (SSO) tokens and SigV4-signed requests from an assumed role. Both avoid static keys entirely.
3. **Set up a usage alarm.** CloudWatch metric `CallCount` for `bedrock-runtime:InvokeModel` will fire on any anomalous call from a new region or service.
4. **Purge from git history** with `git filter-repo` or BFG, then re-scan the cleaned repo with `gitleaks detect --source .`.
5. **Enable AWS CloudTrail Lake integration** with this repo to confirm whether the key was used by an attacker.

## References

- [AWS Bedrock Authentication and access control](https://docs.aws.amazon.com/bedrock/latest/userguide/auth-iam.html)
- [AWS long-term vs short-term credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [gitleaks](https://github.com/gitleaks/gitleaks) — uses the same `aws-amazon-bedrock-api-key-long-lived` rule
- [truffleHog](https://github.com/trufflesecurity/trufflehog) — verifier for AWS keys
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
