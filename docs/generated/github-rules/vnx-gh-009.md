---
title: "VNX-GH-009 – OIDC token minted outside a protected environment"
description: "A job with id-token: write is not bound to an environment with reviewers or a branch policy."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

id-token: write lets the job request an OIDC token that cloud providers exchange for credentials. Cloud trust policies commonly match on repository only; without an environment gate, any branch, and any code that can run in that job, can obtain cloud credentials.

**Severity:** Medium | **Confidence:** medium | **CWE:** [CWE-285](https://cwe.mitre.org/data/definitions/285.html), [CWE-863](https://cwe.mitre.org/data/definitions/863.html) | **Command:** `vulnetix gha workflows`

**Uses, when available:** environments, to rate each finding against the repository's own configuration.

## Remediation

Bind the job to an environment with required reviewers or a protected-branch policy, and scope the cloud trust policy's subject to that environment (repo:owner/name:environment:prod).

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
