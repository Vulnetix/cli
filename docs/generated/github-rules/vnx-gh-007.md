---
title: "VNX-GH-007 – Workflow token permissions not declared"
description: "Neither the workflow nor the job declares permissions:, so the token gets the repository default."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Without a permissions: block the GITHUB_TOKEN gets the repository or organisation default, which for many repositories is read/write on every scope. Any compromised step — a vulnerable action, an injection — can then push code, publish packages or approve pull requests.

**Severity:** Medium | **Confidence:** medium | **CWE:** [CWE-250](https://cwe.mitre.org/data/definitions/250.html), [CWE-272](https://cwe.mitre.org/data/definitions/272.html) | **Command:** `vulnetix gha workflows`

**Uses, when available:** repo, to rate each finding against the repository's own configuration.

## Remediation

Add `permissions: {}` (or `contents: read`) at the top of the workflow, and grant individual jobs only the scopes they need.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:M/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
