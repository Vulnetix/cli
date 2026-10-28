---
title: "VNX-GH-008 – Excessive token permissions"
description: "The token is granted write-all, or write scopes at workflow level that every job inherits."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

write-all grants every scope including actions, packages, pages and id-token. Workflow-level write scopes apply to every job, including jobs that run untrusted code or third-party actions.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-250](https://cwe.mitre.org/data/definitions/250.html), [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | **Command:** `vulnetix gha workflows`

## Remediation

Use `permissions: {}` at the workflow level and grant each job only the specific scopes it needs.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
