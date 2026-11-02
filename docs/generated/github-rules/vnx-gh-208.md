---
title: "VNX-GH-208 – Workflow token defaults to write"
description: "Workflows without a permissions: block get a read/write token."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Every workflow that omits permissions: — including ones added later by contributors — runs with write access to contents, packages, issues and pull requests.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-250](https://cwe.mitre.org/data/definitions/250.html), [CWE-276](https://cwe.mitre.org/data/definitions/276.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, actions policy. Without them the rule is reported as not evaluated.

## Remediation

Set Settings → Actions → General → Workflow permissions to "Read repository contents and packages permissions".

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
