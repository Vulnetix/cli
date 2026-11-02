---
title: "VNX-GH-308 – Organisation lets Actions approve pull requests"
description: "Workflows across the organisation may create and approve pull requests."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Repositories inherit this permission; a workflow token can then satisfy one-approval rules by approving its own pull request.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | **Command:** `vulnetix gha org`

**Needs:** org. Without them the rule is reported as not evaluated.

## Remediation

Disable "Allow GitHub Actions to create and approve pull requests" at the organisation level.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
