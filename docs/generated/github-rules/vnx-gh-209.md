---
title: "VNX-GH-209 – GitHub Actions can approve pull requests"
description: "Workflows may create and approve pull requests."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

A workflow token that can approve pull requests satisfies a one-approval rule on its own: one compromised workflow opens and approves its own change.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, actions policy. Without them the rule is reported as not evaluated.

## Remediation

Disable "Allow GitHub Actions to create and approve pull requests".

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
