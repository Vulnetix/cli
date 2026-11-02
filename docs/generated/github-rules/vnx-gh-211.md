---
title: "VNX-GH-211 – Any action may run"
description: "The allowed-actions policy permits every action and reusable workflow."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

With no allow-list a contributor can introduce any third-party action in a pull request, and it runs on merge with the workflow's token and secrets.

**Severity:** Low | **Confidence:** high | **CWE:** [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, actions policy. Without them the rule is reported as not evaluated.

## Remediation

Allow GitHub-owned and verified-creator actions plus an explicit list, and require SHA pinning.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:M/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
