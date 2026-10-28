---
title: "VNX-GH-207 – No required status checks"
description: "Pull requests can merge with failing or missing CI."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Security checks (tests, scanners, signature verification) only protect the branch if a failing result blocks the merge.

**Severity:** Low | **Confidence:** high | **CWE:** [CWE-754](https://cwe.mitre.org/data/definitions/754.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, branches. Without them the rule is reported as not evaluated.

## Remediation

Require the security-relevant checks to pass before merging.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:L/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
