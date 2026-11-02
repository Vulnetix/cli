---
title: "VNX-GH-202 – Default branch merges without review"
description: "Protection exists but requires no approving review."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Without a required approval a single account — or a single stolen credential — can land any change on the default branch.

**Severity:** High | **Confidence:** high | **CWE:** [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, branches. Without them the rule is reported as not evaluated.

## Remediation

Require at least one approving review (two for repositories that publish releases), and require approval of the most recent push.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
