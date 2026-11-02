---
title: "VNX-GH-218 – Signed commits not required"
description: "The default branch accepts unsigned commits."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Commit author fields are free text. Without signature verification a commit can claim any author, which undermines audit trails and author-based automation.

**Severity:** Low | **Confidence:** high | **CWE:** [CWE-345](https://cwe.mitre.org/data/definitions/345.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, branches. Without them the rule is reported as not evaluated.

## Remediation

Require signed commits on the default branch.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:L/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
