---
title: "VNX-GH-205 – Force pushes or deletion allowed on the default branch"
description: "Protection permits force pushes or deleting the branch."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

A force push rewrites history that downstream builds, tags and audits rely on, and can remove a reviewed change after the fact.

**Severity:** High | **Confidence:** high | **CWE:** [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, branches. Without them the rule is reported as not evaluated.

## Remediation

Block force pushes and deletions on the default branch.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
