---
title: "VNX-GH-203 – Approvals survive new commits"
description: "Stale reviews are not dismissed and approval of the last push is not required."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

An author can get a harmless change approved, then push different code and merge on the old approval.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, branches. Without them the rule is reported as not evaluated.

## Remediation

Enable dismiss stale approvals and require approval of the most recent reviewable push.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
