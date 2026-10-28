---
title: "VNX-GH-201 – Default branch is not protected"
description: "Neither branch protection nor a ruleset applies to the default branch."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Anyone with write access — including a compromised token, a leaked deploy key, or a workflow with contents: write — can push directly to the default branch, rewrite its history or delete it, and the change ships without review.

**Severity:** High | **Confidence:** high | **CWE:** [CWE-284](https://cwe.mitre.org/data/definitions/284.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, branches. Without them the rule is reported as not evaluated.

## Remediation

Add a ruleset targeting the default branch that requires pull requests with at least one approval, blocks force pushes and deletions, and requires status checks.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
