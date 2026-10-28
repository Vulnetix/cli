---
title: "VNX-GH-214 – Environment secrets deployable without approval"
description: "An environment holds secrets but has no required reviewers and no branch policy."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Environment secrets exist so that only gated jobs see them. An ungated environment gives its secrets to any job on any branch that names it — including a branch pushed by any writer.

**Severity:** High | **Confidence:** high | **CWE:** [CWE-284](https://cwe.mitre.org/data/definitions/284.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, environments. Without them the rule is reported as not evaluated.

## Remediation

Add required reviewers (with prevent self-review) or restrict the environment to protected branches.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
