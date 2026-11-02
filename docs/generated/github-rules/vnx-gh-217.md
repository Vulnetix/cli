---
title: "VNX-GH-217 – Outside collaborator with admin access"
description: "Someone outside the organisation can change protection, secrets and settings."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Admin access includes disabling branch protection, reading environment configuration and adding deploy keys. Outside collaborators are not covered by the organisation's 2FA, SSO and offboarding.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-269](https://cwe.mitre.org/data/definitions/269.html) | **Command:** `vulnetix gha settings`

**Needs:** collaborators. Without them the rule is reported as not evaluated.

## Remediation

Reduce outside collaborators to write or lower, or bring them into the organisation.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
