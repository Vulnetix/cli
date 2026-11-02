---
title: "VNX-GH-309 – Organisation webhook deliveries can be forged or intercepted"
description: "An organisation webhook has no secret, or disables TLS verification."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Organisation webhooks receive events from every repository. An unsigned or unverified hook lets an attacker forge or read them.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-345](https://cwe.mitre.org/data/definitions/345.html), [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | **Command:** `vulnetix gha org`

**Needs:** org. Without them the rule is reported as not evaluated.

## Remediation

Set a webhook secret and enable SSL verification.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:M/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
