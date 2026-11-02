---
title: "VNX-GH-011 – Secrets context exposed in bulk"
description: "toJSON(secrets) or a computed secrets[...] index loads every secret into the job."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Secrets are only sent to a runner when referenced. toJSON(secrets) or a dynamic index forces every secret the workflow can see onto the runner, so a single compromised step can read all of them, and log masking is weaker for structured values.

**Severity:** High | **Confidence:** high | **CWE:** [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-532](https://cwe.mitre.org/data/definitions/532.html) | **Command:** `vulnetix gha workflows`

## Remediation

Reference each secret by name, only in the step that needs it.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
