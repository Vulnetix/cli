---
title: "VNX-GH-111 – Remote script piped into an interpreter"
description: "A run: step downloads a script and executes it without verifying it."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

curl | sh runs whatever the server returns at that moment, with the job's token and secrets. A compromised host, CDN or DNS response becomes code execution in CI.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-494](https://cwe.mitre.org/data/definitions/494.html), [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | **Command:** `vulnetix gha actions`

## Remediation

Download to a file, verify a pinned checksum or signature, then execute it — or use a pinned action or package instead.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
