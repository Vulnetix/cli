---
title: "VNX-GH-017 – Secret printed to the job log"
description: "A run: step prints a secret, relying on log masking to hide it."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Masking only redacts exact matches. Encoded, split or transformed output (base64, JSON, a substring, a multi-line value) is printed in clear to a log readable by everyone with read access.

**Severity:** Medium | **Confidence:** medium | **CWE:** [CWE-532](https://cwe.mitre.org/data/definitions/532.html) | **Command:** `vulnetix gha workflows`

## Remediation

Never print secrets. Pass them to tools through environment variables or files with restricted permissions.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:M/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
