---
title: "VNX-GH-305 – Organisation workflow token defaults to write"
description: "New repositories inherit a read/write workflow token."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

The organisation default sets the ceiling for every repository that does not override it, including every repository created from now on.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-250](https://cwe.mitre.org/data/definitions/250.html), [CWE-276](https://cwe.mitre.org/data/definitions/276.html) | **Command:** `vulnetix gha org`

**Needs:** org. Without them the rule is reported as not evaluated.

## Remediation

Set the organisation's default workflow permissions to read.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
