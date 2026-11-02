---
title: "VNX-GH-306 – Organisation secret visible to every repository"
description: "An organisation secret has visibility all, so any repository — including public ones — can read it."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

A secret shared with all repositories is only as safe as the weakest workflow in the organisation. With visibility all, public repositories' workflows can read it too.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-668](https://cwe.mitre.org/data/definitions/668.html) | **Command:** `vulnetix gha org`

**Needs:** org. Without them the rule is reported as not evaluated.

## Remediation

Set the secret's visibility to selected repositories, or private repositories at most.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
