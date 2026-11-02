---
title: "VNX-GH-012 – Hard-coded container registry credentials"
description: "A job container or service declares a literal password instead of a secret reference."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Credentials written into the workflow file are visible to anyone who can read the repository and persist in git history.

**Severity:** High | **Confidence:** high | **CWE:** [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | **Command:** `vulnetix gha workflows`

## Remediation

Store the password as an Actions secret and reference it as ${{ secrets.NAME }}. Rotate the exposed credential.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
