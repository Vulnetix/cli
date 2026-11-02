---
title: "VNX-GH-002 – Untrusted input written to GITHUB_ENV or GITHUB_PATH"
description: "Attacker-controlled text is appended to the job's environment or PATH file."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Lines appended to $GITHUB_ENV become environment variables for every later step, and lines appended to $GITHUB_PATH prepend directories to PATH. A value containing a newline can define LD_PRELOAD, NODE_OPTIONS, BASH_ENV or a new PATH entry, giving code execution in later steps even when those steps are written safely.

**Severity:** High | **Confidence:** high | **CWE:** [CWE-77](https://cwe.mitre.org/data/definitions/77.html), [CWE-427](https://cwe.mitre.org/data/definitions/427.html) | **Command:** `vulnetix gha workflows`

**Mappings:** T1574

## Remediation

Do not write untrusted values to GITHUB_ENV/GITHUB_PATH. If a later step needs the value, pass it through a step output and env:, or use a random heredoc delimiter and validate the value first.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
