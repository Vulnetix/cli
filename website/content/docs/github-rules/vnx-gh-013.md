---
title: "VNX-GH-013 – Deprecated workflow commands re-enabled"
description: "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables ::set-env and ::add-path."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

With this variable set, any process that prints to stdout — a test, a dependency, a log line containing user text — can set environment variables or PATH for later steps by printing a workflow command.

**Severity:** High | **Confidence:** high | **CWE:** [CWE-77](https://cwe.mitre.org/data/definitions/77.html) | **Command:** `vulnetix gha workflows`

## Remediation

Remove ACTIONS_ALLOW_UNSECURE_COMMANDS and write to $GITHUB_ENV / $GITHUB_PATH instead.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
