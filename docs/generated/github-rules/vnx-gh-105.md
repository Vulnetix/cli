---
title: "VNX-GH-105 – Action version has a published vulnerability"
description: "The referenced version of the action is affected by a known advisory."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Actions are dependencies. A vulnerable version — command injection through its inputs, credential leakage, or a compromised release — exposes every workflow that runs it.

**Severity:** High | **Confidence:** high | **CWE:** [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | **Command:** `vulnetix gha actions`

**Needs:** action refs. Without them the rule is reported as not evaluated.

## Remediation

Upgrade to the fixed version named in the advisory and re-pin to its SHA.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
