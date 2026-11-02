---
title: "VNX-GH-206 – Branch protection can be bypassed"
description: "Administrators are exempt, or a broad role or app is a ruleset bypass actor."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

An exemption is a standing path around review. Admin accounts and app installations are the highest-value credentials to steal precisely because they skip the controls.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-284](https://cwe.mitre.org/data/definitions/284.html), [CWE-863](https://cwe.mitre.org/data/definitions/863.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, branches. Without them the rule is reported as not evaluated.

## Remediation

Enforce protection for administrators and limit ruleset bypass to a named break-glass team with pull-request-only bypass.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
