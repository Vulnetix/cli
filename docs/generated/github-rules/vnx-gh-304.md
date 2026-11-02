---
title: "VNX-GH-304 – Organisation allows any action"
description: "The organisation policy permits every action and reusable workflow in every repository."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

An organisation-wide allow-list is the one control that stops a new, unreviewed third-party action from running anywhere.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | **Command:** `vulnetix gha org`

**Needs:** org. Without them the rule is reported as not evaluated.

## Remediation

Allow GitHub-owned, verified-creator and explicitly listed actions only.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
