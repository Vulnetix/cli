---
title: "VNX-GH-220 – Public repository has no private vulnerability reporting"
description: "Researchers have no private channel to report a vulnerability."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Without private vulnerability reporting, a researcher's only route is often a public issue, which discloses the flaw before a fix exists.

**Severity:** Low | **Confidence:** high | **CWE:** [CWE-1059](https://cwe.mitre.org/data/definitions/1059.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, security and analysis. Without them the rule is reported as not evaluated.

## Remediation

Enable private vulnerability reporting in the repository's security settings.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:L/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
