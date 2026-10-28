---
title: "VNX-GH-019 – Obfuscated action reference or expression"
description: "A uses: path or ${{ }} expression is written in a form that hides what it resolves to."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

uses: owner/repo/./@ref and github['event']['issue']['title'] resolve to the same thing as their plain forms but evade reviewers, allow-lists and simple scanners. Legitimate workflows rarely need them.

**Severity:** Low | **Confidence:** medium | **CWE:** [CWE-656](https://cwe.mitre.org/data/definitions/656.html) | **Command:** `vulnetix gha workflows`

## Remediation

Write the reference or expression in its plain form.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:L/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
