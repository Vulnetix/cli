---
title: "VNX-GH-015 – Condition always evaluates to true"
description: "An if: mixes ${{ }} with surrounding text, or is a block scalar, so it is a non-empty string and always true."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

When an if: value contains text outside a single ${{ }} expression (including a trailing newline from a | block), GitHub evaluates the whole thing as a string, and any non-empty string is truthy. The guard — often an authorisation check — never blocks.

**Severity:** High | **Confidence:** high | **CWE:** [CWE-570](https://cwe.mitre.org/data/definitions/570.html), [CWE-571](https://cwe.mitre.org/data/definitions/571.html), [CWE-697](https://cwe.mitre.org/data/definitions/697.html) | **Command:** `vulnetix gha workflows`

## Remediation

Write the condition as a single expression, either bare (if: a && b) or entirely inside one ${{ }}.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
