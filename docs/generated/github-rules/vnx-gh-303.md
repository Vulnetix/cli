---
title: "VNX-GH-303 – Members can create public repositories"
description: "Any member can publish a repository under the organisation's name."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Public repositories can be created by mistake with internal code, or used to host look-alike actions that appear to be official.

**Severity:** Low | **Confidence:** high | **CWE:** [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | **Command:** `vulnetix gha org`

**Needs:** org. Without them the rule is reported as not evaluated.

## Remediation

Restrict public repository creation to owners.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:L/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
