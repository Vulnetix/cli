---
title: "VNX-GH-109 – Action owner resembles a popular publisher"
description: "The action's owner is one character away from a widely used publisher."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Typosquatted owners (actoins/checkout, aws-action/...) are registered to catch mistyped references and run attacker code with the job's privileges.

**Severity:** High | **Confidence:** medium | **CWE:** [CWE-1357](https://cwe.mitre.org/data/definitions/1357.html) | **Command:** `vulnetix gha actions`

**Mappings:** T1195.001

## Remediation

Check the owner's spelling; reference the intended publisher.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
