---
title: "VNX-GH-301 – Organisation does not require two-factor authentication"
description: "Members and outside collaborators can sign in with a password alone."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Every member account is a path to every repository it can write to. Phished or reused passwords are the most common way into an organisation.

**Severity:** High | **Confidence:** high | **CWE:** [CWE-308](https://cwe.mitre.org/data/definitions/308.html) | **Command:** `vulnetix gha org`

**Needs:** org. Without them the rule is reported as not evaluated.

## Remediation

Require two-factor authentication for the organisation.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
