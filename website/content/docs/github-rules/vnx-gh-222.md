---
title: "VNX-GH-222 – Actions secret not rotated in a year"
description: "A repository secret was last updated more than 365 days ago."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

A long-lived secret has had more time to be copied — into logs, forks, laptops — and its owner may have left. Rotation bounds how long a leaked copy stays useful.

**Severity:** Low | **Confidence:** medium | **CWE:** [CWE-324](https://cwe.mitre.org/data/definitions/324.html) | **Command:** `vulnetix gha settings`

**Needs:** secrets. Without them the rule is reported as not evaluated.

## Remediation

Rotate the credential at its issuer and update the secret; prefer OIDC federation over stored cloud keys.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:L/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
