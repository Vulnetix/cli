---
title: "VNX-GH-302 – Broad default repository permission for members"
description: "Every member gets write or admin on every repository."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

With a write default, one compromised member account can push to, and run workflows in, every repository in the organisation.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-276](https://cwe.mitre.org/data/definitions/276.html) | **Command:** `vulnetix gha org`

**Needs:** org. Without them the rule is reported as not evaluated.

## Remediation

Set the base permission to read or none and grant write through teams.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
