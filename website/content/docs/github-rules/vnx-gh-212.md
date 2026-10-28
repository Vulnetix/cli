---
title: "VNX-GH-212 – Secret scanning or push protection disabled"
description: "Committed credentials are neither blocked at push time nor alerted on."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Push protection stops a credential before it reaches history; secret scanning finds the ones that got through. Without either, a leaked key is found first by whoever is looking.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, security and analysis. Without them the rule is reported as not evaluated.

## Remediation

Enable secret scanning and push protection.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
