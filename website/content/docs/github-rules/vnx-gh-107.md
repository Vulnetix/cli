---
title: "VNX-GH-107 – Action major version runs on a retired runtime"
description: "The action version uses a Node.js runtime or backend service GitHub has retired."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Retired runtimes receive no security patches and are forced onto newer runtimes by the runner, which can change behaviour; retired artifact and cache backends fail outright.

**Severity:** Low | **Confidence:** high | **CWE:** [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) | **Command:** `vulnetix gha actions`

## Remediation

Upgrade to the current major version of the action.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:L/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
