---
title: "VNX-GH-307 – Self-hosted runners available to public repositories"
description: "A runner group with self-hosted runners allows public repositories."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Any GitHub user can trigger pull_request workflows in a public repository. If those jobs can land on your self-hosted runners, outsiders run code inside your network.

**Severity:** High | **Confidence:** high | **CWE:** [CWE-668](https://cwe.mitre.org/data/definitions/668.html), [CWE-829](https://cwe.mitre.org/data/definitions/829.html) | **Command:** `vulnetix gha org`

**Needs:** runner groups. Without them the rule is reported as not evaluated.

## Remediation

Disable "Allow public repositories" on runner groups that contain self-hosted runners, or make those runners ephemeral and network-isolated.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
