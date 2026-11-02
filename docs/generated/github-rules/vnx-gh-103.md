---
title: "VNX-GH-103 – Pinned commit is not in the action's repository"
description: "The pinned SHA exists only in a fork of the action repository."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

GitHub serves commits from any fork through the parent repository's URL. An attacker can push malicious code to a fork and propose a pin to that SHA; it looks like owner/repo@<sha> but the commit was never part of owner/repo.

**Severity:** Critical | **Confidence:** high | **CWE:** [CWE-345](https://cwe.mitre.org/data/definitions/345.html), [CWE-494](https://cwe.mitre.org/data/definitions/494.html) | **Command:** `vulnetix gha actions`

**Needs:** action refs. Without them the rule is reported as not evaluated.

**Mappings:** T1195.001

## Remediation

Replace the SHA with one that is reachable from a branch or tag of the action repository itself.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
