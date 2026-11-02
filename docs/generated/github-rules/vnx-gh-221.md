---
title: "VNX-GH-221 – Security policy files missing"
description: "SECURITY.md, CODEOWNERS or a Dependabot configuration is absent."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

SECURITY.md is the reporting route, CODEOWNERS names who must review sensitive paths, and a Dependabot configuration keeps dependencies — including pinned actions — updated. Each missing file removes one of those controls.

**Severity:** Low | **Confidence:** high | **CWE:** [CWE-1059](https://cwe.mitre.org/data/definitions/1059.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, repo files. Without them the rule is reported as not evaluated.

## Remediation

Add the missing files; include a github-actions entry in dependabot.yml so action pins are kept current.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:L/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
