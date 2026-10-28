---
title: "VNX-GH-213 – Dependabot alerts or security updates disabled"
description: "Vulnerable dependencies, including pinned actions, are not raised as update pull requests."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

SHA-pinned actions only stay safe if something updates them. Security updates open the fix as a pull request as soon as an advisory is published.

**Severity:** Low | **Confidence:** high | **CWE:** [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, security and analysis. Without them the rule is reported as not evaluated.

## Remediation

Enable Dependabot security updates, and add a github-actions ecosystem entry to dependabot.yml.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:L/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
