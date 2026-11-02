---
title: "VNX-GH-210 – Fork pull request workflows run without approval"
description: "Outside contributors' pull requests run workflows without a maintainer approving them, or private-repo forks get secrets or write tokens."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Approval is the human check before an outsider's code runs on your runners. Only requiring it for accounts new to GitHub lets any established account — or a bought one — run code immediately. On private repositories, sending secrets or write tokens to fork workflows hands them to every fork.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, actions policy. Without them the rule is reported as not evaluated.

## Remediation

Require approval for all outside collaborators; on private repositories, do not send write tokens or secrets to fork pull request workflows.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:M/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
