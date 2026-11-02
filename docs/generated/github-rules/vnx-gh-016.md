---
title: "VNX-GH-016 – Self-hosted runner reachable from pull requests"
description: "A job triggered by pull requests runs on a self-hosted runner."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Self-hosted runners are not ephemeral by default: code from a pull request can persist on the machine, read credentials from earlier jobs, and reach the internal network the runner sits on. On a public repository any GitHub user can trigger this.

**Severity:** High | **Confidence:** medium | **CWE:** [CWE-829](https://cwe.mitre.org/data/definitions/829.html), [CWE-668](https://cwe.mitre.org/data/definitions/668.html) | **Command:** `vulnetix gha workflows`

**Uses, when available:** repo, runner groups, to rate each finding against the repository's own configuration.

**Mappings:** T1078

## Remediation

Run pull request workflows on GitHub-hosted runners, or on ephemeral (just-in-time) self-hosted runners in an isolated runner group that public repositories cannot use.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
