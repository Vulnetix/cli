---
title: "VNX-GH-219 – Repository secret used by an untrusted-trigger workflow"
description: "A repository-level secret (not an environment secret) is read by a workflow outsiders can trigger."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Repository secrets are available to every job. When a pull_request_target, issue_comment or workflow_run workflow reads one, any flaw in that workflow exposes it; an environment secret would add a gate.

**Severity:** High | **Confidence:** medium | **CWE:** [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-668](https://cwe.mitre.org/data/definitions/668.html) | **Command:** `vulnetix gha settings`

**Needs:** repo. Without them the rule is reported as not evaluated.

## Remediation

Move the secret to an environment with required reviewers, and reference it only from the job bound to that environment.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
