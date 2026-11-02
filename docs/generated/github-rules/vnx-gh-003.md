---
title: "VNX-GH-003 – Privileged workflow runs code from an untrusted pull request"
description: "A pull_request_target, workflow_run or comment-triggered job checks out the pull request's code and then executes it."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

pull_request_target, workflow_run and issue_comment run in the base repository's context: a write-capable GITHUB_TOKEN and every secret. Checking out the pull request head and then running a script, a build, or a local action executes code the pull request author wrote with those privileges. Build scripts, package manager hooks, test configuration and local actions all count as execution.

**Severity:** Critical | **Confidence:** high | **CWE:** [CWE-829](https://cwe.mitre.org/data/definitions/829.html), [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | **Command:** `vulnetix gha workflows`

**Uses, when available:** repo, environments, to rate each finding against the repository's own configuration.

**Mappings:** CAPEC-437, T1195.002

## Remediation

Split the work: run untrusted code under pull_request (no secrets, read-only token) and hand results to a privileged workflow as data via an artifact. If the privileged job must see the code, never execute it — and gate the job on an environment with required reviewers.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
