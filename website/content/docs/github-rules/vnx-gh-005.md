---
title: "VNX-GH-005 – Privileged workflow consumes artifacts from an untrusted run"
description: "A workflow_run job downloads artifacts produced by a fork-triggered run and extracts them into the workspace."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Artifacts uploaded by a pull_request run are written by the pull request's code. A workflow_run job that downloads them into the working directory lets that code overwrite scripts, configuration or binaries the privileged job then uses.

**Severity:** High | **Confidence:** medium | **CWE:** [CWE-494](https://cwe.mitre.org/data/definitions/494.html), [CWE-345](https://cwe.mitre.org/data/definitions/345.html) | **Command:** `vulnetix gha workflows`

**Mappings:** T1195.002

## Remediation

Download into a dedicated directory outside the workspace (e.g. ${{ runner.temp }}/artifacts), treat contents as untrusted data, and validate them before use. Never execute anything from the artifact.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
