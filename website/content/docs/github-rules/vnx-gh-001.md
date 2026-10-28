---
title: "VNX-GH-001 – Untrusted input expanded into an executed script"
description: "A ${{ }} expression carrying attacker-controlled text is substituted into a shell or script before it runs."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

GitHub substitutes ${{ }} expressions into run: scripts (and script inputs such as actions/github-script's script) as text, before the interpreter parses them. Text that an outsider controls — a pull request title, a branch name, a comment, a commit message — becomes code that runs with the job's token and secrets. The engine follows the value through env:, GITHUB_ENV, step outputs, job outputs and local composite actions, and only reports sources the workflow's triggers can actually populate.

**Severity:** Critical | **Confidence:** high | **CWE:** [CWE-94](https://cwe.mitre.org/data/definitions/94.html), [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | **Command:** `vulnetix gha workflows`

**Uses, when available:** repo, to rate each finding against the repository's own configuration.

**Mappings:** CAPEC-242, T1059, T1195.002

## Remediation

Pass the value through an environment variable and reference it as a shell variable ("$TITLE"), or as process.env in github-script, so it is data rather than code.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
