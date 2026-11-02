---
title: "VNX-GH-020 – Pull request head ref used as a branch or tag name without quoting"
description: "A shell variable holding the head branch name is passed to git or gh unquoted or without --."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Moving an untrusted value into env: fixes script injection, but `git checkout $BRANCH` still lets a branch named --upload-pack=... or -o... inject options. Branch names can start with a dash.

**Severity:** Medium | **Confidence:** medium | **CWE:** [CWE-88](https://cwe.mitre.org/data/definitions/88.html) | **Command:** `vulnetix gha workflows`

## Remediation

Quote the variable and end option parsing: git checkout -- "$BRANCH" (or git switch "refs/heads/$BRANCH").

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:M/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
