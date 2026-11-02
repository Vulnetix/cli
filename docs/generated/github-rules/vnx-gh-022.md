---
title: "VNX-GH-022 – Privileged job restores a cache keyed on contributor input"
description: "In a pull_request_target, workflow_run or comment-triggered job, a cache key or the cached content is derived from the pull request."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

A key built from the head branch or head SHA lets a contributor choose which entry the privileged job restores; restoring a cache after checking out the pull request saves the contributor's files under a key later trusted runs restore.

**Severity:** High | **Confidence:** medium | **CWE:** [CWE-349](https://cwe.mitre.org/data/definitions/349.html), [CWE-494](https://cwe.mitre.org/data/definitions/494.html) | **Command:** `vulnetix gha workflows`

## Remediation

Key caches only on base-branch content (hashFiles of the base checkout), and do not cache in a job that checked out untrusted code.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
