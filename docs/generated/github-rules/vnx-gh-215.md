---
title: "VNX-GH-215 – Deploy key with write access, or unused"
description: "A deploy key can push to the repository."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Deploy keys are not tied to a user, do not expire, and are typically stored on build or deployment hosts. A write key there can push to unprotected branches and tags.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | **Command:** `vulnetix gha settings`

**Needs:** deploy keys. Without them the rule is reported as not evaluated.

## Remediation

Make the key read-only, or replace it with a GitHub App installation token scoped to the repository.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
