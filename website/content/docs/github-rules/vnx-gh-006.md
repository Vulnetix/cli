---
title: "VNX-GH-006 – Release workflow restores a cache writable by untrusted runs"
description: "A workflow that publishes releases restores dependency caches that other workflows on the default branch can write."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Caches are shared across workflows in the same branch scope. A compromised or injectable workflow on the default branch can save a poisoned cache entry that a release workflow later restores and ships inside a published artifact.

**Severity:** High | **Confidence:** medium | **CWE:** [CWE-349](https://cwe.mitre.org/data/definitions/349.html), [CWE-494](https://cwe.mitre.org/data/definitions/494.html) | **Command:** `vulnetix gha workflows`

**Mappings:** T1195.002

## Remediation

Disable caching in workflows that publish releases or sign artifacts (remove cache: / actions/cache), or use a cache key namespace no other workflow writes.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
