---
title: "VNX-GH-104 – Action repository archived, missing or hijackable"
description: "The referenced action is archived, deleted, or its owner was renamed or removed."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

An archived action gets no security fixes. A deleted repository, or an owner that was renamed or removed, lets anyone register the old name and publish code under it (repo-jacking); unpinned references then run it.

**Severity:** High | **Confidence:** high | **CWE:** [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html), [CWE-494](https://cwe.mitre.org/data/definitions/494.html) | **Command:** `vulnetix gha actions`

**Needs:** action refs. Without them the rule is reported as not evaluated.

**Mappings:** T1195.001

## Remediation

Replace the action with a maintained alternative, or vendor it into this repository as a local action.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
