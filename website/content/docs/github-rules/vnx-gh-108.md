---
title: "VNX-GH-108 – Action not permitted by the allowed-actions policy"
description: "The workflow references an action that the repository's allowed-actions policy does not list."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

The run will fail at start-up, or — if the policy is relaxed to make it pass — the allow-list stops meaning anything. Either way the drift should be resolved deliberately.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | **Command:** `vulnetix gha actions`

**Needs:** actions policy. Without them the rule is reported as not evaluated.

## Remediation

Replace the action with an allowed one, or add it (pinned) to the allow-list after review.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:L/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
