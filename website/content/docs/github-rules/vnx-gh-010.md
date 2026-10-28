---
title: "VNX-GH-010 – All secrets passed to a reusable workflow"
description: "secrets: inherit hands every repository, environment and organisation secret to the called workflow."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

The called workflow receives every secret the caller can see, not just the ones it uses. A reusable workflow in another repository, or one pinned to a mutable ref, becomes a way to exfiltrate all of them.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-668](https://cwe.mitre.org/data/definitions/668.html) | **Command:** `vulnetix gha workflows`

**Uses, when available:** repo, to rate each finding against the repository's own configuration.

## Remediation

Pass only the secrets the called workflow declares under on.workflow_call.secrets, by name.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
