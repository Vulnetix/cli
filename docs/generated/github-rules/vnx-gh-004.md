---
title: "VNX-GH-004 – Checkout credentials persisted into an uploaded workspace"
description: "actions/checkout writes the token into .git/config and the workspace is then uploaded as an artifact."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

By default actions/checkout stores the job's GITHUB_TOKEN in .git/config so later git commands authenticate. Uploading the checkout directory as an artifact publishes that token to anyone who can download the run's artifacts — on a public repository, everyone — while the job is still running.

**Severity:** High | **Confidence:** high | **CWE:** [CWE-522](https://cwe.mitre.org/data/definitions/522.html), [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | **Command:** `vulnetix gha workflows`

## Remediation

Set persist-credentials: false on actions/checkout, and upload only the build output directory, never the repository root.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
