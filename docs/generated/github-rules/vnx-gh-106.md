---
title: "VNX-GH-106 – Container image not pinned to a digest"
description: "docker:// steps, job containers and services reference an image by tag."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Image tags are mutable. The image that runs with the job's token and workspace can change without any change to the workflow.

**Severity:** Low | **Confidence:** high | **CWE:** [CWE-829](https://cwe.mitre.org/data/definitions/829.html), [CWE-494](https://cwe.mitre.org/data/definitions/494.html) | **Command:** `vulnetix gha actions`

## Remediation

Reference images by digest (image@sha256:...), and let an update bot refresh it.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:M/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
