---
title: "VNX-GH-021 – Secrets sent to an external host"
description: "A step sends the secrets context, the environment, or an encoded secret over the network, or sends any secret to a request-capture host or raw IP."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Token-theft campaigns add a step that dumps every secret (or the whole environment) and posts it to a server they control, often base64-encoded to slip past log masking, then remove the workflow. Authenticated calls that pass a single secret to an API are not reported; only bulk dumps, encoded secrets, and destinations with no legitimate use are.

**Severity:** Critical | **Confidence:** high | **CWE:** [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-506](https://cwe.mitre.org/data/definitions/506.html) | **Command:** `vulnetix gha workflows`

**Mappings:** T1552.001, T1567

## Remediation

Remove the step and treat every secret available to the workflow as compromised: rotate them, then review who added the change.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
