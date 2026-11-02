---
title: "VNX-GH-102 – SHA pin does not match its version comment"
description: "uses: owner/repo@<sha> # vX.Y.Z, but vX.Y.Z resolves to a different commit."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Reviewers and update bots read the version comment, not the SHA. A SHA that does not match its comment either predates an update that only changed the comment, or was swapped deliberately to run a different commit under a trusted-looking version.

**Severity:** High | **Confidence:** high | **CWE:** [CWE-345](https://cwe.mitre.org/data/definitions/345.html), [CWE-451](https://cwe.mitre.org/data/definitions/451.html) | **Command:** `vulnetix gha actions`

**Needs:** action refs. Without them the rule is reported as not evaluated.

## Remediation

Re-pin to the commit the intended version resolves to, and update the comment and SHA together.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
