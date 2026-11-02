---
title: "VNX-GH-101 – Action or reusable workflow not pinned to a commit SHA"
description: "uses: references a branch or tag, which the action's owner (or anyone who compromises them) can move."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Tags and branches are mutable. When an action repository is compromised, the attacker re-points existing tags at malicious code and every workflow referencing them runs it on its next execution — as happened in widely used actions. A full 40-character SHA is the only immutable reference.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-829](https://cwe.mitre.org/data/definitions/829.html), [CWE-494](https://cwe.mitre.org/data/definitions/494.html) | **Command:** `vulnetix gha actions`

**Uses, when available:** action refs, actions policy, repo, to rate each finding against the repository's own configuration.

**Mappings:** T1195.001

## Remediation

Pin to the full commit SHA and keep the version in a trailing comment (uses: owner/repo@<sha> # v1.2.3); let Dependabot or Renovate update both.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:L/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
