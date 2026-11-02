---
title: "VNX-GH-204 – Workflow changes bypass code owners"
description: "CODEOWNERS does not cover .github/workflows, or code owner review is not required."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

Workflows hold the keys: secrets, deployment credentials and release signing. If any approver can sign off a workflow change, a reviewer unfamiliar with CI security can approve a change that exfiltrates secrets.

**Severity:** Medium | **Confidence:** high | **CWE:** [CWE-862](https://cwe.mitre.org/data/definitions/862.html) | **Command:** `vulnetix gha settings`

**Needs:** repo, branches, codeowners. Without them the rule is reported as not evaluated.

## Remediation

Add `/.github/ @your-org/ci-owners` to CODEOWNERS and require code owner review on the default branch.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:M/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
