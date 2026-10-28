---
title: "VNX-GH-014 – Authorisation by spoofable actor name"
description: "An if: trusts github.actor == '<bot>[bot]' in a workflow outsiders can trigger."
---

<!-- Generated from vdb-sca-match ghaudit; do not edit. -->

## Overview

github.actor is whoever caused the latest event, not who wrote the code. An attacker can open a pull request that a bot later updates (for example by asking Dependabot to rebase), making the bot the actor while the attacker's commits run with the privileges the check was meant to reserve for the bot.

**Severity:** High | **Confidence:** medium | **CWE:** [CWE-290](https://cwe.mitre.org/data/definitions/290.html), [CWE-863](https://cwe.mitre.org/data/definitions/863.html) | **Command:** `vulnetix gha workflows`

## Remediation

Check the pull request author (github.event.pull_request.user.login) and that the head repository is the base repository, or use the bot's own metadata action.

## Scoring

CWSS vector at the rule's default severity: `CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:M/EC:N/P:W`. A finding whose severity the repository's settings moved is scored at its adjusted severity.
