---
title: GitHub Rules
weight: 7
description: "Vulnetix GitHub posture rules: workflow injection and privilege flaws, the action supply chain, and repository and organisation settings."
---

<!-- Generated from vdb-sca-match ghaudit by `GHRULES_UPDATE=1 go test ./internal/ghtasks/`; do not edit. -->

The GitHub rules run in `vulnetix gha workflows`, `actions`, `settings`, `org` and `audit`, and in the
Vulnetix Software Factory on GitHub App events, from the same engine. Rules marked *needs* report
"not evaluated" when those GitHub settings could not be read, never a pass. Rules marked *uses* run
on the files alone and read the settings, when present, to lower or raise a finding's severity.

## Workflows (`vulnetix gha workflows`)

| Rule | Severity | Context |
|---|---|---|
| [VNX-GH-001 – Untrusted input expanded into an executed script](vnx-gh-001/) | Critical | uses repo |
| [VNX-GH-002 – Untrusted input written to GITHUB_ENV or GITHUB_PATH](vnx-gh-002/) | High |  |
| [VNX-GH-003 – Privileged workflow runs code from an untrusted pull request](vnx-gh-003/) | Critical | uses repo, environments |
| [VNX-GH-004 – Checkout credentials persisted into an uploaded workspace](vnx-gh-004/) | High |  |
| [VNX-GH-005 – Privileged workflow consumes artifacts from an untrusted run](vnx-gh-005/) | High |  |
| [VNX-GH-006 – Release workflow restores a cache writable by untrusted runs](vnx-gh-006/) | High |  |
| [VNX-GH-007 – Workflow token permissions not declared](vnx-gh-007/) | Medium | uses repo |
| [VNX-GH-008 – Excessive token permissions](vnx-gh-008/) | Medium |  |
| [VNX-GH-009 – OIDC token minted outside a protected environment](vnx-gh-009/) | Medium | uses environments |
| [VNX-GH-010 – All secrets passed to a reusable workflow](vnx-gh-010/) | Medium | uses repo |
| [VNX-GH-011 – Secrets context exposed in bulk](vnx-gh-011/) | High |  |
| [VNX-GH-012 – Hard-coded container registry credentials](vnx-gh-012/) | High |  |
| [VNX-GH-013 – Deprecated workflow commands re-enabled](vnx-gh-013/) | High |  |
| [VNX-GH-014 – Authorisation by spoofable actor name](vnx-gh-014/) | High |  |
| [VNX-GH-015 – Condition always evaluates to true](vnx-gh-015/) | High |  |
| [VNX-GH-016 – Self-hosted runner reachable from pull requests](vnx-gh-016/) | High | uses repo, runner groups |
| [VNX-GH-017 – Secret printed to the job log](vnx-gh-017/) | Medium |  |
| [VNX-GH-018 – Comment-triggered workflow without an author check](vnx-gh-018/) | High | uses repo |
| [VNX-GH-019 – Obfuscated action reference or expression](vnx-gh-019/) | Low |  |
| [VNX-GH-020 – Pull request head ref used as a branch or tag name without quoting](vnx-gh-020/) | Medium |  |
| [VNX-GH-021 – Secrets sent to an external host](vnx-gh-021/) | Critical |  |
| [VNX-GH-022 – Privileged job restores a cache keyed on contributor input](vnx-gh-022/) | High |  |

## Actions and images (`vulnetix gha actions`)

| Rule | Severity | Context |
|---|---|---|
| [VNX-GH-101 – Action or reusable workflow not pinned to a commit SHA](vnx-gh-101/) | Medium | uses action refs, actions policy, repo |
| [VNX-GH-102 – SHA pin does not match its version comment](vnx-gh-102/) | High | needs action refs |
| [VNX-GH-103 – Pinned commit is not in the action's repository](vnx-gh-103/) | Critical | needs action refs |
| [VNX-GH-104 – Action repository archived, missing or hijackable](vnx-gh-104/) | High | needs action refs |
| [VNX-GH-105 – Action version has a published vulnerability](vnx-gh-105/) | High | needs action refs |
| [VNX-GH-106 – Container image not pinned to a digest](vnx-gh-106/) | Low |  |
| [VNX-GH-107 – Action major version runs on a retired runtime](vnx-gh-107/) | Low |  |
| [VNX-GH-108 – Action not permitted by the allowed-actions policy](vnx-gh-108/) | Medium | needs actions policy |
| [VNX-GH-109 – Action owner resembles a popular publisher](vnx-gh-109/) | High |  |
| [VNX-GH-111 – Remote script piped into an interpreter](vnx-gh-111/) | Medium |  |

## Repository settings (`vulnetix gha settings`)

| Rule | Severity | Context |
|---|---|---|
| [VNX-GH-201 – Default branch is not protected](vnx-gh-201/) | High | needs repo, branches |
| [VNX-GH-202 – Default branch merges without review](vnx-gh-202/) | High | needs repo, branches |
| [VNX-GH-203 – Approvals survive new commits](vnx-gh-203/) | Medium | needs repo, branches |
| [VNX-GH-204 – Workflow changes bypass code owners](vnx-gh-204/) | Medium | needs repo, branches, codeowners |
| [VNX-GH-205 – Force pushes or deletion allowed on the default branch](vnx-gh-205/) | High | needs repo, branches |
| [VNX-GH-206 – Branch protection can be bypassed](vnx-gh-206/) | Medium | needs repo, branches |
| [VNX-GH-207 – No required status checks](vnx-gh-207/) | Low | needs repo, branches |
| [VNX-GH-208 – Workflow token defaults to write](vnx-gh-208/) | Medium | needs repo, actions policy |
| [VNX-GH-209 – GitHub Actions can approve pull requests](vnx-gh-209/) | Medium | needs repo, actions policy |
| [VNX-GH-210 – Fork pull request workflows run without approval](vnx-gh-210/) | Medium | needs repo, actions policy |
| [VNX-GH-211 – Any action may run](vnx-gh-211/) | Low | needs repo, actions policy |
| [VNX-GH-212 – Secret scanning or push protection disabled](vnx-gh-212/) | Medium | needs repo, security and analysis |
| [VNX-GH-213 – Dependabot alerts or security updates disabled](vnx-gh-213/) | Low | needs repo, security and analysis |
| [VNX-GH-214 – Environment secrets deployable without approval](vnx-gh-214/) | High | needs repo, environments |
| [VNX-GH-215 – Deploy key with write access, or unused](vnx-gh-215/) | Medium | needs deploy keys |
| [VNX-GH-216 – Webhook deliveries can be forged or intercepted](vnx-gh-216/) | Medium | needs webhooks |
| [VNX-GH-217 – Outside collaborator with admin access](vnx-gh-217/) | Medium | needs collaborators |
| [VNX-GH-218 – Signed commits not required](vnx-gh-218/) | Low | needs repo, branches |
| [VNX-GH-219 – Repository secret used by an untrusted-trigger workflow](vnx-gh-219/) | High | needs repo |
| [VNX-GH-220 – Public repository has no private vulnerability reporting](vnx-gh-220/) | Low | needs repo, security and analysis |
| [VNX-GH-221 – Security policy files missing](vnx-gh-221/) | Low | needs repo, repo files |
| [VNX-GH-222 – Actions secret not rotated in a year](vnx-gh-222/) | Low | needs secrets |

## Organisation settings (`vulnetix gha org`)

| Rule | Severity | Context |
|---|---|---|
| [VNX-GH-301 – Organisation does not require two-factor authentication](vnx-gh-301/) | High | needs org |
| [VNX-GH-302 – Broad default repository permission for members](vnx-gh-302/) | Medium | needs org |
| [VNX-GH-303 – Members can create public repositories](vnx-gh-303/) | Low | needs org |
| [VNX-GH-304 – Organisation allows any action](vnx-gh-304/) | Medium | needs org |
| [VNX-GH-305 – Organisation workflow token defaults to write](vnx-gh-305/) | Medium | needs org |
| [VNX-GH-306 – Organisation secret visible to every repository](vnx-gh-306/) | Medium | needs org |
| [VNX-GH-307 – Self-hosted runners available to public repositories](vnx-gh-307/) | High | needs runner groups |
| [VNX-GH-308 – Organisation lets Actions approve pull requests](vnx-gh-308/) | Medium | needs org |
| [VNX-GH-309 – Organisation webhook deliveries can be forged or intercepted](vnx-gh-309/) | Medium | needs org |
