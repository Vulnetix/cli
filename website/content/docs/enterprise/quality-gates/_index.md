---
title: "Quality Gates"
weight: 4
description: "Org-wide scan enforcement — severity, exploits, EOL, unpinned deps, and SCA autofix policy applied automatically to every authenticated scan."
---

The **Quality Gate** is a per-organization policy that governs how `vulnetix scan` (and the scoped `sca`, `sast`, `secrets`, `containers`, `iac` commands) decides to pass or fail. Where the [Package Firewall](/docs/enterprise/package-firewall/) enforces policy at the registry proxy, the Quality Gate enforces policy at the **scan** — the values you set here are pulled in before the gate is evaluated and override the matching scan flags.

Configure it from the Vulnetix console, or with [`vulnetix config set quality-gate`](/docs/cli-reference/#config-set-quality-gate) and [`vulnetix config get quality-gate`](/docs/cli-reference/#config-get-quality-gate). The organization is resolved from your authenticated session (`vulnetix auth login`).

## Enforcement settings

Nine settings map one-to-one onto the equivalent `vulnetix scan` flags. Each is optional — a setting you never configure stays **unset**, and the caller's flag (or the builtin default) applies for it.

| Setting | Type | Value | Gates on |
| --- | --- | --- | --- |
| **Block EOL** | bool | `true\|false` | A runtime or package dependency that is end-of-life. |
| **Block malware** | bool | `true\|false` | A dependency that is a known malicious package — **and** any malware found by the in-process [malscan](../../cli-reference/malscan/) pass over the installed bytes. |
| **Block unpinned** | bool | `true\|false` | A direct dependency using a version range instead of an exact pin. |
| **Cooldown** | int | `≥ 0` | A dependency version published within the last *n* days (`0` disables). |
| **Version lag** | int | `≥ 0` | A dependency within the *n* most recently published versions (`0` disables). |
| **SCA autofix max major bump** | int | `≥ 0` | Refuses autofix targets crossing more than *n* major versions. |
| **Exploits** | string | `poc\|active\|weaponized` | Exploit maturity reaching the threshold. |
| **Severity** | string | `low\|medium\|high\|critical` | Any vulnerability or SAST finding meeting or exceeding the level. |
| **SCA autofix strategy** | string | `latest\|safest\|stable` | Target strategy for `--sca-autofix`. |

Each setting is independently **set**, **unset**, or **left unchanged**. From the CLI, pass a value to set it, or `null` to unset it entirely for the org (`vulnetix config set quality-gate --severity null`); from the console, clear the field. An **unset** setting reverts to the member's own scan flag or the builtin default — it is not the same as setting `false` or `0`, which actively enforce that value.

> **Block malware covers two layers.** When enforced, the malware gate fails the build on both the backend known-malicious-package verdict (a name+version lookup) **and** any malware the in-process [malscan](../../cli-reference/malscan/) pass finds in the installed bytes (STIX IOCs, install-script patterns, bad hashes). `malscan` runs automatically as part of `scan`; `sca` runs it when the malware gate is in effect.

## EOL severity buckets

The Quality Gate also carries the four **end-of-life calendar-quarter severity buckets**, which assign a synthetic finding severity based on how soon a product reaches end-of-life. The buckets are literal calendar quarters (Q1 Jan–Mar, Q2 Apr–Jun, Q3 Jul–Sep, Q4 Oct–Dec); a product's EOL date is classified by which quarter it lands in. These are **shared time buckets**, not a per-product mapping.

| Bucket | CLI flag | Value |
| --- | --- | --- |
| Next quarter | `--next-quarter-severity` | `skip\|low\|medium\|high\|critical` |
| This quarter | `--this-quarter-severity` | `skip\|low\|medium\|high\|critical` |
| Within 30 days | `--within-30-days-severity` | `skip\|low\|medium\|high\|critical` |
| Retired (past EOL) | `--retired-severity` | `skip\|low\|medium\|high\|critical` |

Set a bucket to `skip` to suppress findings for that bucket entirely. Configure the buckets with [`vulnetix config set eol-policy`](/docs/cli-reference/#config-set-eol-policy).

## Override behaviour: org policy always wins

When a scan runs while authenticated, the CLI fetches your organization's Quality Gate and applies every setting the org has configured **before the gate is evaluated**:

- **A setting the org configured overrides the matching scan flag — even one passed explicitly on the command line.** If the caller passed a different value, the run is still evaluated with the org's value.
- **A setting the org left unset** is untouched: the caller's flag, or the builtin default, applies.

This is deliberate: an organization can tighten — or relax — a member's scan regardless of the flags they pass. With `--verbose`, each applied or superseded setting is announced so the operator can see exactly what changed.

{{< callout type="info" >}}
Org policy always wins. This is **not** "most restrictive wins" — if the org sets `--severity low`, a member who passes `--severity critical` is evaluated at `low`.
{{< /callout >}}

### Verbose output example

Given an org policy of `severity=high` and `cooldown=3`, a member running a scan with a conflicting flag sees:

```bash
vulnetix scan --severity low --verbose
```

```text
--severity low superseded by org policy: high
org policy applied: --cooldown 3
Org quality gate: applied 2 settings from org policy (org policy always wins).
```

When the member passes no conflicting flag, only the applied note appears:

```text
org policy applied: --severity high
org policy applied: --cooldown 3
Org quality gate: applied 2 settings from org policy (org policy always wins).
```

Run [`vulnetix config get quality-gate`](/docs/cli-reference/#config-get-quality-gate) at any time to inspect the active policy; settings the org never configured render as **not set**.

## Non-authenticated scans

{{< callout type="warning" >}}
When no credentials are configured (or the community fallback is used), there is no organization to read a policy from. **Non-authenticated scans use only the CLI flags** you pass — no org override is applied.
{{< /callout >}}
