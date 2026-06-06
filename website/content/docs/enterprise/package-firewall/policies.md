---
title: "Configuring policies"
weight: 31
description: "Set Package Firewall thresholds, block toggles, cooldown, and upstream mirrors in the Vulnetix console."
---

Policy is configured **per organization** in the Vulnetix console, not in the CLI. The same policy applies to every ecosystem your plan includes. Open the console at [www.vulnetix.com/vdb-package-firewall](https://www.vulnetix.com/vdb-package-firewall) (sign in with your VDB account).

## Score thresholds

A package is blocked when any matching CVE meets or exceeds a threshold. Set a threshold to `0` to disable it.

| Setting | Blocks when |
| --- | --- |
| **CVSS threshold** | The maximum CVSS base score ≥ your value (e.g. `8.0`). |
| **EPSS threshold** | The exploit-prediction probability ≥ your value (`0.0`–`1.0`). |
| **CESS threshold** | The Vulnetix exploitability severity score ≥ your value. |

## Block toggles

Each toggle blocks a package version when the condition is true:

| Toggle | Blocks a version that… |
| --- | --- |
| **Block malware** | is flagged as a malicious package. |
| **Block KEV** | has a CVE in CISA KEV or VulnCheck KEV. |
| **Block weaponized** | has weaponized exploitation reported by VulnCheck canaries. |
| **Block active** | has active exploitation sightings (CrowdSec). |
| **Block PoC** | has a public proof-of-concept or exploit record. |
| **Block bad actors** | has a CVE linked to actors with malicious reputation. |
| **Block EOL** | belongs to an end-of-life package. |

## Cooldown

**Cooldown (days)** blocks any version published within the last *N* days — a quarantine against compromised or accidentally-published releases. A request for a too-new version returns `425 Too Early` with a `Retry-After` header. Cooldown applies wherever the registry exposes a publish time (npm, PyPI, Cargo, pub.dev, NuGet, Composer, Conda, Helm, Chef, Hex); it is skipped where it does not (Maven, CRAN, Conan, Julia, Go, and the OS/container ecosystems).

## Upstream mirrors

Each ecosystem has an ordered list of upstream mirrors. The firewall tries them by priority and serves the first that responds. Defaults are seeded automatically (for example `registry.npmjs.org` for npm); add your own regional or internal mirrors per ecosystem in the **Mirrors** tab.

## Decision log

Every PASS / BLOCK / ERROR decision is recorded with its ecosystem, package, version, action, and reason. Filter the log by **ecosystem** and **action** in the console to audit what the firewall has allowed or blocked.

{{< callout type="info" >}}
Policy changes are cached by the firewall for up to 60 seconds, so a new threshold takes effect within a minute.
{{< /callout >}}
