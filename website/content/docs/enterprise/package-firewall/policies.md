---
title: "Configuring policies"
weight: 31
description: "Set Package Firewall thresholds, block toggles, cooldown, and upstream mirrors — from the Vulnetix console or the CLI."
---

Policy is configured **per organization** — in the Vulnetix console or with the Vulnetix CLI. The same policy applies to every ecosystem your plan includes. Open the console at [www.vulnetix.com/vdb-package-firewall](https://www.vulnetix.com/vdb-package-firewall) (sign in with your VDB account), or use [`vulnetix config set package-firewall`](#configure-from-the-cli) and [`vulnetix config get package-firewall`](#read-the-current-configuration).

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

Each ecosystem has an ordered list of upstream mirrors. The firewall tries them by priority and serves the first that responds. Defaults are seeded automatically (for example `registry.npmjs.org` for npm); add your own regional or internal mirrors per ecosystem in the **Mirrors** tab of the console, or with [`vulnetix config set package-firewall <ecosystem> <url>`](#manage-mirrors).

## Decision log

Every PASS / BLOCK / ERROR decision is recorded with its ecosystem, package, version, action, and reason. Filter the log by **ecosystem** and **action** in the console to audit what the firewall has allowed or blocked.

{{< callout type="info" >}}
Policy changes are cached by the firewall for up to 60 seconds, so a new threshold takes effect within a minute.
{{< /callout >}}

## Configure from the CLI

`vulnetix config set package-firewall` writes the same per-organization policy as the console. The org is resolved from your authenticated session — no `--org-id` needed when you are logged in (`vulnetix auth login`).

```bash
vulnetix config set package-firewall \
  --cvss-threshold 8.0 \
  --block-malware true \
  --block-kev true \
  --cooldown-days 7
```

Each call is a **partial update** — only the flags you pass change; everything else keeps its current value. A first call creates the policy row for your organization; later calls update it in place.

| Flag | Value | Sets |
| --- | --- | --- |
| `--cvss-threshold` | `0`–`10` | Block when the maximum CVSS base score ≥ value (`0` disables). |
| `--epss-threshold` | `0`–`1` | Block when EPSS probability ≥ value. |
| `--cess-threshold` | `0`–`10` | Block when the Vulnetix CESS score ≥ value. |
| `--block-malware` | `true\|false` | Block known-malicious packages. |
| `--block-eol` | `true\|false` | Block end-of-life package versions. |
| `--block-kev` | `true\|false` | Block CVEs in CISA KEV / VulnCheck KEV. |
| `--block-weaponized-exploits` | `true\|false` | Block weaponized exploitation. |
| `--block-active-exploits` | `true\|false` | Block active exploitation sightings. |
| `--block-poc-exploits` | `true\|false` | Block public proof-of-concept / exploit records. |
| `--block-bad-actors` | `true\|false` | Block CVEs linked to malicious actors. |
| `--cooldown-days` | `n` (≥ 0) | Quarantine versions published within the last *n* days. |
| `--version-lag` | `n` (≥ 0) | Require at least *n* newer versions before a version is allowed. |

The boolean flags accept an explicit value, so `--block-malware true` and `--block-malware=false` are both valid and distinguishable from leaving the flag unset.

### Manage mirrors

Add or update an ecosystem mirror by passing the ecosystem and an absolute upstream URL:

```bash
# Add a mirror (priority auto-increments per ecosystem: 0, 1, 2, …)
vulnetix config set package-firewall npm https://registry.npmjs.org

# Pin an explicit priority (lower is tried first)
vulnetix config set package-firewall npm https://npm.internal.example --priority 0

# Disable or re-enable a mirror, matched by ecosystem + url (priority unchanged)
vulnetix config set package-firewall npm https://registry.npmjs.org --disable
vulnetix config set package-firewall npm https://registry.npmjs.org --enable
```

| Argument / flag | Meaning |
| --- | --- |
| `<ecosystem>` | Ecosystem id (`go`, `npm`, `pypi`, `cargo`, …). |
| `<url>` | Absolute upstream mirror URL. |
| `--priority <n>` | Order within the ecosystem. Omit to append at `max(priority)+1`. |
| `--enable` / `--disable` | Toggle `isActive` on the mirror matched by `<ecosystem>` + `<url>`. |

### Read the current configuration

`vulnetix config get package-firewall` prints the org-wide policy and every mirror across all ecosystems:

```bash
vulnetix config get package-firewall
```

```text
Package Firewall policy
  CVSS threshold             8
  EPSS threshold             0
  CESS threshold             0
  Block malware              Yes
  Block EOL                  No
  Block KEV                  Yes
  Block weaponized exploits  No
  Block active exploits      No
  Block PoC exploits         No
  Block bad actors           No
  Cooldown days              7
  Version lag                0

Mirrors
  Ecosystem   Priority   Active   URL
  go          0          Yes      https://proxy.golang.org
  npm         0          No       https://registry.npmjs.org
```

Add `-o json` for a machine-readable `{ "config": …, "mirrors": [ … ] }` payload suitable for CI:

```bash
vulnetix config get package-firewall -o json
```

A brand-new organization that has never set a policy or had a proxied request prints *"No policy configured — proxy defaults apply"* and *"No mirrors configured"*; the firewall seeds defaults on first use.
