---
title: "Conda"
weight: 12
description: "Configure Conda (Anaconda / conda-forge) to use the Vulnetix Package Firewall."
---

Conda packages (Python/R) are firewalled by pointing channels at the proxy. Automatic CLI config is not yet implemented — configure manually.

- **Proxy URL:** `https://packages.vulnetix.com/conda`
- **Plan:** Pro
- **Enforcement:** Filter — blocked versions are removed from `repodata.json`.

## Getting started

{{< callout type="warning" >}}
`vulnetix package-firewall conda` is not yet automated and will report "not implemented yet". Configure `~/.condarc` manually as below.
{{< /callout >}}

Conda uses the `requests` library, which reads `~/.netrc` — run any `vulnetix package-firewall <ecosystem>` once to populate netrc, or add the entry yourself.

## Configuration

`~/.condarc`:

```yaml
channels:
  - https://packages.vulnetix.com/conda/main
  - https://packages.vulnetix.com/conda/conda-forge
default_channels:
  - https://packages.vulnetix.com/conda/main
```

`~/.netrc`:

```text
machine packages.vulnetix.com
login YOUR_ORG_UUID
password YOUR_API_KEY
```

## Use it

```bash
conda install numpy
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. conda resolves an allowed version; a blocked version is absent from `repodata.json`. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall conda` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization — in the Vulnetix console or with the CLI (`vulnetix config set package-firewall`). See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- Auth is via `~/.netrc` (conda/requests reads it); ensure the entry exists and is mode 600.
- Run `conda clean -i` to drop cached channel indexes after switching.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
