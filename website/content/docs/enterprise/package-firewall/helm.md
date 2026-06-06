---
title: "Helm"
weight: 19
description: "Configure Helm (Helm chart repository) to use the Vulnetix Package Firewall."
---

Helm charts are firewalled by adding a chart repository whose index is filtered.

- **Proxy URL:** `https://packages.vulnetix.com/helm`
- **Plan:** Enterprise
- **Enforcement:** Filter — blocked chart versions are removed from `index.yaml`.

## Getting started

```bash
vulnetix package-firewall helm
```

This resolves your organization credentials, writes them to `~/.netrc`, and writes `~/.config/helm/repositories.yaml`. Re-run any time; it updates in place.

**Flags:** `--proxy-url` (default `https://packages.vulnetix.com`), `--base-url` (VDB API), `--dry-run` to preview without writing.

## Configuration

The setup adds a repo with credentials. Equivalent CLI:

```bash
helm repo add vulnetix https://packages.vulnetix.com/helm \
  --username YOUR_ORG_UUID --password YOUR_API_KEY --pass-credentials
helm repo update
```

## Use it

```bash
helm install myrelease vulnetix/<chart>
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. Helm resolves an allowed chart version; a blocked version is absent from `index.yaml`. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall helm` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization — in the Vulnetix console or with the CLI (`vulnetix config set package-firewall`). See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- Use `--pass-credentials` so Helm sends auth to the chart download host.
- OCI-based Helm charts use the Docker/OCI path instead — see [Docker / OCI](/docs/enterprise/package-firewall/docker/).
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
