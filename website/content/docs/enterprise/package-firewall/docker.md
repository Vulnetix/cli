---
title: "Docker / OCI"
weight: 15
description: "Configure Docker / OCI (Docker Hub / OCI registries) to use the Vulnetix Package Firewall."
---

Container images are firewalled by using the proxy as a registry mirror. Requires root to edit the Docker daemon config — configure manually.

- **Proxy URL:** `https://packages.vulnetix.com`
- **Plan:** Enterprise
- **Enforcement:** Gate — image pulls are gated by tag/digest; manifests are not rewritten.

## Getting started

{{< callout type="warning" >}}
`vulnetix package-firewall docker` is not yet automated and the Docker daemon config requires root. Configure it manually.
{{< /callout >}}

## Configuration

`/etc/docker/daemon.json`:

```json
{ "registry-mirrors": ["https://packages.vulnetix.com"] }
```

Authenticate and restart the daemon:

```bash
docker login packages.vulnetix.com   # username: org UUID, password: API key
sudo systemctl restart docker
```

## Use it

```bash
docker pull nginx:1.25
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. A blocked image tag/digest pull returns the policy status (for example `423` for a KEV image). See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall docker` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization — in the Vulnetix console or with the CLI (`vulnetix config set package-firewall`). See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- The Docker registry mirror only applies to Docker Hub images by default; other registries need explicit configuration.
- Restart the daemon after editing `daemon.json`. Use `docker info` to confirm the mirror is registered.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
