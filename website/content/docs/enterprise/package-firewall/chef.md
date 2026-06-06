---
title: "Chef"
weight: 20
description: "Configure Chef (Chef Supermarket) to use the Vulnetix Package Firewall."
---

Chef cookbooks are firewalled by pointing Supermarket/Berkshelf at the proxy. Automatic CLI config is not yet implemented — configure manually.

- **Proxy URL:** `https://packages.vulnetix.com/chef`
- **Plan:** Enterprise
- **Enforcement:** Filter — blocked cookbook versions are removed from the API listing.

## Getting started

{{< callout type="warning" >}}
`vulnetix package-firewall chef` is not yet automated. Configure the tool manually.
{{< /callout >}}

## Configuration

**Berkshelf** — `Berksfile`:

```ruby
source "https://packages.vulnetix.com/chef"
```

**knife** — `knife.rb`:

```ruby
knife[:supermarket_site] = "https://packages.vulnetix.com/chef"
```

## Use it

```bash
berks install
knife supermarket download <cookbook>
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. An allowed cookbook version resolves; a blocked version is absent from the listing. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall chef` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization — in the Vulnetix console or with the CLI (`vulnetix config set package-firewall`). See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- Cookbook downloads are served from object storage; the firewall enforces at the metadata listing.
- Provide credentials via the tool's auth mechanism or `~/.netrc`.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
