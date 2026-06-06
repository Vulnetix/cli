---
title: "Terraform"
weight: 21
description: "Configure Terraform (Terraform Registry) to use the Vulnetix Package Firewall."
---

Terraform providers and modules are firewalled via a network mirror that filters the versions list. Automatic CLI config is not yet implemented — configure manually.

- **Proxy URL:** `https://packages.vulnetix.com/terraform`
- **Plan:** Enterprise
- **Enforcement:** Filter — blocked provider/module versions are removed from the versions list.

## Getting started

{{< callout type="warning" >}}
`vulnetix package-firewall terraform` is not yet automated. Configure the CLI config file manually.
{{< /callout >}}

## Configuration

`~/.terraformrc` (or `%APPDATA%/terraform.rc` on Windows):

```hcl
provider_installation {
  network_mirror {
    url = "https://packages.vulnetix.com/terraform/"
  }
  direct {}
}
```

Provide credentials with a `credentials` block or the `TF_TOKEN_packages_vulnetix_com` environment variable.

## Use it

```bash
terraform init
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. Terraform resolves an allowed version; a blocked provider/module version is absent from the versions list. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall terraform` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization in the Vulnetix console — not in the CLI. See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- The GPG signature is on the provider checksums, not the versions list, so filtering versions does not break verification.
- Versions have no publish time, so cooldown does not apply.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
