---
title: "Package Firewall"
weight: 3
description: "Proxy and policy-enforce dependencies across 21 package ecosystems — npm, PyPI, Cargo, Go, Maven, NuGet, Docker/OCI, Debian and more."
---

The Vulnetix Package Firewall sits between your package manager and its upstream registry. It authenticates your organization, evaluates each requested package against your policy, and proxies allowed packages from trusted mirrors at `https://packages.vulnetix.com`.

One proxy fronts **21 ecosystems**. Point a package manager at the firewall (the [`vulnetix package-firewall`](/docs/cli-reference/) command writes the config for you) and every install is checked before it reaches your build.

## How it works

1. **You point a package manager at the firewall** instead of the public registry, with Basic-auth credentials (`orgUUID:apiKey`).
2. **The firewall authenticates** the request against your organization and resolves your subscription plan.
3. **It evaluates policy** for the requested package/version against the Vulnetix VDB — CVSS/EPSS/CESS scores, CISA KEV, malware flags, exploit maturity, bad-actor reputation, end-of-life, and a release cooldown window.
4. **Allowed packages are proxied** from a trusted upstream mirror. **Blocked packages** are withheld or rejected with a semantic HTTP status — see [Block responses & exit codes](/docs/enterprise/package-firewall/responses/).

### Enforcement modes

| Mode | What a developer sees | Ecosystems |
| --- | --- | --- |
| **Filter** (unsigned metadata) | Blocked versions are removed from the index/metadata, so your resolver never selects them. A version you pin explicitly returns a policy status. | npm, PyPI, Cargo, Go, RubyGems, pub.dev, Maven, NuGet, Composer, Conda, CRAN, Helm, Chef, Terraform |
| **Gate** (signed / digest-addressed metadata) | The index is served unchanged so signature verification still passes; a blocked version's **download** returns a policy status. | Hex, Conan, Julia, Docker/OCI, Debian, RPM, Alpine |

You don't configure the mode — it's chosen per ecosystem so the firewall never breaks a registry's signature checks.

## Plans

Go is free for every community account. All other ecosystems require a paid plan; container and OS ecosystems require Enterprise. Requests for an ecosystem outside your plan return `402 Payment Required`.

| Tier | Ecosystems |
| --- | --- |
| **Community** (free) | Go |
| **Pro** (and Teams) | npm, PyPI, Cargo, RubyGems, Hex, pub.dev, Maven, NuGet, Composer, Conan, Conda, CRAN, Julia |
| **Enterprise** | Docker/OCI, Debian/Ubuntu, RPM, Alpine, Helm, Chef, Terraform |

See [vulnetix.com/pricing](https://www.vulnetix.com/pricing) for details.

## Ecosystems

{{< cards >}}
  {{< card link="go" title="Go" subtitle="GOPROXY module proxy. Free, community tier." >}}
  {{< card link="npm" title="npm" subtitle="JavaScript / Node.js packuments." >}}
  {{< card link="pypi" title="PyPI" subtitle="Python — pip Simple index." >}}
  {{< card link="cargo" title="Cargo" subtitle="Rust — sparse registry." >}}
  {{< card link="gem" title="RubyGems" subtitle="Ruby — compact index / Bundler." >}}
  {{< card link="hex" title="Hex" subtitle="Elixir / Erlang — signed registry." >}}
  {{< card link="pub" title="pub.dev" subtitle="Dart / Flutter." >}}
  {{< card link="maven" title="Maven" subtitle="Java / Kotlin / Gradle." >}}
  {{< card link="nuget" title="NuGet" subtitle=".NET — v3 service index." >}}
  {{< card link="composer" title="Composer" subtitle="PHP — Packagist v2." >}}
  {{< card link="conan" title="Conan" subtitle="C / C++ — remotes." >}}
  {{< card link="conda" title="Conda" subtitle="Python / R — channels." >}}
  {{< card link="cran" title="CRAN" subtitle="R — package repository." >}}
  {{< card link="julia" title="Julia" subtitle="Julia — Pkg server." >}}
  {{< card link="docker" title="Docker / OCI" subtitle="Container images. Enterprise." >}}
  {{< card link="debian" title="Debian / Ubuntu" subtitle="APT. Enterprise." >}}
  {{< card link="rpm" title="RPM" subtitle="RHEL / Fedora — dnf/yum. Enterprise." >}}
  {{< card link="alpine" title="Alpine" subtitle="apk. Enterprise." >}}
  {{< card link="helm" title="Helm" subtitle="Kubernetes charts. Enterprise." >}}
  {{< card link="chef" title="Chef" subtitle="Supermarket cookbooks. Enterprise." >}}
  {{< card link="terraform" title="Terraform" subtitle="Provider / module registry. Enterprise." >}}
{{< /cards >}}

## Reference

{{< cards >}}
  {{< card link="responses" title="Block responses & exit codes" subtitle="HTTP status codes, what each means, and CLI exit codes." >}}
  {{< card link="policies" title="Configuring policies" subtitle="Set thresholds, block toggles, and cooldown in the console." >}}
  {{< card link="troubleshooting" title="Troubleshooting" subtitle="Auth, shells, and package-manager issues." >}}
{{< /cards >}}

## Authentication, in brief

Every ecosystem authenticates with the same organization credentials — your **org UUID** as the username and your **API key** as the password — against the host `packages.vulnetix.com`.

`vulnetix package-firewall <ecosystem>` resolves your credentials (from the environment, `~/.vulnetix/credentials.json`, or `~/.netrc`), writes them to `~/.netrc` for tools that honour it, and writes the ecosystem-specific registry config. Run [`vulnetix auth status`](/docs/cli-reference/vdb/) to see which package managers are currently pointed at the firewall.

See each ecosystem page for the exact files and commands.
