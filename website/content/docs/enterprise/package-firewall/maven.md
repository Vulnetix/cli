---
title: "Maven"
weight: 8
description: "Configure Maven (Maven Central) to use the Vulnetix Package Firewall."
---

Java/Kotlin packages (Maven, Gradle, sbt) are firewalled with a Maven mirror that filters version metadata.

- **Proxy URL:** `https://packages.vulnetix.com/maven/`
- **Plan:** Pro
- **Enforcement:** Filter — blocked versions are removed from `maven-metadata.xml`; per-version artifact requests are also gated.

## Getting started

```bash
vulnetix package-firewall maven
```

This resolves your organization credentials, writes them to `~/.netrc`, and writes `~/.m2/settings.xml`. Re-run any time; it updates in place.

**Flags:** `--proxy-url` (default `https://packages.vulnetix.com`), `--base-url` (VDB API), `--dry-run` to preview without writing.

## Configuration

`~/.m2/settings.xml`:

```xml
<settings>
  <servers>
    <server>
      <id>vulnetix-package-firewall</id>
      <username>YOUR_ORG_UUID</username>
      <password>YOUR_API_KEY</password>
    </server>
  </servers>
  <mirrors>
    <mirror>
      <id>vulnetix-package-firewall</id>
      <mirrorOf>*</mirrorOf>
      <url>https://packages.vulnetix.com/maven/</url>
    </mirror>
  </mirrors>
</settings>
```

**Gradle:** point dependency resolution at the same URL with `maven { url "https://packages.vulnetix.com/maven/"; credentials { username = ...; password = ... } }` in `settings.gradle`. The Gradle *build cache* is a separate feature and is not firewalled.

## Use it

```bash
mvn dependency:resolve
./gradlew build
```

## Block responses & exit codes

A blocked package returns a semantic HTTP status with a JSON body — `423` malware, `426` vulnerable (upgrade), `425` cooldown, `428` bad actor, `422` end-of-life, `402` plan not entitled. A pinned blocked version's artifact request returns the policy status; ranges/`LATEST` resolve to an allowed version. See [Block responses & exit codes](/docs/enterprise/package-firewall/responses/) for the full table. The `vulnetix package-firewall maven` command exits `0` on success and `1` on failure.

## Configure policies

Thresholds (CVSS/EPSS/CESS), block toggles (malware, KEV, weaponized, …), and the release cooldown window are set per organization — in the Vulnetix console or with the CLI (`vulnetix config set package-firewall`). See [Configuring policies](/docs/enterprise/package-firewall/policies/).

## Troubleshooting

- Maven version metadata has no publish time, so the cooldown policy does not apply to Maven.
- `<mirrorOf>*</mirrorOf>` routes all repositories through the firewall; narrow it if you need a repo to bypass.
- See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/) for shared auth, shell, and cache guidance, and [`vulnetix auth status`](/docs/cli-reference/vdb/) to confirm what is configured.
