---
title: Authentication
weight: 2
description: "Credential methods, storage backends, precedence, file permissions, and rotation for the Vulnetix CLI and Package Firewall."
---

Every Vulnetix product authenticates against a single organization identity. This section covers how to obtain credentials, where to put them, how the CLI decides which one to use, and how to store them safely on developer machines, in containers, and in CI.

{{< callout type="info" >}}
**Short answer for most people:**

```sh
vulnetix auth login --store keyring
```

Browser device flow, secret held in the OS keychain, nothing sensitive on disk. Everything below is detail for the cases where that is not possible.
{{< /callout >}}

## The Three Credential Methods

| Method | Flag | Environment | Requires `--org-id` | Header sent |
|--------|------|-------------|---------------------|-------------|
| **Bearer token** | `--token` | `VULNETIX_API_TOKEN` | No — org resolved server-side | `Authorization: Bearer <token>` |
| **ApiKey** | `--api-key` | `VULNETIX_API_KEY` + `VULNETIX_ORG_ID` | Yes | `Authorization: ApiKey <org>:<key>` |
| **SigV4** | `--secret` | `VVD_ORG` + `VVD_SECRET` | Yes | `Authorization: ApiKey <org>:<hmac>` (derived) |

`--api-key`, `--secret`, and `--token` are mutually exclusive. Passing more than one fails with `choose only one of --api-key, --secret, or --token`.

{{< callout type="warning" >}}
`--secret` is **not** an alias for `--api-key`. It takes the SigV4 HMAC secret, from which the CLI derives `HMAC-SHA256(secret, orgID)`. Passing an ApiKey to `--secret` produces a wrong signature and the login fails.
{{< /callout >}}

## The Four Storage Backends

| Backend | Location | Secret at rest |
|---------|----------|----------------|
| **Keyring** (recommended) | OS keychain + metadata in `~/.vulnetix/credentials.json` | OS keychain |
| **Home file** | `~/.vulnetix/credentials.json` | Plaintext JSON, mode `0600` |
| **Project file** | `./.vulnetix/credentials.json` | Plaintext JSON, mode `0600` |
| **netrc** | `~/.netrc` (`~/_netrc` on Windows) | Plaintext, mode `0600` enforced |

Environment variables are a fifth source — they persist nothing and take precedence over all files.

## Sections

{{< cards >}}
  {{< card link="methods" title="Credential Methods" subtitle="Bearer token, ApiKey, SigV4, and the community fallback." icon="key" >}}
  {{< card link="precedence" title="Credential Precedence" subtitle="Exactly which source wins, and how to inspect it." icon="switch-horizontal" >}}
  {{< card link="storage" title="Credential Storage" subtitle="Keyring, home file, project file, custom directories." icon="database" >}}
  {{< card link="file-permissions" title="File Permissions & Isolation" subtitle="Linux, macOS, Windows, containers, SELinux, AppArmor, seccomp." icon="lock-closed" >}}
  {{< card link="netrc" title="netrc & Package Firewall" subtitle="The shared netrc contract across CLI, Go, npm, pip, and packages.vulnetix.com." icon="server" >}}
  {{< card link="ci-cd" title="Authentication in CI/CD" subtitle="Ephemeral credentials, masking, and per-platform secret wiring." icon="cog" >}}
  {{< card link="rotation" title="Rotation & Revocation" subtitle="Rotation cadence, compromise response, and audit." icon="refresh" >}}
  {{< card link="troubleshooting" title="Troubleshooting" subtitle="Every auth error message and what to do about it." icon="support" >}}
{{< /cards >}}

## Commands

| Command | Purpose |
|---------|---------|
| `vulnetix auth` / `vulnetix auth login` | Authenticate. Browser device flow by default. |
| `vulnetix auth status` | Show the active credential, its source, your plan, and the state of **every** credential source. |
| `vulnetix auth verify` | Validate credentials against the API without saving or modifying anything. Designed for CI. |
| `vulnetix auth logout` | Remove credentials from both file stores and clear the matching OS keychain entries. |

`vulnetix auth verify` never writes. Use it as the first step of any pipeline that assumes credentials are present.

## Unauthenticated Community Access

The CLI ships with an embedded community organization credential. When no credential is found, VDB lookups still work at community rate limits — `vulnetix auth status` reports `Community - unauthenticated (VDB only)`.

The embedded credential is intentionally public. It traverses the identical API gateway, auth headers, and rate-limit enforcement as any registered user, so it grants no privilege a stranger could not obtain by signing up. Uploads, org-scoped data, and enterprise features require a real credential.
