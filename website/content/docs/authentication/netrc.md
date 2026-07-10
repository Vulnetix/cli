---
title: "netrc & Package Firewall"
weight: 5
description: "The shared netrc contract across the Vulnetix CLI, Package Firewall, Go, npm, pip, and packages.vulnetix.com."
---

Vulnetix products adhere to the standard `netrc` format. One entry authenticates the CLI, the Package Firewall, and every package manager that speaks Basic auth against `packages.vulnetix.com`.

## Location

| Platform | Path |
|----------|------|
| Linux, macOS, BSD | `~/.netrc` |
| Windows | `%USERPROFILE%\_netrc` |

This is the same file and the same lookup that `curl`, `git`, `go`, `npm`, `pip`, and `wget` use. Vulnetix does not invent a private format or a private location.

## Entry Format

```
machine packages.vulnetix.com
  login 8ff8f1e4-0000-4000-8000-000000000000
  password 6e40f1c324576b65f85dc3c9ff93d31eb65298836b46b540fa18825b47174ce8
```

- `login` is your **organization UUID**.
- `password` is your **ApiKey** hex digest.

The parser accepts the entry on one line or several, strips `#` comments, and stops at the next `machine` or `default` token. A `default` entry is not used as a Vulnetix credential — only an explicit `machine packages.vulnetix.com`.

## Writing It

Let the CLI do it. `vulnetix package-firewall setup` creates or updates the entry idempotently and sets mode `0600`:

```sh
vulnetix package-firewall setup --dry-run   # show what would change
vulnetix package-firewall setup
```

It also writes the per-ecosystem configuration (`GOPROXY`/`GOAUTH`, `.npmrc`, `pip.conf`, and so on). See [Package Firewall](/docs/enterprise/package-firewall/).

Writing it by hand:

```sh
umask 077
cat >> ~/.netrc <<EOF
machine packages.vulnetix.com
  login $VULNETIX_ORG_ID
  password $VULNETIX_API_KEY
EOF
chmod 600 ~/.netrc
```

## Permissions Are Enforced on Read

Unlike `credentials.json`, netrc permissions are validated every time the file is read. If any group or other bit is set, the CLI refuses the credential:

```
/home/you/.netrc permissions are too open; run chmod 600 /home/you/.netrc
```

This is not a warning. The source is reported as `unusable` by `vulnetix auth status` and skipped, and resolution continues to the next source — most often the community fallback, which is why the symptom presents as "my uploads stopped working" rather than an auth error.

```sh
chmod 600 ~/.netrc
vulnetix auth status
```

{{< callout type="warning" >}}
On Windows the permission check is a no-op, because POSIX mode bits do not exist there. `_netrc` is protected only by its NTFS ACL, which you must set yourself. See [File Permissions](../file-permissions/#windows).
{{< /callout >}}

## netrc as a CLI Credential

An entry for `packages.vulnetix.com` is the **sixth** and last real source in the [precedence chain](../precedence/). If it is present, the CLI is authenticated even with no credentials file and no environment variables.

Two consequences:

- Running `vulnetix package-firewall setup` implicitly authenticates the CLI.
- `vulnetix auth logout` does **not** clear netrc. To fully deauthenticate:

```sh
vulnetix auth logout
vulnetix package-firewall uninstall   # removes the netrc entry and ecosystem config
```

Or edit `~/.netrc` and delete the `machine packages.vulnetix.com` stanza by hand.

Confirm:

```sh
vulnetix auth status
# Auth state
# ⚠ Community - unauthenticated (VDB only)
```

## Consumers of the Same Entry

Once the entry exists, these all authenticate without further configuration:

| Tool | Mechanism |
|------|-----------|
| Vulnetix CLI | netrc source in the credential chain |
| Go | `GOPROXY=https://packages.vulnetix.com/...`, `GOAUTH=netrc` |
| curl | `curl -n` / `--netrc` |
| git | `git config credential.helper netrc` |
| npm, pip, cargo, maven, … | Basic auth via the registry config the Package Firewall writes |

Because a single credential backs all of them, its blast radius on compromise is the whole organization's package supply chain. Treat it accordingly — see [Rotation & Revocation](../rotation/).

## Secrets Hygiene

netrc is plaintext by design. There is no keyring path for it, because the tools that consume it do not know how to read a keyring.

- Never commit it. `~/.netrc` is outside the repo; keep it that way.
- Exclude it from container images and bind mounts unless the container genuinely needs to fetch packages.
- Exclude it from backups you do not fully control.
- On shared or multi-user hosts, prefer per-user entries over a system-wide one.
- Rotate the ApiKey it contains on the same schedule as any other credential.
