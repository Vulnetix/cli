---
title: "Credential Precedence"
weight: 2
description: "The exact order in which the CLI resolves credentials, and how to inspect what it chose."
---

## Resolution Order

The CLI walks these sources top to bottom and uses the **first complete match**. It never merges sources.

| # | Source | Complete when |
|---|--------|---------------|
| 1 | `VULNETIX_API_TOKEN` | The variable is non-empty |
| 2 | `VULNETIX_API_KEY` **and** `VULNETIX_ORG_ID` | Both are non-empty |
| 3 | `VVD_ORG` **and** `VVD_SECRET` | Both are non-empty |
| 4 | Project file `./.vulnetix/credentials.json` | File parses and has `org_id` (or a token) |
| 5 | Home file `~/.vulnetix/credentials.json` | Same |
| 6 | netrc entry for `packages.vulnetix.com` | Entry has both `login` and `password` |
| 7 | Embedded community credential | Always |

Consequences worth internalising:

- **A stale `VULNETIX_API_TOKEN` in your shell silently shadows a fresh `vulnetix auth login`.** The login writes to the keyring; resolution never gets that far.
- **A project `.vulnetix/credentials.json` beats your home credential.** Cloning a repo that ships one hijacks your identity for that directory. See [File Permissions](../file-permissions/#never-commit-credentials).
- **Half-set environment pairs are ignored, not errors.** `VULNETIX_API_KEY` without `VULNETIX_ORG_ID` falls through to the files, which is easy to misread as "the env var didn't work".
- **netrc is a genuine credential source, not just Package Firewall config.** Running `vulnetix package-firewall setup` makes the CLI authenticable even after `vulnetix auth logout`.

## The Keyring Is Not a Separate Level

Keyring-stored secrets are reached *through* levels 4 and 5. The credentials file holds metadata plus a flag (`hmac_in_keyring`, `token_in_keyring`, `api_key_in_keyring`); the secret itself is hydrated from the OS keychain when the file is loaded.

Delete the credentials file and the keychain entry becomes unreachable, even though it still exists. `vulnetix auth logout` removes both.

## Inspecting the Active Source

```sh
vulnetix auth status
```

Output has three parts:

1. **Auth state** — organization, method, active source, plan, masked secret.
2. **Credential sources** — every source, each marked `set`, `not set`, `unusable`, or `active`.
3. **Package Firewall** — which ecosystems are configured against `packages.vulnetix.com`.

`unusable` is the interesting state. It means the source exists but cannot be used — a corrupt JSON file, a credentials file referencing a keyring entry that has been deleted, or a netrc with permissions that are too open. An `unusable` source **does not block** resolution; the CLI moves to the next one. If your identity silently changes after a keychain reset, this is why.

## Verifying Without Side Effects

```sh
vulnetix auth verify
```

Loads the winning credential, calls an authenticated endpoint, and exits non-zero on failure. It writes nothing. Put it at the top of a pipeline so a credential problem fails on line one rather than halfway through a scan.

```sh
vulnetix auth verify --base-url https://api.vdb.vulnetix.com/v1
```

## Forcing a Specific Source

There is no `--source` flag. To force a source, remove the ones above it:

```sh
# Force the home credential, ignoring env and project files
env -u VULNETIX_API_TOKEN -u VULNETIX_API_KEY -u VVD_SECRET \
  sh -c 'test ! -f .vulnetix/credentials.json && vulnetix auth status'
```

In CI, prefer to set exactly one source and assert on it:

```sh
vulnetix auth status | grep -q 'environment (VULNETIX_API_TOKEN)' \
  || { echo "unexpected credential source"; exit 1; }
```
