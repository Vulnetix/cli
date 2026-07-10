---
title: "Credential Storage"
weight: 3
description: "Keyring, home file, project file, custom directories, and what is written where."
---

`vulnetix auth login --store <backend>` chooses where the credential is persisted. The default is `home`.

```sh
vulnetix auth login --store keyring   # recommended
vulnetix auth login --store home
vulnetix auth login --store project
```

{{< callout type="info" >}}
**Always prefer `--store keyring` when a keychain is available.** The secret goes into the OS keychain, protected by the same access control as your other saved passwords. Only non-sensitive metadata reaches the filesystem.
{{< /callout >}}

---

## Keyring

Secrets are stored in the OS keychain under service name `vulnetix`:

| Platform | Backend |
|----------|---------|
| macOS | Keychain Services (login keychain) |
| Windows | Credential Manager |
| Linux | freedesktop Secret Service over the D-Bus session bus (GNOME Keyring, KWallet) |

Account names are scoped per organization:

| Credential | Keychain account |
|------------|------------------|
| SigV4 secret | `hmac-secret:<orgID>` |
| Bearer token | `token:<orgID>` |
| ApiKey | `apikey:<orgID>` |

### Keyring Still Writes a File

This surprises people. `--store keyring` writes **metadata** to `~/.vulnetix/credentials.json` and the **secret** to the keychain:

```json
{
  "org_id": "8ff8f1e4-…",
  "method": "apikey",
  "api_key_in_keyring": true
}
```

The `*_in_keyring` flags tell the loader to hydrate the secret from the keychain. Deleting the file orphans the keychain entry: the secret still exists but nothing will read it. Use `vulnetix auth logout`, which clears both.

Note that keyring metadata always lands in the **home** directory, never the project directory, even if you previously used `--store project`.

### When There Is No Keychain

Headless Linux, containers, and CI runners usually have no Secret Service on the session bus. `--store keyring` detects this, warns, and falls back to `home`:

```
no OS keychain backend detected on linux/amd64: …
  expected: a freedesktop Secret Service provider (GNOME Keyring / KWallet) running on the D-Bus session bus — headless sessions usually have none
  setup guide: https://vulnetix.com/docs/cli/keychain
  alternatively store credentials in a file with --store home|project
No usable OS keychain - falling back to file storage.
```

The login still succeeds. If you need the fallback to be a hard failure instead, use environment variables and skip `auth login` entirely — see [Authentication in CI/CD](../ci-cd/).

Check availability before you rely on it:

```sh
vulnetix auth status   # the "keyring" row reports set / not set / unusable
```

---

## Home File

```
~/.vulnetix/credentials.json
```

Directory created mode `0700`, file written mode `0600`. Contains the secret in plaintext unless the keyring flags are set.

Use it when there is no keychain but the machine has a single trusted user.

## Project File

```
./.vulnetix/credentials.json
```

Same permissions. Resolved **before** the home file, so a project credential overrides your user credential inside that directory tree.

{{< callout type="error" >}}
The project file is the highest-risk store. It sits in your working tree, where it can be committed, copied into a Docker build context, matched by a `COPY . .`, or archived into a release tarball. Add `.vulnetix/credentials.json` to `.gitignore` and `.dockerignore` before you create one.
{{< /callout >}}

Reasonable uses: short-lived CI checkouts on ephemeral runners, or a container whose filesystem is destroyed at exit. Not reasonable: a long-lived developer clone.

## Custom Directory

Two overrides move the *home* credential directory. Project credentials are unaffected by both.

```sh
# Flag, per invocation
vulnetix auth login --store keyring --store-dir /run/user/1000/vulnetix

# Environment, process-wide
export VULNETIX_CREDENTIALS_DIR=/run/user/1000/vulnetix
vulnetix auth status
```

The flag wins over the environment variable, which wins over `$HOME/.vulnetix`. If the home directory cannot be determined at all, the CLI falls back to a relative `.vulnetix` directory in the current working directory — worth knowing before you run the CLI as a service account with no `$HOME`.

Pointing `VULNETIX_CREDENTIALS_DIR` at a `tmpfs` such as `/run/user/$UID` gives you credentials that never touch persistent storage and vanish on reboot:

```sh
export VULNETIX_CREDENTIALS_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/vulnetix"
```

---

## The Credentials File Format

```json
{
  "org_id": "8ff8f1e4-…",
  "api_key": "6e40f1c3…",
  "secret": "…",
  "token": "…",
  "method": "apikey",
  "hmac_in_keyring": false,
  "token_in_keyring": false,
  "api_key_in_keyring": false
}
```

Only the fields for the active method are present. `method` is one of `token`, `apikey`, `sigv4`.

Do not hand-edit this file to rotate a credential — `vulnetix auth login` verifies against the API before writing, so a typo fails loudly instead of leaving you with a file that only breaks on the next scan.

## Removing Credentials

```sh
vulnetix auth logout
```

Removes both the home and project files and deletes any keychain entries they referenced. It does **not** unset environment variables and does **not** touch netrc — if `vulnetix auth status` still shows you authenticated after a logout, one of those two is why.

To clear netrc credentials, see [netrc & Package Firewall](../netrc/).
