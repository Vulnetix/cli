---
title: "Troubleshooting"
weight: 8
description: "Every authentication error message, what causes it, and how to resolve it."
---

Start here, always:

```sh
vulnetix auth status
```

It prints the active credential, its source, and the state of every source. Most authentication problems are a source you forgot about winning the [precedence chain](../precedence/).

---

## Error Messages

### `choose only one of --api-key, --secret, or --token`

The three credential flags are mutually exclusive. Pick the one matching the credential you hold. `--secret` is the SigV4 HMAC secret, not an ApiKey.

### `--org-id must be a valid UUID, got: …`

`--org-id` is validated before any network call. Copy the organization UUID from your account; do not use the org *name* or the `<org>:<key>` composite.

### `--org-id is required with --api-key`

You are on a non-TTY (CI, a pipe, a container without a terminal) and omitted `--org-id`. On an interactive terminal the CLI would have prompted. Pass the flag, or set `VULNETIX_ORG_ID`.

### `--method is deprecated; use --api-key + --org-id (ApiKey), --secret + --org-id (SigV4), or --token (Bearer)`

Drop `--method`. The credential flag now selects the method. See [Credential Methods](../methods/#deprecated---method).

### `--noninteractive uses ApiKey credentials only; use --api-key with --org-id`

`--noninteractive` cannot be combined with `--secret` or `--token`. Drop the flag, or switch to an ApiKey.

### `missing ApiKey or org for noninteractive login`

`--noninteractive` found neither `--api-key`/`VULNETIX_API_KEY` nor `--org-id`/`VULNETIX_ORG_ID`. Note that both are required; setting only one falls into this error rather than falling through to another source.

### `authentication test failed: …`

`auth login` verified the credential against the API and the API rejected it. The credential is wrong, revoked, or is the wrong *kind*:

- An ApiKey passed to `--secret` fails here, because the CLI derives `HMAC-SHA256(apikey, orgID)` and sends a signature that does not match anything.
- A Bearer token passed to `--api-key` fails here.
- An ApiKey paired with the wrong org UUID fails here.

Nothing is written when this error appears; your previous credential is untouched.

### `no credentials found. Run 'vulnetix auth login' or set VULNETIX_API_KEY + VULNETIX_ORG_ID environment variables`

Every source in the chain came up empty. Confirm with `vulnetix auth status` — a source showing `unusable` counts as empty.

### `netrc credentials are not usable: …`

The netrc file exists, has a `packages.vulnetix.com` entry, and is broken. Usually permissions:

```
/home/you/.netrc permissions are too open; run chmod 600 /home/you/.netrc
```

Or a malformed stanza missing `login` or `password`. Note this is one of the few cases where an unusable source produces a hard error rather than a silent fall-through.

### `credentials file … references an unusable keyring secret: keyring entry "hmac-secret:…" not found`

The credentials file says the secret is in the keychain, and it is not. Causes: the keychain was reset, the entry was deleted manually, you copied `credentials.json` between machines, or you are running under a different user than the one that stored it.

```sh
vulnetix auth logout
vulnetix auth login --store keyring
```

### `credentials file … is missing org_id`

Hand-edited or truncated file. Do not repair it; re-run `auth login`.

### `no OS keychain backend detected on linux/amd64: …`

There is no Secret Service on the D-Bus session bus. Normal for SSH sessions, containers, and CI runners.

The login still succeeds — the CLI warns and falls back to `--store home`. If you want the keychain, start a Secret Service provider (`gnome-keyring-daemon --start`) and ensure `DBUS_SESSION_BUS_ADDRESS` is set. If you are in CI, use environment variables instead; see [Authentication in CI/CD](../ci-cd/).

### `GITHUB_TOKEN environment variable is required`

Not a Vulnetix credential problem. `vulnetix gha upload` needs a GitHub token to list workflow artifacts. Pass `GITHUB_TOKEN: ${{ github.token }}` on the step.

### `device flow timed out`

The five-minute window elapsed with no browser authorization, on a non-TTY where retry cannot be prompted. Use `--noninteractive` with an ApiKey, or environment variables.

---

## Symptoms Without Errors

### "I logged in but the CLI still acts unauthenticated"

An environment variable outranks the credential you just wrote. `VULNETIX_API_TOKEN` beats everything; `VULNETIX_API_KEY` + `VULNETIX_ORG_ID` beat both file stores.

```sh
env | grep -E 'VULNETIX_|VVD_'
```

### "I logged out but I am still authenticated"

`auth logout` clears the two credential files and their keychain entries. It does not clear environment variables, and it does not touch netrc.

```sh
vulnetix auth status              # look at the Source line
vulnetix package-firewall uninstall   # if the source is netrc
```

### "It works locally but uses community access in CI"

The secret name is misspelled, or the platform did not inject it. Azure DevOps in particular does **not** pass secret variables into the task environment unless you map them explicitly with an `env:` block.

Fail loudly instead of degrading silently:

```sh
vulnetix auth status | grep -q 'environment' || {
  echo "expected an environment credential"; exit 1;
}
```

### "My identity changed when I `cd`'d into a repo"

A project-scoped `./.vulnetix/credentials.json` in that repository outranks your home credential. Check whether it was committed by someone else:

```sh
git log --oneline -- .vulnetix/credentials.json
```

If it was, that credential is compromised. See [Rotation & Revocation](../rotation/#compromise-response).

### "Uploads stopped working after I restored my home directory from backup"

Permissions drifted. netrc is rejected outright when group- or world-readable, and the CLI falls through to community access — which can read VDB but cannot upload.

```sh
chmod 600 ~/.netrc
chmod 600 ~/.vulnetix/credentials.json
chmod 700 ~/.vulnetix
```

### "Keyring prompts every single run" (macOS)

The login keychain is locked, or the CLI binary changed and the keychain ACL no longer trusts it. Reinstalling or rebuilding `vulnetix` produces a new binary identity. Choose *Always Allow* at the prompt, or accept the prompt as intended behaviour on a locked keychain.

---

## Diagnostic Checklist

```sh
# 1. What credential is active, and from where?
vulnetix auth status

# 2. Does it actually work?
vulnetix auth verify

# 3. Is an environment variable shadowing a stored credential?
env | grep -E 'VULNETIX_|VVD_'

# 4. Is there a project credential you did not create?
ls -la .vulnetix/credentials.json 2>/dev/null

# 5. Are permissions intact?
stat -c '%a %n' ~/.vulnetix ~/.vulnetix/credentials.json ~/.netrc 2>/dev/null

# 6. Is netrc claiming the credential?
grep -A2 'machine packages.vulnetix.com' ~/.netrc 2>/dev/null
```

If steps 1 and 2 disagree — status says authenticated, verify fails — the credential was valid when stored and has since been revoked or rotated. Re-authenticate.
