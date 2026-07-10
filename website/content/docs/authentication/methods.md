---
title: "Credential Methods"
weight: 1
description: "Bearer token, ApiKey, SigV4, browser device flow, and the community fallback."
---

## Browser Device Flow (Default)

Running `vulnetix auth` or `vulnetix auth login` with no credential flag starts an [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) device authorization grant.

```sh
vulnetix auth login --store keyring
```

The flow uses two codes, and the distinction is the whole security model:

| Code | Who sees it | What it grants |
|---|---|---|
| `device_code` | The CLI only. Never printed, never typed. | Everything. Possession redeems the ApiKey. |
| `user_code` | Printed in your terminal, typed into the browser. | Nothing. It is only an approval handle. |

1. Before any browser opens, the CLI asks `https://www.vulnetix.com` for a grant and receives a secret `device_code` plus a six-character `user_code` (`ABC-123`).
2. The CLI opens `https://www.vulnetix.com/cli-login-code`, pre-filled with the `user_code`, and prints the same code so you can confirm they match.
3. Signed in to your VDB account, you approve the code. The browser is never shown an ApiKey.
4. The CLI redeems its `device_code`, receives an org ID and an ApiKey, verifies them against the API, and persists them to the store you chose.

The grant expires after five minutes and each `device_code` is single-use — a redeemed or denied grant cannot mint a second key. On an interactive terminal you are prompted for the store, and an expiry offers a retry. On a non-TTY the `--store` flag decides, and an expiry is a hard failure.

Device flow always yields an **ApiKey** credential.

### Pointing the flow at another host

`VULNETIX_WEB_URL` overrides the console base URL (default `https://www.vulnetix.com`). This exists for local verification against a dev website; it is not something a normal install needs.

```sh
VULNETIX_WEB_URL=http://localhost:5173 vulnetix auth login --verbose
```

`--verbose` prints the resolved authorize and token endpoints before the first request.

---

## Bearer Token

The current, self-service credential. Create one from your account's `/auth` page (Tokens and App passwords).

```sh
# Flag
vulnetix auth login --token "$TOKEN" --store keyring

# Environment — no login step needed
export VULNETIX_API_TOKEN="…"
vulnetix scan
```

The token is org-less: the server resolves your organization from the token itself, so `--org-id` is optional. Supplying `VULNETIX_ORG_ID` alongside `VULNETIX_API_TOKEN` records the org in the credential but does not change the request.

Sent as `Authorization: Bearer <token>`.

{{< callout type="info" >}}
`VULNETIX_API_TOKEN` sits at the **top** of the precedence chain. If it is set, nothing else is consulted — not your keyring, not your credentials file. This is deliberate: an explicit environment token always wins.
{{< /callout >}}

---

## ApiKey

An org-scoped hex digest. Requires `--org-id`.

```sh
# Flag — --org-id is mandatory
vulnetix auth login \
  --api-key "$VULNETIX_API_KEY" \
  --org-id "$VULNETIX_ORG_ID" \
  --store keyring

# Environment — no login step needed
export VULNETIX_ORG_ID="8ff8f1e4-…"   # must be a valid UUID
export VULNETIX_API_KEY="6e40f1c3…"   # hex digest
vulnetix scan
```

Sent as `Authorization: ApiKey <orgID>:<key>`.

### The `<org>:<key>` Prefix

Your account GUI presents the ApiKey as `<orgId>:<hex>`. The CLI builds that header itself, so it strips a leading `<org>:` if you paste the full value. Both of these are equivalent:

```sh
vulnetix auth login --org-id 8ff8f1e4-… --api-key 8ff8f1e4-…:6e40f1c3…
vulnetix auth login --org-id 8ff8f1e4-… --api-key 6e40f1c3…
```

### Non-interactive Mode

`--noninteractive` forces ApiKey from flags or environment and never opens a browser or prompts.

```sh
vulnetix auth login --noninteractive --store keyring
```

It reads `--api-key` or `VULNETIX_API_KEY`, and `--org-id` or `VULNETIX_ORG_ID`. Combining it with `--secret` or `--token` is an error. Use it in provisioning scripts where a hung browser prompt would block forever.

---

## SigV4

An org-scoped HMAC secret. Requires `--org-id`.

```sh
# Flag
vulnetix auth login \
  --secret "$VVD_SECRET" \
  --org-id "$VVD_ORG" \
  --store keyring

# Environment — no login step needed
export VVD_ORG="8ff8f1e4-…"
export VVD_SECRET="…"
vulnetix scan
```

Note the environment variable names: **`VVD_ORG` and `VVD_SECRET`**, not the `VULNETIX_*` pair. They are only read together; setting one alone has no effect.

The CLI derives the request credential as `HMAC-SHA256(secret, orgID)` and sends `Authorization: ApiKey <orgID>:<derived>`. At login, `vulnetix auth verify` performs a full token exchange against the API to prove the secret is real, which is a stronger check than the ApiKey path.

{{< callout type="warning" >}}
The SigV4 secret is the highest-value credential the CLI handles: it derives request keys rather than being one. Store it in the keyring. Never place it in a project file, a container image, or a shell history line.
{{< /callout >}}

---

## `--org-id` Applies to Both ApiKey and SigV4

`--org-id` is required by `--api-key` and `--secret`, and ignored by `--token`.

It must be a valid UUID. A malformed value fails before any network call:

```
--org-id must be a valid UUID, got: my-org
```

On an interactive terminal, omitting `--org-id` with `--api-key` or `--secret` prompts for it. On a non-TTY it is a hard error:

```
--org-id is required with --api-key
```

Set `VULNETIX_ORG_ID` once in your shell profile and you can omit the flag entirely.

---

## Deprecated: `--method`

`--method apikey|sigv4` is deprecated. The credential flag now selects the method:

| Old | New |
|-----|-----|
| `--method apikey --api-key K --org-id O` | `--api-key K --org-id O` |
| `--method sigv4 --secret S --org-id O` | `--secret S --org-id O` |

Passing `--method` with no credential flag fails:

```
--method is deprecated; use --api-key + --org-id (ApiKey), --secret + --org-id (SigV4), or --token (Bearer)
```

---

## Community Fallback

With no credential configured, the CLI authenticates as an embedded community organization. VDB lookups work at community rate limits; uploads and org-scoped features do not.

The community credential is hardcoded in the binary on purpose. It is not a back door: it goes through the same API gateway, the same `ApiKey` header, and the same rate-limit enforcement as a registered user, so it confers nothing beyond what signing up would give you. Publishing it costs nothing and removes an entire class of "unauthenticated side channel" from the design.

`vulnetix auth status` reports this state explicitly rather than pretending to be logged in.
