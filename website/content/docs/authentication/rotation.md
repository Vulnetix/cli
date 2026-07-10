---
title: "Rotation & Revocation"
weight: 7
description: "Rotation cadence, zero-downtime rollover, compromise response, and audit."
---

## Cadence

| Credential | Rotate | Rationale |
|------------|--------|-----------|
| Bearer token (CI) | 90 days, or per pipeline lifetime | Individually revocable; cheapest to rotate |
| Bearer token (developer) | 180 days, or on device change | Tied to a person and a machine |
| ApiKey | 180 days | Org-scoped; wider blast radius |
| SigV4 secret | 365 days, or immediately on any suspicion | Derives request credentials; highest value |
| netrc entry | Whenever the ApiKey inside it rotates | It *is* an ApiKey |

Rotate immediately, regardless of schedule, when:

- A credential appeared in a commit, a build log, a screenshot, a support ticket, or a shell history file.
- Someone with access leaves the team.
- A laptop or CI runner is lost, reimaged, or suspected compromised.
- A dependency in a pipeline that had access is found to be malicious.
- `vulnetix auth status` shows a credential source you did not configure.

## Zero-Downtime Rollover

Credentials are additive: issue the new one before revoking the old one.

1. **Issue** a new token or key from your account.
2. **Update** the consumer. For CI, change the secret value in the platform's secret store; for a developer machine, re-run `vulnetix auth login`.
3. **Verify** the new credential is the one in use.
   ```sh
   vulnetix auth verify
   vulnetix auth status   # confirm Organization, Method, and Source
   ```
4. **Wait** one full pipeline cycle so any in-flight job with the old value completes.
5. **Revoke** the old credential from your account.
6. **Confirm** the old credential is dead.
   ```sh
   VULNETIX_API_TOKEN="$OLD_TOKEN" vulnetix auth verify   # must exit non-zero
   ```

Step 6 is the one people skip. Revocation that was never verified is a credential you still believe is dead.

## Rotating Each Store

### Keyring

```sh
vulnetix auth logout                # clears file metadata and keychain entries
vulnetix auth login --store keyring # re-authenticate with the new credential
```

Do not edit the keychain entry by hand. The metadata file and the keychain account name must agree, and `logout`/`login` keeps them consistent.

### File Stores

```sh
vulnetix auth logout
vulnetix auth login --api-key "$NEW_KEY" --org-id "$ORG" --store home
```

`auth login` verifies against the API before writing, so a bad key fails without destroying the working credential — but `auth logout` has already run by then. On a machine you cannot easily re-provision, verify first:

```sh
VULNETIX_API_KEY="$NEW_KEY" VULNETIX_ORG_ID="$ORG" vulnetix auth verify \
  && vulnetix auth logout \
  && vulnetix auth login --api-key "$NEW_KEY" --org-id "$ORG" --store keyring
```

### netrc

```sh
vulnetix package-firewall uninstall   # removes the entry and ecosystem config
vulnetix package-firewall setup       # rewrites it with the current credential
```

Every package manager configured against `packages.vulnetix.com` picks up the new value on its next fetch. There is no cache to clear.

### Environment Variables

Rotation is a redeploy. Confirm nothing stale survives in a shell, a `.env` file, a systemd unit, or a container image:

```sh
grep -rlE 'VULNETIX_(API_KEY|API_TOKEN)|VVD_SECRET' \
  ~/.bashrc ~/.zshrc ~/.profile ~/.config/fish/config.fish \
  /etc/environment /etc/systemd/system 2>/dev/null
```

---

## Compromise Response

Work in this order. Revocation first: containment beats investigation.

1. **Revoke** the credential from your account. Do not wait to understand the scope.
2. **Rotate** every credential that shared the exposure surface. A leaked CI token means every secret that pipeline could read is suspect, not just this one.
3. **Check `vulnetix auth status`** on affected machines. An attacker with filesystem access may have written a project `.vulnetix/credentials.json`, a netrc entry, or exported an environment variable — all of which outrank your home credential in the precedence chain.
   ```sh
   vulnetix auth status
   find . -name credentials.json -path '*/.vulnetix/*'
   grep -c 'machine packages.vulnetix.com' ~/.netrc
   ```
4. **Audit** what the credential could reach: uploaded artifacts, org policy changes, Package Firewall configuration, private package fetches.
5. **Purge** the value from wherever it landed — build logs, artifact stores, chat history, ticket attachments. Purging is cleanup, not remediation; step 1 was the remediation.
6. **Re-provision** consumers with fresh, individually scoped credentials.

Rewriting git history does not un-leak a pushed secret. Assume every clone, fork, CI cache, and mirror has it.

## Blast Radius by Credential

Understand what you are protecting before deciding how hard to protect it.

| Credential | Grants |
|------------|--------|
| Bearer token | Everything the issuing user can do, scoped to their org |
| ApiKey | Full org API access: uploads, findings, policy reads |
| SigV4 secret | Full org API access, and the ability to derive ApiKeys for that org |
| netrc entry | Org package-registry access via `packages.vulnetix.com`, plus CLI auth |

The SigV4 secret is the only credential from which other credentials can be derived. It is the one that belongs in a keychain or a vault, never in a file, never in an environment variable on a shared runner, and never in a project directory.

## Audit

Establish a periodic check on every machine and pipeline that authenticates:

```sh
# Which source is actually in use, and is anything unusable?
vulnetix auth status

# Any credential file with permissions that drifted?
find "$HOME/.vulnetix" -type f ! -perm 600 -print
stat -c '%a %n' ~/.netrc 2>/dev/null

# Any credential committed to this repository?
vulnetix secrets
```

`vulnetix secrets` scans the working tree for hardcoded credentials, including high-entropy strings that match the ApiKey shape. Run it in CI so a credential can never land in `main`. See [Secrets](/docs/cli-reference/secrets/).

Finally, prefer credentials that are attributable. A Bearer token issued per person and per pipeline tells you *whose* credential leaked and *which* system leaked it. A single org-wide ApiKey shared by twelve pipelines tells you nothing.
