# Policy Fetch

Last Updated: 2026-07-14

The CLI fetches three kinds of organisation policy from vdb-api. This document covers what each fetch does with the answer, and (the part worth reading) what `{"config": null}` used to mean and no longer does.

Server side: [vdb-api/.repo/auth-and-tenancy.md](https://github.com/vulnetix/vdb-api/blob/main/.repo/auth-and-tenancy.md). Identity model: [vulnetix-authentic-aws/.repo/identity-model.md](https://github.com/vulnetix/vulnetix-authentic-aws/blob/main/.repo/identity-model.md).

## The three fetches

| Endpoint | Client method (`pkg/vdb/api_cli.go`) | Consumers |
| --- | --- | --- |
| `POST /v2/cli.quality-gate-get` | `CliQualityGateGet` | `applyOrgQualityGate` at scan time (`cmd/quality_gate_enforce.go`); `config get quality-gate` (`renderQualityGateGet`) |
| `POST /v2/cli.package-firewall-get` | `CliPackageFirewallGet` | `config get package-firewall` (`renderPackageFirewallGet`) |
| `POST /v2/cli.ai-firewall-baseline` | `CliAiFirewallBaseline` | `ai-firewall baseline`; composed into `ai-firewall apply` when `spec.baseline.enabled` |

All three are read-only, all three carry an empty payload. The org is resolved from the authenticated request, and none of them creates anything server-side.

The uuid in the API key identifies a **principal**. The policy that comes back belongs to that principal's **tenant**, resolved server-side by `TenantOrgID`. A Teams member and their owner run the same `vulnetix scan` and are gated by one policy, which is the entire point of the split.

## Quality gate at scan time

```mermaid
sequenceDiagram
    participant Scan as vulnetix scan
    participant AQG as applyOrgQualityGate
    participant API as vdb-api
    participant SA as SaaS Postgres

    Scan->>AQG: qualityGateOverridePointers{9 scan-time locals}
    AQG->>AQG: auth.LoadCredentials()
    alt no creds, or community tier
        AQG-->>Scan: no-op, scan flags and builtin defaults stand
    end
    AQG->>API: POST /v2/cli.quality-gate-get (ApiKey = principal)
    API->>API: TenantOrgID(principal) → tenant
    API->>SA: SELECT ... FROM "CliQualityGateConfig" WHERE "orgUuid" = tenant
    alt lookup fails
        API-->>AQG: error
        AQG-->>Scan: no-op, scan flags stand (verbose notes it)
    end
    SA-->>API: row (or none)
    API-->>AQG: {"config": {...}} or {"config": null}

    alt config == null
        AQG-->>Scan: "no policy configured", scan flags stand
    else config present
        loop each of the 9 enforcement fields
            AQG->>AQG: field null? → leave the caller's local alone
            AQG->>AQG: field set?  → OVERWRITE the local; ORG POLICY ALWAYS WINS
        end
        AQG-->>Scan: locals now carry the org's enforcement
    end
```

Two semantics are decided and should not be relitigated without a reason.

**Org policy always wins.** A value the org has set overrides even an explicitly-passed CLI flag. `noteOverride` prints `--severity high superseded by org policy: critical` under `--verbose`. A security policy a developer can turn off with a flag is not a policy.

**NULL means "not set", not "false".** `qgConfigBool` / `qgConfigInt` / `qgConfigString` each return a second boolean that is false when the field is absent or JSON `null`, and the caller then leaves its local untouched. This is what makes the seeded defaults safe: a freshly-provisioned org has all nine enforcement columns NULL, so its CI behaves exactly as it did before it had a policy row at all.

## What `{"config": null}` used to mean

It meant **every organisation**, and it meant that for the entire life of the product.

Nothing ever seeded a `CliQualityGateConfig` row. Not `register`, not the OIDC callback, not the Stripe webhook. The three doors each did their own thing and none of them wrote a line of policy. So `POST /v2/cli.quality-gate-get` returned `{"config": null}` for every org that had ever existed, and `applyOrgQualityGate` took its "no policy configured" early return every single time. The four EOL-to-severity columns (`eolNextQuarterSeverity`, `eolThisQuarterSeverity`, `eolWithin30DaysSeverity`, `eolRetiredSeverity`), all with perfectly good defaults, were unreachable dead schema. The feature was wired end to end and could not fire.

Since `ProvisionOrg` ([vdb-site/.repo/org-provisioning.md](https://github.com/vulnetix/vdb-site/blob/main/.repo/org-provisioning.md)), a new org is seeded at creation with the EOL buckets populated and the nine enforcement columns left NULL. So today:

- **`{"config": null}`** means an org that predates the seeder and has not been backfilled. It is now the exception, not the rule.
- **`{"config": {...}}` with every enforcement field null** means a seeded org that has not opted into enforcement. This is the normal state of a new org, and it is why an upgrade does not suddenly start failing builds that used to pass. Enforcement is a decision a human makes.
- **`{"config": {...}}` with fields set** means an owner configured it, and it wins.

The CLI needs no change for any of this: `renderQualityGateGet` already prints a "no policy configured" line for a nil config and "not set" for each null field, and `applyOrgQualityGate` already treats the two cases differently. What changed is which branch actually gets taken.

## Package firewall

`CliPackageFirewallGet` returns `{"config": {...}|null, "mirrors": [...]}`. For a nil config, `renderPackageFirewallGet` reports that no policy is configured and that the proxy defaults apply, which is now literally true: the proxy's in-memory defaults are the same open values the columns declare, and package-firewall no longer writes a row on a read ([package-firewall/.repo/org-policy-resolution.md](https://github.com/vulnetix/package-firewall/blob/main/.repo/org-policy-resolution.md)).

A seeded org has a permissive config row (every threshold `0`, every block `false`) plus the mirrors package-firewall backfills for each ecosystem. The `mirrors` array is populated from the tenant's config row, so every member of an org sees the same mirror set.

## AI firewall baseline

`CliAiFirewallBaseline` fetches the server's recommended guardrail set. It is composed into `ai-firewall apply` when `spec.baseline.enabled` is true, and it **soft-fails on 404** unless `--baseline-required`. An older server simply may not have the endpoint.

The same baseline is what vdb-site seeds onto a new org, and this is deliberate: vdb-site embeds the output of vdb-api's `cmd/baseline-export` rather than keeping a hand-copied second list, so "baseline 2026.07.1" cannot be one set of rules over the wire and a different set in the database. 23 guardrails, 21 enabled; `injection-delimiter-spoof` and `pii-phone` ship disabled because a guardrail that cries wolf teaches an organisation to switch the firewall off.

The practical consequence for `apply`: on a freshly provisioned org, the guardrails the server reports as the baseline are already present as rows, so a first `apply` with the baseline composed in is close to a no-op rather than a bulk create. Guardrails reconcile by **name**, which is what makes that idempotent.

## Related documents

- [vdb-api/.repo/auth-and-tenancy.md](https://github.com/vulnetix/vdb-api/blob/main/.repo/auth-and-tenancy.md). How the API key becomes a tenant, and the 401/403/409/503 rules the CLI's retry logic sees.
- [vdb-site/.repo/org-provisioning.md](https://github.com/vulnetix/vdb-site/blob/main/.repo/org-provisioning.md). What gets seeded and why the defaults are asymmetric.
- [vulnetix-authentic-aws/.repo/identity-model.md](https://github.com/vulnetix/vulnetix-authentic-aws/blob/main/.repo/identity-model.md), the hub.
