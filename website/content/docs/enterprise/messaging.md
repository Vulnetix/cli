---
title: "Messaging"
weight: 3
description: "Send scan findings, Pix sandbox and agent activity, Belai dispatches and sensitive account activity to Slack, Microsoft Teams, Discord, Google Chat, Jira, GitHub Issues or a signed webhook."
---

The messaging centre in the Vulnetix console (**Configuration → Messaging**) sends Vulnetix
events to the tools your team already uses. A **route** says which events go to which
**connections**, who is @-mentioned, and which **template** words the message.

## Connections

| Provider | How it connects | What it sends |
|----------|-----------------|---------------|
| Slack | Install from **Integrations**, then choose a channel | A message with blocks, buttons and mentions |
| Microsoft Teams | A Workflows "When a Teams webhook request is received" URL | An Adaptive Card |
| Discord | A channel webhook URL | An embed (`@everyone` never fires) |
| Google Chat | A space webhook URL | A card |
| Jira Cloud | Your `https://<site>.atlassian.net`, an account email and an API token | An issue; a repeat comments on the open issue |
| GitHub Issues | The Vulnetix GitHub App, installed from **Integrations** | An issue with labels; a repeat comments on the open issue |
| Signed webhook | Any https endpoint you run | JSON signed per [Standard Webhooks](https://www.standardwebhooks.com/) |

Every credential (bot token, webhook URL, API token, signing secret) is stored in the
secrets vault, encrypted with AWS KMS. It is never shown again after you save it, and only
the Vulnetix server opens it.

## Events

| Category | Events |
|----------|--------|
| Scans and findings | `scan.completed`, `scan.build_broken`, `findings.auto_resolved`, `scan.ingested` (every `vulnetix` scan and finalize) |
| Uploads | `upload.processed` (an SBOM or results file finished processing) |
| Pix sandbox | `pix.<kind>`, such as `pix.egress.blocked`, `pix.forge.pr`, `pix.forge.fail`, `pix.launch.state` |
| Pix agent activity | `pix.agent.<kind>`, such as `pix.agent.worker.started`, `pix.agent.finding.carded`, `pix.agent.repo.publish` |
| Belai | `belai.<kind>`, `belai.dispatch.created` … `belai.dispatch.refused` (remote-control dispatches) |
| Sensitive account activity | `security.mfa.*`, `security.password.*`, `security.member.*`, `security.service_account.*`, `security.org_key.created`, `security.org_secret.regenerated` |
| Secrets vault | `vault.entry.created`, `vault.entry.rotated`, `vault.entry.revoked` and more |

A route can listen for one type, a family (`pix.agent.*`) or everything (`*`).

**Sensitive events** (security, vault, and the admin-only sandbox events) are shown in a
reduced form: the action, who it was about, and when.
- They go to a GitHub repository only if it is private.
- They go to a signed webhook only if the route allows it.
- Only owners and admins can route them or see them in the activity log.

## Routes

A route has:
- event types and a minimum severity (`info`, `notice`, `warning`, `critical`)
- **scope**: an application name, version, upload or repository
- **findings thresholds**, for scans and uploads: CVSS, EPSS and CESS minimums, severities,
  malware, exploitable, new in this scan, ignore test code. A scan is reported only when at
  least one finding meets every threshold you set.
- **who caused it**: anyone, only some members, or everyone but some
- **mentions**: members to @-mention wherever they have an id on that provider (the
  **People** tab; Slack and Jira ids can be looked up by email)
- **targets**: the connections it sends to, with the GitHub repository or Jira project for
  issues
- **a template**: a system template, or your organisation's own copy
- **delivery**:
  - each event at once, or a digest every 15 or 60 minutes, or daily at an hour in your
    time zone
  - an hourly limit, after which the rest of the hour becomes one digest
- **mode**: live, or shadow (logged on the Activity tab, never sent)

**Dry run** shows whether a route would take a recent event, why not, and what each target
would receive.

## Templates

Copy a system template to change its title, body, fields, buttons, issue wording or digest
lines. Each field takes values like `{{.event.title}}` and `{{.data.repo}}`, and lists like
`{{range .findings.top}}…{{end}}`.

**Preview.** Every change is previewed for each provider by the same engine that sends.

**Versions.** Saving adds a version, and an old version can be restored.

**What a template cannot do.** It cannot call arbitrary functions or loops. Every value is
escaped, so event data cannot add formatting, links or mentions.

## Verifying a signed webhook

```
webhook-id: <delivery id>
webhook-timestamp: <unix seconds>
webhook-signature: v1,<base64 HMAC-SHA256>
X-Vulnetix-Event: <event type>
```

1. Take the bytes after `whsec_` in your signing secret, base64 decoded, as the key.
2. Compute the HMAC-SHA256 of `webhook-id + "." + webhook-timestamp + "." + body`.
3. Compare it with each `v1,` value in `webhook-signature`. During a secret rotation there
   are two for 24 hours.
4. Reject a timestamp older than five minutes.

Use `webhook-id` to drop a repeat: delivery is at least once.

## Delivery

- **Retries.** A failed delivery is retried with backoff for about a day, honouring
  `Retry-After`.
- **Broken connections.** A connection that refuses its credential three times in a row is
  marked broken. Fix it on the **Connections** tab.
- **The log.** Every delivery, its outcome and a link to the message or issue is on the
  **Activity** tab, where a failed one can be retried.
