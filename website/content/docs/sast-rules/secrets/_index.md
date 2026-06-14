---
title: "Secrets / Credentials"
description: "Exhaustive, high-fidelity hardcoded-secret detection rules grouped by category."
weight: 6
---

Vulnetix detects hardcoded credentials, API keys, tokens and private keys across source code, configuration, binaries (via printable-string and EXIF extraction) and full git history. Each rule runs a cheap keyword/prefix prefilter, extracts the candidate token, then applies allowlist and Shannon-entropy filtering to suppress false positives before reporting a SARIF finding.

## Categories

{{< cards >}}
  {{< card link="cloud" title="Secrets — Cloud Providers" subtitle="83 rules" >}}
  {{< card link="source-control" title="Secrets — Source Control & CI/CD" subtitle="70 rules" >}}
  {{< card link="ai" title="Secrets — AI / LLM Providers" subtitle="72 rules" >}}
  {{< card link="payment" title="Secrets — Payment Processors" subtitle="82 rules" >}}
  {{< card link="communication" title="Secrets — Communication & Messaging" subtitle="79 rules" >}}
  {{< card link="package-registries" title="Secrets — Package Registries" subtitle="1 rules" >}}
  {{< card link="monitoring" title="Secrets — Monitoring & Observability" subtitle="45 rules" >}}
  {{< card link="saas" title="Secrets — SaaS & Developer APIs" subtitle="433 rules" >}}
  {{< card link="database" title="Secrets — Database Credentials" subtitle="49 rules" >}}
  {{< card link="private-keys" title="Secrets — Private Keys & Certificates" subtitle="14 rules" >}}
  {{< card link="crypto-blockchain" title="Secrets — Crypto & Blockchain" subtitle="78 rules" >}}
  {{< card link="webhooks" title="Secrets — Webhooks & Signed URLs" subtitle="4 rules" >}}
{{< /cards >}}
