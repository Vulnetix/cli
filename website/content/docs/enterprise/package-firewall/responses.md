---
title: "Block responses & exit codes"
weight: 30
description: "The HTTP status codes the Package Firewall returns when it blocks a package, and the CLI exit codes."
---

When the firewall blocks a request it returns a **semantic HTTP status code** with a JSON body, identically across every ecosystem. Your package manager surfaces this as a failed fetch.

## Block status codes

```json
{
  "error": "blocked by policy",
  "reason": "CVSS score 9.8 meets or exceeds threshold 8.0",
  "details": { "cvss": 9.8, "epss": 0.00452, "version": "2.0.0" }
}
```

| Status | Reason | Meaning | What to do |
| --- | --- | --- | --- |
| `423 Locked` | Malware | The package version is flagged as malicious. | Do not use it. There is no safe version of this artifact. |
| `426 Upgrade Required` | Vulnerable | A blocking CVE applies — CISA KEV, weaponized/active exploitation, public PoC, or a CVSS/EPSS/CESS score over your threshold. | Upgrade to a fixed version. |
| `428 Precondition Required` | Bad actor | The CVE is linked to actors with malicious reputation. | Review and obtain an exception before proceeding. |
| `425 Too Early` | Cooldown | The version was published inside your cooldown window. A `Retry-After` header gives the seconds remaining. | Wait for the window to pass, or pin an older release. |
| `422 Unprocessable Content` | End-of-life / policy | The package is end-of-life or violates another policy. | Migrate to a supported package. |
| `402 Payment Required` | Plan | This ecosystem is not included in your subscription plan. The body includes `"upgrade": "/pricing"`. | Upgrade your plan — see [pricing](https://www.vulnetix.com/pricing). |

Other statuses you may see:

| Status | Meaning |
| --- | --- |
| `401 Unauthorized` | Missing or invalid credentials. See [Troubleshooting](/docs/enterprise/package-firewall/troubleshooting/). |
| `404 Not Found` / `410 Gone` | A definitive answer from the upstream registry (e.g. the package or version does not exist). Passed through unchanged. |
| `502 Bad Gateway` | The firewall could not reach any upstream mirror for this ecosystem. |

{{< callout type="info" >}}
**Filter vs gate.** For *filter*-mode ecosystems a blocked version is removed from the index, so a normal resolve simply never selects it and you see no error. You only get a `4xx` when you request that exact blocked version (for example by pinning it). For *gate*-mode ecosystems the index is unchanged and the block lands on the artifact download. See the [overview](/docs/enterprise/package-firewall/#enforcement-modes).
{{< /callout >}}

## Response headers

Every block (and every advisory — see below) also carries `X-Vulnetix-Firewall-*` headers. These survive HTTP/2 and explain *why* a request was stopped, which matters because most package managers discard the JSON body on a failed download.

| Header | Example | Meaning |
| --- | --- | --- |
| `X-Vulnetix-Firewall` | `blocked` / `advisory` | Whether the request was blocked or merely flagged. |
| `X-Vulnetix-Firewall-Reason` | `malware` | Block reason — `malware`, `vuln`, `bad_actor`, `cooldown`, `eol`, `plan`. |
| `X-Vulnetix-Firewall-Status` | `423` | The semantic status code (same as the HTTP status). |
| `X-Vulnetix-Firewall-Message` | `package is flagged as malicious` | Human-readable explanation. |
| `X-Vulnetix-Firewall-Package` | `node` | The package the decision applies to. |
| `X-Vulnetix-Firewall-Version` | `26.3.1` | The version requested. |
| `X-Vulnetix-Firewall-Ecosystem` | `homebrew-bottle` | The ecosystem. |
| `X-Vulnetix-Firewall-Docs` | this page | A link back to this reference (anchored to the reason). |
| `X-Vulnetix-Firewall-Cvss` / `-Epss` / `-Cess` | `9.8` | Threat scores, when the block is score-driven. |
| `X-Vulnetix-Firewall-Digest` | `sha256:…` | The offending artifact digest (known-bad-hash blocks). |
| `X-Vulnetix-Firewall-Required-Tier` / `-Plan` | `pro` | Plan details (on a `402`). |
| `X-Vulnetix-Firewall-Published-At` / `-Cooldown-Days` | `2026-06-20T…` / `14` | Cooldown details (on a `425`). |
| `X-Vulnetix-Firewall-Advisory` | `wildcard malware advisory …` | Present only on an `advisory` response (the request was allowed). |

{{< callout type="info" >}}
**Homebrew shows only the status code by default.** Homebrew downloads bottles with `curl --fail`, which throws away the response body *and* the headers, so a block surfaces as a bare `curl: (22) The requested URL returned error: 423`. To see the full reason, re-run with verbose curl:

```console
$ HOMEBREW_CURL_VERBOSE=1 brew upgrade node
…
< HTTP/2 423
< x-vulnetix-firewall: blocked
< x-vulnetix-firewall-reason: malware
< x-vulnetix-firewall-message: package is flagged as malicious
< x-vulnetix-firewall-docs: https://www.vulnetix.com/docs/enterprise/package-firewall/responses#malware
```

A bare `423` against `packages.vulnetix.com` is a firewall policy block by your organisation — check the [decision log in the Vulnetix dashboard](https://www.vulnetix.com/) or ask your security team.
{{< /callout >}}

## Wildcard malware advisories

Some malicious-package records cover *every* version of a package (a `*` "all-versions-affected" wildcard). Because that wildcard is prone to false positives — it would tar current, legitimate releases of a popular package — the firewall does **not** block on a wildcard match. Instead it:

- **allows** the request (no `4xx`),
- adds `X-Vulnetix-Firewall: advisory` headers describing the advisory, and
- records the decision as a **`WARN`** in the decision log.

An **exact-version** malware record still blocks with `423`. To review wildcard advisories, filter the decision log for the `WARN` action in the dashboard.

## CLI exit codes

The `vulnetix package-firewall <ecosystem>` command exits:

| Code | Meaning |
| --- | --- |
| `0` | Configuration written (or already up to date, including `--dry-run`). |
| `1` | A failure occurred. The error is printed to stderr. |

Common causes of a non-zero exit:

- **Authentication required** — no usable credentials were found. Run `vulnetix auth login` first.
- **Authentication test failed** — the resolved API key was rejected by the VDB API.
- **Invalid `--proxy-url`** — the value is not an absolute URL.
- **`automatic <ecosystem> configuration is not implemented yet`** — the CLI does not yet write this ecosystem's config; follow the manual steps on its page.
- **File write error** — the target config file or directory could not be written (permissions).

Use `--dry-run` to preview every file change without writing anything; it still exits `0`.
