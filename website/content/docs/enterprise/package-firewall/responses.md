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
