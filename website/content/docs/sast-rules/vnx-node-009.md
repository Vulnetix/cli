---
title: "VNX-NODE-009 – Node.js Server-Side Request Forgery"
description: "Reports a server-side HTTP request (fetch, axios, http(s).get/request, got, needle, superagent, undici, request, or curl/wget run as a subprocess) whose destination URL or host comes from req.query/body/params/headers/cookies or Koa ctx, directly or through a variable assigned from one. Fixed-host URLs and allowlisted destinations are not reported, and a request whose response is relayed back to the client is reported by VNX-441 instead."
---

## Overview

This rule detects cases where user-supplied request data (`req.query`, `req.body`, `req.params`) is passed directly as the URL argument to HTTP client calls — `fetch()`, `axios.get()`, `axios.post()`, `axios()`, `http.get()`, `got()`, or `request()`. Server-Side Request Forgery (SSRF) allows an attacker to make the server issue HTTP requests to arbitrary destinations, including internal services, cloud metadata APIs, and localhost-bound administrative interfaces that are not accessible from the public internet. This is CWE-918 (Server-Side Request Forgery).

**Severity:** High | **CWE:** [CWE-918 – Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)

## Why This Matters

SSRF is particularly devastating in cloud-hosted environments. In AWS, GCP, and Azure, the instance metadata service runs on a fixed non-routable IP (169.254.169.254) and provides IAM credentials, SSH keys, and configuration data to any process that can reach it via localhost. An attacker who can make your server fetch an arbitrary URL can request `http://169.254.169.254/latest/meta-data/iam/security-credentials/` and obtain temporary cloud credentials with the permissions of your compute instance's role — often enough for full account takeover.

Beyond cloud metadata, SSRF enables attackers to port-scan your internal network, reach Redis or Memcached instances with no authentication, trigger internal webhooks, or interact with admin interfaces on `localhost:9200` (Elasticsearch), `localhost:8500` (Consul), or similar services that assume they are unreachable from outside.

## What Gets Flagged

The destination of the request (the first argument, or the `url`/`host`/`hostname`/`baseURL` member of an options object) must come from the incoming request, on the same line or through a variable assigned from it a few lines above.

```javascript
// FLAGGED: the URL is the client's
const page = await fetch(req.query.url);
await axios.post(req.body.callback, { ok: true });
const r = await got(`http://${req.params.host}/health`);

// FLAGGED: two lines, through an intermediate assignment
const host = req.query.host;
const target = 'https://' + host + ':8443/status';
const reply = await fetch(target, { method: 'GET' });

// FLAGGED: options object and a curl subprocess
http.get({ host: req.query.host, path: '/latest/meta-data/' }, cb);
spawnSync('curl', ['-s', endpoint]);   // endpoint = req.body.endpoint
```

Not flagged: a URL whose host is fixed (`API_BASE + '/items/' + req.params.id`, `` `${config.apiUrl}/users/${id}` ``), request values sent only as headers, params or a body, a destination checked against an allowlist (`ALLOWED_HOSTS.has(target.hostname)`), and methods named `fetch` on other objects (`cache.fetch(key)`).

A request whose response is then sent back to the client (`res.send(upstream.data)`, `upstream.pipe(res)`, `ctx.body = r.data`) is reported by [VNX-441](../vnx-441/) instead: the service is an open proxy, the form of SSRF in which the attacker also reads what the server fetched, and one request is one finding. Python SSRF is [VNX-918](../vnx-918/).

## Remediation

1. **Validate the URL with `new URL()` and check the hostname against an explicit allowlist** of permitted external domains:

   ```javascript
   // SAFE: allowlist of permitted hosts
   const ALLOWED_HOSTS = new Set(['api.example.com', 'webhooks.partner.com']);

   async function safeFetch(userUrl) {
     let parsed;
     try {
       parsed = new URL(userUrl);
     } catch {
       throw new Error('Invalid URL');
     }
     if (!['https:'].includes(parsed.protocol)) {
       throw new Error('Only HTTPS is permitted');
     }
     if (!ALLOWED_HOSTS.has(parsed.hostname)) {
       throw new Error(`Host ${parsed.hostname} is not permitted`);
     }
     return fetch(userUrl);
   }

   app.get('/proxy', async (req, res) => {
     try {
       const response = await safeFetch(req.query.url);
       res.send(await response.text());
     } catch (err) {
       res.status(400).json({ error: err.message });
     }
   });
   ```

2. **Block private and link-local IP ranges.** After resolving the hostname, reject connections to RFC-1918 addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x), loopback (127.0.0.1, ::1), and the link-local metadata range (169.254.x.x):

   ```javascript
   // Use the ssrf-req-filter or ssrf-agent npm package:
   const SsrfFilter = require('ssrf-req-filter');
   const agent = SsrfFilter.agent();
   await axios.get(userUrl, { httpAgent: agent, httpsAgent: agent });
   ```

3. **Install a dedicated SSRF protection library:**

   ```bash
   npm install ssrf-req-filter
   # or
   npm install ssrf-agent
   ```

4. **Never reflect the full response body back to the caller.** If you must fetch a remote resource, extract only the specific fields your application needs and return those — never proxy the raw response.

5. **Apply egress firewall rules** at the infrastructure level to block outbound connections from your application servers to the metadata range and internal subnets, providing defence-in-depth independent of application-layer validation.

## References

- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [CAPEC-664: Server-Side Request Forgery](https://capec.mitre.org/data/definitions/664.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [ssrf-req-filter npm package](https://www.npmjs.com/package/ssrf-req-filter)
- [AWS IMDS – credential access via SSRF](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
