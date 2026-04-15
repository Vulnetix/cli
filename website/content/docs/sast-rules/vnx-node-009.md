---
title: "VNX-NODE-009 – Node.js Server-Side Request Forgery"
description: "Detects user input from req.query, req.body, or req.params used to construct server-side HTTP requests with fetch, axios, or http.get, enabling SSRF attacks against internal services."
---

## Overview

This rule detects cases where user-supplied request data (`req.query`, `req.body`, `req.params`) is passed directly as the URL argument to HTTP client calls — `fetch()`, `axios.get()`, `axios.post()`, `axios()`, `http.get()`, `got()`, or `request()`. Server-Side Request Forgery (SSRF) allows an attacker to make the server issue HTTP requests to arbitrary destinations, including internal services, cloud metadata APIs, and localhost-bound administrative interfaces that are not accessible from the public internet. This is CWE-918 (Server-Side Request Forgery).

**Severity:** High | **CWE:** [CWE-918 – Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)

## Why This Matters

SSRF is particularly devastating in cloud-hosted environments. In AWS, GCP, and Azure, the instance metadata service runs on a fixed non-routable IP (169.254.169.254) and provides IAM credentials, SSH keys, and configuration data to any process that can reach it via localhost. An attacker who can make your server fetch an arbitrary URL can request `http://169.254.169.254/latest/meta-data/iam/security-credentials/` and obtain temporary cloud credentials with the permissions of your compute instance's role — often enough for full account takeover.

Beyond cloud metadata, SSRF enables attackers to port-scan your internal network, reach Redis or Memcached instances with no authentication, trigger internal webhooks, or interact with admin interfaces on `localhost:9200` (Elasticsearch), `localhost:8500` (Consul), or similar services that assume they are unreachable from outside.

## What Gets Flagged

The rule matches lines containing direct user-input injection into HTTP client calls: `fetch(req.query`, `fetch(req.body`, `fetch(req.params`, `axios.get(req.query`, `axios.get(req.body`, `axios.post(req.query`, `axios(req.query`, `http.get(req.query`, `got(req.query`, or `request(req.query`.

```javascript
// FLAGGED: user URL passed to fetch
app.get('/proxy', async (req, res) => {
  const response = await fetch(req.query.url);
  const data = await response.text();
  res.send(data);
});

// FLAGGED: user-controlled URL in axios
app.post('/webhook-test', async (req, res) => {
  const result = await axios.get(req.body.endpoint);
  res.json(result.data);
});
```

An attacker sends `?url=http://169.254.169.254/latest/meta-data/` and receives AWS credentials in the response.

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
