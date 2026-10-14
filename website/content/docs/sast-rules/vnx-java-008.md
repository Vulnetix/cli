---
title: "VNX-JAVA-008 – Java Server-Side Request Forgery (SSRF)"
description: "Reports Java outbound requests (URL, RestTemplate, WebClient, HttpClient, OkHttp, Jsoup, Socket) whose URL or host is a request value or a variable assigned from one, unless a fixed host prefixes it or a guard checks it."
---

## Overview

This rule detects Java code that reads a URL or hostname from a servlet request parameter (`request.getParameter`, `req.getParameter`) and immediately uses it to construct a `java.net.URL`, `URI`, `HttpURLConnection`, Spring `RestTemplate` call, or Spring `WebClient` request. When the destination of a server-side HTTP request is attacker-controlled, the result is Server-Side Request Forgery (CWE-918): the attacker can use the application as a proxy to reach internal services that are not directly accessible from the internet.

**Severity:** High | **CWE:** [CWE-918 – Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)

## Why This Matters

In cloud-hosted environments (AWS, GCP, Azure), the instance metadata service is reachable at a well-known address (`169.254.169.254` for AWS IMDSv1). A single SSRF request to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` returns the IAM role name; a follow-up request returns temporary AWS credentials with whatever permissions the role holds. The 2019 Capital One breach, which exposed over 100 million customer records, began with an SSRF vulnerability in a WAF that allowed an attacker to extract IAM credentials from the EC2 metadata service.

Beyond cloud metadata, SSRF can be used to reach internal microservices that trust requests from within the VPC (authentication bypasses), interact with services on `localhost` that are not exposed externally (Redis, Memcached, Elasticsearch, internal admin panels), perform port scanning of the internal network, and in some configurations exploit services speaking non-HTTP protocols via `gopher://`, `ftp://`, or `file://` schemes.

## What Gets Flagged

The rule reports `new URL()`, RestTemplate `getForObject`/`getForEntity`/`exchange`..., `WebClient.create()`/`baseUrl()`/`uri()`, `HttpRequest.newBuilder()`, Apache `new HttpGet(...)`, OkHttp `Request.Builder().url()`, `Jsoup.connect()` and `new Socket(host, ...)` when the URL or host reads the request, is a `@RequestParam`/`@PathVariable`/`@RequestHeader`/`@RequestBody` parameter, or is a variable assigned from one through up to two intermediate assignments within the 40 lines above. It does not report a URL with a fixed scheme and host in front (`"https://catalog.example/items/" + id`), a value checked by a host allowlist or `startsWith` guard first, configured URLs, or a URL handed in as a plain method parameter. Building a `URI` alone is not a request and is not reported.

```java
// FLAGGED: user-supplied URL passed to new URL()
String target = request.getParameter("url");
HttpURLConnection conn = (HttpURLConnection) new URL(target).openConnection();

// FLAGGED: host from a header
URL api = new URL("http://" + host + ":8080/status");

// FLAGGED: RestTemplate with a @RequestParam URL
return restTemplate.getForObject(url, String.class);

// FLAGGED: WebClient with user-controlled base URL
WebClient.create(request.getParameter("service")).get().retrieve().bodyToMono(String.class);
```

## Remediation

1. **Validate the destination against an allowlist of permitted hosts before making any request.** Parse the supplied URL, extract the scheme and host, and compare both against a hardcoded set of trusted values. Reject anything that doesn't match — including IP literals, `localhost`, `127.x.x.x`, `169.254.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`.

   ```java
   // SAFE: allowlist-based URL validation before outbound request
   private static final Set<String> ALLOWED_HOSTS = Set.of(
       "api.partner.com", "cdn.example.com"
   );

   String rawUrl = request.getParameter("url");
   URI uri;
   try {
       uri = new URI(rawUrl).normalize();
   } catch (URISyntaxException e) {
       response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid URL");
       return;
   }

   String host = uri.getHost();
   String scheme = uri.getScheme();

   if (host == null || !ALLOWED_HOSTS.contains(host.toLowerCase())
           || !"https".equals(scheme)) {
       response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Disallowed destination");
       return;
   }

   // Now safe to make the outbound request
   HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
   ```

2. **Block requests to private and loopback address ranges.** After resolving the hostname to an IP address, verify the resolved address is not in a private range. This prevents DNS rebinding attacks where a hostname initially resolves to a public IP but subsequently resolves to `169.254.169.254`.

   ```java
   // SAFE: DNS rebinding protection
   InetAddress addr = InetAddress.getByName(uri.getHost());
   if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()
           || addr.isLinkLocalAddress() || addr.isAnyLocalAddress()) {
       throw new SecurityException("SSRF: private address blocked");
   }
   ```

3. **Accept a resource identifier, not a URL.** Design the API so the caller submits a logical identifier (e.g., a product ID or partner code) that the server maps to a URL from a configuration file. The user never controls the URL directly.

4. **Use Spring Security's `WebClient` with a restricted base URL.** Configure a `WebClient` bean with a hardcoded `baseUrl` and only use `uriBuilder.path(...)` for path segments, never accepting a fully qualified URL from user input.

## References

- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [CAPEC-664: Server-Side Request Forgery](https://capec.mitre.org/data/definitions/664.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 A10:2021 – Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [AWS IMDSv2 – Mitigating SSRF](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [OWASP ASVS V5 – Validation, Sanitization and Encoding](https://owasp.org/www-project-application-security-verification-standard/)
