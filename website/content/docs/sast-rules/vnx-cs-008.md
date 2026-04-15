---
title: "VNX-CS-008 – C# SSRF via WebClient or HttpClient with User-Supplied URL"
description: "Detects C# code where WebClient, HttpClient, HttpWebRequest, or WebRequest HTTP methods are invoked with a non-literal URL argument, enabling Server-Side Request Forgery when the URL contains attacker-controlled input."
---

## Overview

This rule scans C# files (`.cs`) for calls to HTTP client methods — `OpenRead`, `OpenReadAsync`, `DownloadString`, `DownloadStringAsync`, `DownloadData`, `DownloadDataAsync`, `UploadString`, `UploadData`, `GetAsync`, `PostAsync`, `SendAsync`, `GetStringAsync` — where the URL argument is a variable rather than a string literal, and where the surrounding ten-line context references `WebClient`, `HttpClient`, `WebRequest`, or `HttpWebRequest`. A non-literal argument indicates the URL is constructed dynamically and may incorporate user-supplied values.

Server-Side Request Forgery (SSRF) occurs when a server-side component makes an HTTP request to a URL that is fully or partially controlled by an external party. The request originates from the server rather than from the client's browser, so it carries the server's network identity and access credentials. This allows attackers to reach internal services, cloud metadata endpoints, and other resources that are not directly accessible from the internet.

**Severity:** High | **CWE:** [CWE-918 – Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)

## Why This Matters

SSRF is a critical vulnerability class that entered the OWASP Top 10 as its own category (A10:2021) due to its prevalence in cloud-hosted applications. In cloud environments, the instance metadata service (IMDS) endpoint at `169.254.169.254` is accessible from every EC2, Azure VM, and GCP instance. An SSRF vulnerability allows an attacker to reach this endpoint and retrieve instance metadata including IAM role credentials, which can be used to access AWS S3 buckets, DynamoDB tables, and other services with the instance's permissions.

Beyond cloud credential theft, SSRF can be used to port-scan internal networks (by observing connection timing and error messages), access internal HTTP services that assume requests come only from trusted sources (dashboards, admin APIs, microservices), and bypass IP-based access controls. In some configurations, SSRF can escalate to remote code execution via internal services that accept commands.

Real-world SSRF exploits include the 2019 Capital One breach, where an SSRF vulnerability in a WAF allowed access to AWS metadata credentials, resulting in the exposure of over 100 million customer records. This maps to CAPEC-664 and ATT&CK T1090.

## What Gets Flagged

```csharp
// FLAGGED: HttpClient.GetAsync with variable URL from request parameter
string targetUrl = Request.Query["url"];
using var client = new HttpClient();
var response = await client.GetAsync(targetUrl);  // SSRF: user controls target

// FLAGGED: WebClient.DownloadString with dynamic URL
string imageUrl = userProfile.AvatarUrl;
var webClient = new WebClient();
string content = webClient.DownloadString(imageUrl);
```

## Remediation

1. Validate the target URL against an allowlist of permitted hostnames before making the request. Reject or sanitise any URL that does not match the allowlist.
2. Use `Uri.TryCreate` to parse the URL and then check `uri.Host` against a set of permitted hosts.
3. Disable redirects, or validate redirect destinations against the same allowlist to prevent redirect-based SSRF bypass.
4. Consider blocking requests to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.1, ::1) regardless of hostname, using DNS resolution validation.

```csharp
// SAFE: allowlist validation before issuing HTTP request
private static readonly HashSet<string> AllowedHosts = new(StringComparer.OrdinalIgnoreCase)
{
    "api.example.com",
    "cdn.example.com"
};

public async Task<string> FetchExternalResource(string userUrl)
{
    if (!Uri.TryCreate(userUrl, UriKind.Absolute, out var uri) ||
        (uri.Scheme != "https") ||
        !AllowedHosts.Contains(uri.Host))
    {
        throw new ArgumentException("URL is not in the permitted allowlist.");
    }

    using var client = new HttpClient();
    return await client.GetStringAsync(uri);
}
```

## References

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP – Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP .NET Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html)
- [Microsoft Security Advisory – SSRF mitigations in Azure](https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices)
- [CAPEC-664: Server-Side Request Forgery](https://capec.mitre.org/data/definitions/664.html)
