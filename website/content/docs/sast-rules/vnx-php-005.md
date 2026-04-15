---
title: "VNX-PHP-005 – PHP Server-Side Request Forgery"
description: "Detect PHP code that passes user-supplied input directly to file_get_contents(), fopen(), or curl_setopt(CURLOPT_URL), enabling SSRF attacks against internal services and cloud metadata endpoints."
---

## Overview

This rule flags PHP code where user-supplied values from `$_GET`, `$_POST`, or `$_REQUEST` are passed directly to functions that initiate outbound HTTP or file-system requests: `file_get_contents()`, `fopen()`, and `curl_setopt()` with `CURLOPT_URL`. When an attacker controls the URL, they can make the server issue requests to internal network addresses, cloud provider metadata endpoints, and other services that are normally unreachable from the public internet. This maps to [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html).

**Severity:** High | **CWE:** [CWE-918 – Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)

## Why This Matters

In cloud-hosted environments, SSRF is a critical vulnerability because the instance metadata service (IMDS) is accessible at the well-known address `169.254.169.254` from any process running on the host. An attacker who can make the server fetch `http://169.254.169.254/latest/meta-data/iam/security-credentials/` can retrieve short-lived AWS, GCP, or Azure credentials with the permissions of the server's IAM role — often giving them access to S3 buckets, KMS keys, or the ability to call cloud management APIs.

Beyond cloud metadata, SSRF can be used to port-scan internal networks (by varying the target IP and observing timing or error differences), bypass firewall rules that block external access to internal services (databases, Elasticsearch, Redis, admin panels), trigger SSRF-to-RCE chains via internal services that trust requests from localhost, and exfiltrate data by encoding it in DNS lookups.

The `CURLOPT_FOLLOWLOCATION` option multiplies the risk: if curl is configured to follow HTTP redirects, an SSRF that initially targets a controlled external URL can chain through redirects to internal addresses, bypassing naive host-validation checks that only examine the initial URL.

## What Gets Flagged

The rule matches lines where `file_get_contents()`, `fopen()`, or `CURLOPT_URL` receive a value directly from a superglobal.

```php
// FLAGGED: file_get_contents with GET parameter
$url = $_GET['url'];
$data = file_get_contents($url);

// FLAGGED: fopen with POST data
$handle = fopen($_POST['source'], 'r');

// FLAGGED: curl with user-supplied URL
curl_setopt($ch, CURLOPT_URL, $_GET['endpoint']);

// FLAGGED: request parameter used in curl
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $_REQUEST['target']);
curl_exec($ch);
```

## Remediation

1. **Validate the target URL against an allowlist of permitted hosts.** Extract the host from the user-supplied URL and verify it matches an explicit set of approved external services. Reject anything else before issuing any request:

```php
// SAFE: validate host against an allowlist before fetching
function fetch_allowed_url(string $url): string {
    $allowed_hosts = ['api.trusted-service.com', 'cdn.example.com'];

    $parsed = parse_url($url);

    if (!isset($parsed['host']) || !in_array($parsed['host'], $allowed_hosts, true)) {
        throw new \InvalidArgumentException('URL host is not permitted');
    }

    // Enforce HTTPS only
    if (($parsed['scheme'] ?? '') !== 'https') {
        throw new \InvalidArgumentException('Only HTTPS URLs are permitted');
    }

    return file_get_contents($url);
}
```

2. **Block private IP ranges and loopback addresses.** After resolving the hostname to an IP address, verify the resolved IP is not in a private, loopback, or link-local range before connecting. Libraries such as `symfony/http-client` include SSRF-safe request modes; alternatively, resolve with `gethostbyname()` and validate the IP:

```php
// SAFE: resolve hostname and reject private/internal IPs
function is_public_ip(string $host): bool {
    $ip = gethostbyname($host);
    if ($ip === $host) {
        return false; // DNS resolution failed
    }
    // Reject loopback, RFC1918, link-local, and APIPA
    return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
}
```

3. **Disable `CURLOPT_FOLLOWLOCATION` or set a `CURLOPT_MAXREDIRS` of 0** when the target URL is user-supplied. Redirect chaining is the primary bypass technique for host-validation checks:

```php
// SAFE: curl configured without redirect following
$ch = curl_init($validated_url);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); // do not follow redirects
curl_setopt($ch, CURLOPT_TIMEOUT, 5);
curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS); // HTTPS only
$response = curl_exec($ch);
curl_close($ch);
```

4. **Prefer indirect references.** If your application only needs to proxy a small set of known resources, replace the URL parameter with a key that maps to a hardcoded URL on the server side. The user never supplies a URL at all:

```php
// SAFE: indirect reference — user supplies an ID, server resolves the URL
$resources = [
    'avatar'  => 'https://cdn.example.com/default-avatar.png',
    'banner'  => 'https://cdn.example.com/default-banner.jpg',
];

$key = $_GET['resource'] ?? '';
if (!array_key_exists($key, $resources)) {
    http_response_code(400);
    exit;
}

$data = file_get_contents($resources[$key]);
```

5. **Apply IMDSv2 or disable the metadata service** on cloud instances where your application does not need it. AWS IMDSv2 requires a PUT request to obtain a session token before the GET request that retrieves credentials, which cannot be triggered by a simple SSRF that only issues GET requests.

## References

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [CAPEC-664: Server-Side Request Forgery](https://capec.mitre.org/data/definitions/664.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP manual: file_get_contents()](https://www.php.net/manual/en/function.file-get-contents.php)
- [PHP manual: curl_setopt()](https://www.php.net/manual/en/function.curl-setopt.php)
- [PortSwigger Web Security – SSRF](https://portswigger.net/web-security/ssrf)
