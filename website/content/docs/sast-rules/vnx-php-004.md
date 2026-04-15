---
title: "VNX-PHP-004 – PHP Open Redirect"
description: "Detect PHP redirect calls that pass user-supplied input directly to header('Location: ...'), enabling attackers to redirect users to malicious external sites for phishing and credential theft."
---

## Overview

This rule flags PHP code that constructs an HTTP redirect using `header('Location: ...')` or a framework redirect function where the target URL is taken directly from user-supplied superglobals (`$_GET`, `$_POST`, `$_REQUEST`) without validation. An attacker can supply any URL as the redirect target and use your legitimate domain as a launchpad to deliver phishing pages, malware downloads, or OAuth token theft pages. This maps to [CWE-601: URL Redirection to Untrusted Site (Open Redirect)](https://cwe.mitre.org/data/definitions/601.html).

**Severity:** Medium | **CWE:** [CWE-601 – URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

## Why This Matters

An open redirect turns your domain's reputation into an attack asset. Because the initial request originates from your site (`https://yourapp.com/login?redirect=https://evil.com`), email security filters, browser warnings, and cautious users who hover over links all see a URL on a domain they trust. Phishing campaigns that leverage open redirects on legitimate sites have materially higher click rates than direct links to attacker infrastructure.

The risk extends beyond phishing. OAuth 2.0 authorization flows that use a `redirect_uri` parameter to deliver tokens are a particularly high-value target: if the authorization server allows your domain as a valid redirect host, an open redirect on your domain can be chained with an OAuth flow to redirect an access token to an attacker-controlled server. This is a known attack class documented in the OAuth 2.0 Security Best Current Practice (RFC 9700).

## What Gets Flagged

The rule matches lines where `header("Location: ")` or `header('Location: ')` is concatenated with a value from `$_GET`, `$_POST`, or `$_REQUEST`, as well as direct calls to `redirect()` with those superglobals.

```php
// FLAGGED: redirect target from GET parameter — no validation
header("Location: " . $_GET['next']);
exit;

// FLAGGED: redirect with POST data
header('Location: ' . $_POST['return_url']);
exit;

// FLAGGED: framework redirect with raw request data
redirect($_REQUEST['url']);

// FLAGGED: combined form — vulnerable even with 'exit' present
$dest = $_GET['redirect'];
header("Location: " . $dest);
exit;
```

## Remediation

1. **Validate the redirect target with `parse_url()` and an allowlist of permitted hosts.** Extract the host component from the supplied URL and verify it matches a set of domains your application owns:

```php
// SAFE: validate host against an allowlist before redirecting
function safe_redirect(string $url): void {
    $allowed_hosts = ['yourapp.com', 'www.yourapp.com', 'api.yourapp.com'];

    $parsed = parse_url($url);

    // Reject anything that has a host not in the allowlist,
    // or that lacks a host (relative paths are OK — check separately).
    if (isset($parsed['host']) && !in_array($parsed['host'], $allowed_hosts, true)) {
        http_response_code(400);
        exit('Invalid redirect destination');
    }

    header('Location: ' . $url);
    exit;
}

$next = $_GET['next'] ?? '/dashboard';
safe_redirect($next);
```

2. **Prefer relative paths over absolute URLs for on-site redirects.** If the redirect only ever needs to navigate within your application, accept only a path (no scheme or host) and prepend your own origin:

```php
// SAFE: only allow relative paths; prepend own origin
$path = $_GET['next'] ?? '/dashboard';

// Strip scheme/host — keep only path, query, fragment
$parsed = parse_url($path);
if (isset($parsed['scheme']) || isset($parsed['host'])) {
    $path = '/dashboard'; // fallback for absolute URLs
}

header('Location: ' . $path);
exit;
```

3. **Use an indirect reference map for a small number of destinations.** If you have a fixed set of post-login or post-action destinations, map numeric or token keys to URLs and never expose the raw URL in the request:

```php
// SAFE: indirect reference map — user supplies a key, not a URL
$destinations = [
    'dashboard' => '/dashboard',
    'profile'   => '/user/profile',
    'settings'  => '/user/settings',
];

$key  = $_GET['next'] ?? 'dashboard';
$dest = $destinations[$key] ?? $destinations['dashboard'];

header('Location: ' . $dest);
exit;
```

4. **Always call `exit` immediately after `header('Location: ...')`.** PHP continues executing the script after setting a redirect header unless you explicitly exit. Code that runs after an unexited redirect header may still be exploitable.

## References

- [CWE-601: URL Redirection to Untrusted Site (Open Redirect)](https://cwe.mitre.org/data/definitions/601.html)
- [CAPEC-194: Fake the Source of Data](https://capec.mitre.org/data/definitions/194.html)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP manual: header()](https://www.php.net/manual/en/function.header.php)
- [PHP manual: parse_url()](https://www.php.net/manual/en/function.parse-url.php)
- [RFC 9700 – OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
