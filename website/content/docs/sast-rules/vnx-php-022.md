---
title: "VNX-PHP-022 – PHP open redirect via non-literal redirect destination"
description: "Detects header('Location:') or framework redirect calls with user-controlled or non-literal URLs, enabling open redirect attacks that facilitate phishing and credential theft."
---

## Overview

This rule detects PHP redirect operations — `header('Location: ...')`, `$this->redirect()`, and Laravel's `Redirect::to()` — where the destination URL is constructed from user-controlled input or is not a hardcoded string literal. When a web application redirects users to an arbitrary URL specified in a request parameter without validation, attackers can craft links that appear to lead to the trusted domain but actually redirect victims to attacker-controlled sites.

Open redirect vulnerabilities arise when the redirect destination is taken from a query string, POST body, or cookie value and passed to the redirect mechanism without verifying that the destination is within the application's trusted domain. The application itself is benign, but it becomes an enabler for phishing: a link like `https://trusted-bank.com/login?next=https://evil.com/steal` appears legitimate in email clients, security scanners, and link preview tools.

The three most common PHP patterns are: `header('Location: ' . $_GET['redirect'])`, framework redirect helpers called with request data, and chained redirects where a variable derived from user input is used as the redirect target several lines after the original assignment.

**Severity:** Medium | **CWE:** [CWE-601 – URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

## Why This Matters

Open redirects are frequently used as a component in phishing campaigns and OAuth token theft attacks. In phishing, the trusted domain lends credibility to the malicious link — users who hover over the URL see the organisation's domain and proceed to click. The redirect then sends them to a credential-harvesting page styled to look like the real site.

In OAuth flows, an open redirect on the authorisation server can be chained with a crafted `redirect_uri` parameter to redirect the authorisation code or access token to the attacker's domain. This is particularly impactful because it bypasses the `redirect_uri` allowlist that OAuth providers are supposed to enforce — a redirect chain that passes through a trusted domain can satisfy the allowlist while ultimately delivering tokens to the attacker.

Applications that implement "return to previous page after login" functionality are especially prone to open redirects because they naturally store and follow a user-specified URL.

## What Gets Flagged

```php
// FLAGGED: header Location with superglobal value
header('Location: ' . $_GET['redirect']);
exit;

// FLAGGED: framework redirect called with non-literal variable
$this->redirect($returnUrl);  // $returnUrl derived from user input

// FLAGGED: Laravel Redirect::to() with variable destination
return Redirect::to($_POST['next']);
```

## Remediation

1. **Validate the redirect target against an allowlist** of known safe internal paths or domains before redirecting.

2. **Use relative paths for internal redirects** — a destination that starts with `/` cannot redirect to an external domain.

3. **For post-login redirects**, store the intended destination in the session (set by your own code, not from user input) rather than in a URL parameter.

4. **If the destination must come from user input**, strip the scheme and host and use only the path component, then verify it starts with `/` and does not start with `//`.

```php
<?php
// SAFE: allowlist of permitted redirect paths
function safeRedirect(string $destination): void {
    $allowed = ['/dashboard', '/profile', '/orders'];
    if (!in_array($destination, $allowed, true)) {
        $destination = '/dashboard'; // fall back to safe default
    }
    header('Location: ' . $destination);
    exit;
}

safeRedirect($_GET['next'] ?? '/dashboard');

// SAFE (Laravel): validate with regex for internal paths only
$next = $request->input('next', '/dashboard');
if (!preg_match('#^/[a-zA-Z0-9/_-]*$#', $next)) {
    $next = '/dashboard';
}
return redirect($next);
```

## References

- [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
- [CAPEC-194: Fake the Source of Data](https://capec.mitre.org/data/definitions/194.html)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [Laravel Documentation – Redirects](https://laravel.com/docs/responses#redirects)
- [PortSwigger Web Security Academy – Open Redirects](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)
