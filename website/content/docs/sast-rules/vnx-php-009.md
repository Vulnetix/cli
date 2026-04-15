---
title: "VNX-PHP-009 – PHP preg_replace() with /e Modifier"
description: "Detect use of the /e (eval) modifier in preg_replace() calls, which evaluates the replacement string as PHP code and enables remote code execution. This modifier was deprecated in PHP 5.5 and removed in PHP 7.0."
---

## Overview

This rule flags calls to `preg_replace()` that include the `/e` modifier in the pattern string. The `/e` flag causes PHP to evaluate the replacement string as PHP code after performing the substitution — effectively turning any `preg_replace()` call that operates on user-controlled input into an `eval()` call. This modifier was deprecated in PHP 5.5.0 and entirely removed in PHP 7.0.0; code that uses it either belongs to a legacy codebase still running PHP 5 or was written without awareness of the security implications. This maps to [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html).

**Severity:** Critical | **CWE:** [CWE-94 – Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

## Why This Matters

The `/e` modifier was designed to allow dynamic replacement strings in regex substitution, but it was fundamentally unsafe because the evaluated expression is constructed from the match result before any sanitization can be applied. If an attacker controls any part of the string being searched — the subject of `preg_replace()` — they can inject PHP code into the replacement result, which is then executed. Unlike `eval()` on a variable, the code injection is indirect and easy to miss in a code review.

Consider a CMS that uses `preg_replace()` with `/e` to process template tags in user-submitted content. An attacker who can submit content containing crafted regex matches can have arbitrary PHP code evaluated by the web server process, leading to full remote code execution, data exfiltration, or a persistent web shell.

Legacy PHP 5 applications are the primary target, but `/e` usage also appears in code that was migrated to PHP 7 with the broken assumption that PHP silently ignores the flag (it does not — it raises a fatal error, so code using `/e` on PHP 7+ either never reaches this line in production, or the application is pinned to PHP 5).

## What Gets Flagged

The rule matches `.php` files where `preg_replace()` is called with a pattern string that includes the `e` modifier flag.

```php
// FLAGGED: /e modifier evaluates replacement as PHP code
$output = preg_replace('/\[b\](.*?)\[\/b\]/e', '"<b>".$1."</b>"', $user_input);

// FLAGGED: /ei — case-insensitive and eval
$result = preg_replace('/\{(\w+)\}/ei', '$this->$1', $template);

// FLAGGED: pattern using # delimiters with e flag
preg_replace('#\{\{(.+?)\}\}#e', '$this->render($1)', $content);

// FLAGGED: common legacy BBCode parser pattern
preg_replace("|\[code\](.+?)\[/code\]|es", "highlight_string('$1')", $post);
```

## Remediation

1. **Replace `preg_replace()` with `preg_replace_callback()`.** This is the direct, safe replacement. Instead of embedding a PHP expression in the replacement string, provide a callback function that receives the match array and returns the replacement string:

```php
// SAFE: preg_replace_callback() — explicit callback, no eval
$output = preg_replace_callback(
    '/\[b\](.*?)\[\/b\]/',
    function (array $matches): string {
        return '<b>' . htmlspecialchars($matches[1], ENT_QUOTES, 'UTF-8') . '</b>';
    },
    $user_input
);
```

2. **For template engines, use an explicit tag-to-value map.** Rather than evaluating PHP expressions, look up replacement values from a predefined array:

```php
// SAFE: map-based template substitution — no dynamic code execution
$vars = [
    'username' => htmlspecialchars($user->name, ENT_QUOTES, 'UTF-8'),
    'date'     => date('Y-m-d'),
];

$output = preg_replace_callback(
    '/\{\{(\w+)\}\}/',
    function (array $m) use ($vars): string {
        return $vars[$m[1]] ?? '';
    },
    $template
);
```

3. **If the codebase still runs on PHP 5, migrate to PHP 8.x immediately.** PHP 5 reached end-of-life in December 2018 and has received no security patches since. The continued use of PHP 5 means your application is exposed to hundreds of unpatched CVEs in addition to this code-level vulnerability.

4. **Audit all `preg_replace()` calls for `/e`** using a global search before deploying any fix:

```bash
grep -rn "preg_replace\s*(" /path/to/project --include="*.php" | grep "['\"].*\/.*e[a-z]*['\"]"
```

5. **Consider a mature template engine** such as Twig or Blade for user-facing template rendering. These engines compile templates to PHP functions rather than evaluating arbitrary expressions, and they escape output by default.

## References

- [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
- [CAPEC-242: Code Injection](https://capec.mitre.org/data/definitions/242.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [PHP manual: preg_replace() — e modifier deprecation notice](https://www.php.net/manual/en/reference.pcre.pattern.modifiers.php)
- [PHP manual: preg_replace_callback()](https://www.php.net/manual/en/function.preg-replace-callback.php)
- [PHP 7.0 Migration Guide – preg_replace /e removed](https://www.php.net/manual/en/migration70.incompatible.php)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
