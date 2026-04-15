---
title: "VNX-PHP-002 – Dangerous Function in PHP"
description: "Detect calls to PHP functions that execute OS commands or arbitrary code — eval(), exec(), system(), passthru(), shell_exec(), popen(), and proc_open() — where user-controlled input can lead to remote code execution."
---

## Overview

This rule flags calls to PHP functions that execute operating system commands or evaluate arbitrary PHP code: `eval()`, `exec()`, `system()`, `passthru()`, `shell_exec()`, `popen()`, and `proc_open()`. Any of these functions, when called with an argument that includes attacker-controlled data, provides a direct path to remote code execution on the server. This maps to [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html).

**Severity:** High | **CWE:** [CWE-78 – Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)

## Why This Matters

When an attacker can influence the argument to one of these functions, they gain the ability to run any OS command with the privileges of the web server process — typically `www-data` on Linux. From there they can read `/etc/passwd`, `/proc/self/environ`, application `.env` files, and database credentials; exfiltrate data over HTTP; write a PHP web shell for persistent access; or pivot laterally to other services on the internal network.

The PHP runtime makes this particularly dangerous because `eval()` accepts a full PHP string, meaning an attacker can upload a base64-encoded payload through a seemingly innocuous input field and then have it executed as PHP code without any file write required. Shell-execution functions (`system`, `exec`, `passthru`, `shell_exec`) pass their argument to `/bin/sh -c`, so shell metacharacters — `;`, `|`, `&&`, backticks, `$()` — all work as command separators and substitution operators.

## What Gets Flagged

The rule matches any `.php` file where a line contains one of the dangerous function names followed immediately by `(`.

```php
// FLAGGED: unsanitized user input passed directly to system()
$cmd = $_GET['tool'];
system($cmd);

// FLAGGED: exec() with concatenated user input
exec('ls -la ' . $_POST['dir'], $output);

// FLAGGED: eval() on user-supplied data
eval($_POST['code']);

// FLAGGED: shell_exec() with interpolated variable
$file = $_REQUEST['filename'];
$result = shell_exec("cat $file");

// FLAGGED: passthru() with user value
passthru('/usr/bin/convert ' . $_GET['src'] . ' output.png');
```

## Remediation

1. **Eliminate OS command calls wherever possible.** For most tasks that developers reach for `exec()` or `system()` — file conversion, image resizing, PDF generation, archive extraction — there are pure-PHP libraries that never invoke a shell. Prefer `Imagick` or `GD` over `convert`, `ZipArchive` over `unzip`, and `setasign/fpdf` over command-line PDF tools.

2. **If you must call a shell command, pass each argument through `escapeshellarg()`.** This wraps the value in single quotes and escapes any embedded single quotes, preventing the shell from interpreting metacharacters. Use `escapeshellcmd()` only for the command path itself — it escapes the full string and is not appropriate for individual arguments.

```php
// SAFE: each argument individually escaped with escapeshellarg()
$filename = escapeshellarg($_GET['filename']);
$output   = shell_exec('/usr/bin/file ' . $filename);
```

3. **Validate input against an allowlist before use.** `escapeshellarg()` is a last-resort mitigation; the first line of defence is rejecting anything that does not match an expected pattern:

```php
// SAFE: allowlist validation before shell execution
$allowed = ['convert', 'resize', 'thumbnail'];
$action  = $_GET['action'];

if (!in_array($action, $allowed, true)) {
    http_response_code(400);
    exit('Invalid action');
}

$src  = escapeshellarg($_FILES['image']['tmp_name']);
$dest = escapeshellarg('/tmp/output_' . uniqid() . '.jpg');
exec('/usr/bin/convert ' . $src . ' -resize 200x200 ' . $dest);
```

4. **Never use `eval()` on external data.** There is no safe way to use `eval()` with user-supplied input. Refactor the logic to use a dispatch table (array of closures), a strategy pattern, or a template engine. If the goal is to let users supply expressions, use a sandboxed expression evaluator library rather than raw PHP eval.

5. **Disable dangerous functions in `php.ini` for environments that do not need them.** If your application never intentionally calls these functions, removing the capability at the runtime level is the strongest control:

```ini
; php.ini — disable dangerous functions in production
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,eval
```

6. **Run the web server process with minimal OS privileges.** Even if an injection succeeds, a process running as a dedicated low-privilege user with no write access outside its working directory, no sudo rights, and no access to secrets limits the blast radius substantially.

## References

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP manual: escapeshellarg()](https://www.php.net/manual/en/function.escapeshellarg.php)
- [PHP manual: escapeshellcmd()](https://www.php.net/manual/en/function.escapeshellcmd.php)
- [PHP manual: disable_functions](https://www.php.net/manual/en/ini.core.php#ini.disable-functions)
