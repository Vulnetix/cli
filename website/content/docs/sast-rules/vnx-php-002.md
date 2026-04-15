---
title: "VNX-PHP-002 – Dangerous Function in PHP"
description: "Detect calls to eval(), exec(), system(), passthru(), shell_exec(), popen(), and proc_open() which execute OS commands or arbitrary PHP code and can lead to remote code execution when arguments are user-controlled."
---

## Overview

This rule flags any `.php` file that calls one of PHP's command-execution or code-evaluation functions: `eval()`, `exec()`, `system()`, `passthru()`, `shell_exec()`, `popen()`, and `proc_open()`. When the argument to any of these functions includes attacker-controlled data, the result is remote code execution (RCE) on the server.

**Severity:** High | **CWE:** [CWE-78 – Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html) | **CAPEC:** [CAPEC-88](https://capec.mitre.org/data/definitions/88.html) | **ATT&CK:** [T1059](https://attack.mitre.org/techniques/T1059/)

> **PHP default behavior:** All of these functions are **enabled by default** in a standard PHP installation. The `disable_functions` directive in `php.ini` is empty by default. Production environments that do not use these functions should explicitly disable them.

## Why This Matters

When an attacker controls the argument to one of these functions, they gain the ability to run any OS command with the privileges of the web server process — typically `www-data` or `apache` on Linux. From there they can:

- Read `/etc/passwd`, `/proc/self/environ`, `.env` files, and database credentials
- Write a PHP web shell for persistent access
- Exfiltrate data over HTTP or DNS
- Pivot to other services on the internal network

`eval()` accepts a full PHP string, allowing an attacker to deliver a base64-encoded payload through a form field and execute it without writing any file. Shell functions pass their argument to `/bin/sh -c`, so shell metacharacters — `;`, `|`, `&&`, `$()`, backticks — all work as separators and substitution operators.

**OWASP ASVS v4.0 mapping:** V5.2.4 — Verify that the application does not use eval() or other dynamic code execution features; V5.2.2 — Verify that the application protects against OS command injection.

## What Gets Flagged

Any `.php` line that contains one of the dangerous function names followed by `(`.

```php
// FLAGGED: unsanitized user input passed to system()
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

// FLAGGED: proc_open with user-controlled command
proc_open($_POST['cmd'], $descriptors, $pipes);
```

## Remediation

**1. Eliminate OS command calls wherever possible.** Most tasks developers reach for `exec()` or `system()` to accomplish — file conversion, image resizing, PDF generation, archive extraction — have pure-PHP library alternatives that never invoke a shell:

| Task | Shell command to replace | Pure-PHP alternative |
|------|--------------------------|----------------------|
| Image resize | `convert` (ImageMagick) | `Imagick` extension or `GD` |
| ZIP creation | `zip` | `ZipArchive` |
| PDF generation | `wkhtmltopdf` | `dompdf`, `TCPDF`, `FPDF` |
| File type detection | `file` | `finfo_open()` / `mime_content_type()` |

**2. If you must call a shell command, escape every argument with `escapeshellarg()`.**

```php
// SAFE: each argument individually escaped
$filename = escapeshellarg($_GET['filename']);
$output   = shell_exec('/usr/bin/file ' . $filename);
```

`escapeshellarg()` wraps the value in single quotes and escapes embedded single quotes. Use `escapeshellcmd()` only on the command path — it is not a substitute for per-argument escaping.

**3. Validate input against an allowlist before use.**

```php
// SAFE: allowlist + escapeshellarg
$allowed = ['convert', 'resize', 'thumbnail'];
$action  = $_GET['action'] ?? '';

if (!in_array($action, $allowed, true)) {
    http_response_code(400);
    exit('Invalid action');
}

$src  = escapeshellarg($_FILES['image']['tmp_name']);
$dest = escapeshellarg('/tmp/output_' . bin2hex(random_bytes(8)) . '.jpg');
exec('/usr/bin/convert ' . $src . ' -resize 200x200 ' . $dest);
```

**4. Never use `eval()` on external data.** There is no safe way to use `eval()` with user-supplied input. Refactor to a dispatch table (array of closures), a strategy pattern, or a template engine. For user-supplied expressions, use a sandboxed evaluator library.

**5. Disable dangerous functions in `php.ini`** for environments that do not need them:

```ini
; php.ini — production: disable dangerous functions
disable_functions = exec,passthru,shell_exec,system,proc_open,popen
```

Note: `eval` is a language construct and cannot be disabled via `disable_functions`. It can only be prevented through code review and static analysis.

**6. Run the web server process as a least-privilege user** with no write access outside the web root and no access to secrets files.

## References

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [OWASP ASVS v4.0 – V5.2 Injection Prevention](https://owasp.org/www-project-application-security-verification-standard/)
- [PHP manual: escapeshellarg()](https://www.php.net/manual/en/function.escapeshellarg.php)
- [PHP manual: disable_functions](https://www.php.net/manual/en/ini.core.php#ini.disable-functions)
- [PHP manual: exec()](https://www.php.net/manual/en/function.exec.php)
