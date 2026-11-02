---
title: "VNX-C-003 – OS Command Injection via system() or popen() with Non-Literal Argument"
description: "Reports C and C++ calls that hand a non-constant string to a shell (system, popen, _popen, _wsystem, p2open, std::system, execl of sh -c) when the command comes from argv, getenv or input, or was composed nearby with sprintf/snprintf/asprintf %s, strcat/strcpy or C++ string concatenation, and wordexp() without WRDE_NOCMD. Literal commands, exec without a shell, validated or quoted input, wrapper parameters and comments are not reported."
---

## Overview

This rule reports calls that pass a command string to a shell (`system`, `popen`, `_popen`, `_wpopen`, `_wsystem`, `p2open`, `std::system`, and `execl`/`execlp`/`execle` of `sh`/`bash`/`zsh`/`dash` with `-c`) when the command is `argv[...]` or `getenv(...)`, a variable read from `getenv`, `argv`, `readline`, `fgets`, `read`, `recv`, `fread`, `getline` or `scanf` in the 25 lines above, or a variable composed in those lines from non-constant data (`sprintf`/`snprintf`/`asprintf` with a `%s` argument, `strcat`/`strcpy` of a non-constant, C++ `std::string` concatenation, `append()` or `<<`). It also reports `wordexp()` of a non-literal without `WRDE_NOCMD`. It does not report literal or macro commands, `system(NULL)`, commands built only from literals and `%d` numbers, a command that is a parameter of the enclosing function, a command preceded by validation or quoting (`is_valid_*`, `sanitize`, `escape`, `g_shell_quote`, `strspn`/`strpbrk`), `exec*` without a shell, `posix_spawn`, prototypes, string literals and comments.

All four of these functions pass their argument to a shell for interpretation. `system()` and `popen()` invoke `/bin/sh -c <command>`, `p2open()` is a Solaris extension that does the same, and `wordexp()` performs shell-style word expansion including variable substitution and command substitution. When any portion of the command string derives from external input — user-supplied data, environment variables, filenames read from the filesystem, HTTP headers, or network packet fields — an attacker who controls that portion can inject shell metacharacters (`;`, `|`, `&&`, `$(...)`, `` ` ``) to execute arbitrary commands.

**Severity:** Critical | **CWE:** [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CWE-88](https://cwe.mitre.org/data/definitions/88.html), [CWE-676](https://cwe.mitre.org/data/definitions/676.html)

## Why This Matters

OS command injection is consistently ranked in the OWASP Top 10 and requires no memory corruption knowledge to exploit — semicolons and pipes are the only primitives needed. A single unguarded `system()` call that incorporates network-supplied data can give an attacker full remote code execution at the privilege level of the running process.

Real-world examples:

- **CVE-2014-6271 (Shellshock)** — CGI programs that ran Bash as part of request processing passed HTTP headers into environment variables. Bash's bug meant function definitions stored in environment variables could include trailing commands that executed unconditionally. Web servers that invoked CGI scripts via `system()` or `popen()` were trivially exploitable: an attacker sent a crafted `User-Agent` or `Referer` header and achieved remote code execution on any CGI-enabled server running a vulnerable Bash. Exploitation was automated within hours of disclosure and affected millions of servers.
- **CVE-2018-1000861 (Jenkins)** — A Groovy sandbox bypass in Jenkins' Stapler framework led to a `Runtime.exec()` call (Java's equivalent of `system()`) being reachable with attacker-controlled arguments, giving unauthenticated RCE.
- **CVE-2006-3747 (Apache mod_rewrite)** — An off-by-one error in `mod_rewrite` combined with `system()` calls in CGI scripts that incorporated rewritten URLs led to command injection.

Embedded systems and network appliances are especially affected because they frequently use `system()` and `popen()` as quick wrappers around CLI tools (`ping`, `iptables`, `ifconfig`) and process user input from web interfaces directly. These patterns map to CAPEC-88 (OS Command Injection) and ATT&CK T1059.

**SEI CERT C rule:** ENV33-C — Do not call `system()`.

**OWASP ASVS v4.0:** V5.2.4 — Verify that the application avoids the use of `eval()` or other dynamic code execution features. Where there is no alternative, any user input being included must be sanitized or sandboxed before being executed.

## What Gets Flagged

```c
// FLAGGED: command composed from a caller-supplied host name
char cmd[256];
snprintf(cmd, sizeof(cmd), "ping -c 1 %s > /dev/null", host);
return system(cmd);

// FLAGGED: command assembled with strcat
strcpy(cmd, "grep -c ");
strcat(cmd, pattern);
fp = popen(cmd, "r");

// FLAGGED: argv, the environment and stdin straight to the shell
system(argv[1]);
return system(getenv("POST_HOOK"));
while (fgets(line, sizeof(line), stdin) != NULL)
    system(line);
```

```cpp
// FLAGGED: C++ string concatenation
std::string cmd = "tar -xf " + archive + " -C " + dest;
return std::system(cmd.c_str());
FILE *p = popen(("ls " + dir).c_str(), "r");
```

Not flagged: `system("date")`, `popen("uname -r", "r")`, `execvp(argv[0], argv)` (no shell), and a command whose input passed `is_valid_hostname(host)` first.

## Remediation

**The preferred fix is to avoid shell-invoking functions entirely and use `execve`/`execvp` with an argument array.**

When arguments are passed as an array to `execve` or `execvp`, they are delivered directly to the target program without involving a shell. Shell metacharacters in the arguments are treated as literal characters — injection is structurally impossible regardless of the argument content.

```c
// SAFE: execvp — no shell, arguments are passed directly to the program
char *const args[] = {
    "convert",
    user_filename,   // passed as a literal argument; ";" is just a character
    "output.png",
    NULL
};
execvp("convert", args);
// Note: execvp replaces the current process; call fork() first if you need to continue

// SAFE: fork() + execvp() + pipe to replace popen()
int pipefd[2];
if (pipe(pipefd) == -1) { handle_error(); }
pid_t pid = fork();
if (pid == 0) {
    // Child: connect write-end of pipe to stdout, exec grep
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[1]);
    char *const grep_args[] = {"grep", "--", search_term, "/var/log/app.log", NULL};
    execvp("grep", grep_args);
    _exit(1);  // execvp failed
}
// Parent: read from pipefd[0]
close(pipefd[1]);
```

**If `system()` or `popen()` cannot be avoided:**

1. Build an allowlist of the exact literal commands permitted and reject anything not on the list.
2. Use `snprintf` to construct the command and then validate the result matches an allowlist pattern before calling `system()`.
3. Never interpolate user-supplied filenames, hostnames, search terms, or identifiers directly into a shell command string without strict character allowlisting (alphanumerics and limited punctuation only, rejecting any shell metacharacter).

**Compiler and runtime hardening (not a substitute for the fix above):**

```sh
-D_FORTIFY_SOURCE=2       # catches some dangerous uses of libc functions
-fsanitize=address        # AddressSanitizer for test builds
```

Privilege reduction: ensure the process calling `system()` or `popen()` runs with the minimum necessary OS privileges. An OS command injection vulnerability in a low-privilege process causes less damage than one running as root.

## References

- [CWE-78: Improper Neutralisation of Special Elements Used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-88: Argument Injection](https://cwe.mitre.org/data/definitions/88.html)
- [SEI CERT C – ENV33-C: Do not call system()](https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=87152177)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
- [OWASP – OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [CVE-2014-6271 – Shellshock (NVD)](https://nvd.nist.gov/vuln/detail/cve-2014-6271)
- [Huntress – Shellshock CVE-2014-6271 Analysis](https://www.huntress.com/threat-library/vulnerabilities/cve-2014-6271)
- [ImmuniWeb – OS Command Injection / CWE-78](https://www.immuniweb.com/vulnerability/os-command-injection.html)
