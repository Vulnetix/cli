---
title: "VNX-CS-002 – C# Command Injection via Process.Start with User Input"
description: "Detects calls to System.Diagnostics.Process.Start or ProcessStartInfo.FileName/Arguments assignments that incorporate user-controlled input through string concatenation or interpolation."
---

## Overview

This rule identifies C# code that passes user-controlled values into OS process invocations without sanitisation. The patterns detected are: a `Process.Start(...)` call on the same line as a string concatenation (`+`), `string.Format()`, or an interpolated string (`$"..."`); and assignments to `ProcessStartInfo.FileName` or `ProcessStartInfo.Arguments` that follow the same patterns.

When user input is embedded in the filename or arguments of a shell command, an attacker can break out of the intended command structure and execute arbitrary code on the host. Unlike SQL injection, command injection gives the attacker direct access to the operating system rather than just the database, making it one of the most severe vulnerability classes (CWE-78, CAPEC-88, MITRE ATT&CK T1059).

The rule covers both the concise `Process.Start(string fileName, string arguments)` overload and the object-initialiser pattern that sets `StartInfo.FileName` or `StartInfo.Arguments` separately, since both patterns appear in real-world .NET codebases.

**Severity:** High | **CWE:** [CWE-78 – Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)

## Why This Matters

A command injection vulnerability gives an attacker the ability to run arbitrary programs on the server under the identity of the web application process. A single semicolon, pipe character, or backtick in an unvalidated argument can route execution to a second command chosen entirely by the attacker. With a foothold on the server, attackers pivot to reading credentials, installing reverse shells, accessing cloud metadata endpoints, and moving laterally inside the network.

Real-world examples abound: CVE-2014-6271 (Shellshock) and CVE-2021-44228 (Log4Shell) both relied on environments that evaluated attacker-controlled strings as executable code. Many bespoke web applications contain equivalent flaws when they shell out to utilities like `ffmpeg`, `ImageMagick`, `git`, or ZIP tools using user-supplied filenames.

Even when user input is passed as an argument rather than a filename, command interpretation by `cmd.exe` or `/bin/sh` can allow argument injection — for instance, many command-line tools accept `--exec`, `--output`, or similar flags as arguments that significantly change program behaviour. The only safe approach is either to avoid shelling out entirely or to pass arguments as a structured list rather than a parsed string.

## What Gets Flagged

```csharp
// FLAGGED: filename constructed with user input
Process.Start("convert " + userInput + ".png output.jpg");

// FLAGGED: interpolated string passed as arguments
var psi = new ProcessStartInfo();
psi.FileName = "bash";
psi.Arguments = $"-c \"cat {userProvidedPath}\"";

// FLAGGED: string.Format in FileName assignment
psi.FileName = string.Format("/usr/bin/tool {0}", request.QueryString["cmd"]);
```

## Remediation

1. Avoid shelling out when a managed .NET library can accomplish the same task — use libraries for image processing, file archiving, Git operations, and similar tasks.
2. If you must invoke a process, pass arguments as a structured list using the `ArgumentList` property (available since .NET 5) instead of a single parsed string, eliminating shell metacharacter interpretation.
3. Apply a strict allowlist to any user-supplied values used as arguments — reject anything that does not match a known-safe pattern.
4. Run application processes under a least-privilege service account without shell access where possible.

```csharp
// SAFE: use ArgumentList to bypass shell parsing entirely (.NET 5+)
var psi = new ProcessStartInfo
{
    FileName = "/usr/bin/convert",
    UseShellExecute = false,
};
psi.ArgumentList.Add(safeInputPath);   // sanitised/allowlisted value
psi.ArgumentList.Add("output.jpg");
Process.Start(psi);

// SAFE: validate input against a strict allowlist before any use
var allowedFiles = new HashSet<string> { "report.pdf", "summary.csv" };
if (!allowedFiles.Contains(requestedFile))
    return Forbid();
Process.Start("viewer", requestedFile);
```

## References

- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [OWASP .NET Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html)
- [Microsoft Docs: ProcessStartInfo.ArgumentList](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist)
- [CAPEC-88: OS Command Injection](https://capec.mitre.org/data/definitions/88.html)
