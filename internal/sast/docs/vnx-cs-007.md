---
title: "VNX-CS-007 – C# Path Traversal via Path.Combine with User Input"
description: "Detects C# Path.Combine/Path.Join, MapPath and file-system APIs (File, Directory, FileStream, StreamReader, PhysicalFile, TransmitFile, SaveAs) whose path argument contains HTTP request data, an uploaded file name, an archive entry name (zip slip) or a controller action parameter, without Path.GetFileName or a GetFullPath/StartsWith containment check."
---

## Overview

This rule reports `Path.Combine`/`Path.Join` and `MapPath` (any argument), `File.Copy`/`Move`/`Replace`, and the path argument of `File.Read*`/`Write*`/`Append*`/`Open*`/`Create`/`Delete`, `Directory` enumeration and deletion, `new FileStream`/`StreamReader`/`StreamWriter`/`FileInfo`/`DirectoryInfo`, `PhysicalFile`, `Results.File` and `Response.TransmitFile`/`WriteFile`/`SaveAs`, when that argument contains request data: `Request.Query`/`QueryString`/`Form`/`Params`/`Cookies`/`Headers`/`Path`, `Request[...]`, `RouteData.Values`, a WebForms `TextBox.Text`, an uploaded file's `FileName`, a string parameter of a controller action, a `[FromQuery]`/`[FromRoute]`/`[FromForm]` parameter or a minimal-API lambda parameter, inline or through a variable assigned up to 15 lines above. A flow is reported once, at its first sink. Values passed through `Path.GetFileName`, a path resolved with `GetFullPath` and checked with `StartsWith`, values checked by `Regex.IsMatch` or an allowlist, `Guid`/`int` parameters, request data written as file content, and parameters of non-controller methods are not reported.

`Path.Combine` in .NET concatenates path segments but does not validate the result. If a user-supplied segment contains `../` sequences (or their URL-encoded equivalents `%2e%2e%2f`), the resolved path escapes the intended base directory. An attacker can use this to read arbitrary files readable by the web application process, write files to unintended locations, or overwrite critical system files if the process has sufficient privilege.

The vulnerability is particularly common in file upload handlers, file download endpoints, and any feature that constructs a filesystem path from a user-supplied filename or path component.

**Severity:** High | **CWE:** [CWE-22 – Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)](https://cwe.mitre.org/data/definitions/22.html)

## Why This Matters

Path traversal vulnerabilities have affected a wide range of applications including web servers, file managers, and document management systems. The OWASP Top 10 has consistently included path traversal under "Broken Access Control". Exploits are simple: an attacker submits a filename like `../../appsettings.json` or `../../../windows/win.ini` and the server returns the file contents, potentially exposing database connection strings, API keys, and other configuration secrets.

In ASP.NET applications, path traversal in file download endpoints is a common finding in penetration tests. A vulnerable endpoint that constructs a path as `Path.Combine(baseDir, Request.Query["file"])` allows reading any file accessible to the IIS/Kestrel worker process, including `web.config` files with database credentials and the `appsettings.json` configuration. In write scenarios, attackers may overwrite the application's own DLLs or web configuration, leading to code execution.

The attack is covered by CAPEC-126 (Path Traversal) and ATT&CK T1083 (File and Directory Discovery). Modern WAFs may detect some traversal patterns, but canonicalisation-based bypasses (double-encoding, Unicode normalisation tricks) mean that WAF-only defence is insufficient.

## What Gets Flagged

```csharp
// FLAGGED: Path.Combine with query string value, no validation
string filename = Request.Query["file"];
string fullPath = Path.Combine(uploadDir, filename);
return File(System.IO.File.ReadAllBytes(fullPath), "application/octet-stream");

// FLAGGED: controller action parameter
public IActionResult Download(string name)
{
    var path = Path.Combine(_root, name);
    return PhysicalFile(path, "application/pdf");
}

// FLAGGED: WebForms MapPath and an uploaded file's own name
FileInfo fi = new FileInfo(Server.MapPath(Request["image"]));
var dest = Path.Combine(root, "uploads", file.FileName);

// FLAGGED: zip slip, an archive entry name keeps its ../ segments
entry.ExtractToFile(Path.Combine(Root, entry.FullName), overwrite: true);
```

## Remediation

1. Use `Path.GetFileName(userInput)` to strip any directory components from the user-supplied value before passing it to `Path.Combine`. This ensures only the bare filename is used.
2. After combining, resolve the full canonical path with `Path.GetFullPath()` and verify it starts with your intended base directory using `string.StartsWith(baseDir, StringComparison.OrdinalIgnoreCase)`.
3. Maintain an allowlist of permitted file names or use GUIDs as file identifiers instead of accepting user-supplied names.
4. Apply least-privilege to the process account so even a successful traversal cannot reach sensitive files outside the application's directory.

```csharp
// SAFE: strip directory components from user input first
string userFilename = Request.Query["file"];
string safeFilename = Path.GetFileName(userFilename);  // removes any ../ components
string fullPath = Path.Combine(uploadDir, safeFilename);

// SAFE: canonicalise and verify the resulting path is within the base directory
string baseDir = Path.GetFullPath("/var/app/uploads");
string requested = Path.Combine(baseDir, userFilename);
string canonical = Path.GetFullPath(requested);

if (!canonical.StartsWith(baseDir + Path.DirectorySeparatorChar, 
    StringComparison.OrdinalIgnoreCase))
{
    return Forbid();  // path traversal detected
}
return File(System.IO.File.ReadAllBytes(canonical), "application/octet-stream");
```

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP – Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP .NET Security Cheat Sheet – File Upload](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html#file-uploads)
- [Microsoft Docs – Path.GetFullPath for security validation](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.getfullpath)
- [CAPEC-126: Path Traversal](https://capec.mitre.org/data/definitions/126.html)
