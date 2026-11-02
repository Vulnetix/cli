---
title: "VNX-JAVA-009 – Java Path Traversal"
description: "Reports Java file and path APIs (new File, FileInputStream/FileOutputStream, FileReader/FileWriter, Paths.get, Path.of, Path.resolve, Files.*, FileSystemResource) whose path argument carries servlet request data, an upload file name or an annotated Spring/JAX-RS handler parameter, directly or through up to five local assignments, unless the path is checked for containment or reduced to a bare file name."
---

## Overview

This rule detects Java file-access code — `new File(...)`, `new FileInputStream(...)`, `new FileReader(...)`, `Paths.get(...)`, and `Files.readAllBytes(Paths.get(...))` — where the path argument is sourced directly from `request.getParameter()` or `req.getParameter()` without validation or canonicalization. An attacker can supply `../` sequences to escape the intended directory and access arbitrary files on the server's filesystem. This is path traversal, CWE-22.

**Severity:** High | **CWE:** [CWE-22 – Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

## Why This Matters

Path traversal is a direct path to sensitive file disclosure. On a typical Linux-hosted Java application, an attacker submitting `filename=../../../../etc/passwd` can retrieve the system password file. More targeted inputs like `../../../../home/app/.ssh/id_rsa` (private SSH keys), `../../../../opt/app/application.properties` (database credentials), or `../../../../proc/self/environ` (environment variables containing secrets injected at deployment time) can provide everything needed for lateral movement.

Write variants are even more dangerous: an attacker able to supply a path to a `FileOutputStream` or `FileWriter` call can overwrite the application's configuration files, inject a JSP web shell into the webroot, or corrupt critical system files. Combined with a file upload endpoint, path traversal enables persistent code execution.

## What Gets Flagged

The rule reports the file or path call whose argument carries request data: a servlet request value, `MultipartFile.getOriginalFilename()`, a Spring or JAX-RS annotated handler parameter, or a local assigned from one up to five assignments earlier in the same method (the look-back stops at the method declaration, at most 120 lines up). Paths checked with `startsWith` after normalising or canonicalising, names tested for `..`, names reduced with `FilenameUtils.getName` or converted to numbers, and request bodies written as file content are not reported.

```java
// FLAGGED: File constructor with raw user input
String filename = request.getParameter("file");
File f = new File("/var/app/uploads/" + filename);

// FLAGGED: FileInputStream with user-controlled path
FileInputStream fis = new FileInputStream(request.getParameter("report"));

// FLAGGED: Paths.get with user input
Path p = Paths.get("/data/reports/" + request.getParameter("id"));
byte[] content = Files.readAllBytes(p);

// FLAGGED: FileReader from parameter
FileReader reader = new FileReader(new File(req.getParameter("template")));
```

### Following the value through the method

The look-back stops at the enclosing method's declaration (at most 120 lines up), and the method is read before the call is reported:

- a definition on a branch that never runs is dropped: an `if`/`else` or ternary whose condition folds to a constant (integer literals, and `int` locals assigned once from a literal), or a `case` that a `switch` on a constant does not select;
- a local that provably holds a constant at the call stops carrying the request value: a literal on every path, the element a list index or map key actually holds, or the result of a method in the same file (including a nested class) whose every `return` is a constant;
- a request value stored in a list, map or builder and read back is followed, so `list.add(request.getParameter("x"))` followed by `list.get(0)` is request data.

```java
// NOT FLAGGED: 3 * 40 > 100, so name is always "default.html"
int maxTemplates = 40;
if (3 * maxTemplates > 100) name = "default.html";
else name = request.getParameter("template");

// FLAGGED: the map key read back holds the header value
byKind.put("custom", request.getHeader("X-Layout"));
byKind.put("standard", "standard.html");
String path = byKind.get("custom");
```

Anything the analysis cannot resolve stays reported: a condition on request data, a call into another class that is handed a run-time value (a call with constant arguments is read as inert, below), a collection filled in a loop or handed to another method, a helper that returns (a transform of) its parameter, which stays as tainted as the argument it is handed (see Helpers in other files).

### Helpers in other files

A call into another class of the project is read from that class's own source instead of being guessed at. For `obj.m(args)`, `Cls.m(args)` and `new Cls(args).m(args)` the class is found by the declared type of `obj` (a local, a parameter, or the `new Cls(...)` it was assigned from) or by the static class name, and the method (at most 60 lines, overloads told apart by arity) is summarised as one of:

- **constant**: every return is a literal, an `UPPER_CASE` name, a field initialised to a literal and never assigned again, or the result of a constant method of the same class. The call is as constant as that literal, whatever it is handed.
- **a function of its arguments**: every return is constant once the parameters, and the fields the class's one constructor stores from its own parameters, are taken as constants. The call is only as risky as the arguments it depends on: a getter of a value stored by `new Cls(arg)` is as tainted as `arg`, and a method that ignores one of its parameters is not tainted by it.
- **opaque**: anything else, such as a method that reads a request value or a header, a field a setter can change, or a call the summary cannot see through.

A value of an interface or base class type runs the method of every project class that extends or implements it, so one implementation that returns its parameter keeps the call as tainted as that parameter. What is still reported: opaque calls, a simple class name that two files declare (ambiguous), a class outside the project, a type with an anonymous subclass, and a callee that hands the value to a third class (a callee is read one level deep). A method of the same file called without a receiver is summarised the same way.

```java
// NOT FLAGGED: Sanitizer.clean ignores its argument and returns a literal
String value = sanitizer.clean(request.getParameter("value"));
new FileInputStream(ROOT + value);

// NOT FLAGGED: the constructor argument is a literal, so the getter is too
Holder holder = new Holder("report");
new FileInputStream(ROOT + holder.get());

// FLAGGED: Echo.same returns its argument
String value = echo.same(request.getParameter("value"));
new FileInputStream(ROOT + value);

// FLAGGED: the getter returns what the constructor was given
Holder holder = new Holder(request.getParameter("value"));
new FileInputStream(ROOT + holder.get());
```

### Calls that cannot bring data in

A call into code the scan cannot see (another class or module) is treated as **inert**, and its value as a constant, when all of these hold:

- its name is not that of a source (`read*`, `next*`, `getParameter*`, `getHeader*`, `getCookie*`, `getenv`, `getProperty`, `query`, `execute`);
- every argument is a constant: a literal, or a name the method fixes;
- its receiver is a type name, a `new` expression with constant arguments, or a local built from such a call, and that local is only ever called with constant arguments.

```java
// NOT REPORTED: the helper is given literals only
Names names = NamesFactory.create();
String picked = names.pick("summary");
new FileInputStream(ROOT + picked);

// REPORTED: a run-time argument
String picked = names.pick(param);

// REPORTED: the receiver was built from, or fed, a run-time value
Names names = new Names(param);
String picked = names.pick("summary");

// REPORTED: a source-like method name
String picked = Prompts.readLine("file");
```

Anything that fails one of the tests stays reported, so a helper that hands back its argument is never mistaken for a constant.

## Remediation

1. **Canonicalize the resolved path and verify it stays within the allowed base directory.** `File.getCanonicalPath()` resolves all `..` sequences and symbolic links, returning an absolute path. After resolving, check that the result starts with your intended base directory.

   ```java
   // SAFE: canonical path validation
   private static final String BASE_DIR = "/var/app/uploads/";

   String filename = request.getParameter("file");
   File requestedFile = new File(BASE_DIR, filename);

   // Resolve symlinks and .. sequences
   String canonicalPath = requestedFile.getCanonicalPath();

   if (!canonicalPath.startsWith(BASE_DIR)) {
       response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
       return;
   }

   // Safe to read
   byte[] data = Files.readAllBytes(Paths.get(canonicalPath));
   response.getOutputStream().write(data);
   ```

2. **Validate the filename format before constructing any path.** Reject filenames that contain path separators (`/`, `\`), null bytes (`\0`), or `..` sequences. An allowlist regular expression is more reliable than a denylist.

   ```java
   // SAFE: strict filename validation before any file access
   String filename = request.getParameter("file");
   if (filename == null || !filename.matches("[a-zA-Z0-9._-]{1,64}")) {
       response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid filename");
       return;
   }
   // Now safe to join with the base directory
   Path filePath = Paths.get("/var/app/uploads/").resolve(filename).normalize();
   ```

3. **Store files by a server-generated identifier, not a user-supplied name.** When files are uploaded, assign them a UUID or a content-addressed hash as the storage key. Users never submit the actual filename for retrieval — only the opaque identifier. This eliminates the path traversal surface entirely.

   ```java
   // SAFE: files are stored and retrieved by UUID, not by name
   String fileId = request.getParameter("id");
   if (!fileId.matches("[0-9a-f-]{36}")) {
       response.sendError(HttpServletResponse.SC_BAD_REQUEST);
       return;
   }
   Path storedPath = Paths.get("/var/app/storage/", fileId);
   // No user-controlled path segments
   ```

4. **Use the `java.nio.file` API consistently.** `Path.resolve()` followed by `Path.normalize()` and a `startsWith()` check on the base path is idiomatic, safe, and portable. Prefer it over `java.io.File` for new code.

5. **Serve static files through the web server, not the application.** If users need to download files from a known directory, configure Nginx or Apache to serve that directory directly. Move the routing decision out of application code entirely.

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [CAPEC-126: Path Traversal](https://capec.mitre.org/data/definitions/126.html)
- [MITRE ATT&CK T1083 – File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP Java Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html)
- [OWASP ASVS V12 – Files and Resources](https://owasp.org/www-project-application-security-verification-standard/)
