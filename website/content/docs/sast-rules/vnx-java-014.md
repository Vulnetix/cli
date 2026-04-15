---
title: "VNX-JAVA-014 – Java Zip Slip via ZipEntry getName()"
description: "Detects Java code that passes ZipEntry.getName() to File or Paths constructors without validating for path traversal sequences, enabling arbitrary file write outside the intended extraction directory."
---

## Overview

This rule flags Java code where `ZipEntry.getName()` is passed directly to `new File()` or `Paths.get()` without first verifying that the resolved path remains within the intended destination directory. A maliciously crafted ZIP archive can contain entry names such as `../../../../etc/cron.d/backdoor` or `../webapps/ROOT/shell.jsp` that, when joined with a destination directory and written to disk, place files entirely outside the target folder. This is the "Zip Slip" vulnerability, a specialised form of path traversal covered by [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html).

**Severity:** High | **CWE:** [CWE-22 – Path Traversal ('Zip Slip')](https://cwe.mitre.org/data/definitions/22.html)

## Why This Matters

Java's `ZipEntry.getName()` returns the raw string stored in the archive's central directory with no sanitization whatsoever. When an application naively constructs an output path by joining a destination directory with the entry name, the OS path resolution rules (`..` segments stepping up directories) cause the output path to escape the intended directory.

Arbitrary file write is a high-impact primitive. In web applications, an attacker who can trigger archive extraction can:

- **Overwrite JSP or servlet files** in the web root, achieving remote code execution on the next request to that path.
- **Replace startup scripts or systemd unit files** to establish persistence across server reboots.
- **Write to `/etc/cron.d/`** (on Linux systems where the server runs as root or a cron-capable user) to schedule attacker code.
- **Overwrite `authorized_keys`** to gain SSH access if the server user has a home directory with an `.ssh` folder.

The vulnerability is particularly dangerous because it exploits a design blind spot: the `ZipFile` and `ZipInputStream` APIs in the Java standard library offer no safe extraction helper — they delegate full path handling to the application. Developers who copy archive-extraction code from online examples frequently reproduce the vulnerable pattern verbatim.

Zip Slip affects all archive formats that support path components in entry names: ZIP, JAR, WAR, TAR, GZip, 7-Zip, CPIO, APK, and RAR. The same pattern applies to `TarArchiveEntry.getName()` in Apache Commons Compress and similar APIs in other libraries.

## What Gets Flagged

The rule matches any `.java` file where `new File(...)` or `Paths.get(...)` is called with the result of `getName()` on what is presumed to be a `ZipEntry` (or similar archive entry object).

```java
// FLAGGED: ZipEntry name used without traversal check
ZipEntry entry = zis.getNextEntry();
File outFile = new File(destDir, entry.getName());  // Zip Slip!
FileOutputStream fos = new FileOutputStream(outFile);

// FLAGGED: Paths.get() form — same vulnerability
Path outPath = Paths.get(destDir.toString(), entry.getName());  // Zip Slip!
Files.copy(zis, outPath, StandardCopyOption.REPLACE_EXISTING);

// FLAGGED: combined on one line
new File(destDir, zipFile.getEntry(name).getName());
```

## Remediation

The canonical fix is to resolve the full canonical (symlink-resolved, `..`-resolved) path of the output file and assert that it starts with the canonical path of the destination directory before writing.

1. **Validate the canonical path against the destination directory:**

   ```java
   // SAFE: canonical path validation prevents Zip Slip
   private static final File DEST_DIR = new File("/var/app/uploads").getCanonicalFile();

   public void extractZip(InputStream zipStream) throws IOException {
       try (ZipInputStream zis = new ZipInputStream(zipStream)) {
           ZipEntry entry;
           while ((entry = zis.getNextEntry()) != null) {
               File outFile = new File(DEST_DIR, entry.getName());

               // Resolve to canonical path (collapses ".." segments and symlinks)
               String canonicalDest = DEST_DIR.getCanonicalPath() + File.separator;
               String canonicalOut  = outFile.getCanonicalPath();

               if (!canonicalOut.startsWith(canonicalDest)) {
                   throw new SecurityException(
                       "Zip Slip detected — entry escapes destination: "
                       + entry.getName());
               }

               if (entry.isDirectory()) {
                   outFile.mkdirs();
               } else {
                   outFile.getParentFile().mkdirs();
                   try (FileOutputStream fos = new FileOutputStream(outFile)) {
                       zis.transferTo(fos);
                   }
               }
               zis.closeEntry();
           }
       }
   }
   ```

   Note that `getCanonicalPath()` resolves symbolic links. The check must use `getCanonicalPath()` — not `getAbsolutePath()` or `toRealPath()` — to correctly handle the case where a symlink inside the archive points outside the destination.

2. **Reject entries containing `..` path components as an additional early guard:**

   ```java
   // Supplementary guard: fast pre-check before canonical resolution
   String entryName = entry.getName();
   if (entryName.contains("..") || entryName.startsWith("/")) {
       throw new SecurityException("Suspicious zip entry name: " + entryName);
   }
   // Still perform canonical path check as the primary control
   ```

   This check is useful as a fast-fail but should not replace the canonical path check, as obfuscated traversal sequences (e.g. URL-encoded `%2e%2e`) may bypass a simple string check.

3. **Use Apache Commons Compress with path traversal protection.** Apache Commons Compress 1.22+ provides `ArchiveStreamFactory` and entry-level utilities. Pair it with your own canonical path guard, as the library itself does not automatically validate paths:

   ```java
   // With Apache Commons Compress
   try (TarArchiveInputStream tis = new TarArchiveInputStream(inputStream)) {
       TarArchiveEntry entry;
       while ((entry = tis.getNextTarEntry()) != null) {
           File outFile = new File(destDir, entry.getName());
           String canonical = outFile.getCanonicalPath();
           if (!canonical.startsWith(destDir.getCanonicalPath() + File.separator)) {
               throw new SecurityException("Tar slip: " + entry.getName());
           }
           // ... write file
       }
   }
   ```

4. **Limit extraction permissions.** Run the service user with write access restricted to the specific upload or working directory. Even if a traversal check is missed, OS-level permissions reduce the blast radius by preventing writes to sensitive system paths.

5. **Validate archive contents before extraction.** For user-supplied archives, perform a first-pass scan that checks all entry names against the traversal rules before extracting any content. Reject the entire archive if any entry fails validation. This prevents partial extraction states where some benign files are written before the malicious entry is discovered.

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [CAPEC-139: Relative Path Traversal](https://capec.mitre.org/data/definitions/139.html)
- [MITRE ATT&CK T1083 – File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [SEI CERT FIO16-J: Canonicalize path names before validating them](https://wiki.sei.cmu.edu/confluence/display/java/FIO16-J.+Canonicalize+path+names+before+validating+them)
- [Zip Slip Vulnerability – Snyk Security Research](https://security.snyk.io/research/zip-slip-vulnerability)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP ASVS V12.3 – File Execution](https://owasp.org/www-project-application-security-verification-standard/)
- [Java ZipEntry documentation](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/zip/ZipEntry.html)
