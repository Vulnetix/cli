---
title: "VNX-66 – Improper Handling of File Names that Identify Virtual Resources"
description: "An uploaded file is stored under the name the client sent, so a name such as CON, NUL, AUX, COM1 or LPT1 opens a Windows device instead of a file. Stripping directories with basename or GetFileName does not prevent it."
---

## Overview

VNX-66 maps to [CWE-66: Improper Handling of File Names that Identify Virtual Resources](https://cwe.mitre.org/data/definitions/66.html). It reports a client-supplied upload file name used as the on-disk file name, on the write line or through a variable assigned from it in the 15 lines above.

**Severity:** Medium | **CWE:** [CWE-66](https://cwe.mitre.org/data/definitions/66.html) | **Languages:** csharp, go, java, python

## Why This Matters

On Windows, `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9` and `LPT1`-`LPT9` name devices in every directory, with or without an extension. An upload called `aux.png` or `con.txt` does not create a file: the write blocks the worker, vanishes into `NUL`, or goes to a serial port. `Path.GetFileName`, `basename` and `FilenameUtils.getName` remove directories but leave the device name intact.

## What Gets Flagged

```python
f = request.files["document"]
f.save(os.path.join(UPLOAD_DIR, f.filename))
```

```java
file.transferTo(new File(dir, file.getOriginalFilename()));
```

```csharp
var path = Path.Combine(_env.WebRootPath, "uploads", file.FileName);

string filename = Path.GetFileName(FileUpload1.FileName);
FileUpload1.SaveAs(Server.MapPath("~/uploads/") + filename);
```

```go
dst, err := os.Create(filepath.Join("uploads", header.Filename))
```

Not flagged: a name passed through `secure_filename` or a sanitize function, a generated name on the write line (UUID, GUID, `GetRandomFileName`, a hash or timestamp), a project that checks names against the reserved device list, a name that is only logged or stored as data, and test code.

## Remediation

1. Store uploads under a generated name (a UUID plus a validated extension) and keep the original name as metadata.
2. If the original name must be used, run it through `werkzeug.utils.secure_filename` or an equivalent that rejects reserved device names, and reject names whose stem is `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9` or `LPT1`-`LPT9`.

## References

- [CWE-66: Improper Handling of File Names that Identify Virtual Resources](https://cwe.mitre.org/data/definitions/66.html)
- [Microsoft: Naming Files, Paths, and Namespaces](https://learn.microsoft.com/windows/win32/fileio/naming-a-file)
