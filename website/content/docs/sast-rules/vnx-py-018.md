---
title: "VNX-PY-018 – Insecure Temporary File Creation via tempfile.mktemp()"
description: "Detect Python code that uses tempfile.mktemp(), which is vulnerable to a TOCTOU race condition allowing an attacker to intercept the temporary file path before creation."
---

## Overview

This rule detects calls to `tempfile.mktemp()`, a deprecated function that returns a filename guaranteed to be unique at the moment of the call but does **not** create the file. The gap between the name being returned and the application opening the file is a classic Time-of-Check to Time-of-Use (TOCTOU) race condition: any process that observes or guesses the generated name can create a file, directory, or symbolic link at that path before the calling application does.

The vulnerability is particularly dangerous in privileged processes. If a setuid binary or a service running as root calls `tempfile.mktemp()` and an attacker wins the race, they can place a symlink pointing to a sensitive system file (`/etc/passwd`, `/etc/shadow`, a TLS private key). The privileged process then reads from or writes to the attacker-controlled target, enabling data exfiltration or privilege escalation.

The fix is straightforward: use `tempfile.NamedTemporaryFile()` (which creates and opens the file atomically) or `tempfile.mkstemp()` (which returns both a file descriptor and a path, having created the file atomically). Both functions use `os.open()` with `O_EXCL` to prevent race conditions at the kernel level.

**Severity:** Medium | **CWE:** [CWE-377 – Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

## Why This Matters

TOCTOU vulnerabilities in temporary file creation have a long history of real-world exploitation. The classic attack scenario involves a predictable `/tmp` filename: many older utilities named temporary files using the process ID (`/tmp/prog.12345`), which an attacker could predict and pre-create as a symlink. Python's `tempfile.mktemp()` generates random names, but randomness alone does not close the race window — it only makes brute-forcing the name harder, not impossible.

In container environments and multi-tenant systems, the risk increases because multiple users share the same `/tmp` filesystem. An attacker with local access can use `inotifywait` or a tight polling loop to race against any process that uses `mktemp()`. The window is small but reliably exploitable on loaded systems where scheduling delays are common.

Beyond active exploitation, auditors and compliance frameworks (FIPS, Common Criteria) flag `tempfile.mktemp()` usage as an automatic finding because its insecurity is inherent to its design, not its configuration.

## What Gets Flagged

```python
import tempfile
import os

# FLAGGED: mktemp() returns a path but does not create the file
def process_upload(data: bytes) -> str:
    tmp_path = tempfile.mktemp()  # Race window begins here
    with open(tmp_path, "wb") as f:  # Attacker can win this race
        f.write(data)
    return tmp_path

# FLAGGED: mktemp() with suffix/prefix
def build_report(content: str) -> str:
    path = tempfile.mktemp(suffix=".html", prefix="report_")
    with open(path, "w") as f:
        f.write(content)
    return path
```

The rule applies only to `.py` files.

## Remediation

1. Replace `tempfile.mktemp()` with `tempfile.NamedTemporaryFile()` for use cases where you need a file object, or `tempfile.mkstemp()` when you need a path.
2. Use `delete=True` (the default) on `NamedTemporaryFile` so the OS cleans up automatically; use `delete_on_close=False` (Python 3.12+) if the file must be readable by a subprocess.
3. Never construct `/tmp` paths manually using `os.path.join("/tmp", some_name)` — always use the `tempfile` module functions.

```python
import tempfile
import os

# SAFE: NamedTemporaryFile — created atomically, auto-deleted on close
def process_upload_safe(data: bytes) -> None:
    with tempfile.NamedTemporaryFile(delete=True) as tmp:
        tmp.write(data)
        tmp.flush()
        process_file(tmp.name)
    # File is automatically deleted when the context manager exits

# SAFE: mkstemp() — returns (fd, path), file already exists before you get the path
def build_report_safe(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".html", prefix="report_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        return path
    except Exception:
        os.unlink(path)
        raise

# SAFE: TemporaryDirectory for a whole working directory
def extract_archive_safe(archive_path: str) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        # Work inside tmpdir — cleaned up automatically
        extract_to(archive_path, tmpdir)
```

## References

- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)
- [Python tempfile Module Documentation](https://docs.python.org/3/library/tempfile.html)
- [OWASP Path Traversal Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP Python Security Project](https://owasp.org/www-project-python-security/)
- [CAPEC-29: Leveraging Time-of-Check and Time-of-Use (TOCTOU) Race Conditions](https://capec.mitre.org/data/definitions/29.html)
- [MITRE ATT&CK T1574 – Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)
- [Python Security Considerations – tempfile](https://docs.python.org/3/library/tempfile.html#tempfile.mktemp)
