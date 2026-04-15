---
title: "VNX-PY-020 – tarfile.extractall() Without Path Validation (Zip Slip)"
description: "Detect Python code that calls tarfile.extractall() without a members filter or path validation, leaving the application vulnerable to zip-slip path traversal attacks."
---

## Overview

This rule detects calls to `tarfile.extractall()` that do not pass a `filter=` parameter (Python 3.12+) or a `members=` argument containing pre-validated paths. When `extractall()` is called without any such guard, it extracts every member in the archive exactly as named. If an archive contains members with paths like `../../etc/cron.d/backdoor` or `/etc/passwd`, those files will be written outside the intended extraction directory, potentially overwriting critical system files.

This class of vulnerability is known as **zip slip** or **path traversal during archive extraction**. It affects ZIP, TAR, GZIP, BZ2, XZ, and other archive formats whenever extraction is performed without validating member paths. The attack requires no exploitation of a memory corruption flaw — the archive format itself supports the malicious paths, and a naive extraction routine faithfully creates them.

Python 3.12 introduced the `filter` parameter to `extractall()` as the preferred mitigation. Passing `filter='data'` restricts extraction to safe files, rejecting absolute paths, `..` components, and special files. For older Python versions, members must be filtered manually before passing them to `extractall(members=safe_members)`.

**Severity:** High | **CWE:** [CWE-22 – Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

## Why This Matters

Zip slip attacks have been exploited against production systems in a variety of languages and frameworks. The [Snyk zip slip research](https://snyk.io/research/zip-slip-vulnerability) documented vulnerable extractors in Java, Ruby, Go, Python, and .NET. In Python specifically, the `tarfile` module has been widely used in deployment tooling, package managers, CI/CD scripts, and data pipelines — all high-value targets where writing an arbitrary file can lead to code execution.

A realistic attack scenario: a user-uploaded archive is processed by a data pipeline service. The archive contains `../../../../home/appuser/.ssh/authorized_keys` as one of its members. When `extractall()` is called against an upload directory, the attacker's SSH public key is written into the service account's `authorized_keys`, granting immediate shell access to the server.

The vulnerability is especially insidious because malicious archives look identical to legitimate ones in most archive viewers and the error only manifests at extraction time.

## What Gets Flagged

```python
import tarfile
import os

# FLAGGED: extractall() with no members filter and no filter= parameter
def extract_upload(archive_path: str, dest_dir: str) -> None:
    with tarfile.open(archive_path) as tar:
        tar.extractall(dest_dir)  # No validation — zip slip possible

# FLAGGED: extractall() with a path argument but no member filtering
def process_package(pkg_path: str) -> None:
    with tarfile.open(pkg_path, "r:gz") as tar:
        tar.extractall("/tmp/workspace")  # Members with ../.. will escape

# FLAGGED: extractall() called on the object directly
def unpack(tar: tarfile.TarFile, output: str) -> None:
    tar.extractall(output)  # No filter= and no members=
```

The rule applies only to `.py` files. It does **not** flag calls that already include `filter=` or `members=`.

## Remediation

1. On Python 3.12+, pass `filter='data'` to reject dangerous members automatically.
2. On older Python versions, pre-validate each member's path with `os.path.realpath()` to ensure it resolves inside the destination directory.
3. Never trust archive member names from untrusted sources without validation.

```python
import tarfile
import os

# SAFE (Python 3.12+): use the built-in 'data' filter
def extract_safe_312(archive_path: str, dest_dir: str) -> None:
    with tarfile.open(archive_path) as tar:
        tar.extractall(dest_dir, filter="data")

# SAFE (Python 3.6–3.11): manually validate each member path
def _safe_members(tar: tarfile.TarFile, dest: str):
    dest_real = os.path.realpath(dest)
    for member in tar.getmembers():
        member_path = os.path.realpath(
            os.path.join(dest_real, member.name)
        )
        if not member_path.startswith(dest_real + os.sep):
            raise ValueError(
                f"Attempted path traversal in archive member: {member.name!r}"
            )
        yield member

def extract_safe_legacy(archive_path: str, dest_dir: str) -> None:
    os.makedirs(dest_dir, exist_ok=True)
    with tarfile.open(archive_path) as tar:
        tar.extractall(dest_dir, members=_safe_members(tar, dest_dir))

# SAFE: reject absolute paths and dotdot sequences explicitly
def is_safe_member(member: tarfile.TarInfo) -> bool:
    name = member.name
    return (
        not os.path.isabs(name)
        and ".." not in name.split("/")
        and not name.startswith("/")
    )

def extract_with_allowlist(archive_path: str, dest_dir: str) -> None:
    with tarfile.open(archive_path) as tar:
        safe = [m for m in tar.getmembers() if is_safe_member(m)]
        tar.extractall(dest_dir, members=safe)
```

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [Python tarfile Module Documentation – filter parameter](https://docs.python.org/3/library/tarfile.html#tarfile.TarFile.extractall)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [Snyk Zip Slip Vulnerability Research](https://snyk.io/research/zip-slip-vulnerability)
- [CAPEC-139: Relative Path Traversal](https://capec.mitre.org/data/definitions/139.html)
- [MITRE ATT&CK T1083 – File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
