---
title: "VNX-59 – Improper Link Resolution Before File Access ('Link Following')"
description: "A fixed file name in a shared temporary directory is written or chmod'ed without O_EXCL/O_NOFOLLOW, a path is checked with access()/lstat() and then opened by name, or os.Readlink is given a request or command-line path."
---

## Overview

VNX-59 maps to [CWE-59: Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html). It reports writes through a path that another local user can plant a symbolic link at, and the check-then-open race that lets a link be swapped in.

**Severity:** High | **CWE:** [CWE-59](https://cwe.mitre.org/data/definitions/59.html) | **Languages:** c, cpp, go, python

## Why This Matters

Anyone on the host can create `/tmp/appd.pid` before your program does, as a symbolic link to `~victim/.bashrc` or `/etc/cron.d/x`. A plain `fopen(..., "w")`, `os.Create` or `chmod` then follows the link and truncates, overwrites or re-permissions the target with your program's privileges. `access()` followed by `open()` has the same problem: the file checked is not necessarily the file opened.

## What Gets Flagged

```c
int fd = open("/tmp/appd.pid", O_WRONLY | O_CREAT | O_TRUNC, 0600);  /* owner-only, but no O_EXCL */
FILE *f = fopen("/tmp/appd.state", "r+");
chmod("/tmp/appd.sock", 0777);
std::ofstream out("/tmp/cache.idx");
if (access(path, W_OK) == 0) { return open(path, O_WRONLY | O_APPEND); }
```

In C and C++, creating a fixed name in a shared temporary directory with permissions other users can use is reported by [VNX-378](../vnx-378/), not here: `fopen()` with a `w`/`a` mode (no `x`), and `open()`/`creat()` with a mode that grants other users access and no `O_EXCL`. That is the same defect in its C-specific form, so the line is reported once.

```c
FILE *f = fopen("/tmp/appd.log", "a");                                /* reported by VNX-378 */
int fd = open("/tmp/appd.lock", O_WRONLY | O_CREAT | O_TRUNC, 0644);  /* reported by VNX-378 */
```

```python
with open("/tmp/report.csv", "w") as fh: ...
path = os.path.join(tempfile.gettempdir(), "cache.db")
with open(path, "wb") as fh: ...
os.chmod("/tmp/app.sock", 0o777)
```

```go
f, err := os.Create("/tmp/agent.pid")
lock := filepath.Join(os.TempDir(), "agent.lock")
return os.Create(lock)
```

Not flagged: `mkstemp`, `NamedTemporaryFile`, `os.CreateTemp`, `os.MkdirTemp` names, opens with `O_EXCL` or `O_NOFOLLOW`, Python mode `"x"`, reads, writes outside shared temporary directories, test code, the same text in comments or strings, and the C/C++ temporary-file creation that VNX-378 reports.

## Remediation

1. Let the system choose a unique name: `mkstemp()`, `tempfile.NamedTemporaryFile`/`mkstemp`, `os.CreateTemp`.
2. If the name must be fixed, put it in a directory only your user can write (`$XDG_RUNTIME_DIR`, a 0700 directory from `mkdtemp`), and open with `O_CREAT | O_EXCL | O_NOFOLLOW`.
3. Replace `access()` + `open()` with `open()` (`O_NOFOLLOW`) followed by `fstat()` on the descriptor.

## References

- [CWE-59: Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html)
- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)
