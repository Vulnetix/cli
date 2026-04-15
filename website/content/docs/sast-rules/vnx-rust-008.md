---
title: "VNX-RUST-008 – Path Traversal in Actix-web or Axum File-Serving Handler"
description: "Detect Rust web handlers that join a base directory with a user-supplied path parameter without verifying that the resolved path stays within the base directory, enabling attackers to read arbitrary server files."
---

## Overview

This rule flags Rust web handlers (using Actix-web or Axum) that construct a filesystem path by joining a base directory with a value extracted from a URL path parameter, without subsequently calling `canonicalize()` and verifying that the result is a child of the expected base directory. When a user-supplied path component is joined directly, an attacker can embed `../` sequences to escape the intended directory and request arbitrary files from the server's filesystem.

The rule detects this pattern by checking for path-construction calls (`PathBuf::new`, `.join()`, `path::Path::new`) within a code window that also references Actix-web or Axum path extraction APIs (`Path(`, `axum::extract::Path`, `params.get(`, etc.), and that does not already contain a `canonicalize()` call or a `starts_with()` check to confine the path.

This rule corresponds to [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html).

**Severity:** High | **CWE:** [CWE-22 – Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

## Why This Matters

Path traversal vulnerabilities in file-serving endpoints are straightforward to exploit and can have severe consequences. An attacker does not need to compromise the server or find an authentication bypass — they simply send a crafted URL to an endpoint that was intended for legitimate file access.

A typical attack begins with the attacker sending a request like `GET /files/../../../../etc/passwd` or the URL-encoded equivalent `%2e%2e%2f` sequences. If the handler blindly joins the base directory with this value, the resolved path escapes the intended directory. On a Linux server, common high-value targets include `/etc/passwd`, `/etc/shadow`, application configuration files containing database credentials, private TLS key files, and cloud instance metadata accessible via well-known paths.

In microservice architectures, the file server may run alongside services whose configuration files contain secrets for databases, message queues, or cloud providers. A path traversal vulnerability in the file-serving handler can expose the credentials of entirely unrelated services on the same host.

## What Gets Flagged

The rule detects `.rs` files where path-joining operations appear within approximately 15 lines of Actix-web or Axum path parameter extraction, without a subsequent canonicalization and prefix check.

```rust
// FLAGGED: user path joined directly, no canonicalization
async fn serve_file(Path(filename): Path<String>) -> impl Responder {
    let base = PathBuf::from("/var/www/files");
    let path = base.join(&filename); // ../../etc/passwd escapes base
    match tokio::fs::read(&path).await {
        Ok(data) => HttpResponse::Ok().body(data),
        Err(_) => HttpResponse::NotFound().finish(),
    }
}

// FLAGGED: Axum handler with unvalidated path join
async fn download(axum::extract::Path(name): axum::extract::Path<String>) -> Vec<u8> {
    let p = std::path::Path::new("/srv/data").join(&name);
    tokio::fs::read(p).await.unwrap()
}
```

## Remediation

1. **Canonicalize the resolved path and verify it starts with the base directory.** `canonicalize()` resolves all `..` components and symlinks, and `starts_with()` then confirms the result is within the intended tree:

```rust
// SAFE: canonicalize + starts_with prevents traversal
async fn serve_file(Path(filename): Path<String>) -> impl Responder {
    let base = PathBuf::from("/var/www/files").canonicalize().unwrap();
    let requested = base.join(&filename);

    let resolved = match requested.canonicalize() {
        Ok(p) => p,
        Err(_) => return HttpResponse::NotFound().finish(),
    };

    if !resolved.starts_with(&base) {
        return HttpResponse::Forbidden().finish();
    }

    match tokio::fs::read(&resolved).await {
        Ok(data) => HttpResponse::Ok().body(data),
        Err(_) => HttpResponse::NotFound().finish(),
    }
}
```

2. **Strip or reject `..` components before joining.** For simpler cases, reject any filename that contains a path separator or `..`:

```rust
// SAFE: reject filenames with path components
async fn serve_file(Path(filename): Path<String>) -> impl Responder {
    if filename.contains('/') || filename.contains("..") {
        return HttpResponse::BadRequest().finish();
    }
    let path = PathBuf::from("/var/www/files").join(&filename);
    // ...
}
```

3. **Serve files from an index rather than a direct path.** Map user-visible identifiers to server-side paths in a database or in-memory map, eliminating the need to accept arbitrary filesystem paths from users entirely.

## References

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [CAPEC-126: Path Traversal](https://capec.mitre.org/data/definitions/126.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Rust std::path::Path::canonicalize documentation](https://doc.rust-lang.org/std/path/struct.Path.html#method.canonicalize)
- [Actix-web Extractors documentation](https://actix.rs/docs/extractors/)
- [Axum Path extractor documentation](https://docs.rs/axum/latest/axum/extract/struct.Path.html)
