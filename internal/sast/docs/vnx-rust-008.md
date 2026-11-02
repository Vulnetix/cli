---
title: "VNX-RUST-008 – Path Traversal in Actix-web or Axum File-Serving Handler"
description: "Reports an axum or actix-web request value (Path/Query/Json/Form extractor, web::Path, match_info) that reaches .join, Path::new, File::open, std/tokio fs calls or NamedFile::open in the same handler; canonicalize+starts_with, '..' rejection, file_name() and integer extractors are not reported."
---

## Overview

This rule flags Rust web handlers (using Actix-web or Axum) that construct a filesystem path by joining a base directory with a value extracted from a URL path parameter, without subsequently calling `canonicalize()` and verifying that the result is a child of the expected base directory. When a user-supplied path component is joined directly, an attacker can embed `../` sequences to escape the intended directory and request arbitrary files from the server's filesystem.

The rule follows a value taken from the request (a `Path(name)`, `Path((a, b))`, `Query(q)`, `Json` or `Form` extractor, a `web::Path<...>` / `web::Query<...>` parameter, or `HttpRequest::match_info()`), directly or through one `let` binding, into a path or file operation in the same handler: `.join(...)`, `Path::new`, `PathBuf::from`, `File::open`/`create`, `std::fs` or `tokio::fs` calls, `NamedFile::open`, `ServeFile::new` or `OpenOptions`. It does not report a handler that canonicalizes and checks `starts_with`, rejects `".."`, keeps only `file_name()`, checks `Component::ParentDir`, or calls a sanitize/safe_join helper, nor integer, bool or `Uuid` extractors. Flows through more than one intermediate binding or across functions are not followed.

This rule corresponds to [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html).

**Severity:** High | **CWE:** [CWE-22 – Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

## Why This Matters

Path traversal vulnerabilities in file-serving endpoints are straightforward to exploit and can have severe consequences. An attacker does not need to compromise the server or find an authentication bypass — they simply send a crafted URL to an endpoint that was intended for legitimate file access.

A typical attack begins with the attacker sending a request like `GET /files/../../../../etc/passwd` or the URL-encoded equivalent `%2e%2e%2f` sequences. If the handler blindly joins the base directory with this value, the resolved path escapes the intended directory. On a Linux server, common high-value targets include `/etc/passwd`, `/etc/shadow`, application configuration files containing database credentials, private TLS key files, and cloud instance metadata accessible via well-known paths.

In microservice architectures, the file server may run alongside services whose configuration files contain secrets for databases, message queues, or cloud providers. A path traversal vulnerability in the file-serving handler can expose the credentials of entirely unrelated services on the same host.

## What Gets Flagged

The finding is reported on the line where the request value reaches the path or file operation.

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

// FLAGGED: inline format argument names the file
async fn logs(service: web::Path<String>) -> HttpResponse {
    let service = service.into_inner();
    let body = std::fs::read_to_string(format!("/var/log/app/{service}.log"));
    ...
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
