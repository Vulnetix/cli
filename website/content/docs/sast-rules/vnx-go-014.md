---
title: "VNX-GO-014 – sync.Mutex Lock() Without Deferred Unlock()"
description: "Detects sync.Mutex.Lock() or sync.RWMutex.RLock() calls that are not immediately followed by a deferred Unlock or RUnlock, risking goroutine deadlocks on panic or early return."
---

## Overview

This rule detects calls to `sync.Mutex.Lock()` or `sync.RWMutex.RLock()` that are not immediately followed by a `defer mu.Unlock()` or `defer mu.RUnlock()` on the next non-blank line. When a mutex is locked without a deferred unlock, any panic or early return between the lock and the eventual unlock call leaves the mutex permanently held. Subsequent goroutines that attempt to acquire the same lock will block indefinitely, causing a goroutine leak and a denial-of-service condition. This maps to CWE-667 (Improper Locking) and CWE-833 (Deadlock).

The idiomatic Go pattern for safe mutex usage is to call `defer mu.Unlock()` immediately after `mu.Lock()` on the next line. This guarantees that the unlock occurs regardless of how the function exits — whether through a normal return, an error return, or a panic that is recovered higher up the stack. Any pattern that deviates from this — such as conditionally unlocking, or unlocking only on the happy path — is a source of latent deadlock bugs.

The rule checks the immediately following non-blank, non-comment line after every lock call. It does not attempt full data-flow analysis, so patterns where the deferred unlock is placed further away are flagged conservatively.

**Severity:** High | **CWE:** [CWE-667 – Improper Locking](https://cwe.mitre.org/data/definitions/667.html), [CWE-833 – Deadlock](https://cwe.mitre.org/data/definitions/833.html)

## Why This Matters

Deadlocks in Go services are particularly insidious because they are silent: the process continues to run, passes health checks that only test process liveness, and consumes memory and file descriptors, but stops serving requests. A single code path that panics while holding a mutex will cause all subsequent requests that touch the same resource to hang until the process is restarted.

MITRE ATT&CK T1499 (Endpoint Denial of Service) covers resource exhaustion attacks. An attacker who can trigger a specific code path — for example by sending a crafted request that causes a nil pointer dereference — can deliberately induce a deadlock to take down a service. Even without an attacker, lock leaks from early returns are a common source of production incidents that are difficult to reproduce in tests because they only manifest under specific error conditions.

Go's `go vet` and `staticcheck` tools catch some deadlock patterns but do not reliably detect the missing-defer case, making this a valuable additional check.

## What Gets Flagged

```go
// FLAGGED: Lock() not followed immediately by defer Unlock()
func (s *Store) Set(key, value string) {
    s.mu.Lock()
    // some code here before eventual Unlock — panic risk
    if key == "" {
        return // mutex is never released!
    }
    s.data[key] = value
    s.mu.Unlock()
}

// FLAGGED: RLock() without deferred RUnlock()
func (s *Store) Get(key string) string {
    s.mu.RLock()
    val := s.data[key]
    s.mu.RUnlock()
    return val
}
```

## Remediation

1. **Place `defer mu.Unlock()` on the line immediately following `mu.Lock()`.** This is the canonical Go mutex pattern and is enforced by most Go style guides.

   ```go
   // SAFE: deferred unlock guarantees release on all exit paths
   func (s *Store) Set(key, value string) {
       s.mu.Lock()
       defer s.mu.Unlock()

       if key == "" {
           return // defer fires, mutex released
       }
       s.data[key] = value
   }
   ```

2. **Apply the same pattern to read locks.**

   ```go
   // SAFE: deferred RUnlock
   func (s *Store) Get(key string) string {
       s.mu.RLock()
       defer s.mu.RUnlock()
       return s.data[key]
   }
   ```

3. **For performance-critical paths** where you must unlock before the function returns (e.g., to avoid holding a lock during an I/O operation), use an anonymous function to scope the lock and defer within it.

   ```go
   // SAFE: lock scoped to a closure, unlocked before I/O
   func (s *Store) Flush() error {
       var snapshot map[string]string
       func() {
           s.mu.RLock()
           defer s.mu.RUnlock()
           snapshot = maps.Clone(s.data)
       }()
       return writeToFile(snapshot) // no lock held during I/O
   }
   ```

## References

- [CWE-667: Improper Locking](https://cwe.mitre.org/data/definitions/667.html)
- [CWE-833: Deadlock](https://cwe.mitre.org/data/definitions/833.html)
- [Go documentation – sync.Mutex](https://pkg.go.dev/sync#Mutex)
- [Effective Go – Share by communicating](https://go.dev/doc/effective_go#concurrency)
- [OWASP Go-SCP – Concurrency](https://owasp.org/www-project-go-secure-coding-practices-guide/)
- [staticcheck SA2001 – Empty critical section](https://staticcheck.dev/docs/checks/#SA2001)
- [Google Go Style Guide – Mutex patterns](https://google.github.io/styleguide/go/decisions#synchronization)
