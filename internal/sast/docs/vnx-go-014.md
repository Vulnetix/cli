---
title: "VNX-GO-014 – sync.Mutex Lock() Without Deferred Unlock()"
description: "Detects sync.Mutex.Lock() or sync.RWMutex.RLock() calls that can leave the mutex held: the function returns, panics or continues its loop on a path that never reaches an Unlock, or never unlocks and no other function releases it, and no deferred Unlock covers it."
---

## Overview

This rule detects calls to `sync.Mutex.Lock()` or `sync.RWMutex.RLock()` that can be left held: no deferred `Unlock`/`RUnlock` covers the lock, and the function either never unlocks or can return or panic first. When a mutex is locked without a deferred unlock, any panic or early return between the lock and the eventual unlock call leaves the mutex permanently held. Subsequent goroutines that attempt to acquire the same lock will block indefinitely, causing a goroutine leak and a denial-of-service condition. This maps to CWE-667 (Improper Locking) and CWE-833 (Deadlock).

The idiomatic Go pattern for safe mutex usage is to call `defer mu.Unlock()` immediately after `mu.Lock()` on the next line. This guarantees that the unlock occurs regardless of how the function exits — whether through a normal return, an error return, or a panic that is recovered higher up the stack. Any pattern that deviates from this — such as conditionally unlocking, or unlocking only on the happy path — is a source of latent deadlock bugs.

The rule follows each lock to the end of its function. It reports the lock when there is no deferred unlock for that receiver and either the function never unlocks it, or a `return` or `panic` is reached before the first matching `Unlock`. A short critical section that locks, does its work and unlocks with nothing that can exit in between is correct and is not reported, and neither is a lock followed by any `defer`red unlock (or a `defer func() {` block) further down. Wrapper methods named `Lock`/`RLock` (whose caller owns the unlock) and test files are skipped. There is no full data-flow analysis: a panic raised by a call in the middle of a critical section is not seen.

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

// NOT FLAGGED: a short critical section with no exit between Lock and Unlock
func (s *Store) Get(key string) string {
    s.mu.RLock()
    val := s.data[key]
    s.mu.RUnlock()
    return val
}

// FLAGGED: a return while the lock is held
func (s *Store) Lookup(key string) (string, error) {
    s.mu.RLock()
    val, ok := s.data[key]
    if !ok {
        return "", ErrMissing // RUnlock never runs on this path
    }
    s.mu.RUnlock()
    return val, nil
}

// FLAGGED: the first error path unlocks, the second forgets
func (l *Ledger) Withdraw(id string, amt int64) error {
    l.mu.Lock()
    bal, ok := l.balances[id]
    if !ok {
        l.mu.Unlock()
        return ErrUnknown
    }
    if bal < amt {
        return ErrInsufficient // still locked
    }
    l.balances[id] = bal - amt
    l.mu.Unlock()
    return nil
}

// FLAGGED: a lock taken inside a loop, skipped with continue
for _, d := range docs {
    mu.Lock()
    if d.ID == "" {
        continue // the next iteration's Lock deadlocks
    }
    byID[d.ID] = d
    mu.Unlock()
}
```

Not reported: an `Unlock` deferred anywhere in the function (or a `defer func() {` whose body unlocks or releases; a deferred `recover()` or log line does not count), a `return` inside a func literal or a `continue` of a loop opened inside the critical section, a lock re-acquired after the function released it (the `sync.Cond` unlock, wait, lock shape), a wrapper whose name is `Lock`, `RLock`, `Acquire`, `Enter` or `Begin...`, and a lock whose release half is another function in the same file that unlocks the same field without locking it (`NewTxn`/`Commit`, `start`/`end`). Test files are skipped.

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
