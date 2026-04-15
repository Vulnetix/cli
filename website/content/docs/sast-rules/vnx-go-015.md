---
title: "VNX-GO-015 – sync.WaitGroup.Add() Called Inside Goroutine"
description: "Detects WaitGroup.Add() calls placed inside an anonymous goroutine body, which creates a race condition between Add() and Wait() that can cause premature completion or a panic."
---

## Overview

This rule detects `WaitGroup.Add()` calls that appear inside an anonymous goroutine (i.e., after a `go func(` launch expression). Calling `wg.Add()` inside the goroutine body introduces a race condition: if the scheduler does not begin executing the goroutine before the calling goroutine reaches `wg.Wait()`, the `Wait()` will return immediately because the counter is still zero — even though work is still pending. In the worst case the program panics with a negative WaitGroup counter when `wg.Done()` is called after `Wait()` has already returned and the counter has underflowed. This maps to CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization) and CWE-667 (Improper Locking).

The correct pattern is to call `wg.Add(n)` synchronously in the goroutine-launching code, before calling `go func()`, so that the counter is incremented before `Wait()` could possibly be called. The goroutine body then calls `defer wg.Done()` to decrement the counter when it finishes.

**Severity:** High | **CWE:** [CWE-362 – Race Condition](https://cwe.mitre.org/data/definitions/362.html), [CWE-667 – Improper Locking](https://cwe.mitre.org/data/definitions/667.html)

## Why This Matters

Race conditions in concurrency primitives are some of the hardest bugs to reproduce, because they depend on goroutine scheduling order which varies between runs, CPU counts, and system load. A `WaitGroup` misuse that works reliably on a developer laptop with one CPU may fail intermittently in production on a 64-core host or under high concurrency.

When `wg.Wait()` returns prematurely because the goroutine had not yet called `wg.Add()`, subsequent code proceeds as if all work is complete. Depending on the application, this can mean: returning an incomplete result set to a user, committing a transaction before all writes are flushed, or closing a shared resource while goroutines are still using it — causing a nil pointer dereference or use-after-close panic. None of these failures will be consistent or deterministic, making them extremely difficult to debug.

Go's race detector (`go test -race`) will often surface this pattern, but only if the racy interleaving actually occurs during the test run, which is not guaranteed.

## What Gets Flagged

```go
// FLAGGED: wg.Add() called inside the goroutine body
var wg sync.WaitGroup
for _, item := range items {
    go func(i Item) {
        wg.Add(1)           // race: may not execute before wg.Wait()
        defer wg.Done()
        process(i)
    }(item)
}
wg.Wait()
```

## Remediation

1. **Call `wg.Add(1)` before launching each goroutine.** This ensures the counter is always incremented before `Wait()` is called.

   ```go
   // SAFE: Add() called before the goroutine is launched
   var wg sync.WaitGroup
   for _, item := range items {
       wg.Add(1)
       go func(i Item) {
           defer wg.Done()
           process(i)
       }(item)
   }
   wg.Wait()
   ```

2. **When launching a known number of goroutines, call `wg.Add(n)` once before the loop.** This is more efficient and equally safe.

   ```go
   // SAFE: add total count before any goroutine is launched
   var wg sync.WaitGroup
   wg.Add(len(items))
   for _, item := range items {
       go func(i Item) {
           defer wg.Done()
           process(i)
       }(item)
   }
   wg.Wait()
   ```

3. **Consider using `golang.org/x/sync/errgroup`** for fan-out patterns that also need to propagate errors. `errgroup.Group` manages the WaitGroup internally and eliminates the Add/Done error class entirely.

   ```go
   // SAFE: errgroup handles Add/Done automatically
   g, ctx := errgroup.WithContext(context.Background())
   for _, item := range items {
       i := item
       g.Go(func() error {
           return process(ctx, i)
       })
   }
   if err := g.Wait(); err != nil {
       return err
   }
   ```

## References

- [CWE-362: Concurrent Execution Using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)
- [CWE-667: Improper Locking](https://cwe.mitre.org/data/definitions/667.html)
- [Go documentation – sync.WaitGroup](https://pkg.go.dev/sync#WaitGroup)
- [Go documentation – errgroup](https://pkg.go.dev/golang.org/x/sync/errgroup)
- [OWASP Go-SCP – Concurrency](https://owasp.org/www-project-go-secure-coding-practices-guide/)
- [Go race detector documentation](https://go.dev/doc/articles/race_detector)
- [Google Go Style Guide – WaitGroup](https://google.github.io/styleguide/go/decisions#goroutines)
