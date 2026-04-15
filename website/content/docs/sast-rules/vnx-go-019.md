---
title: "VNX-GO-019 – Go Server Binding to All Interfaces (0.0.0.0)"
description: "Detects net.Listen, tls.Listen, or http.ListenAndServe calls that bind to 0.0.0.0 or all interfaces with :PORT notation, exposing the service on every network interface including public ones."
---

## Overview

This rule detects Go server bindings using `net.Listen()`, `tls.Listen()`, or `http.ListenAndServe()`/`http.ListenAndServeTLS()` with an address of `0.0.0.0:PORT`, `:PORT`, or an empty host component. Binding to `0.0.0.0` causes the service to accept connections on every network interface attached to the host — including public-facing interfaces, cloud instance metadata interfaces, and container bridge networks. If the service handles sensitive data, exposes administrative functionality, or lacks authentication, this creates an unnecessarily broad attack surface. This maps to CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).

Many services are intended to be accessed only from localhost (a metrics endpoint, a debug pprof handler, an internal management API) or only from a specific private network interface. Binding such services to `0.0.0.0` exposes them to any host that can route to the machine. In containerised and cloud environments, this is frequently broader than the developer intends.

**Severity:** Medium | **CWE:** [CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

## Why This Matters

Go's `net/http/pprof` debug handlers, Prometheus metrics endpoints, and internal health endpoints are routinely bound to `0.0.0.0` during development and accidentally left there in production. These endpoints can expose profiling data, goroutine stack traces, heap dumps, and application metrics that provide significant reconnaissance value to an attacker. CAPEC-1 (Accessing/Intercepting/Modifying HTTP Communication) and MITRE ATT&CK T1046 (Network Service Discovery) apply when an exposed service is discovered and enumerated.

In cloud environments, binding to `0.0.0.0` in a container may expose the service through the host's external IP, a load balancer, or a NodePort depending on how networking is configured. A service that was intended to be internal-only becomes publicly accessible. Several real-world incidents — including exposed Kubernetes dashboard and etcd instances — have followed this pattern.

## What Gets Flagged

```go
// FLAGGED: binding to all interfaces on a fixed port
ln, err := net.Listen("tcp", "0.0.0.0:8080")

// FLAGGED: :PORT shorthand binds to all interfaces
http.ListenAndServe(":9090", metricsHandler)

// FLAGGED: pprof debug server exposed on all interfaces
go http.ListenAndServe(":6060", nil) // pprof registered via import
```

## Remediation

1. **Bind to `127.0.0.1` for services intended to be localhost-only**, such as pprof, metrics, or internal debug endpoints.

   ```go
   // SAFE: pprof debug server restricted to localhost
   go func() {
       if err := http.ListenAndServe("127.0.0.1:6060", nil); err != nil {
           log.Printf("pprof server error: %v", err)
       }
   }()
   ```

2. **Bind to a specific private interface address** for services that must be reachable within a cluster but not from public networks.

   ```go
   // SAFE: bind to a specific internal address
   ln, err := net.Listen("tcp", "10.0.0.1:8080")
   if err != nil {
       return fmt.Errorf("listen failed: %w", err)
   }
   ```

3. **Make the bind address configurable** and default to localhost in the configuration. Require an explicit operator decision to expose the service more broadly.

   ```go
   // SAFE: configurable bind address, safe default
   addr := cfg.BindAddr
   if addr == "" {
       addr = "127.0.0.1:8080"
   }
   srv := &http.Server{Addr: addr, Handler: mux}
   if err := srv.ListenAndServe(); err != nil {
       return err
   }
   ```

4. **For public-facing services that must bind to `0.0.0.0`**, ensure authentication and TLS are enforced at the application level and document the binding decision explicitly.

## References

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CAPEC-1: Accessing/Intercepting/Modifying HTTP Communication](https://capec.mitre.org/data/definitions/1.html)
- [MITRE ATT&CK T1046 – Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [Go documentation – net.Listen](https://pkg.go.dev/net#Listen)
- [Go pprof security considerations](https://pkg.go.dev/net/http/pprof)
- [OWASP Go-SCP – Network security](https://owasp.org/www-project-go-secure-coding-practices-guide/)
- [CIS Kubernetes Benchmark – API server binding](https://www.cisecurity.org/benchmark/kubernetes)
