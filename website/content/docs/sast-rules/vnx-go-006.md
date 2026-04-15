---
title: "VNX-GO-006 – Go Server-Side Request Forgery"
description: "Detect Go HTTP handlers that use user-controlled input to construct outbound HTTP requests, enabling server-side request forgery attacks against internal services and cloud metadata endpoints."
---

## Overview

This rule detects Go HTTP handlers that pass `r.FormValue()` or `r.URL.Query()` values directly to `http.Get`, `http.Post`, or `http.NewRequest` without validating the destination. Server-side request forgery (SSRF) allows an attacker to make your server perform HTTP requests to destinations of their choosing — typically internal services that are not exposed to the internet. This maps to [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html).

**Severity:** High | **CWE:** [CWE-918 – Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)

## Why This Matters

In cloud environments, SSRF is a critical vulnerability class because virtually every major cloud platform exposes an instance metadata service at a well-known IP address (`169.254.169.254` on AWS, GCP, and Azure). By making your server fetch that URL, an attacker can retrieve IAM credentials, account identifiers, and bootstrap tokens — granting them access to your entire cloud infrastructure without any other foothold. Beyond the metadata service, SSRF enables attackers to probe and interact with internal microservices, databases, and management interfaces that are firewalled from the public internet. It can also be used to bypass IP-based allowlists, as the requests originate from your trusted server.

## What Gets Flagged

The rule fires when `http.Get`, `http.Post`, or `http.NewRequest` is called with a URL argument taken directly from `r.FormValue()` or `r.URL.Query()`.

```go
// FLAGGED: user-supplied URL fetched server-side
func fetchHandler(w http.ResponseWriter, r *http.Request) {
    target := r.FormValue("url")
    resp, err := http.Get(target)
    // Attacker sends: url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
    // Server fetches cloud credentials and returns them
    if err == nil {
        io.Copy(w, resp.Body)
    }
}
```

```go
// FLAGGED: user-supplied URL in http.NewRequest
func proxyHandler(w http.ResponseWriter, r *http.Request) {
    dest := r.URL.Query().Get("dest")
    req, _ := http.NewRequest("GET", dest, nil)
    client := &http.Client{}
    resp, _ := client.Do(req)
    io.Copy(w, resp.Body)
}
```

## Remediation

1. **Validate the destination URL against an allowlist of permitted hosts.** Parse the URL and check that the host matches an explicit list of allowed external services. Reject anything else, including private IP ranges.

```go
import (
    "fmt"
    "net"
    "net/http"
    "net/url"
)

var allowedHosts = map[string]bool{
    "api.trusted-partner.com": true,
    "cdn.example.com":         true,
}

func isAllowedURL(rawURL string) error {
    u, err := url.Parse(rawURL)
    if err != nil {
        return fmt.Errorf("invalid URL")
    }
    if u.Scheme != "https" {
        return fmt.Errorf("only HTTPS is permitted")
    }
    host := u.Hostname()
    if !allowedHosts[host] {
        return fmt.Errorf("host %q is not in the allowlist", host)
    }
    return nil
}

// SAFE: allowlist validation before outbound request
func fetchHandler(w http.ResponseWriter, r *http.Request) {
    target := r.FormValue("url")
    if err := isAllowedURL(target); err != nil {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    resp, err := http.Get(target)
    if err != nil {
        http.Error(w, "upstream error", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()
    io.Copy(w, resp.Body)
}
```

2. **Block private and loopback IP ranges.** After DNS resolution, verify that the resolved IP address is not in a private or reserved range (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `::1`). Use a custom `http.Transport` with a dial hook.

```go
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
    host, port, _ := net.SplitHostPort(addr)
    ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
    if err != nil {
        return nil, err
    }
    for _, ip := range ips {
        if isPrivateIP(ip.IP) {
            return nil, fmt.Errorf("request to private IP %s is forbidden", ip.IP)
        }
    }
    return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(host, port))
}
```

3. **Disable redirects or validate them.** SSRF attacks sometimes chain redirects to reach internal resources. Configure your `http.Client` to disallow redirects or re-validate the destination on each redirect.

## References

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Go net/http package documentation](https://pkg.go.dev/net/http)
- [Go net/url package documentation](https://pkg.go.dev/net/url)
- [AWS SSRF and IMDSv2 mitigation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [CAPEC-664: Server-Side Request Forgery](https://capec.mitre.org/data/definitions/664.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
