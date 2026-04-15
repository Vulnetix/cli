---
title: "VNX-RUBY-010 – OpenSSL Certificate Verification Disabled (VERIFY_NONE)"
description: "Detect use of OpenSSL::SSL::VERIFY_NONE in Ruby code, which disables TLS certificate chain validation and exposes all connections to man-in-the-middle interception."
---

## Overview

This rule flags any occurrence of `OpenSSL::SSL::VERIFY_NONE` in Ruby source files. This constant, when assigned to the `verify_mode` attribute of an `OpenSSL::SSL::SSLContext`, instructs Ruby's OpenSSL bindings to skip all certificate chain validation. The TLS handshake completes regardless of whether the server's certificate is expired, self-signed, issued by an untrusted authority, or belongs to a completely different hostname.

The practical consequence is that the "S" in HTTPS provides no security guarantee. While the connection is still encrypted, the application has no assurance about the identity of the remote party. An attacker positioned on the network path — on a shared Wi-Fi network, at a compromised router, or via DNS poisoning — can terminate the TLS connection, present a fraudulent certificate, and transparently proxy all traffic. Neither the application nor its users will observe anything unusual.

This rule corresponds to [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html).

**Severity:** High | **CWE:** [CWE-295 – Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

## Why This Matters

`VERIFY_NONE` is often introduced as a quick fix for SSL certificate errors during development — a self-signed cert, an expired cert in a staging environment, or a corporate proxy with its own root CA that is not in the system trust store. The fix makes the error disappear, and the code is sometimes committed and deployed to production without the developer realising the implication.

In production, the consequences can be severe. API credentials, OAuth tokens, webhook payloads, and user personal data transmitted over the "secured" connection are readable by anyone on the network path. For applications that call payment processors, identity providers, or internal microservices, credential theft can lead to account takeover, financial fraud, or full infrastructure compromise.

The Ruby ecosystem makes `VERIFY_PEER` the correct and default option for a reason: it enforces that the certificate chain is valid, trusted, and matches the hostname. Developers encountering certificate errors should fix the underlying certificate problem rather than disabling verification.

## What Gets Flagged

The rule matches `.rb` files containing the string `VERIFY_NONE`.

```ruby
# FLAGGED: disables all certificate validation
http = Net::HTTP.new("api.example.com", 443)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_NONE

# FLAGGED: disabled via SSLContext
ctx = OpenSSL::SSL::SSLContext.new
ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ctx)

# FLAGGED: disabled in Faraday / HTTP client configuration
conn = Faraday.new(ssl: { verify: false }) # often paired with VERIFY_NONE
ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
```

## Remediation

1. **Use `OpenSSL::SSL::VERIFY_PEER` (the default) for all production connections.** This is the standard setting and requires no extra configuration when the server has a valid, CA-signed certificate:

```ruby
# SAFE: explicit VERIFY_PEER (also the default)
http = Net::HTTP.new("api.example.com", 443)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_PEER
```

2. **If a custom CA is required (e.g., internal PKI), provide the CA bundle.** Do not disable verification; instead, supply the trusted CA certificate so that validation can succeed:

```ruby
# SAFE: trust a custom CA bundle without disabling verification
ctx = OpenSSL::SSL::SSLContext.new
ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
ctx.ca_file = "/etc/ssl/certs/internal-ca.crt"
```

3. **Fix underlying certificate issues rather than suppressing them.** If the error is a hostname mismatch or an expired certificate in staging, fix the certificate. Use tools like Let's Encrypt for free, automatically renewing certificates.

4. **Audit all HTTP client configurations.** Search for `verify: false`, `verify_ssl: false`, and `VERIFY_NONE` across the codebase. High-level clients like Faraday, HTTParty, and RestClient all have their own certificate verification settings that must also be checked.

## References

- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CAPEC-94: Man in the Middle Attack](https://capec.mitre.org/data/definitions/94.html)
- [Ruby OpenSSL::SSL::SSLContext documentation](https://ruby-doc.org/stdlib/libdoc/openssl/rdoc/OpenSSL/SSL/SSLContext.html)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [OWASP Ruby on Rails Security Guide – TLS](https://guides.rubyonrails.org/security.html#injection)
- [Let's Encrypt – Free TLS Certificates](https://letsencrypt.org/)
