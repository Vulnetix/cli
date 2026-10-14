---
title: "VNX-KOTLIN-004 – Kotlin Unencrypted Plain Socket"
description: "Detects Kotlin plain TCP sockets (java.net.Socket, ServerSocket, NIO channels, SocketFactory.getDefault(), Ktor raw sockets) opened to or listening on a non-loopback address in a file that never applies TLS."
---

## Overview

Using `java.net.Socket` or `java.net.ServerSocket` directly for network communication sends and receives data as cleartext bytes. Any network device between the client and server — a router, a proxy, a Wi-Fi access point, or any system with access to the network path — can read or modify the data stream without detection. This is CWE-319 (Cleartext Transmission of Sensitive Information).

This rule flags Kotlin code (`.kt`, `.kts`) that opens a plain TCP socket to, or listens for, a non-loopback peer in a file that never applies TLS. It recognises `Socket(host, port, ...)` constructors, an unconnected `Socket()` or `SocketChannel.open()` later connected with `connect(InetSocketAddress(host, port))`, `SocketFactory.getDefault().createSocket(host, port)`, `SocketChannel.open(InetSocketAddress(host, port))`, `ServerSocket(port[, backlog[, address]])`, a `ServerSocket()` or `ServerSocketChannel` bound with `bind(InetSocketAddress(...))`, and Ktor raw sockets `aSocket(selector).tcp().connect(...)` / `.bind(...)`.

It does not report loopback peers and bind addresses (`localhost`, `127.x`, `::1`, `InetAddress.getLoopbackAddress()`, `getLocalHost()`, the Android emulator host `10.0.2.2`); files that apply TLS anywhere (`SSLSocketFactory`, `SSLServerSocketFactory`, `SSLContext`, `SSLSocket`, `SSLEngine`, `startHandshake`, Ktor `.tls()`, Netty `SslHandler`), which covers STARTTLS upgrades and proxies that wrap the raw socket; unconnected `Socket()` / `Socket(proxy)` objects and `Socket` subclasses; `LocalSocket`, Bluetooth, WebSocket and UDP `DatagramSocket`; test sources; comments and string literals. It does not judge whether the data sent is sensitive.

Plain sockets are appropriate only for communication that is already encrypted at a higher layer (e.g., inside an established SSH tunnel) or for local loopback connections where network interception is not a threat. Any socket that traverses a network that could be accessed by an adversary must use TLS.

**Severity:** High | **CWE:** [CWE-319 – Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

## Why This Matters

Network eavesdropping is trivially easy on many network segments. Public Wi-Fi networks are the most obvious example — passive sniffing requires no special hardware and is undetectable by the target. But internal corporate networks, cloud virtual networks, and containerised environments are also subject to interception by compromised or malicious hosts with network access.

Man-in-the-middle attacks are a step beyond passive sniffing: by intercepting and replaying or modifying the plaintext stream, an attacker can inject commands, steal session tokens, alter financial data in transit, or replace software update payloads with malicious binaries. Tools such as `mitmproxy`, `ettercap`, and `Burp Suite` make these attacks accessible to non-specialists.

Android applications using plain sockets are particularly exposed because Android devices frequently connect to public or semi-trusted Wi-Fi networks. The Android Network Security Configuration explicitly disallows cleartext traffic by default from API level 28 onwards — a plain socket bypasses this protection because it is not HTTP.

## What Gets Flagged

```kotlin
// FLAGGED: plain Socket for outbound connection
val socket = Socket("api.example.com", 8080)
val writer = PrintWriter(socket.getOutputStream(), true)
writer.println("GET /data HTTP/1.0")

// FLAGGED: plain ServerSocket for inbound connections
val server = ServerSocket(9090)
val client = server.accept()

// FLAGGED: NIO channel and Ktor raw socket
val channel = SocketChannel.open(InetSocketAddress(upstream, 6000))
val conn = aSocket(selector).tcp().connect(host, 9002)
```

Not flagged:

```kotlin
Socket("127.0.0.1", 6379)                              // loopback peer
ServerSocket(0, 50, InetAddress.getLoopbackAddress())  // loopback bind
(SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(host, 443)
```

## Remediation

1. **Use `SSLSocketFactory` for outbound client connections.** Obtain the default factory from `SSLSocketFactory.getDefault()` or configure a custom `SSLContext` for certificate pinning.

2. **Use `SSLServerSocketFactory` for inbound server sockets.**

3. **Enforce TLS 1.2 or higher** by configuring the enabled protocols on the `SSLSocket`.

4. **Consider using OkHttp, Ktor's HTTP client, or `HttpsURLConnection`** for HTTP-level communication instead of raw sockets, as these libraries handle TLS configuration and certificate validation correctly by default.

```kotlin
// SAFE: TLS client socket using SSLSocketFactory
import javax.net.ssl.SSLSocketFactory

val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
val socket = factory.createSocket("api.example.com", 443)
val sslSocket = socket as javax.net.ssl.SSLSocket
sslSocket.enabledProtocols = arrayOf("TLSv1.2", "TLSv1.3")
sslSocket.startHandshake()
val writer = PrintWriter(sslSocket.outputStream, true)
```

```kotlin
// SAFE: TLS server socket
import javax.net.ssl.SSLServerSocketFactory

val factory = SSLServerSocketFactory.getDefault() as SSLServerSocketFactory
val serverSocket = factory.createServerSocket(9443) as javax.net.ssl.SSLServerSocket
serverSocket.needClientAuth = false
val client = serverSocket.accept()
```

## References

- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [Android Developer Security Guide: Network Security](https://developer.android.com/privacy-and-security/security-tips#networking)
- [Android Network Security Configuration](https://developer.android.com/privacy-and-security/network-security-config)
- [Kotlin Networking with OkHttp](https://square.github.io/okhttp/)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
