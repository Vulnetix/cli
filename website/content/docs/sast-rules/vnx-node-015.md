---
title: "VNX-NODE-015 – WebSocket Server Without Origin Verification (CSWSH)"
description: "Detect WebSocket or Socket.IO servers created without origin validation, enabling Cross-Site WebSocket Hijacking attacks."
---

## Overview

This rule flags Node.js code where a `WebSocket.Server` is created without a `verifyClient` callback, or where a Socket.IO server is configured with `cors: { origin: '*' }`. Without origin checking, a malicious website can open a WebSocket connection to the server using the victim's cookies, enabling Cross-Site WebSocket Hijacking (CSWSH). This maps to [CWE-1385: Missing Origin Validation in WebSockets](https://cwe.mitre.org/data/definitions/1385.html).

**Severity:** High | **CWE:** [CWE-1385 – Missing Origin Validation in WebSockets](https://cwe.mitre.org/data/definitions/1385.html)

## Why This Matters

WebSocket connections are not subject to the same-origin policy in the same way as XHR/fetch requests. A browser will send cookies with a WebSocket upgrade request regardless of the origin making the request. If the server does not validate the `Origin` header, an attacker's page at `evil.com` can open a WebSocket to `wss://your-app.com` using the victim's session cookies, then read and write messages as the authenticated user. This is especially dangerous for real-time applications handling financial data, chat messages, or administrative commands.

## What Gets Flagged

```javascript
// FLAGGED: WebSocket.Server without verifyClient
const wss = new WebSocket.Server({ port: 8080 });

// FLAGGED: Socket.IO with wildcard CORS origin
const io = new Server(httpServer, { cors: { origin: '*' } });
```

## Remediation

1. **Add a `verifyClient` callback that validates the Origin header:**

```javascript
// SAFE: origin validation via verifyClient
const wss = new WebSocket.Server({
  port: 8080,
  verifyClient: (info) => {
    const allowedOrigins = ['https://your-app.com'];
    return allowedOrigins.includes(info.origin);
  }
});
```

2. **For Socket.IO, restrict the CORS origin to specific domains:**

```javascript
// SAFE: explicit CORS origin
const io = new Server(httpServer, {
  cors: { origin: ['https://your-app.com'], credentials: true }
});
```

3. **Use CSRF tokens** in the WebSocket handshake as an additional defense layer.

## References

- [CWE-1385: Missing Origin Validation in WebSockets](https://cwe.mitre.org/data/definitions/1385.html)
- [OWASP WebSocket Security](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#websockets)
- [Cross-Site WebSocket Hijacking (Christian Schneider)](https://christian-schneider.net/CrossSiteWebSocketHijacking.html)
- [ws library documentation – verifyClient](https://github.com/websockets/ws/blob/HEAD/doc/ws.md#new-websocketserveroptions-callback)
- [Socket.IO CORS documentation](https://socket.io/docs/v4/handling-cors/)
- [CAPEC-62: Cross Site Request Forgery](https://capec.mitre.org/data/definitions/62.html)
