---
title: "VNX-NODE-015 – WebSocket Server Without Origin Verification (CSWSH)"
description: "Reports a ws WebSocket server created without a verifyClient callback in a file that never checks the Origin header, and a Socket.IO server whose cors origin is '*' or true (or origins '*:*') without allowRequest, both of which allow Cross-Site WebSocket Hijacking."
---

## Overview

This rule detects `WebSocket.Server` instantiation without a `verifyClient` callback, and Socket.IO servers configured with `cors: { origin: '*' }`. Both patterns make the server vulnerable to Cross-Site WebSocket Hijacking (CSWSH), where a malicious web page silently opens a WebSocket connection using the victim's browser credentials (cookies, HTTP authentication) and reads or controls the authenticated session. This is CWE-1385 (Missing Origin Validation in WebSockets).

**Severity:** High | **CWE:** [CWE-1385 – Missing Origin Validation in WebSockets](https://cwe.mitre.org/data/definitions/1385.html) | **CAPEC:** [CAPEC-62 – Cross-Site Request Forgery](https://capec.mitre.org/data/definitions/62.html)

## Why This Matters

Unlike regular HTTP requests, WebSocket upgrade requests include cookies and HTTP authentication headers automatically. The WebSocket API does not enforce the Same-Origin Policy at the protocol level — browsers allow any page to initiate a WebSocket connection to any server. This means a malicious site at `https://evil.example` can open a WebSocket to `wss://bank.example/ws` and the victim's session cookie will be included in the upgrade request.

If the server does not validate the `Origin` header, the attacker receives a fully authenticated WebSocket session. They can issue commands, read data feeds, or subscribe to private channels as the victim — all silently in the background with no user interaction.

The `ws` library's `WebSocket.Server` does **not** perform origin validation by default. The `verifyClient` option must be explicitly provided. Similarly, Socket.IO has no safe default for origins in server-side configurations and requires an explicit allowlist. Setting `cors: { origin: '*' }` is equivalent to disabling origin validation entirely.

**OWASP ASVS v4:** V13.5.2 — Verify that WebSocket connections are authenticated and only accept connections from the expected origins.

## What Gets Flagged

```javascript
// FLAGGED: no verifyClient and no origin check in the file
const wss = new WebSocket.Server({ port: 8080 });
const live = new WebSocketServer({ server, path: '/live' });

// FLAGGED: Socket.IO accepts every origin
const io = new Server(httpServer, {
  cors: {
    origin: '*',
    credentials: true,
  },
});
```

Not flagged: `verifyClient: ({ origin }) => ALLOWED.has(origin)`, a `noServer` server whose `upgrade` handler checks `req.headers.origin`, Socket.IO with a list of origins, Express `cors({ origin: '*' })` middleware, browser `new WebSocket(...)` clients and test files.

## Remediation

1. **Add a `verifyClient` callback to `WebSocket.Server`** that validates the `Origin` header against an explicit allowlist. This is **not the default** — it must be set explicitly:

   ```javascript
   const WebSocket = require('ws');

   const ALLOWED_ORIGINS = new Set([
     'https://app.example.com',
     'https://www.example.com',
   ]);

   const wss = new WebSocket.Server({
     port: 8080,
     verifyClient: ({ origin }, callback) => {
       if (!origin || !ALLOWED_ORIGINS.has(origin)) {
         callback(false, 403, 'Forbidden');
         return;
       }
       callback(true);
     },
   });
   ```

2. **Configure Socket.IO with an explicit origin allowlist** rather than a wildcard. The `credentials: true` option is required when using cookie-based authentication:

   ```javascript
   const { Server } = require('socket.io');

   const io = new Server(httpServer, {
     cors: {
       origin: ['https://app.example.com', 'https://www.example.com'],
       methods: ['GET', 'POST'],
       credentials: true,
     },
   });
   ```

3. **Require token-based authentication during the WebSocket handshake**, independent of cookie session state. Validate a JWT before accepting any connection:

   ```javascript
   const jwt = require('jsonwebtoken');

   io.use((socket, next) => {
     const token = socket.handshake.auth.token;
     try {
       socket.data.user = jwt.verify(token, process.env.JWT_SECRET);
       next();
     } catch {
       next(new Error('Authentication error'));
     }
   });
   ```

4. **For the `ws` library, also validate inside the `connection` event** as a second layer if origin checks cannot be performed at upgrade time:

   ```javascript
   wss.on('connection', (ws, req) => {
     const origin = req.headers.origin;
     if (!ALLOWED_ORIGINS.has(origin)) {
       ws.close(1008, 'Forbidden');
       return;
     }
     // handle authenticated connection
   });
   ```

5. **Serve all WebSocket endpoints over TLS (`wss://`).** Plain `ws://` is vulnerable to network-level hijacking in addition to CSWSH.

## References

- [CWE-1385: Missing Origin Validation in WebSockets](https://cwe.mitre.org/data/definitions/1385.html)
- [CAPEC-62: Cross-Site Request Forgery](https://capec.mitre.org/data/definitions/62.html)
- [OWASP Testing for WebSockets](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets)
- [OWASP ASVS v4 – V13.5.2 WebSocket Authentication](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [ws – verifyClient option](https://github.com/websockets/ws/blob/master/doc/ws.md#new-websocketserveroptions-callback)
- [Socket.IO – Handling CORS](https://socket.io/docs/v4/handling-cors/)
- [PortSwigger: Cross-site WebSocket hijacking](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking)
- [MITRE ATT&CK T1185 – Browser Session Hijacking](https://attack.mitre.org/techniques/T1185/)
