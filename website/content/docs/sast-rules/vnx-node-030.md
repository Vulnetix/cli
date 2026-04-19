---
title: "VNX-NODE-030 – TURN server allowing reserved IP addresses"
description: "Detects WebRTC TURN server IP filtering logic in Node.js that may permit connections to reserved or private IP ranges, enabling SSRF via WebRTC relay."
---

## Overview

This rule detects IP filtering logic in JavaScript files associated with WebRTC TURN server implementations where reserved IP address literals (`127.0.0.1`, `localhost`, `10.x.x.x`, `192.168.x.x`, `172.16–31.x.x`, `0.0.0.0`) appear in conditions or configuration that governs which relay targets are permitted. A TURN (Traversal Using Relays around NAT) server proxies WebRTC media and data traffic between peers; if it can be induced to relay connections to internal network addresses, it becomes a powerful Server-Side Request Forgery (SSRF) pivot. This is classified as CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor).

TURN servers that do not enforce a blocklist of reserved IP ranges can be abused by any authenticated WebRTC client to probe and relay traffic to internal hosts — including the host itself (localhost), private cloud services, Kubernetes API servers, and instance metadata endpoints. The attack leverages the TURN protocol's relay semantics: the client asks the TURN server to allocate a relay address and then sends data to an arbitrary peer IP, causing the server to originate outbound connections from its own network interface.

**Severity:** Medium | **CWE:** [CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html) | **OWASP:** [A10:2021 – Server-Side Request Forgery (SSRF)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/) | **CAPEC:** [CAPEC-200 – Removal of filters](https://capec.mitre.org/data/definitions/200.html) | **ATT&CK:** [T1046](https://attack.mitre.org/techniques/T1046/)

## Why This Matters

SSRF via TURN relay is a documented attack class that has affected open-source TURN server projects and custom implementations alike. It is particularly dangerous in cloud environments because the TURN server can reach the instance metadata service (`169.254.169.254`) and retrieve temporary IAM credentials, which then grant the attacker the cloud permissions of the server's service identity. In Kubernetes environments, the TURN server may be able to reach the API server or other pods on the cluster network.

Unlike traditional SSRF that requires an HTTP endpoint, TURN-based SSRF also works for arbitrary TCP and UDP protocols, enabling port scanning, service fingerprinting, and data exfiltration from internal services that do not speak HTTP. The attack surface is as wide as all hosts reachable from the TURN server's network interface.

## What Gets Flagged

```javascript
// FLAGGED: allowlist logic that may pass reserved IPs
function isAllowedPeer(ip) {
  // Missing: no check for 127.x, 10.x, 192.168.x, 172.16-31.x
  return ip !== '0.0.0.0';
}

// FLAGGED: TURN relay target checked only against localhost literal
if (peerAddress !== 'localhost' && peerAddress !== '127.0.0.1') {
  turn.relay(peerAddress, port); // still permits 10.x, 192.168.x, etc.
}

// FLAGGED: configuration object with no reserved-IP filter
const turnConfig = {
  listeningIps: ['0.0.0.0'],
  // no peerIpFilter or blocklist configured
};
```

## Remediation

1. Implement an explicit blocklist of all reserved IP ranges (RFC 1918, loopback, link-local, and unspecified) that is applied to every relay target before the connection is established.
2. Use an established library (e.g., `ip-range-check`, `netmask`) to test candidate IPs against the reserved ranges rather than string-matching individual literals.
3. Validate that the resolved IP of hostname-based peer addresses is also checked against the blocklist — DNS rebinding can bypass hostname-level checks.
4. Configure your TURN server (coturn, node-turn, etc.) using its built-in `denied-peer-ip` or equivalent configuration directive to enforce the blocklist at the server level.

```javascript
// SAFE: comprehensive reserved-IP blocklist applied before relaying
const ipRangeCheck = require('ip-range-check');

const BLOCKED_RANGES = [
  '0.0.0.0/8',         // unspecified
  '10.0.0.0/8',        // RFC 1918 private
  '100.64.0.0/10',     // Shared Address Space
  '127.0.0.0/8',       // loopback
  '169.254.0.0/16',    // link-local (includes cloud metadata)
  '172.16.0.0/12',     // RFC 1918 private
  '192.168.0.0/16',    // RFC 1918 private
  '::1/128',           // IPv6 loopback
  'fc00::/7',          // IPv6 unique local
  'fe80::/10',         // IPv6 link-local
];

function isRelayAllowed(ip) {
  if (ipRangeCheck(ip, BLOCKED_RANGES)) {
    return false; // deny reserved ranges
  }
  return true;
}

turn.on('allocateRequest', (req, res) => {
  const peerIp = req.peerAddress;
  if (!isRelayAllowed(peerIp)) {
    return res.reject(403, 'Peer address not allowed');
  }
  res.accept();
});
```

## References

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [RFC 5766 — Traversal Using Relays around NAT (TURN)](https://datatracker.ietf.org/doc/html/rfc5766)
- [RFC 1918 — Address Allocation for Private Internets](https://datatracker.ietf.org/doc/html/rfc1918)
- [WebRTC SSRF via TURN — Bishop Fox Research](https://bishopfox.com/blog/webrtc-turn-server-ssrf)
- [coturn — denied-peer-ip configuration](https://github.com/coturn/coturn/blob/master/examples/etc/turnserver.conf)
