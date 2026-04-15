---
title: "VNX-SEC-030 – Google OAuth Client Secret Hardcoded"
description: "Detect Google OAuth 2.0 client secrets (GOCSPX- prefix) hardcoded in source code, which enable application impersonation and OAuth token theft when combined with the corresponding client ID."
---

## Overview

This rule flags source files containing a string matching the Google OAuth 2.0 client secret format: the prefix `GOCSPX-` followed by 28 alphanumeric, hyphen, or underscore characters. A Google OAuth client secret is the credential used alongside a client ID to authenticate an application's identity during the OAuth 2.0 authorization code flow. Together they identify the registered application to Google's authorization servers.

When a client secret is hardcoded in source code, an attacker who obtains it can impersonate the legitimate application in OAuth flows, redirect users to attacker-controlled endpoints through the authorization code flow, and potentially steal access and refresh tokens issued for the application. Depending on the OAuth scopes the application requests, this may expose Google Drive files, Gmail messages, Google Calendar events, or other sensitive user data.

This rule corresponds to [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html).

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Google OAuth applications are frequently used for social login and for accessing Google Workspace APIs on behalf of users or service accounts. The client secret is the application's proof of identity in the three-legged OAuth flow. An attacker who has both the client ID (which is semi-public) and the client secret can construct a malicious OAuth flow that uses the victim application's identity.

A practical attack involves the attacker registering a redirect URI on their own infrastructure, then constructing an authorization URL that appears to come from the legitimate application. Users who follow the link are asked to grant permissions to what appears to be the legitimate service. The authorization code issued by Google is sent to the attacker's redirect URI, and the attacker exchanges it for access tokens using the stolen client secret.

Even without user-facing attacks, a leaked client secret enables an attacker to make API calls that consume the application's quota, potentially disrupting service availability, or to enumerate the application's OAuth configuration for further attacks.

## What Gets Flagged

The rule matches any file (excluding lock files, checksums, and minified assets) containing a string that begins with `GOCSPX-` followed by 28 characters.

```json
// FLAGGED: client secret in a credentials.json file committed to git
{
  "web": {
    "client_id": "123456789-abcdefgh.apps.googleusercontent.com",
    "client_secret": "GOCSPX-aBcDeFgHiJkLmNoPqRsTuVwXyZ0"
  }
}
```

## Remediation

1. **Rotate the client secret immediately.** Go to [console.cloud.google.com/apis/credentials](https://console.cloud.google.com/apis/credentials), find the OAuth 2.0 client, and generate a new secret. The old secret becomes invalid immediately.

2. **Store the secret in a secrets manager or environment variable.** Never commit `client_secret.json` or `credentials.json` files to version control. Use `.gitignore` to exclude them:

```bash
# SAFE: load credentials from environment variable
CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
```

3. **Add credentials files to `.gitignore`.** Prevent future accidental commits of Google credential files:

```gitignore
# .gitignore — prevent credential file commits
credentials.json
client_secret*.json
google_credentials.json
```

4. **For server-side applications, use service accounts with Workload Identity.** When running on Google Cloud, use a service account with the minimum required IAM roles, authenticated via Workload Identity Federation rather than a long-lived key or secret.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [Google Identity – OAuth 2.0 client credentials](https://developers.google.com/identity/protocols/oauth2)
- [Google Cloud – API credentials best practices](https://cloud.google.com/docs/authentication/api-keys#securing_an_api_key)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [Google Cloud – Secret Manager](https://cloud.google.com/secret-manager/docs)
