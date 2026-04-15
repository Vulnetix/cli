---
title: "VNX-SEC-005 – GCP API Key"
description: "Detects hardcoded Google Cloud Platform API keys (AIza prefix) in source code, which can be used to access billable GCP services and exfiltrate data."
---

## Overview

This rule detects GCP API keys matching the `AIza[0-9A-Za-z\-_]{35}` pattern in source files. GCP API keys are simple credentials used to call Google APIs such as Maps, Places, YouTube, Vision, and Translation. Unlike service account keys, they do not authenticate as a specific identity, but they do authorize API calls that may incur costs or expose data. An unrestricted GCP API key found in a public repository can lead to significant billing fraud and data exfiltration.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

GCP API keys have been abused extensively to run up fraudulent bills against the key owner's account. There are documented cases of developers committing Google Maps API keys to public GitHub repositories only to find tens of thousands of dollars in unexpected charges days later as bots discovered and exploited the keys for geocoding, translation, or other paid API calls. Some GCP APIs also expose sensitive data — a leaked Vision API key can be used to analyze images at your expense, or a Firebase key may expose real-time database access.

Because GCP API keys do not expire and are not tied to a user identity, detecting their unauthorized use requires careful review of GCP Console logs. The key remains usable until it is explicitly deleted or restricted.

## What Gets Flagged

Any source line containing a string matching `AIza` followed by 35 alphanumeric, hyphen, or underscore characters.

```python
# FLAGGED: hardcoded GCP API key
import googlemaps

gmaps = googlemaps.Client(key='AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')
result = gmaps.geocode('Sydney, Australia')
```

```javascript
// FLAGGED: key embedded in JavaScript
const apiKey = 'AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
const map = new google.maps.Map(document.getElementById('map'), {
  zoom: 10,
  center: { lat: -33.8688, lng: 151.2195 }
});
```

## Remediation

1. **Restrict or delete the exposed key immediately.** In the GCP Console go to APIs & Services → Credentials → find the key → Edit. Either delete it and create a new one, or apply restrictions immediately before creating a replacement.

2. **Apply key restrictions to any new keys.** GCP allows you to restrict keys by:
   - **Application restrictions:** Limit to specific HTTP referrers, IP addresses, Android apps, or iOS apps.
   - **API restrictions:** Limit to only the specific APIs the key needs (e.g., Maps JavaScript API only).

```bash
# Restrict key to specific IP addresses via gcloud
gcloud services api-keys update KEY_ID \
  --allowed-ips=203.0.113.0/24
```

3. **Remove from source code.** Load the key from environment variables instead:

```python
# SAFE: load from environment variable
import os
import googlemaps

gmaps = googlemaps.Client(key=os.environ['GOOGLE_MAPS_API_KEY'])
```

4. **Use Application Default Credentials (ADC) as the proper alternative.** For server-side GCP services (Vertex AI, Cloud Storage, BigQuery), ADC authenticates automatically using the service account attached to the compute resource — no API key or credentials file needed:

```python
# SAFE: ADC for GCP server-side APIs — no key required
from google.cloud import storage

client = storage.Client()  # Uses ADC automatically
bucket = client.bucket('my-bucket')
```

5. **Check GCP audit logs** for unauthorized API usage. In the Console go to Logging → Log Explorer and filter for the API key ID. Look for calls from unexpected IP addresses or with unusual request volumes.

6. **Scan git history** for the exposed key:

```bash
gitleaks detect --source . --verbose
git filter-repo --replace-text <(echo 'AIzaSyDxxx==>REDACTED_GCP_KEY')
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [GCP: API key best practices](https://cloud.google.com/docs/authentication/api-keys)
- [GCP: Restricting API keys](https://cloud.google.com/docs/authentication/api-keys#restricting_an_api_key)
- [GCP: Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials)
- [OWASP: Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
