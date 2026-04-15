---
title: "VNX-SEC-019 – GCP Service Account Key"
description: "Detects Google Cloud service account key JSON files committed to source code, which grant broad GCP resource access and should never be stored in version control."
---

## Overview

This rule detects GCP service account key JSON files by matching the string `"type": "service_account"` in source files. Service account keys are downloaded JSON credentials files that authenticate a service account to Google Cloud APIs. They contain a private key, the service account email, and the project ID. Unlike GCP API keys (VNX-SEC-005), service account keys authenticate as an IAM identity with a defined set of IAM roles — often including sensitive permissions like `roles/storage.admin`, `roles/cloudsql.client`, or even `roles/owner`.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Service account keys are among the most powerful credentials in GCP because they represent a machine identity with persistent, long-lived access. Unlike user credentials that expire or can be protected with 2FA, a service account key file works indefinitely until explicitly revoked. If a key with broad IAM permissions is leaked, an attacker can access all resources the service account is authorized to use — across any GCP project where the service account has been granted roles.

Google Cloud's own best practices recommend against service account keys entirely for workloads that run on GCP, because Workload Identity Federation and attached service accounts provide the same functionality without any credential files. The Google Cloud Security Team considers service account key files to be the highest-priority credential to keep out of source control.

## What Gets Flagged

```json
// FLAGGED: GCP service account key JSON file committed to repository
{
  "type": "service_account",
  "project_id": "my-project-123456",
  "private_key_id": "abc123",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n",
  "client_email": "my-service-account@my-project.iam.gserviceaccount.com",
  "client_id": "123456789",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token"
}
```

```python
# FLAGGED: path to service account key file hardcoded
from google.oauth2 import service_account

credentials = service_account.Credentials.from_service_account_file(
    'service-account-key.json',
    scopes=['https://www.googleapis.com/auth/cloud-platform']
)
```

## Remediation

1. **Revoke the service account key immediately.** In the GCP Console go to IAM & Admin → Service Accounts → select the service account → Keys tab → Delete the exposed key. Or via CLI:

```bash
gcloud iam service-accounts keys delete KEY_ID \
  --iam-account=SERVICE_ACCOUNT_EMAIL
```

2. **Review GCP audit logs** for API activity by the service account during the exposure window. In Cloud Console go to Logging → Log Explorer and filter by the service account email:

```
protoPayload.authenticationInfo.principalEmail="my-sa@my-project.iam.gserviceaccount.com"
```

3. **Eliminate the need for service account key files entirely** using Workload Identity Federation. For GKE workloads:

```yaml
# SAFE: GKE Workload Identity — no key file needed
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: default
  annotations:
    iam.gke.io/gcp-service-account: my-sa@my-project.iam.gserviceaccount.com
```

For Cloud Run, Cloud Functions, and Compute Engine, simply attach the service account to the resource — the Google metadata server provides credentials automatically with Application Default Credentials (ADC):

```python
# SAFE: ADC on GCP-hosted workloads — no credentials file needed
from google.cloud import storage

# Automatically uses the attached service account via ADC
client = storage.Client()
```

4. **For workloads running outside GCP** (GitHub Actions, on-premises), use Workload Identity Federation instead of key files:

```yaml
# SAFE: GitHub Actions with Workload Identity Federation (no key file)
- name: Authenticate to GCP
  uses: google-github-actions/auth@v2
  with:
    workload_identity_provider: 'projects/123/locations/global/workloadIdentityPools/my-pool/providers/my-provider'
    service_account: 'my-sa@my-project.iam.gserviceaccount.com'
```

5. **If key files are absolutely required**, store them in Secret Manager and inject at runtime — never commit them:

```python
# SAFE: retrieve service account key from Secret Manager at runtime
import json
from google.cloud import secretmanager
from google.oauth2 import service_account

sm_client = secretmanager.SecretManagerServiceClient()
response = sm_client.access_secret_version(name='projects/my-project/secrets/sa-key/versions/latest')
key_data = json.loads(response.payload.data.decode('UTF-8'))

credentials = service_account.Credentials.from_service_account_info(key_data)
```

6. **Scan git history** for the key file content:

```bash
gitleaks detect --source . --verbose
git filter-repo --path service-account-key.json --invert-paths
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [GCP: Best practices for managing service account keys](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys)
- [GCP: Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [GCP: Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials)
- [google-github-actions/auth: Keyless auth](https://github.com/google-github-actions/auth)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
