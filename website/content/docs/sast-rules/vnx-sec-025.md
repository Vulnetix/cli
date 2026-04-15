---
title: "VNX-SEC-025 – Azure Storage Account Key Hardcoded"
description: "Detect Azure Storage Account keys hardcoded in source code — base64-encoded strings of approximately 88 characters associated with Azure Storage key variable names — which provide full read/write access to all storage resources in the account."
---

## Overview

This rule flags source files where an Azure Storage Account key appears to be hardcoded. The pattern matches lines that reference an Azure storage key variable name (containing `azure`, `storage`, and/or `key` in combination) alongside a base64-encoded string of the characteristic 86-character length followed by `==` padding that Azure Storage keys use.

Azure Storage Account keys provide unrestricted access to every resource within a storage account — all blobs, queues, tables, and file shares — with no further authentication required. Possession of a key is equivalent to being the account owner for the purposes of data access. A key hardcoded in source code is exposed to everyone who can read the repository, including CI systems, third-party integrations, and any developer who has ever cloned the repository.

This rule corresponds to [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html).

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Azure Storage is commonly used to store application logs, database backups, user-uploaded content, and configuration files — all of which may contain sensitive data. An attacker who obtains a storage account key gains immediate access to all of this data regardless of network controls, private endpoint configurations, or firewall rules that might otherwise protect the account.

Beyond data exfiltration, a compromised storage key can be used to tamper with data (overwriting backups or modifying application configuration files to introduce malicious content), to host malware in publicly accessible containers, or to enumerate the storage account structure to understand the application's architecture before mounting further attacks.

Keys committed to version control are particularly dangerous because they persist in git history even after the file is modified. An attacker who gains read access to the repository at any point in time can retrieve historical commits containing the key. Rotation alone is insufficient if the old key was not also revoked.

## What Gets Flagged

The rule matches any file (excluding lock files, checksums, and minified assets) that contains both a pattern matching an Azure storage key variable name and a base64-encoded string matching Azure's 88-character key format.

```python
# FLAGGED: Azure storage key hardcoded in application config
AZURE_STORAGE_ACCOUNT_KEY = "dGhpcyBpcyBhIGZha2Uga2V5IGZvciBkZW1vIHB1cnBvc2VzIG9ubHkgYW5kIG5vdCByZWFsISE="

# FLAGGED: connection string with embedded key
connection_string = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=dGhpcyBpcyBhIGZha2Uga2V5IGZvciBkZW1vIHB1cnBvc2VzIG9ubHkgYW5kIG5vdCByZWFsISE=;EndpointSuffix=core.windows.net"
```

## Remediation

1. **Rotate the key immediately.** In the Azure Portal, navigate to the storage account, select "Access keys", and regenerate the exposed key. Azure provides two keys specifically to allow zero-downtime rotation.

2. **Store secrets in Azure Key Vault.** Applications running on Azure should retrieve storage credentials from Key Vault at runtime using a managed identity, eliminating the need to store credentials in configuration at all:

```python
# SAFE: retrieve from Azure Key Vault using managed identity
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

credential = DefaultAzureCredential()
client = SecretClient(vault_url="https://myvault.vault.azure.net", credential=credential)
storage_key = client.get_secret("storage-account-key").value
```

3. **Use environment variables or managed identities for non-Azure deployments.** If running outside Azure, load the key from an environment variable injected by the deployment system, or use a short-lived SAS token scoped to only the required operations:

```python
# SAFE: load from environment variable
import os
storage_key = os.environ["AZURE_STORAGE_ACCOUNT_KEY"]
```

4. **Purge the key from git history.** Use `git filter-repo` or BFG Repo-Cleaner to remove the commit history containing the secret. After history rewrite, force-push and rotate the secret again.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [Azure Storage Account key management best practices](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage)
- [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/general/overview)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [Azure Managed Identities for Azure resources](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)
