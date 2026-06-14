---
title: "Secrets — Cloud Providers"
description: "AWS, Azure, GCP, Alibaba, Oracle, DigitalOcean, IBM and other cloud-provider credential detection rules."
weight: 1
---

AWS, Azure, GCP, Alibaba, Oracle, DigitalOcean, IBM and other cloud-provider credential detection rules.

All rules in this category are kind `secrets`. They run under `vulnetix secrets` and the secrets stage of `vulnetix scan`.

| Rule ID | Name | Severity | Detection |
|---------|------|----------|-----------|
| <a id="vnx-sec-081"></a>VNX-SEC-081 | Cloudflare API token (cfk_) | Critical | keyword + regex |
| <a id="vnx-sec-082"></a>VNX-SEC-082 | Cloudflare user/account token (cfut_/cfat_) | Critical | keyword + regex |
| <a id="vnx-sec-083"></a>VNX-SEC-083 | Heroku API key (v2 HRKU-) | Critical | keyword + regex |
| <a id="vnx-sec-084"></a>VNX-SEC-084 | Salesforce access token | Critical | regex |
| <a id="vnx-sec-101"></a>VNX-SEC-101 | Oracle Cloud (OCI) API private key | Critical | keyword + regex |
| <a id="vnx-sec-102"></a>VNX-SEC-102 | Oracle Cloud (OCI) auth token | High | keyword + regex + entropy |
| <a id="vnx-sec-103"></a>VNX-SEC-103 | IBM Cloud IAM API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-104"></a>VNX-SEC-104 | Tencent Cloud secret ID (AKID) | High | keyword + regex |
| <a id="vnx-sec-105"></a>VNX-SEC-105 | Tencent Cloud secret key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-106"></a>VNX-SEC-106 | Yandex Cloud IAM token | High | keyword + regex |
| <a id="vnx-sec-107"></a>VNX-SEC-107 | Yandex Cloud OAuth token | Critical | keyword + regex |
| <a id="vnx-sec-108"></a>VNX-SEC-108 | Scaleway secret key (UUID) | Critical | keyword + regex |
| <a id="vnx-sec-109"></a>VNX-SEC-109 | Scaleway access key (SCW prefix) | High | keyword + regex |
| <a id="vnx-sec-110"></a>VNX-SEC-110 | Hetzner Cloud API token | Critical | keyword + regex + entropy |
| <a id="vnx-sec-111"></a>VNX-SEC-111 | Linode personal access token | Critical | keyword + regex |
| <a id="vnx-sec-112"></a>VNX-SEC-112 | Vultr API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-113"></a>VNX-SEC-113 | Fastly API token | High | keyword + regex + entropy |
| <a id="vnx-sec-114"></a>VNX-SEC-114 | Akamai EdgeGrid client token | High | keyword + regex |
| <a id="vnx-sec-115"></a>VNX-SEC-115 | Akamai EdgeGrid client secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-116"></a>VNX-SEC-116 | AWS SES SMTP password | High | keyword + regex + entropy |
| <a id="vnx-sec-117"></a>VNX-SEC-117 | AWS MWS auth token | High | keyword + regex |
| <a id="vnx-sec-118"></a>VNX-SEC-118 | AWS AppSync GraphQL API key (da2-) | High | keyword + regex |
| <a id="vnx-sec-119"></a>VNX-SEC-119 | AWS Cognito identity/user pool ID | Medium | keyword + regex |
| <a id="vnx-sec-120"></a>VNX-SEC-120 | AWS Cognito app client secret | High | keyword + regex + entropy |
| <a id="vnx-sec-121"></a>VNX-SEC-121 | AWS Amplify app deploy/webhook ID | Medium | keyword + regex |
| <a id="vnx-sec-122"></a>VNX-SEC-122 | AWS SNS topic ARN with credentials context | Medium | keyword + regex |
| <a id="vnx-sec-123"></a>VNX-SEC-123 | Azure AD client secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-124"></a>VNX-SEC-124 | Azure SAS token (shared access signature) | High | keyword + regex |
| <a id="vnx-sec-125"></a>VNX-SEC-125 | Azure Service Bus connection string | Critical | keyword + regex |
| <a id="vnx-sec-126"></a>VNX-SEC-126 | Azure Cosmos DB account key | Critical | keyword + regex |
| <a id="vnx-sec-127"></a>VNX-SEC-127 | Azure Cognitive Search admin key | High | keyword + regex + entropy |
| <a id="vnx-sec-128"></a>VNX-SEC-128 | Azure Container Registry password | High | keyword + regex + entropy |
| <a id="vnx-sec-129"></a>VNX-SEC-129 | Azure DevOps personal access token | Critical | keyword + regex + entropy |
| <a id="vnx-sec-130"></a>VNX-SEC-130 | GCP OAuth access token (ya29.) | High | keyword + regex |
| <a id="vnx-sec-131"></a>VNX-SEC-131 | GCP OAuth refresh token (1//) | Critical | keyword + regex |
| <a id="vnx-sec-132"></a>VNX-SEC-132 | Google reCAPTCHA secret key | Medium | keyword + regex |
| <a id="vnx-sec-133"></a>VNX-SEC-133 | Firebase Cloud Messaging server key (AAAA) | High | keyword + regex |
| <a id="vnx-sec-134"></a>VNX-SEC-134 | Firebase Realtime Database URL | Medium | keyword + regex |
| <a id="vnx-sec-135"></a>VNX-SEC-135 | DigitalOcean Spaces access key | High | keyword + regex |
| <a id="vnx-sec-136"></a>VNX-SEC-136 | DigitalOcean Spaces secret key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-137"></a>VNX-SEC-137 | Render API key (rnd_) | Critical | keyword + regex |
| <a id="vnx-sec-138"></a>VNX-SEC-138 | Railway API/project token | Critical | keyword + regex |
| <a id="vnx-sec-139"></a>VNX-SEC-139 | Fly.io API token (fo1_ / FlyV1) | Critical | keyword + regex |
| <a id="vnx-sec-140"></a>VNX-SEC-140 | Aiven API token (aivenv1 / context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-141"></a>VNX-SEC-141 | Cloudflare Origin CA key (v1.0-) | High | keyword + regex |
| <a id="vnx-sec-142"></a>VNX-SEC-142 | Cloudflare Stream signing key context | High | keyword + regex + entropy |
| <a id="vnx-sec-143"></a>VNX-SEC-143 | OVH application secret / consumer key | High | keyword + regex + entropy |
| <a id="vnx-sec-144"></a>VNX-SEC-144 | UpCloud API credentials context | High | keyword + regex + entropy |
| <a id="vnx-sec-145"></a>VNX-SEC-145 | Alibaba Cloud STS temporary access key (STS.) | High | keyword + regex |
| <a id="vnx-sec-146"></a>VNX-SEC-146 | IBM Cloud Object Storage HMAC secret access key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-147"></a>VNX-SEC-147 | Azure Storage connection string | Critical | keyword + regex |
| <a id="vnx-sec-148"></a>VNX-SEC-148 | GCP service account email + key context | High | keyword + regex |
| <a id="vnx-sec-149"></a>VNX-SEC-149 | Google Maps Platform API key (AIza, restricted-context) | Medium | keyword + regex |
| <a id="vnx-sec-150"></a>VNX-SEC-150 | Scaleway API token (UUID, context) | High | keyword + regex |
| <a id="vnx-sec-151"></a>VNX-SEC-151 | Tencent Cloud COS connection (SecretId+SecretKey) | High | keyword + regex |
| <a id="vnx-sec-152"></a>VNX-SEC-152 | Cloudflare Global API key (legacy 37-hex) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-153"></a>VNX-SEC-153 | GCP Firebase web API config apiKey (AIza, firebase context) | Medium | keyword + regex |
| <a id="vnx-sec-154"></a>VNX-SEC-154 | Hetzner DNS API token (context) | High | keyword + regex + entropy |
| <a id="vnx-sec-155"></a>VNX-SEC-155 | Vultr Object Storage S3 secret (context) | High | keyword + regex + entropy |
| <a id="vnx-sec-156"></a>VNX-SEC-156 | Fastly Compute / service ID with token context | Medium | keyword + regex + entropy |
| <a id="vnx-sec-157"></a>VNX-SEC-157 | Render deploy hook URL | Medium | keyword + regex |
| <a id="vnx-sec-158"></a>VNX-SEC-158 | Linode Object Storage access key (context) | High | keyword + regex + entropy |
| <a id="vnx-sec-159"></a>VNX-SEC-159 | Azure Maps subscription key (context) | Medium | keyword + regex + entropy |
| <a id="vnx-sec-160"></a>VNX-SEC-160 | GCP Cloud Run / IAP service identity token (context) | High | keyword + regex |
| <a id="vnx-sec-161"></a>VNX-SEC-161 | Alibaba Cloud secret access key (context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-162"></a>VNX-SEC-162 | OVH application key (context) | Medium | keyword + regex + entropy |
| <a id="vnx-sec-163"></a>VNX-SEC-163 | Yandex Cloud API key (AQVN context) | Critical | keyword + regex |
| <a id="vnx-sec-164"></a>VNX-SEC-164 | IBM Cloud IAM bearer token (context) | High | keyword + regex |
| <a id="vnx-sec-165"></a>VNX-SEC-165 | Aiven service connection URI (context) | Critical | keyword + regex |
| <a id="vnx-sec-166"></a>VNX-SEC-166 | Scaleway IAM API secret key (context) | Critical | keyword + regex |
| <a id="vnx-sec-167"></a>VNX-SEC-167 | Tencent Cloud SCF / API gateway secret (context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-168"></a>VNX-SEC-168 | Cloudflare R2 S3 secret access key (context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-169"></a>VNX-SEC-169 | Azure subscription / tenant credential bundle (context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-170"></a>VNX-SEC-170 | GCP API key (AIza) generic | High | keyword + regex |
| <a id="vnx-sec-171"></a>VNX-SEC-171 | Hetzner Cloud robot webservice password (context) | High | keyword + regex + entropy |
| <a id="vnx-sec-172"></a>VNX-SEC-172 | Vultr deploy / API token (context, hex) | High | keyword + regex + entropy |
| <a id="vnx-sec-173"></a>VNX-SEC-173 | Akamai EdgeGrid access token (context) | High | keyword + regex |
| <a id="vnx-sec-174"></a>VNX-SEC-174 | GCP service account private key (PEM in JSON) | Critical | keyword + regex |
| <a id="vnx-sec-175"></a>VNX-SEC-175 | Railway project deploy token (context, base64) | High | keyword + regex + entropy |
| <a id="vnx-sec-176"></a>VNX-SEC-176 | Oracle Cloud (OCI) config fingerprint+key context | Medium | keyword + regex |
| <a id="vnx-sec-177"></a>VNX-SEC-177 | DigitalOcean App Platform / function deploy URL (context) | Medium | keyword + regex |
| <a id="vnx-sec-178"></a>VNX-SEC-178 | Fly.io org deploy token (FlyV1 macaroon) | High | keyword + regex |
| <a id="vnx-sec-179"></a>VNX-SEC-179 | Tencent Cloud webhook URL (context) | Medium | keyword + regex |

## Remediation

Rotate any exposed credential immediately, remove it from source, and load it from a secrets manager or environment variable instead. Purge it from git history with `git filter-repo`. See [CWE-798](https://cwe.mitre.org/data/definitions/798.html) and the [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).
