# Comprehensive Secrets Detection Patterns Report

## Sources Researched
- **Gitleaks** (gitleaks/gitleaks) — All 130+ Go rule files from `cmd/generate/config/rules/`
- **TruffleHog** (trufflesecurity/trufflehog) — 700+ detectors in `pkg/detectors/`
- **detect-secrets** (Yelp/detect-secrets) — Plugins system
- **shhgit** (eth0izzle/shhgit) — Signatures
- **noseyparker** (woodruffw/noseyparker) — YAML rules
- **git-secrets** (awslabs/git-secrets) — Built-in patterns
- **ggshield** (GitGuardian) — Secret patterns
- **Kubescape** — Secret controls/policies
- **Checkov** — Secret checks
- **SecLists** (danielmiessler/SecLists) — Common credentials
- **AWS CLI patterns** — Official credential formats
- **bandit** (PyCQA/bandit) — Hardcoded password plugins

---

## 1. CLOUD PROVIDER CREDENTIALS

### 1.1 Amazon Web Services (AWS)

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **AWS Access Key ID** | `(?:A3T[A-Z0-9]\|AKIA\|ASIA\|ABIA\|ACCA)[A-Z2-7]{16}` | **Critical** | Gitleaks |
| **AWS Access Key (all known prefixes)** | `(?:A3T[A-Z0-9]\|AKIA\|ABIA\|ACCA\|ASIA\|AGPA\|AIDA\|AROA\|AIPA\|ANPA\|ANVA\|APKA)[A-Z0-9]{16}` | **Critical** | Generic expanded |
| **AWS Secret Access Key** | `[A-Za-z0-9/+=]{40}` (context-aware with `aws_secret_access_key` keyword) | **Critical** | Gitleaks/Generic |
| **AWS Session Token** | `(?i)(?:aws_session_token\|session_token\|x-amz-security-token)(.{0,20})?['\"][A-Za-z0-9+/=]{100,}['\"]` | **High** | Gitleaks/Generic |
| **AWS Account ID** | `\b(?![0-]+)([0-9]{12})\b` | Low | Gitleaks |
| **AWS Bedrock API Key (Long-lived)** | `ABSK[A-Za-z0-9+/]{109,269}={0,2}` | **Critical** | Gitleaks |
| **AWS Bedrock API Key (Short-lived)** | `bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t` | **Critical** | Gitleaks |
| **AWS Marketplace ARN** | `arn:[a-z]+:aws-marketplace:[a-z0-9-]+:[0-9]{12}:product/[A-Z0-9a-z-]+` | Medium | Gitleaks |
| **AWS CLI Credentials File** | `\[default\]\naws_access_key_id\s*=\s*AKIA` (multi-line) | **Critical** | AWS docs |
| **AWS ECS Docker Login** | URL containing `dkr.ecr` with auth token | High | TruffleHog |
| **AWS AppSync API Key** | `da2-[A-Za-z0-9]{26}` | **Critical** | Generic |
| **Amazon MWS Auth Token** | `amzn\.mws\.[0-9a-f\-]{8}-[0-9a-f\-]{4}-[0-9a-f\-]{4}-[0-9a-f\-]{4}-[0-9a-f\-]{12}` | **Critical** | Generic |

### 1.2 Microsoft Azure

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Azure AD Client Secret** | `[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34}` | **Critical** | Gitleaks |
| **Azure Connection String** | `DefaultEndpointsProtocol=https;.*AccountName=.*;AccountKey=` | **Critical** | Gitleaks |
| **Azure Storage Account Key** | `AccountKey=[a-zA-Z0-9+/]{86}==` | **Critical** | Gitleaks/Generic |
| **Azure SAS Token** | `sig=[A-Za-z0-9%+/=]{40,}` (full URL: `https://[^.]+\.(blob\|table\|queue\|file)\.core\.windows\.net/[^?]*\?.*sig=`) | **High** | Gitleaks/Generic |
| **Azure Service Principal Secret** | UUID format with `AZURE_CLIENT_SECRET` keyword | **Critical** | Gitleaks |
| **Azure DevOps PAT** | Base64 encoded blob, format-specific | **Critical** | Gitleaks |
| **Azure Subscription Key** | UUID pattern with `subscription`/`subscription-key` | High | Gitleaks |
| **Azure SQL Connection String** | `Server=tcp:[^;,]+(?::\d+)?;Database=[^;]+;Password=[^;]+;` | **Critical** | Generic |
| **Azure Service Bus Connection String** | `Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;]+` | **Critical** | Generic |
| **Azure Redis Cache Connection** | `[^@]+\.redis\.cache\.windows\.net(:\d+)?,password=[^\s,]+` | **Critical** | Generic |

### 1.3 Google Cloud Platform (GCP)

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **GCP API Key** | `AIza[\w-]{35}` | **Critical** | Gitleaks |
| **GCP Service Account** | `"type": "service_account"` | **Critical** | Gitleaks |
| **GCP OAuth Client ID** | `[0-9]+-[0-9a-zA-Z_]{32}\.apps\.googleusercontent\.com` | **High** | Gitleaks/Generic |
| **GCP OAuth Client Secret** | `GOCSPX-[A-Za-z0-9]{28}` | **High** | Generic |
| **GCP OAuth Access Token** | `ya29\.[0-9A-Za-z\-_]+` | **Critical** | Generic |
| **GCP OAuth Refresh Token** | `1//[A-Za-z0-9\-_\.]{40,}` | **Critical** | Generic |
| **GCP Service Account Private Key Data** | `"private_key": "-----BEGIN PRIVATE KEY-----` | **Critical** | Gitleaks |
| **GCP Firebase URL** | `https://[a-z0-9-]+\.firebaseio\.com` | High | Gitleaks |
| **GCP Firebase Cloud Messaging Key** | `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}` | **High** | Generic |
| **GCP reCAPTCHA Key** | `6L[0-9A-Za-z-_]{38}` | **High** | Generic |
| **GCP Service Account Email** | `[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+\.iam\.gserviceaccount\.com` | **High** | Generic |
| **GCP Storage HMAC Access ID** | `GOOG[A-Za-z0-9]{57}` | **High** | Generic |
| **GCP Private Key ID** | `"private_key_id":\s*"[a-f0-9]{32}"` | **High** | Generic |

### 1.4 Alibaba Cloud

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Alibaba AccessKey ID** | `LTAI(?i)[a-z0-9]{20}` | **Critical** | Gitleaks |
| **Alibaba Secret Access Key** | Generic with `alibaba` keyword + 30 alphanumeric | **Critical** | Gitleaks |

### 1.5 Oracle Cloud (OCI)

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **OCI API Key** | Private key in OCI format | **Critical** | TruffleHog |
| **OCI Auth Token** | Oracle-specific auth format | **High** | TruffleHog |
| **OCI OCID** | `ocid1\.[a-z0-9]+\.[a-z0-9]+\.(?:oc[0-9a-z]+\|ak.*)\.[a-zA-Z0-9]+` | Medium | Gitleaks |

### 1.6 DigitalOcean

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **DigitalOcean PAT** | `dop_v1_[a-f0-9]{64}` | **Critical** | Gitleaks |
| **DigitalOcean OAuth Token** | `doo_v1_[a-f0-9]{64}` | **Critical** | Gitleaks |

### 1.7 Other Cloud Providers

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Cloudflare Global API Key** | Generic with `cloudflare` keyword + 32 hex | **Critical** | Gitleaks |
| **Cloudflare API Token** | `[A-Za-z0-9_-]{40}` with `cloudflare` keyword | **Critical** | Gitleaks |
| **Hetzner Cloud API Token** | Generic with `hetzner` keyword | **High** | TruffleHog |
| **Linode API Token** | Generic with `linode` keyword | **High** | TruffleHog |
| **Scaleway Token** | Generic with `scaleway` keyword | **High** | TruffleHog |
| **Vultr API Key** | Generic pattern | **High** | TruffleHog |
| **UpCloud API Key** | Generic pattern | High | TruffleHog |

---

## 2. SOURCE CONTROL TOKENS

### 2.1 GitHub

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **GitHub Personal Access Token (PAT)** | `ghp_[0-9a-zA-Z]{36}` | **Critical** | Gitleaks |
| **GitHub Fine-Grained PAT** | `github_pat_\w{82}` | **Critical** | Gitleaks |
| **GitHub OAuth Access Token** | `gho_[0-9a-zA-Z]{36}` | **Critical** | Gitleaks |
| **GitHub App Token** | `(?:ghu\|ghs)_[0-9a-zA-Z]{36}` | **Critical** | Gitleaks |
| **GitHub Refresh Token** | `ghr_[0-9a-zA-Z]{36}` | **High** | Gitleaks |
| **GitHub SSH Key** | Full SSH key block | **Critical** | Gitleaks |
| **GitHub App Installation Token** | JWT format with `ghs_` prefix | **Critical** | Gitleaks |

### 2.2 GitLab

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **GitLab PAT** | `glpat-[\w-]{20}` | **Critical** | Gitleaks |
| **GitLab PAT (Routable)** | `\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b` | **Critical** | Gitleaks |
| **GitLab CI/CD Job Token** | `glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}` | **High** | Gitleaks |
| **GitLab Deploy Token** | `gldt-[0-9a-zA-Z_\-]{20}` | **Critical** | Gitleaks |
| **GitLab Feature Flag Client Token** | `glffct-[0-9a-zA-Z_\-]{20}` | High | Gitleaks |
| **GitLab Feed Token** | `glft-[0-9a-zA-Z_\-]{20}` | High | Gitleaks |
| **GitLab Incoming Mail Token** | `glimt-[0-9a-zA-Z_\-]{25}` | High | Gitleaks |
| **GitLab Kubernetes Agent Token** | `glagent-[0-9a-zA-Z_\-]{50}` | **Critical** | Gitleaks |
| **GitLab OAuth App Secret** | `gloas-[0-9a-zA-Z_\-]{64}` | **Critical** | Gitleaks |
| **GitLab Pipeline Trigger Token** | `glptt-[0-9a-f]{40}` | **Critical** | Gitleaks |
| **GitLab Runner Registration Token** | `GR1348941[\w-]{20}` | **Critical** | Gitleaks |
| **GitLab Runner Auth Token** | `glrt-[0-9a-zA-Z_\-]{20}` | **Critical** | Gitleaks |
| **GitLab Runner Auth Token (Routable)** | `\bglrt-t\d_[0-9a-zA-Z_\-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b` | **Critical** | Gitleaks |
| **GitLab SCIM Token** | `glsoat-[0-9a-zA-Z_\-]{20}` | **Critical** | Gitleaks |
| **GitLab Session Cookie** | `_gitlab_session=[0-9a-z]{32}` | **High** | Gitleaks |

### 2.3 Bitbucket

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Bitbucket App Password** | Generic with `bitbucket` keyword | **Critical** | Gitleaks |
| **Bitbucket OAuth Token** | Generic + `bitbucket` keyword | **Critical** | Gitleaks |
| **Bitbucket SSH Key** | SSH key block with `bitbucket` keyword | **Critical** | Gitleaks |

### 2.4 Azure DevOps

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Azure DevOps PAT** | Base64 format or UUID | **Critical** | Gitleaks |
| **Azure DevOps Token** | Pattern with `azure` keyword | **Critical** | Gitleaks |

---

## 3. COMMUNICATION SERVICES

### 3.1 Slack

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Slack Bot Token** | `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*` | **Critical** | Gitleaks |
| **Slack User Token** | `xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}` | **Critical** | Gitleaks |
| **Slack App-Level Token** | `(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+` | **Critical** | Gitleaks |
| **Slack Configuration Access Token** | `(?i)xoxe.xox[bp]-\d-[A-Z0-9]{163,166}` | **Critical** | Gitleaks |
| **Slack Configuration Refresh Token** | `(?i)xoxe-\d-[A-Z0-9]{146}` | **Critical** | Gitleaks |
| **Slack Legacy Bot Token** | `xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}` | **High** | Gitleaks |
| **Slack Legacy Workspace Token** | `xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}` | **High** | Gitleaks |
| **Slack Legacy Token** | `xox[os]-\d+-\d+-\d+-[a-fA-F\d]+` | **High** | Gitleaks |
| **Slack Webhook URL** | `(?:https?://)?hooks.slack.com/(?:services\|workflows\|triggers)/[A-Za-z0-9+/]{43,56}` | **Critical** | Gitleaks |

### 3.2 Twilio

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Twilio API Key** | `SK[0-9a-fA-F]{32}` | **Critical** | Gitleaks |
| **Twilio Account SID** | `AC[0-9a-fA-F]{32}` | **Critical** | Gitleaks |
| **Twilio Auth Token** | Generic + `twilio` keyword | **Critical** | Gitleaks |
| **Twilio Chat Key** | Generic pattern | **Critical** | Gitleaks |

### 3.3 SendGrid

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **SendGrid API Token** | `SG\.(?i)[a-z0-9=_\-\.]{66}` | **Critical** | Gitleaks |

### 3.4 Mailgun

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Mailgun API Key** | Generic with `mailgun` keyword + hex 32 | **Critical** | Gitleaks |

### 3.5 Discord

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Discord Bot Token** | Generic with `discord` keyword + hex 64 | **Critical** | Gitleaks |
| **Discord Client ID** | Generic with `discord` keyword + numeric 18 | High | Gitleaks |
| **Discord Client Secret** | Generic with `discord` keyword + alphanumeric 32 | **Critical** | Gitleaks |
| **Discord Webhook URL** | `https://discord.com/api/webhooks/\d+/[a-zA-Z0-9_-]+` | **Critical** | Gitleaks |

### 3.6 Telegram

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Telegram Bot Token** | `[0-9]{5,16}:(?-i:A)[a-z0-9_\-]{34}` | **Critical** | Gitleaks |

### 3.7 Other Communication

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Mattermost Access Token** | Generic with `mattermost` keyword + 26 alpha | **High** | Gitleaks |
| **MessageBird API Token** | Generic with `message[_-]?bird` keyword + 25 alpha | **High** | Gitleaks |
| **MessageBird Client ID** | UUID-like hex8-4-4-4-12 | High | Gitleaks |
| **Gitter Access Token** | Generic with `gitter` keyword | **High** | Gitleaks |
| **vonage/Nexmo API Key** | Generic pattern | **High** | TruffleHog |
| **Plivo Auth ID/Token** | Generic pattern | **High** | TruffleHog |
| **SendGrid Webhook** | URL containing `sendgrid` with verification key | **High** | Gitleaks |
| **Mailchimp API Key** | `[0-9a-f]{32}-us[0-9]{1,2}` | **Critical** | Gitleaks |

---

## 4. PAYMENT PROVIDERS

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Stripe API Key (Secret)** | `(?:sk\|rk)_(?:test\|live\|prod)_[a-zA-Z0-9]{10,99}` | **Critical** | Gitleaks |
| **Stripe Publishable Key** | `pk_(?:test\|live)_[a-zA-Z0-9]{10,99}` | Medium | Gitleaks |
| **Stripe Webhook Secret** | `whsec_[a-zA-Z0-9]{16,64}` | **Critical** | Gitleaks |
| **PayPal Client ID** | `A[a-zA-Z0-9_-]{79}` | **High** | Gitleaks |
| **PayPal Secret** | `E[a-zA-Z0-9_-]{79}` | **Critical** | Gitleaks |
| **Square Access Token** | `(?:EAAA\|sq0atp-)[\w-]{22,60}` | **Critical** | Gitleaks |
| **Square Secret** | `sq0csp-[\w-]{43}` | **Critical** | Gitleaks |
| **Braintree Production Access Token** | `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}` (`$` must be escaped in regex) | **Critical** | Generic |
| **Braintree Sandbox Access Token** | `access_token\$sandbox\$[0-9a-zA-Z]{14}` | **Critical** | Generic |
| **Adyen API Key** | `AQE[\w+/\=]{20,}` | **Critical** | Generic |
| **Adyen Client Key** | `(test\|live)_[a-f0-9]{32}` | **Critical** | Generic |
| **Paddle API Key** | `pdl_(live\|sdbx)_apikey_[a-z\d]{26}_[a-zA-Z\d]{22}_[a-zA-Z\d]{3}` (69 chars, 5 underscores) | **Critical** | Generic |
| **Recurly API Key** | 32 hex chars (no prefix; context-based) | **High** | Generic |
| **LemonSqueezy Token (JWT)** | `eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9\.[0-9A-Za-z]{314}\.[0-9A-Za-z-_]{512}` (JWT with fixed header) | **Critical** | Generic |
| **GoCardless API Token** | Generic with `gocardless` keyword + `live_(?i)[a-z0-9\-_=]{40}` | **Critical** | Gitleaks |
| **Flutterwave Public Key** | `FLWPUBK_TEST-(?i)[a-h0-9]{32}-X` | **High** | Gitleaks |
| **Flutterwave Secret Key** | `FLWSECK_TEST-(?i)[a-h0-9]{32}-X` | **Critical** | Gitleaks |
| **Freemius Secret Key** | `["']secret_key["']\s*=>\s*["'](sk_[\S]{29})["']` | **Critical** | Gitleaks |
| **Lob Pub API Key** | `(test\|live)_pub_[a-f0-9]{31}` | **High** | Gitleaks |
| **Lob API Key** | `(live\|test)_[a-f0-9]{35}` | **Critical** | Gitleaks |
| **Duffel API Token** | `duffel_(?:test\|live)_(?i)[a-z0-9_\-=]{43}` | **Critical** | Gitleaks |
| **Coinbase Commerce API Key** | 64 alphanumeric/dash/underscore with `coinbase` keyword | **Critical** | Gitleaks |

---

## 5. AI PROVIDERS

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **OpenAI Legacy API Key** | `sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}` | **Critical** | Gitleaks |
| **OpenAI Project API Key** | `sk-proj-[A-Za-z0-9_-]{74}T3BlbkFJ[A-Za-z0-9_-]{74}` | **Critical** | Gitleaks |
| **OpenAI Service Account Key** | `sk-svcacct-[A-Za-z0-9_-]{74}T3BlbkFJ[A-Za-z0-9_-]{74}` | **Critical** | Gitleaks |
| **OpenAI Admin Key** | `sk-admin-[A-Za-z0-9_-]{58}T3BlbkFJ[A-Za-z0-9_-]{58}` | **Critical** | Gitleaks |
| **OpenAI Unified (all formats)** | `sk-(?:proj\|svcacct\|admin)-(?:[A-Za-z0-9_-]{74}\|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}\|[A-Za-z0-9_-]{58})\|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}` | **Critical** | Gitleaks |
| **OpenAI Org Key** | `org-[a-zA-Z0-9]{20,}` | **High** | TruffleHog |
| **Anthropic API Key** | `sk-ant-api03-[a-zA-Z0-9_\-]{93}AA` | **Critical** | Gitleaks |
| **Anthropic Admin API Key** | `sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA` | **Critical** | Gitleaks |
| **Anthropic OAuth Token** | `sk-ant-oat01-[a-zA-Z0-9_\-]{40,}` | **Critical** | Generic |
| **Anthropic Broad Catch-all** | `sk-ant-[A-Za-z0-9_\-]{32,128}` | **Critical** | Generic |
| **Hugging Face Access Token** | `hf_[a-zA-Z0-9]{34,40}` | **Critical** | Gitleaks/Generic |
| **Hugging Face Org API Token** | `api_org_[a-zA-Z]{34}` | **Critical** | Gitleaks |
| **Cohere API Token** | No known prefix; context-based with `cohere`/`CO_API_KEY` keyword + 40 alphanumeric | **Critical** | Gitleaks |
| **Replicate API Token** | `r8_[0-9A-Za-z-_]{37}` | **Critical** | Generic |
| **Perplexity API Key** | `pplx-[a-zA-Z0-9]{48}` | **Critical** | Gitleaks |
| **Google AI/Gemini API Key** | `AIzaSy[A-Za-z0-9_-]{33}` (key prefix `AIza` + 35 total chars) | **Critical** | Generic |
| **Mistral AI API Key** | 32 alphanumeric chars (no prefix; context-based with `mistral_api_key`) | **Critical** | Generic |
| **Together AI API Key** | `tgp_v1_[A-Za-z0-9_-]{43}` | **Critical** | Generic |
| **DeepSeek API Key** | `sk-[a-f0-9]{32}` (lowercase hex only) | **High** | Generic |
| **Stability AI Key** | `sk-[a-zA-Z0-9]{32}` | **Critical** | Generic |
| **ElevenLabs API Key** | `sk_live_[A-Za-z0-9]{24,}` | **Critical** | Generic |
| **AssemblyAI Key** | 32 alphanumeric chars (no prefix; context-based) | **High** | Generic |
| **Azure OpenAI / Cognitive Services** | `[a-f0-9]{32}` (32 hex chars; context with `AZURE_OPENAI_API_KEY` or `*.openai.azure.com` URL) | **Critical** | Generic |

---

## 6. PACKAGE REGISTRIES & DEPENDENCY MANAGEMENT

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **npm Access Token** | `npm_[a-z0-9]{36}` | **Critical** | Gitleaks |
| **PyPI Upload Token** | `pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}` | **Critical** | Gitleaks |
| **RubyGems API Token** | `rubygems_[a-f0-9]{48}` | **Critical** | Gitleaks |
| **Clojars API Token** | `(?i)CLOJARS_[a-z0-9]{60}` | **Critical** | Gitleaks |
| **NuGet API Key** | Generic with `nuget` keyword | **Critical** | Gitleaks |
| **JFrog API Key** | Generic with `jfrog` keyword + 73 alpha | **Critical** | Gitleaks |
| **JFrog Identity Token** | Generic with `jfrog` keyword + 64 alpha | **Critical** | Gitleaks |
| **Artifactory API Key** | `\bAKCp[A-Za-z0-9]{69}\b` | **Critical** | Gitleaks |
| **Artifactory Reference Token** | `\bcmVmd[A-Za-z0-9]{59}\b` | **Critical** | Gitleaks |
| **Docker Hub Personal Access Token** | `dckr_pat_[A-Za-z0-9_-]{27}` (36 chars total) | **Critical** | Generic |
| **Docker Hub Org Access Token** | `dckr_oat_[A-Za-z0-9_-]{32}` (41 chars total) | **Critical** | Generic |
| **SonarQube API Token** | `(?:squ_\|sqp_\|sqa_)?` + 40 alphanumeric | **Critical** | Gitleaks |
| **Snyk API Token** | UUID-like format (hex8-4-4-4-12) with `snyk` keyword | **Critical** | Gitleaks |
| **Codecov Access Token** | Generic with `codecov` keyword + 32 alpha | **High** | Gitleaks |

---

## 7. MONITORING & OBSERVABILITY

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Datadog API Key** | 32 hex chars (no prefix; context-based with `datadog` keyword) | **Critical** | Gitleaks/Generic |
| **Datadog Application Key** | `ddapp_[a-zA-Z0-9]{34}` | **Critical** | Generic |
| **Datadog Personal Access Token** | `ddpat_[a-zA-Z0-9_]+_[a-zA-Z0-9_]+` | **Critical** | Generic |
| **Datadog Service Account Token** | `ddsat_[a-zA-Z0-9_]+_[a-zA-Z0-9_]+` | **Critical** | Generic |
| **New Relic User API Key** | `NRAK-[A-Z0-9]{27}` | **Critical** | Generic |
| **New Relic REST API Key** | `NRRA-[a-f0-9]{42}` | **Critical** | Generic |
| **New Relic Admin API Key** | `NRAA-[a-f0-9]{27}` | **Critical** | Generic |
| **New Relic Insights Insert Key** | `NRII-[A-Za-z0-9-_]{32}` | **Critical** | Generic |
| **New Relic Insights Query Key** | `NRIQ-[A-Za-z0-9-_]{32}` | **Critical** | Generic |
| **New Relic License Key (new)** | `[a-f0-9]{36}NRAL` (ends with `NRAL`) | **Critical** | Generic |
| **New Relic Synthetics Location Key** | `NRSP-[a-z]{2}[0-9]{2}[a-f0-9]{31}` | **Critical** | Generic |
| **Sentry User Auth Token** | `sntryu_[a-f0-9]{64}` | **Critical** | Gitleaks |
| **Sentry Org Auth Token** | `sntrys_[A-Za-z0-9+/]+_[A-Za-z0-9+/]{43}` (base64 JSON + secret) | **Critical** | Gitleaks |
| **PagerDuty API Key (v2)** | `pd_api_key_[a-zA-Z0-9]{16,32}` | **Critical** | Generic |
| **Grafana Service Account Token** | `glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}` | **Critical** | Gitleaks |
| **Grafana Legacy API Key** | `eyJrIjoi[A-Za-z0-9]{70,400}={0,3}` | **Critical** | Gitleaks |
| **Grafana Cloud API Token** | `glc_[A-Za-z0-9+/]{32,400}={0,3}` | **Critical** | Gitleaks |
| **SumoLogic Access ID** | `su[A-Za-z0-9]{12}` (14 chars total) | **High** | Gitleaks |
| **SumoLogic Access Token** | 64 alphanumeric chars (no prefix; context-based with `sumo` keyword) | **Critical** | Gitleaks |
| **Honeycomb Ingest Key** | `hcxik_[a-zA-Z0-9]{56}` | **Critical** | Generic |
| **Honeycomb Config Key** | `hcxlk_[a-zA-Z0-9]{26}` | **High** | Generic |
| **Honeycomb Management Key** | `hcxmk_[a-zA-Z0-9]+_[a-zA-Z0-9]+` | **Critical** | Generic |
| **Rollbar Access Token** | 32 lowercase alphanumeric (no prefix; context-based with `rollbar`) | **High** | Generic |
| **Logz.io Token** | UUID format (hex8-4-4-4-12; context-based with `logz` keyword) | **High** | Generic |
| **Splunk HEC Token** | GUID format `[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}` | **High** | Generic |
| **Elasticsearch API Key (encoded)** | `ApiKey\s+[A-Za-z0-9+/]{20,}={0,2}` (Base64 of `id:api_key`) | **Critical** | Generic |
| **Dynatrace API Token** | `dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}` | **Critical** | Gitleaks |
| **Databricks API Token** | `dapi[a-f0-9]{32}(?:-\d)?` | **Critical** | Gitleaks |
| **Doppler API Token** | `dp\.pt\.(?i)[a-z0-9]{43}` | **Critical** | Gitleaks |

---

## 8. SAAS & ENTERPRISE PLATFORMS

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Shopify Shared Secret** | `shpss_[a-fA-F0-9]{32}` | **Critical** | Gitleaks |
| **Shopify Access Token** | `shpat_[a-fA-F0-9]{32}` | **Critical** | Gitleaks |
| **Shopify Custom Access Token** | `shpca_[a-fA-F0-9]{32}` | **Critical** | Gitleaks |
| **Shopify Private App Token** | `shppa_[a-fA-F0-9]{32}` | **Critical** | Gitleaks |
| **Dropbox API Token (Short-lived)** | `sl\.[a-z0-9\-=_]{135}` | **Critical** | Gitleaks |
| **Dropbox API Token (Legacy)** | Generic with `dropbox` keyword + 15 alpha | **Critical** | Gitleaks |
| **Notion API Token** | `ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3}` | **Critical** | Gitleaks |
| **Linear API Key** | `lin_api_(?i)[a-z0-9]{40}` | **Critical** | Gitleaks |
| **Linear Client Secret** | Generic with `linear` keyword + hex 32 | **Critical** | Gitleaks |
| **HubSpot API Key** | Generic with `hubspot` keyword | **Critical** | Gitleaks |
| **HubSpot App Token** | UUID-like format | **Critical** | Gitleaks |
| **Airtable API Key** | Generic with `airtable` keyword + 17 alpha | **Critical** | Gitleaks |
| **Airtable PAT** | `\b(pat[[:alnum:]]{14}\.[a-f0-9]{64})\b` | **Critical** | Gitleaks |
| **Okta API Token** | Generic with `okta` keyword + 42 alpha | **Critical** | Gitleaks |
| **Algolia API Key** | Generic with `algolia` keyword + `[a-z0-9]{32}` | **Critical** | Gitleaks |
| **Confluent Secret Key** | Generic with `confluent` keyword + 64 alpha | **Critical** | Gitleaks |
| **Confluent Access Token** | Generic with `confluent` keyword + 16 alpha | **Critical** | Gitleaks |
| **Contentful Delivery API Token** | Generic pattern | **High** | Gitleaks |
| **Contentful Preview API Token** | Generic pattern | **High** | Gitleaks |
| **Fastly API Token** | Generic with `fastly` keyword + 32 extended alpha | **Critical** | Gitleaks |
| **Netlify Personal Access Token** | Generic with `netlify` keyword | **Critical** | Gitleaks |
| **Heroku API Key** | Generic with `heroku` keyword + hex 32 | **Critical** | Gitleaks |
| **Vercel Token** | Generic pattern | **Critical** | TruffleHog |
| **Segment Write Key** | Generic pattern | **High** | TruffleHog |
| **Intercom API Key** | Generic with `intercom` keyword + 60 extended alpha | **Critical** | Gitleaks |
| **Zendesk Secret Key** | Generic with `zendesk` keyword + 40 alpha | **Critical** | Gitleaks |
| **LaunchDarkly Access Token** | Generic with `launchdarkly` keyword + 40 extended | **Critical** | Gitleaks |
| **PagerDuty API Token** | Generic with `pagerduty` keyword | **Critical** | TruffleHog |
| **DroneCI Access Token** | Generic with `droneci` keyword + 32 alpha | **High** | Gitleaks |
| **Harness API Key** | `(?:pat\|sat)\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}` | **Critical** | Gitleaks |
| **Pulumi Access Token** | Generic with `pulumi` keyword | **Critical** | Gitleaks |
| **Frame.io API Token** | `fio-u-(?i)[a-z0-9\-_=]{64}` | **High** | Gitleaks |
| **Fly.io Access Token** | `(?:fo1_[\w-]{43}\|fm1[ar]_[a-zA-Z0-9+\/]{100,}={0,3}\|fm2_[a-zA-Z0-9+\/]{100,}={0,3})` | **Critical** | Gitleaks |
| **Postman API Key** | Generic pattern | **High** | Gitleaks |
| **ReadMe API Key** | Generic pattern | **High** | Gitleaks |
| **PlanetScale Password** | Generic pattern | **High** | Gitleaks |
| **Prefect API Token** | Generic pattern | **High** | Gitleaks |
| **PrivateAI API Key** | Generic pattern | **High** | Gitleaks |
| **Scalingo API Token** | Generic pattern | **High** | Gitleaks |
| **Sendbird API Token** | Generic pattern | **High** | Gitleaks |
| **Sendinblue API Key** | Generic pattern (now Brevo) | **High** | Gitleaks |
| **SettleMint API Token** | Generic pattern | **High** | Gitleaks |
| **Shippo API Token** | Generic pattern | **High** | Gitleaks |
| **Sidekiq Secret** | Generic pattern | **High** | Gitleaks |
| **Hashicorp Terraform API Token** | `[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}` | **Critical** | Gitleaks |
| **Hashicorp Vault Service Token** | `(?:hvs\.[\w-]{90,120}\|s\.(?i:[a-z0-9]{24}))` | **Critical** | Gitleaks |
| **Hashicorp Vault Batch Token** | `hvb\.[\w-]{138,300}` | **Critical** | Gitleaks |
| **Travis CI Access Token** | Generic with `travis` keyword + 22 alpha | **High** | Gitleaks |
| **Trello Access Token** | Generic with `trello` keyword + 32 alphanumeric | **High** | Gitleaks |
| **Kubernetes Service Account Token** | JWT format with `kubernetes` keyword | **Critical** | Gitleaks |
| **Authress Service Client Key** | `(?:sc\|ext\|scauth\|authress)_(?i)[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.(?-i:acc)[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120}` | **Critical** | Gitleaks |
| **Cisco Meraki API Key** | Generic with `meraki` keyword + `[0-9a-f]{40}` | **Critical** | Gitleaks |
| **Defined Networking API Token** | `dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52}` | **High** | Gitleaks |
| **NYTimes Access Token** | Generic with `nytimes` keyword + 32 alpha | **High** | Gitleaks |
| **Etsy Access Token** | Generic with `etsy` keyword + 24 alpha | **High** | Gitleaks |
| **Finnhub Access Token** | Generic with `finnhub` keyword + 20 alpha | **High** | Gitleaks |
| **Freshbooks Access Token** | Generic with `freshbooks` keyword + 64 alpha | **High** | Gitleaks |
| **Infracost API Token** | `ico-[a-zA-Z0-9]{32}` | **High** | Gitleaks |
| **MaxMind License Key** | `[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk` | **Critical** | Gitleaks |
| **1Password Service Account Token** | Generic pattern | **High** | Gitleaks |
| **Adafruit API Key** | Generic with `adafruit` keyword + 32 extended | **High** | Gitleaks |
| **Mapbox API Token** | `pk\.[a-z0-9]{60}\.[a-z0-9]{22}` | **High** | Gitleaks |
| **Kraken Access Token** | Generic with `kraken` keyword | **High** | Gitleaks |
| **Kucoin Access Token** | Generic with `kucoin` keyword + hex 24 | **High** | Gitleaks |
| **Kucoin Secret Key** | Generic with `kucoin` keyword + hex8-4-4-4-12 | **Critical** | Gitleaks |
| **Bittrex Access Key** | Generic with `bittrex` keyword + 32 alpha | **High** | Gitleaks |
| **Bittrex Secret Key** | Generic with `bittrex` keyword + 32 alpha | **Critical** | Gitleaks |
| **ClickHouse Cloud API Key** | `\b(4b1d[A-Za-z0-9]{38})\b` | **Critical** | Gitleaks |
| **Beamer API Token** | Generic with `beamer` keyword | **High** | Gitleaks |
| **Twitch API Token** | Generic with `twitch` keyword + 30 alpha | **High** | Gitleaks |
| **Typeform API Token** | Generic with `typeform` keyword | **High** | Gitleaks |
| **Yandex API Key** | Generic with `yandex` keyword | **High** | Gitleaks |
| **Yandex AWS Access Token** | Generic with `yandex` keyword | **High** | Gitleaks |
| **Squarespace Access Token** | UUID-like format | **High** | Gitleaks |
| **Sourcegraph Access Token** | `\b(sgp_(?:[a-fA-F0-9]{16}\|local)_[a-fA-F0-9]{40}\|sgp_[a-fA-F0-9]{40}\|[a-fA-F0-9]{40})\b` | **Critical** | Gitleaks |
| **Okta API Token** | Generic with `okta` keyword | **Critical** | Gitleaks |
| **Auth0 Access Token** | Generic pattern | **Critical** | TruffleHog |
| **Cloudflare API Token** | Generic pattern | **Critical** | Gitleaks |

---

## 9. PRIVATE KEYS & CRYPTOGRAPHIC MATERIAL

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Generic PEM Private Key (catch-all)** | `-----BEGIN\s(?:RSA\s\|DSA\s\|EC\s\|ECDSA\s\|OPENSSH\s\|PGP\s\|SSH2\s)?(?:ENCRYPTED\s)?PRIVATE\s?(?:KEY\sBLOCK\|KEY)-----` | **Critical** | Gitleaks/Generic |
| **Generic Private Key** | `(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----` | **Critical** | Gitleaks |
| **RSA Private Key** | `-----BEGIN RSA PRIVATE KEY-----` block | **Critical** | Gitleaks |
| **DSA Private Key** | `-----BEGIN DSA PRIVATE KEY-----` block | **Critical** | Gitleaks |
| **EC Private Key** | `-----BEGIN EC PRIVATE KEY-----` block | **Critical** | Gitleaks |
| **ECDSA Private Key** | `-----BEGIN ECDSA PRIVATE KEY-----` block | **Critical** | Gitleaks |
| **OpenSSH Private Key** | `-----BEGIN OPENSSH PRIVATE KEY-----` block | **Critical** | Gitleaks |
| **SSH2 Encrypted Private Key** | `-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----` block | **Critical** | Generic |
| **PGP Private Key** | `-----BEGIN PGP PRIVATE KEY BLOCK-----` | **Critical** | Gitleaks |
| **PuTTY SSH RSA Key** | `PuTTY-User-Key-File-2:\s*ssh-rsa` | **Critical** | Generic |
| **PuTTY SSH ECDSA Key** | `PuTTY-User-Key-File-2:\s*ecdsa-sha2-` | **Critical** | Generic |
| **PuTTY SSH Ed25519 Key** | `PuTTY-User-Key-File-2:\s*ssh-ed25519` | **Critical** | Generic |
| **age Secret Key** | `AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}` | **Critical** | Gitleaks |
| **PKCS#12 File** | `.p12` / `.pfx` file extension (path rule) | **Critical** | Gitleaks |
| **PGP Public Key Block** | `-----BEGIN PGP PUBLIC KEY BLOCK-----` | Low | Gitleaks |
| **Wireguard Private Key** | Base64-encoded 32-byte key with `wg` keyword | **Critical** | TruffleHog |
| **SSH Public Key** | `ssh-rsa AAAA...` / `ssh-ed25519 AAAA...` | Low | Generic |
| **SSH Authorized Keys** | `~/.ssh/authorized_keys` content | Low | Generic |

---

## 10. JWTs, OAUTH, BEARER TOKENS

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **JWT (JSON Web Token)** | `ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?` | **Critical** | Gitleaks |
| **JWT (strict, base64url 3-segment)** | `eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*` | **Critical** | Generic |
| **JWT (stricter, vowel 2nd char)** | `(eyJ[AEIOUaeiou][A-Za-z0-9-_+/=]{20,}\.[A-Za-z0-9-_+/=]{20,}\.[A-Za-z0-9-_+/=]{20,})` | **Critical** | Generic |
| **JWT (Base64-encoded)** | `\bZXlK...(base64 variations)` | **Critical** | Gitleaks |
| **JWT (none algorithm)** | `eyJhbGciOiJub25lIn0.` (alg=none) | **Critical** | Gitleaks |
| **JWE (Encrypted JWT)** | Starts with `eyJ` with `enc` header | **Critical** | Gitleaks |
| **OAuth Access Token (generic)** | `Bearer\s+[A-Za-z0-9\-_\.=:]+` | **Critical** | Generic |
| **OAuth Refresh Token (generic)** | Generic with `refresh_token` keyword | **Critical** | Generic |
| **Bearer Token (generic)** | `[Bb]earer\s+[A-Za-z0-9\-._~+/]+={0,2}` | **Critical** | Generic |
| **Google OAuth Access Token** | `ya29\.[0-9A-Za-z\-_]+` | **Critical** | Generic |
| **Google OAuth Client ID** | `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com` | **High** | Generic |
| **Google OAuth Client Secret** | `GOCSPX-[A-Za-z0-9]{28}` | **Critical** | Generic |
| **Google OAuth Refresh Token** | `1//[A-Za-z0-9\-_\.]{40,}` | **Critical** | Generic |
| **Generic API Key (Semi-generic)** | Keyword-based detection for `access\|auth\|api\|credential\|creds\|key\|passw\|secret\|token` + value | **High** | Gitleaks |
| **Facebook Access Token** | `\d{15,16}(\||%)[0-9a-z\-_]{27,40}` | **Critical** | Gitleaks |
| **Facebook App Token** | `EAAC[A-Za-z0-9]{100,}` | **Critical** | Gitleaks |
| **Facebook App Secret** | Generic with `facebook` keyword + hex 32 | **Critical** | Gitleaks |

---

## 11. DATABASE CONNECTION STRINGS

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **PostgreSQL URL** | `postgres(?:ql)?://[a-zA-Z0-9_]+:[^@\s]+@[^/\s]+` | **Critical** | Generic |
| **MySQL/MariaDB URL** | `mysql(?:x)?://[a-zA-Z0-9_]+:[^@\s]+@[^/\s]+` | **Critical** | Generic |
| **MongoDB URL** | `mongodb(?:\+srv)?://[a-zA-Z0-9_]+:[^@\s]+@[^/\s]+` | **Critical** | Generic |
| **Redis URL** | `redis(?:s)?://(?:[^:]+:[^@]+@\|:[^@]+@)[^/\s]+` | **Critical** | Generic |
| **Elasticsearch URL** | `elasticsearch(?:\+https?)?://(?:[^@\s:]+(?::[^@\s]*)?@)?[^/\s]+` | **Critical** | Generic |
| **Cassandra/CQL** | `cassandra://[a-zA-Z0-9_]+:[^@\s]+@[^/\s]+` | **High** | Generic |
| **CockroachDB** | `cockroachdb://(?:[^@\s:]+(?::[^@\s]*)?@)?[^/\s]+(?::26257)?(?:/[^\s?]*)?` | **Critical** | Generic |
| **SQL Server (JDBC)** | `jdbc:sqlserver://[^;]+;(?:user=[^;]+)?(?:;password=[^;]+)?` | **Critical** | Generic |
| **SQL Server (ADO.NET)** | `Server=[^;,]+(?:,\d+)?;Database=[^;]+;Password=[^;]+` | **Critical** | Generic |
| **SQLite** | `sqlite(?:3)?:///[^\s]+\.(?:db\|sqlite\|sqlite3\|db3)` | Medium | Generic |
| **Oracle DB** | `oracle://[a-zA-Z0-9_]+:[^@\s]+@[^/\s]+` | **Critical** | Generic |
| **JDBC URL (generic)** | `jdbc:(?:postgresql\|mysql\|mariadb\|sqlserver\|oracle)://[^:]+:[^@]+@` | **Critical** | Generic |
| **Couchbase** | `couchbase://[a-zA-Z0-9_]+:[^@\s]+@` | **High** | Generic |
| **Neo4j** | `bolt://[a-zA-Z0-9_]+:[^@\s]+@` | **High** | Generic |
| **InfluxDB** | `https://[a-zA-Z0-9_]+:[^@\s]+@[^/\s]+\.influxdata\.com` | **High** | Generic |
| **Snowflake** | `snowflake://[a-zA-Z0-9_]+:[^@\s]+@[^/\s]+` | **Critical** | Generic |
| **Catch-all DB URI with credentials** | `(?:postgres(?:ql)?\|pgsql\|mysql\|mariadb\|mongodb(?:\+srv)?\|redis(?:s)?\|sqlite\|sqlserver\|elasticsearch\|cassandra\|cockroachdb\|oracle\|db2)://[^:]+:[^@]+@` | **Critical** | Generic |

---

## 12. CRYPTO/BLOCKCHAIN

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Ethereum Private Key (0x-prefixed)** | `0x[0-9a-fA-F]{64}` | **Critical** | Generic |
| **Ethereum Private Key (bare, with word boundaries)** | `\b[0-9a-fA-F]{64}\b` (paired with entropy check) | **Critical** | Generic |
| **Bitcoin WIF (uncompressed)** | `5[HJK][1-9A-HJ-NP-Za-km-z]{48,51}` | **Critical** | Generic |
| **Bitcoin WIF (compressed)** | `[KL][1-9A-HJ-NP-Za-km-z]{50,51}` | **Critical** | Generic |
| **Bitcoin WIF (combined)** | `[5KL][1-9A-HJ-NP-Za-km-z]{48,51}` | **Critical** | Generic |
| **Bitcoin BIP38 Encrypted** | `6P[1-9A-HJ-NP-Za-km-z]{56}` | **Critical** | Generic |
| **BIP32 Extended Private Key (xprv)** | `xprv[1-9A-HJ-NP-Za-km-z]{107}` | **Critical** | Generic |
| **BIP39 Mnemonic (12 words)** | `\b[a-z]+\b\s+){11}\b[a-z]+\b` (12 space-separated lowercase words) | **Critical** | Generic |
| **BIP39 Mnemonic (24 words)** | `(?:\b[a-z]+\b\s+){23}\b[a-z]+\b` (24 words) | **Critical** | Generic |
| **Solana Private Key (base58)** | `[1-9A-HJ-NP-Za-km-z]{86,90}` | **Critical** | Generic |
| **Solana Private Key (JSON byte array)** | `\[\s*\d{1,3}(?:\s*,\s*\d{1,3}){63}\s*\]` (64 comma-separated integers) | **Critical** | Generic |
| **Ethereum JSON Keystore** | `{"crypto":{"ciphertext":"` pattern | **Critical** | Generic |
| **Ripple Secret Key** | `s[1-9A-HJ-NP-Za-km-z]{28,31}` | **Critical** | Generic |
| **Cardano Payment Key** | `ed25519e_sk` | **Critical** | Generic |
| **Polkadot/Substrate Seed** | `0x[0-9a-fA-F]{64}` or BIP39 mnemonic | **Critical** | Generic |

---

## 13. WEBHOOK URLS

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Slack Webhook** | `https?://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,10}/B[A-Za-z0-9_]{8,12}/[A-Za-z0-9_]{24}` | **Critical** | Generic |
| **Discord Webhook** | `https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{68}` | **Critical** | Generic |
| **Microsoft Teams Webhook (full URL)** | `https://[A-Za-z0-9-]+\.webhook\.office\.com/webhookb2/[a-f0-9-]+@[a-f0-9-]+/IncomingWebhook/[a-f0-9]+/[a-f0-9-]+` | **Critical** | Gitleaks/Generic |
| **Mattermost Webhook** | URL format with `hooks.mattermost.com` | **High** | Gitleaks |
| **Google Chat Webhook** | `https://chat\.googleapis\.com/v1/spaces/[^/]+/messages` | **High** | Generic |
| **Stripe Webhook** | `whsec_[A-Za-z0-9]{32,}` | **Critical** | Gitleaks |
## 14. URLS WITH EMBEDDED CREDENTIALS

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **URL with password (generic)** | `https?://[^:@\s]+:[^@\s]+@[^/\s]+` | **Critical** | Generic |
| **URL with credentials (permissive)** | `\w+://[^:@\s]+:[^@\s]+@\S+` | **Critical** | Generic |
| **Basic Auth in URL** | `https?://[a-zA-Z0-9_]+:[a-zA-Z0-9_\-\.]+@` | **Critical** | Generic |
| **FTP with credentials** | `ftp://[^:@\s]+:[^@\s]+@\S+` | **Critical** | Generic |
| **AWS ECR Docker Login URL** | `https://[0-9]+\.dkr\.ecr\.[a-z-]+\.amazonaws\.com` | **High** | Generic |

## 15. CONFIG FILE CREDENTIALS

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **.npmrc _authToken** | `(?i)(?:authToken\|_authToken)\s*[=:]\s*['"]?([A-Za-z0-9_\-./=]{10,})['"]?\s*$` | **Critical** | Generic |
| **.npmrc _auth (base64)** | `(?i)_auth\s*=\s*['"]?[A-Za-z0-9+/=]{20,}['"]?` | **Critical** | Generic |
| **npm token (standalone)** | `npm_[a-z0-9]{36}` | **Critical** | Gitleaks |
| **.pypirc password** | `(?i)(?:password\|passwd)\s*[=:]\s*['"]?([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,})['"\s]?` | **Critical** | Generic |
| **PyPI upload token (standalone)** | `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}` | **Critical** | Gitleaks |
| **.netrc machine credentials** | `machine\s+\S+\s+login\s+\S+\s+password\s+\S+` | **Critical** | Generic |
| **.netrc password field** | `(?i)password\s+(\S+)` (in .netrc file context) | **Critical** | Generic |
| **.s3cfg credentials** | `access_key=\s*AKIA` | **Critical** | Generic |
| **.docker/config.json** | `"auth":"[a-zA-Z0-9+/=]+"` | **Critical** | Generic |
| **Jenkins credentialsId** | `credentialsId: '[a-f0-9-]{36}'` | **Critical** | Gitleaks |
| **AWS CLI credentials** | `aws_access_key_id\s*=\s*AKIA` | **Critical** | Gitleaks |

---

## 16. HASH-BASED CREDENTIALS

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **bcrypt hash** | `\$2[abxy]\$[0-9]{2}\$[A-Za-z0-9./]{53}` | Medium | Generic |
| **Argon2 hash** | `\$argon2(id\|i\|d)\$v=19\$m=\d+,t=\d+,p=\d+(?:,keyid=[^,$]+)?(?:,data=[^$]+)?\$[^$]+\$[^$]+` | Medium | Generic |
| **PBKDF2 (Django)** | `pbkdf2_sha256\$\d{1,6}\$[A-Za-z0-9./+]{57}` | Medium | Generic |
| **PBKDF2 (PHC string)** | `\$pbkdf2[-\$][a-zA-Z0-9-]+\$[^$]+\$[^$]+\$[^$]+` | Medium | Generic |
| **Unix crypt SHA-512** | `\$6\$.+\$` | Medium | Generic |
| **Apache htpasswd (apr1)** | `\$apr1\$[A-Za-z0-9./]+$` | Medium | Generic |
| **Catch-all crypt hashes** | `(?:\$2[abxy]\$\|\$argon2\|\$pbkdf2\|\$6\$\|\$5\$\|\$apr1\$\|\$1\$)` | Medium | Generic |

## 17. GENERIC HIGH-ENTROPY / API KEY PATTERNS

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Generic API Key** | Keyword-based detection (`api[_.-]?key\|api[_.-]?token\|secret\|token` etc.) + entropy >= 3.5 | **High** | Gitleaks |
| **Generic Password** | Keyword-based (`password\|passwd\|pass`) with value | **High** | Gitleaks |
| **Generic Secret** | Keyword-based (`secret\|creds\|credential`) with value | **High** | Gitleaks |
| **Base64 (high entropy)** | `[A-Za-z0-9+/_-]{20,}={0,2}` with Shannon entropy >= 4.5 | **Medium** | Gitleaks/Generic |
| **Hex (high entropy)** | `[0-9a-fA-F]{16,}` with Shannon entropy >= 3.0 | **Medium** | Generic |
| **High-entropy assignment** | `(?:api[_-]?key\|access[_-]?token\|secret\|token\|password\|passwd\|pwd)[\s:=]+['"]?([A-Za-z0-9_\-/+=!@#$%^&*(){}[\]:;'"|<>?.~]{20,})['"]?` + entropy >= 3.5 | **High** | Generic |
| **UUID v4** | `[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}` | Low | Generic |
| **Alphanumeric high-entropy** | `[a-zA-Z0-9_-]{30,}` with entropy check | **Medium** | Generic |

### Entropy Thresholds for Implementation
| Charset | Minimum Entropy | Notes |
|---|---|---|
| Base64 charset | >= 4.5 bits/char | Use for generic base64 strings |
| Hex charset | >= 3.0 bits/char | Hex strings (e.g., git SHAs) |
| Alphanumeric | >= 3.5 bits/char | General use |

---

## 18. SOCIAL MEDIA / OTHER PLATFORMS

| Pattern Name | Regex/Format | Severity | Source |
|---|---|---|---|
| **Twitter API Key** | Generic with `twitter` keyword + 25 alpha | **High** | Gitleaks |
| **Twitter API Secret** | Generic with `twitter` keyword + 50 alpha | **Critical** | Gitleaks |
| **Twitter Bearer Token** | `AAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{45}` | **Critical** | Gitleaks |
| **LinkedIn Client ID** | Generic with `linked[_-]?in` keyword + 14 alpha | **High** | Gitleaks |
| **LinkedIn Client Secret** | Generic with `linked[_-]?in` keyword | **Critical** | Gitleaks |
| **Instagram Token** | Generic pattern | **High** | Generic |
| **Facebook Access Token** | `\d{15,16}(\||%)[0-9a-z\-_]{27,40}` | **Critical** | Gitleaks |
| **Facebook App Secret** | Generic + hex 32 | **Critical** | Gitleaks |

---

## 19. ADDITIONAL PATTERNS FROM OTHER TOOLS

### 18.1 shhgit Signatures
- Generic password patterns in code
- Private key detection
- Environment variable leaks (`export.*=.*`)
- JWT tokens
- Connection strings
- Hash-based credentials

### 18.2 detect-secrets (Yelp)
- **Base64HighEntropyString** — High-entropy base64 strings
- **HexHighEntropyString** — High-entropy hex strings
- **PrivateKeyDetector** — Private key PEM blocks
- **PasswordDetector** — Keyword-based password detection
- **AWSKeyDetector** — `AKIA` pattern
- **SlackDetector** — Slack tokens (xoxb-, xoxp-, xoxa-)
- **StripeDetector** — Stripe key patterns (sk_live, pk_live, rk_live)
- **GitHubTokenDetector** — GitHub tokens (ghp_, gho_, ghs_, ghu_, ghr_)
- **MailgunDetector**
- **TwilioDetector**
- **IbmCosHmacDetector**

### 18.3 noseyparker Rules
- Slack tokens (xox[bprsa])
- Generic API keys
- JWT tokens
- AWS access keys
- GitHub tokens
- Private keys

### 18.4 aws-labs/git-secrets
- AWS Access Key: `AKIA[0-9A-Z]{16}`
- AWS Secret Key pattern
- Generic secret patterns

### 18.5 ggshield (GitGuardian)
- 400+ incident types covering all major providers
- API keys for 200+ services
- Database connection strings
- Private keys
- JWT, OAuth tokens
- SAST-based secret scanning
- Full pattern matching similar to Gitleaks

### 18.6 Checkov Secrets Scanning
- Generic password patterns in IaC templates
- Terraform `sensitive` data detection
- CloudFormation secret parameters
- Kubernetes secret YAML validation
- Dockerfile secret detection
- Bicep/ARM secret detection

### 18.7 Kubescape Secrets Controls
- C-0043: Secret in environment variable
- C-0044: Secret in Kubernetes secret manifest
- C-0045: Secret in container image layer
- C-0046: Weak cryptographic policies

### 18.8 TruffleHog Additional Patterns (700+ detectors)
TruffleHog has the largest detector library. Beyond what's covered above, it includes:
- **Ecosystem-specific**: Over 700 detectors for individual SaaS/PaaS/IaaS providers
- **URI/URL-based**: Connection strings, webhooks, API endpoints
- **Private key material**: All PEM, OpenSSH, PGP formats
- **OAuth/JWT**: All JWT variants
- **Social media**: TikTok, Snapchat, Pinterest, Reddit API keys
- **CI/CD**: Jenkins, CircleCI, GitLab CI, GitHub Actions, Travis CI
- **Collaboration**: Jira, Confluence, Monday.com, Asana
- **Video**: YouTube API, Vimeo, Twitch
- **Analytics**: Google Analytics, Amplitude, Mixpanel, FullStory, Hotjar
- **Cloud storage**: Wasabi, Backblaze B2, MinIO, S3-compatible
- **News/Media**: Guardian, NewsAPI, Aylien
- **Travel**: Amadeus, Sabre, Travelport
- **IoT**: Particle, Blynk, Losant
- **Maps**: Mapbox, Google Maps, MapTiler, OpenCage

---

## COMPLETE GITLEAKS RULE INDEX (130+ rules)

| # | Rule ID | Provider | Pattern |
|---|---|---|---|
| 1 | `aws-access-token` | AWS | `(?:A3T\|AKIA\|ASIA\|ABIA\|ACCA)[A-Z2-7]{16}` |
| 2 | `aws-amazon-bedrock-api-key-long-lived` | AWS Bedrock | `ABSK[A-Za-z0-9+/]{109,269}={0,2}` |
| 3 | `aws-amazon-bedrock-api-key-short-lived` | AWS Bedrock | `bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t` |
| 4 | `gcp-api-key` | GCP | `AIza[\w-]{35}` |
| 5 | `gcp-service-account` | GCP | `"type": "service_account"` |
| 6 | `azure-ad-client-secret` | Azure AD | `[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34}` |
| 7 | `alibaba-access-key-id` | Alibaba | `LTAI(?i)[a-z0-9]{20}` |
| 8 | `alibaba-secret-key` | Alibaba | Generic + 30 alpha |
| 9 | `digitalocean-pat` | DigitalOcean | `dop_v1_[a-f0-9]{64}` |
| 10 | `digitalocean-access-token` | DigitalOcean | `doo_v1_[a-f0-9]{64}` |
| 11 | `github-pat` | GitHub | `ghp_[0-9a-zA-Z]{36}` |
| 12 | `github-fine-grained-pat` | GitHub | `github_pat_\w{82}` |
| 13 | `github-oauth` | GitHub | `gho_[0-9a-zA-Z]{36}` |
| 14 | `github-app-token` | GitHub | `(?:ghu\|ghs)_[0-9a-zA-Z]{36}` |
| 15 | `github-refresh-token` | GitHub | `ghr_[0-9a-zA-Z]{36}` |
| 16 | `gitlab-pat` | GitLab | `glpat-[\w-]{20}` |
| 17 | `gitlab-pat-routable` | GitLab | `\bglpat-[\w-]{27,300}\.[\w-]{9}\b` |
| 18 | `gitlab-ptt` | GitLab PTT | `glptt-[0-9a-f]{40}` |
| 19 | `gitlab-rrt` | GitLab Runner | `GR1348941[\w-]{20}` |
| 20 | `gitlab-deploy-token` | GitLab | `gldt-[0-9a-zA-Z_\-]{20}` |
| 21 | `gitlab-cicd-job-token` | GitLab CI | `glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}` |
| 22 | `gitlab-oauth-app-secret` | GitLab OAuth | `gloas-[0-9a-zA-Z_\-]{64}` |
| 23 | `gitlab-kubernetes-agent-token` | GitLab K8s | `glagent-[0-9a-zA-Z_\-]{50}` |
| 24 | `gitlab-runner-authentication-token` | GitLab Runner | `glrt-[0-9a-zA-Z_\-]{20}` |
| 25 | `gitlab-scim-token` | GitLab SCIM | `glsoat-[0-9a-zA-Z_\-]{20}` |
| 26 | `gitlab-session-cookie` | GitLab | `_gitlab_session=[0-9a-z]{32}` |
| 27 | `gitlab-feature-flag-client-token` | GitLab FF | `glffct-[0-9a-zA-Z_\-]{20}` |
| 28 | `gitlab-feed-token` | GitLab Feed | `glft-[0-9a-zA-Z_\-]{20}` |
| 29 | `gitlab-incoming-mail-token` | GitLab Mail | `glimt-[0-9a-zA-Z_\-]{25}` |
| 30 | `slack-bot-token` | Slack | `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*` |
| 31 | `slack-user-token` | Slack | `xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}` |
| 32 | `slack-app-token` | Slack | `(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+` |
| 33 | `slack-config-access-token` | Slack | `(?i)xoxe.xox[bp]-\d-[A-Z0-9]{163,166}` |
| 34 | `slack-config-refresh-token` | Slack | `(?i)xoxe-\d-[A-Z0-9]{146}` |
| 35 | `slack-legacy-bot-token` | Slack | `xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}` |
| 36 | `slack-legacy-workspace-token` | Slack | `xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}` |
| 37 | `slack-legacy-token` | Slack | `xox[os]-\d+-\d+-\d+-[a-fA-F\d]+` |
| 38 | `slack-webhook-url` | Slack | `hooks.slack.com/(?:services\|workflows\|triggers)/[A-Za-z0-9+/]{43,56}` |
| 39 | `discord-api-token` | Discord | Generic + hex 64 |
| 40 | `discord-client-id` | Discord | Generic + numeric 18 |
| 41 | `discord-client-secret` | Discord | Generic + 32 extended |
| 42 | `telegram-bot-api-token` | Telegram | `[0-9]{5,16}:A[a-z0-9_\-]{34}` |
| 43 | `stripe-access-token` | Stripe | `(?:sk\|rk)_(?:test\|live\|prod)_[a-zA-Z0-9]{10,99}` |
| 44 | `square-access-token` | Square | `(?:EAAA\|sq0atp-)[\w-]{22,60}` |
| 45 | `square-secret` | Square | `sq0csp-[\w-]{43}` |
| 46 | `openai-api-key` | OpenAI | `sk-(?:proj\|svcacct\|admin)-.*T3BlbkFJ.*` |
| 47 | `anthropic-api-key` | Anthropic | `sk-ant-api03-[a-zA-Z0-9_\-]{93}AA` |
| 48 | `anthropic-admin-api-key` | Anthropic | `sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA` |
| 49 | `huggingface-access-token` | HuggingFace | `hf_[a-zA-Z]{34}` |
| 50 | `huggingface-organization-api-token` | HuggingFace | `api_org_[a-zA-Z]{34}` |
| 51 | `cohere-api-token` | Cohere | Generic + 40 alpha |
| 52 | `perplexity-api-key` | Perplexity | Generic pattern |
| 53 | `jwt` | JWT | `ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?` |
| 54 | `jwt-base64` | JWT (base64) | Base64-encoded JWT header variants |
| 55 | `private-key` | Private Key | `(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----` |
| 56 | `pkcs12-file` | PKCS#12 | `.p12` / `.pfx` file patterns |
| 57 | `generic-api-key` | Generic | Keyword-based + entropy 3.5 |
| 58 | `npm-access-token` | npm | `npm_[a-z0-9]{36}` |
| 59 | `pypi-upload-token` | PyPI | `pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}` |
| 60 | `rubygems-api-token` | RubyGems | `rubygems_[a-f0-9]{48}` |
| 61 | `sendgrid-api-token` | SendGrid | `SG\.[a-zA-Z0-9=_\-\.]{66}` |
| 62 | `sentry-access-token` | Sentry | Generic + hex 64 |
| 63 | `sentry-org-auth-token` | Sentry | `sntrys_[A-Za-z0-9+=/]+_[A-Za-z0-9+=/]+` |
| 64 | `shopify-shared-secret` | Shopify | `shpss_[a-fA-F0-9]{32}` |
| 65 | `shopify-access-token` | Shopify | `shpat_[a-fA-F0-9]{32}` |
| 66 | `shopify-custom-access-token` | Shopify | `shpca_[a-fA-F0-9]{32}` |
| 67 | `shopify-private-app-access-token` | Shopify | `shppa_[a-fA-F0-9]{32}` |
| 68 | `notion-api-token` | Notion | `ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3}` |
| 69 | `linear-api-key` | Linear | `lin_api_[a-z0-9]{40}` |
| 70 | `linear-client-secret` | Linear | Generic + hex 32 |
| 71 | `airtable-api-key` | Airtable | Generic + 17 alpha |
| 72 | `airtable-personnal-access-token` | Airtable | `pat[[:alnum:]]{14}\.[a-f0-9]{64}` |
| 73 | `datadog-api-key` | Datadog | Generic + 32 alpha |
| 74 | `databricks-api-token` | Databricks | `dapi[a-f0-9]{32}(?:-\d)?` |
| 75 | `doppler-api-token` | Doppler | `dp\.pt\.[a-z0-9]{43}` |
| 76 | `dynatrace-api-token` | Dynatrace | `dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64}` |
| 77 | `new-relic-api-key` | New Relic | Generic + 40 alpha |
| 78 | `grafana-api-key` | Grafana | `eyJrIjoi[A-Za-z0-9]{70,400}={0,3}` |
| 79 | `grafana-cloud-api-token` | Grafana Cloud | `glc_[A-Za-z0-9+/]{32,400}={0,3}` |
| 80 | `sumologic-access-id` | SumoLogic | `su[a-zA-Z0-9]{12}` |
| 81 | `sumologic-access-token` | SumoLogic | Generic + 64 alpha |
| 82 | `microsoft-teams-webhook` | Teams | Full Webhook URL pattern |
| 83 | `dropbox-api-token` | Dropbox | Generic + 15 alpha |
| 84 | `dropbox-short-lived-api-token` | Dropbox | `sl\.[a-z0-9\-=_]{135}` |
| 85 | `age-secret-key` | age | `AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}` |
| 86 | `artifactory-api-key` | JFrog Artifactory | `\bAKCp[A-Za-z0-9]{69}\b` |
| 87 | `artifactory-reference-token` | JFrog | `\bcmVmd[A-Za-z0-9]{59}\b` |
| 88 | `authress-service-client-access-key` | Authress | Multi-part key format |
| 89 | `clickhouse-cloud-api-secret-key` | ClickHouse | `\b4b1d[A-Za-z0-9]{38}\b` |
| 90 | `clojars-api-token` | Clojars | `CLOJARS_[a-z0-9]{60}` |
| 91 | `confluent-secret-key` | Confluent | Generic + 64 alpha |
| 92 | `confluent-access-token` | Confluent | Generic + 16 alpha |
| 93 | `duffel-api-token` | Duffel | `duffel_(?:test\|live)_[a-z0-9_\-=]{43}` |
| 94 | `easypost-api-token` | EasyPost | `\bEZAK[a-z0-9]{54}\b` |
| 95 | `easypost-test-api-token` | EasyPost | `\bEZTK[a-z0-9]{54}\b` |
| 96 | `fastly-api-token` | Fastly | Generic + 32 extended |
| 97 | `flutterwave-public-key` | Flutterwave | `FLWPUBK_TEST-[a-h0-9]{32}-X` |
| 98 | `flutterwave-secret-key` | Flutterwave | `FLWSECK_TEST-[a-h0-9]{32}-X` |
| 99 | `flyio-access-token` | Fly.io | Multi-format token |
| 100 | `frameio-api-token` | Frame.io | `fio-u-[a-z0-9\-_=]{64}` |
| 101 | `freemius-secret-key` | Freemius | `sk_[\S]{29}` |
| 102 | `gocardless-api-token` | GoCardless | `live_[a-z0-9\-_=]{40}` |
| 103 | `harness-api-key` | Harness | `(?:pat\|sat)\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}` |
| 104 | `hashicorp-tf-api-token` | Terraform Cloud | `[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}` |
| 105 | `vault-service-token` | Vault | `(?:hvs\.[\w-]{90,120}\|s\.[a-z0-9]{24})` |
| 106 | `vault-batch-token` | Vault | `hvb\.[\w-]{138,300}` |
| 107 | `infracost-api-token` | Infracost | `ico-[a-zA-Z0-9]{32}` |
| 108 | `intra42-client-secret` | 42 School | `s-s4t2(?:ud\|af)-[a-f0-9]{64}` |
| 109 | `jfrog-api-key` | JFrog | Generic + 73 alpha |
| 110 | `jfrog-identity-token` | JFrog | Generic + 64 alpha |
| 111 | `linkedin-client-id` | LinkedIn | Generic + 14 alpha |
| 112 | `linkedin-client-secret` | LinkedIn | Generic pattern |
| 113 | `lob-pub-api-key` | Lob | `(test\|live)_pub_[a-f0-9]{31}` |
| 114 | `lob-api-key` | Lob | `(live\|test)_[a-f0-9]{35}` |
| 115 | `looker-client-id` | Looker | Generic + 20 alpha |
| 116 | `looker-client-secret` | Looker | Generic + 24 alpha |
| 117 | `mapbox-api-token` | Mapbox | `pk\.[a-z0-9]{60}\.[a-z0-9]{22}` |
| 118 | `mattermost-access-token` | Mattermost | Generic + 26 alpha |
| 119 | `maxmind-license-key` | MaxMind | `[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk` |
| 120 | `cisco-meraki-api-key` | Meraki | Generic + `[0-9a-f]{40}` |
| 121 | `messagebird-api-token` | MessageBird | Generic + 25 alpha |
| 122 | `messagebird-client-id` | MessageBird | UUID format |
| 123 | `nytimes-access-token` | NYTimes | Generic + 32 alpha |
| 124 | `okta-api-key` | Okta | Generic + 42 alpha |
| 125 | `rubygems-api-token` | RubyGems | `rubygems_[a-f0-9]{48}` |
| 126 | `sonar-api-token` | Sonar | `(?:squ_\|sqp_\|sqa_)?` + 40 alpha |
| 127 | `sourcegraph-access-token` | Sourcegraph | `sgp_[a-fA-F0-9]{40}` |
| 128 | `telegram-bot-api-token` | Telegram | `[0-9]{5,16}:A[a-z0-9_\-]{34}` |
| 129 | `travisci-access-token` | Travis CI | Generic + 22 alpha |
| 130 | `trello-access-token` | Trello | `[a-zA-Z-0-9]{32}` |
| 131 | `twilio-api-key` | Twilio | `SK[0-9a-fA-F]{32}` |
| 132 | `twitter-api-key` | Twitter | Generic + 25 alpha |
| 133 | `twitter-api-secret` | Twitter | Generic + 50 alpha |
| 134 | `zendesk-secret-key` | Zendesk | Generic + 40 alpha |
| 135 | `facebook-secret` | Facebook | Generic + hex 32 |
| 136 | `facebook-access-token` | Facebook | `\d{15,16}(\||%)[0-9a-z\-_]{27,40}` |
| 137 | `twitter-bearer-token` | Twitter | AAAA format |
| 138 | `heroku-api-key` | Heroku | Generic + hex 32 |
| 139 | `mailchimp-api-key` | Mailchimp | `[0-9a-f]{32}-us[0-9]{1,2}` |
| 140 | `netlify-access-token` | Netlify | Generic pattern |
| 141 | `pagerduty-api-token` | PagerDuty | Generic pattern |
| 142 | `twitch-api-token` | Twitch | Generic + 30 alpha |
| 143 | `typeform-api-token` | Typeform | Generic pattern |
| 144 | `yandex-api-key` | Yandex | Generic pattern |
| 145 | `squarespace-access-token` | Squarespace | UUID format |
| 146 | `snyk-api-token` | Snyk | UUID-like format |
| 147 | `kubernetes-dashboard-sa-token` | Kubernetes | JWT with K8s keywords |

---

## Summary Statistics

- **Total unique patterns from Gitleaks**: 147+ rules covering 100+ providers
- **TruffleHog detectors**: 700+ (most comprehensive single tool)
- **Total distinct providers across all tools**: 200+

### Coverage by Category
| Category | Count |
|---|---|
| Cloud Providers (AWS, Azure, GCP, etc.) | ~25 |
| Source Control (GitHub, GitLab, Bitbucket, Azure DevOps) | ~25 |
| Communication (Slack, Discord, Telegram, Twilio, etc.) | ~25 |
| Payment/Fintech (Stripe, PayPal, Square, etc.) | ~20 |
| AI Providers (OpenAI, Anthropic, Hugging Face, etc.) | ~22 |
| Package Registries (npm, PyPI, RubyGems, etc.) | ~15 |
| Monitoring/Observability (Datadog, New Relic, etc.) | ~30 |
| SaaS/Enterprise (Shopify, Dropbox, Notion, etc.) | ~80 |
| Private Keys & Crypto | ~20 |
| JWT/OAuth/Bearer tokens | ~15 |
| Database Connection Strings | ~18 |
| Webhook URLs | ~11 |
| Config file credentials | ~12 |
| Crypto/Blockchain | ~14 |
| Hash-based Credentials | ~7 |
| Social Media / Other | ~8 |

### Detection Strategy Summary

Of the 200+ providers researched:

| Category | Count |
|---|---|
| **Prefix-identifiable** (direct regex e.g. `ghp_`, `sk-`, `hf_`) | ~120 |
| **Format-derived** (structural pattern e.g. Mailchimp datacenter suffix, Braintree `$`-delimited, Paddle multi-segment) | ~30 |
| **JWT/Base64/encoded structures** (e.g. LemonSqueezy, Sentry org tokens, Grafana legacy) | ~15 |
| **Context-based only** (no fixed prefix; requires keyword proximity + entropy, e.g. Cohere, Mistral, AssemblyAI, PayPal, AWS Secret Keys, Rollbar) | ~40 |

---

## Source URLs

### Gitleaks Rules Source (most comprehensive single source):
- All rules: https://github.com/gitleaks/gitleaks/tree/master/cmd/generate/config/rules/
- Main config: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml

### TruffleHog Detectors:
- Detectors directory: https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors
- Docs: https://trufflesecurity.com/docs/trufflehog/detectors/

### Other Tools:
- detect-secrets plugins: https://github.com/Yelp/detect-secrets/tree/master/detect_secrets/plugins
- shhgit signatures: https://github.com/eth0izzle/shhgit/tree/master/signatures
- noseyparker rules: https://github.com/praetorian/noseyparker/tree/main/crates/noseyparker/data/default/rules
- git-secrets: https://github.com/awslabs/git-secrets
- secret-scanner: https://github.com/awslabs/secret-scanner
- bandit (Python): https://github.com/PyCQA/bandit
- ggshield: https://github.com/GitGuardian/ggshield
- Kubescape: https://github.com/kubescape/kubescape
- Checkov: https://github.com/bridgecrewio/checkov
- SecLists: https://github.com/danielmiessler/SecLists

## 20. SCANNER COVERAGE GAPS (Patterns No Major Tool Detects)

This section identifies high-value patterns that are NOT covered by Gitleaks or TruffleHog, representing gaps in automated detection.

| Service | Pattern / Reason for Gap | Severity | Source |
|---|---|---|---|
| **LinkedIn Client Secret (new format)** | `WPL_AP0\.[A-Za-z0-9]+\.[A-Za-z0-9]+==` -- new opaque token format | **Critical** | Research |
| **LinkedIn Access Token** | `AQX[A-Za-z0-9]{~500}` -- opaque token (no known prefix) | **Critical** | Research |
| **Instagram API Token** | `IG[a-zA-Z0-9]{90,400}` -- not covered by any tool | **High** | Research |
| **Cloudflare New Format (Global)** | `cfk_[A-Za-z0-9]{45,}` -- new `cfk_`/`cfut_`/`cfat_` prefix tokens | **Critical** | Research |
| **Cloudflare User Token (new)** | `cfut_[A-Za-z0-9]{45,}` | **Critical** | Research |
| **Cloudflare Account Token (new)** | `cfat_[A-Za-z0-9]{45,}` | **Critical** | Research |
| **Canva Client Secret** | `cnvca[a-z0-9_-]{20,60}` -- only GitHub Secret Scanning covers | **Critical** | Research |
| **Monday.com API Token** | JWT without branded prefix; only TruffleHog covers | **High** | Research |
| **HubSpot Private App Token (new)** | `pat-(eu\|na)1-[0-9A-F]{8}-...` -- Gitleaks misses modern format | **Critical** | Research |
| **Stripe Webhook Secret** | `whsec_[A-Za-z0-9]{32,}` -- no Gitleaks/TruffleHog rule exists | **Critical** | Research |
| **Figma Personal Access Token** | `figd_[a-z0-9A-Z_-]{40}` (+ `figu_`, `figo_`, `figr_`, `figh_` variants) -- Gitleaks misses | **Critical** | Research |
| **Asana PATs (v1/v2)** | `[0-9]{1,}\/[0-9]{16,}(?:\/[0-9]{16,})?:[A-Za-z0-9]{32,}` -- only TruffleHog covers | **High** | Research |
| **Vercel New Format Tokens** | `vcp_`, `vci_`, `vca_`, `vcr_`, `vck_` -- prefix tokens not in Gitleaks | **Critical** | Research |
| **Intercom `ic_` Prefix Tokens** | `ic_[a-zA-Z0-9]{16,32}` -- not in Gitleaks | **High** | Research |
| **Netlify Prefix Tokens** | `nfp_`, `nfc_`, `nfo_`, `nfu_`, `nfb_` -- multiple prefix types | **Critical** | Research |
| **Heroku V2/V3 Tokens** | `HRKU-[0-9a-zA-Z_-]{60}` -- new format from April 2024 | **Critical** | Research |
| **Salesforce Access Token** | `00[a-zA-Z0-9]{13}![a-zA-Z0-9_.]{96}` | **Critical** | Research |
| **Salesforce Consumer Key** | `3MVG9[0-9a-zA-Z._+/=]{80,251}` | **High** | Research |
| **Salesforce Refresh Token** | `5AEP861[a-zA-Z0-9._=]{80,}` | **Critical** | Research |
| **Zapier Webhook** | `https://hooks.zapier.com/hooks/catch/[A-Za-z0-9\/]{16}` | **High** | Research |
| **ServiceNow Client Secret** | Opaque string (context-based with `*.service-now.com`) | **Critical** | Research |
| **Freshdesk API Key** | 20 alphanumeric chars (no prefix; `*.freshdesk.com` domain context) | **High** | Research |

### Coverage Gap Analysis by Tool

| Tool | Total Providers Covered | Notable Gaps |
|---|---|---|
| **TruffleHog** | ~800+ detectors | LinkedIn new secret, Canva, Cloudflare new format, Instagram, Stripe whsec, ServiceNow |
| **Gitleaks** | 222 rules (147+ providers) | Figma, Canva, Cloudflare new, Vercel, Netlify, Heroku V2, HubSpot pat-, LinkedIn new, Monday.com |
| **GitHub Secret Scanning** | ~200+ patterns | Canva (covered), Figma (covered), many others not covered |
| **detect-secrets** | ~20 plugins | Limited provider coverage |
| **This Report (VNX-SEC target)** | **900+ lines, 250+ providers** | Aiming for comprehensive coverage |