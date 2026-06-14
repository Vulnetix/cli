---
title: "Secrets — Communication & Messaging"
description: "Slack, Twilio, Discord, Telegram, SendGrid, Mailgun and other messaging credentials."
weight: 5
---

Slack, Twilio, Discord, Telegram, SendGrid, Mailgun and other messaging credentials.

All rules in this category are kind `secrets`. They run under `vulnetix secrets` and the secrets stage of `vulnetix scan`.

| Rule ID | Name | Severity | Detection |
|---------|------|----------|-----------|
| <a id="vnx-sec-097"></a>VNX-SEC-097 | Postmark server API token | High | keyword + regex |
| <a id="vnx-sec-401"></a>VNX-SEC-401 | Mailchimp API key (-us datacenter) | Critical | keyword + regex |
| <a id="vnx-sec-402"></a>VNX-SEC-402 | Mandrill API key | High | keyword + regex + entropy |
| <a id="vnx-sec-403"></a>VNX-SEC-403 | SparkPost API key | High | keyword + regex + entropy |
| <a id="vnx-sec-404"></a>VNX-SEC-404 | Mailjet API key (public) | Medium | keyword + regex + entropy |
| <a id="vnx-sec-405"></a>VNX-SEC-405 | Mailjet secret key | High | keyword + regex + entropy |
| <a id="vnx-sec-406"></a>VNX-SEC-406 | Vonage/Nexmo API secret | High | keyword + regex + entropy |
| <a id="vnx-sec-407"></a>VNX-SEC-407 | Vonage/Nexmo API key | Medium | keyword + regex + entropy |
| <a id="vnx-sec-408"></a>VNX-SEC-408 | MessageBird/Bird access key | High | keyword + regex + entropy |
| <a id="vnx-sec-409"></a>VNX-SEC-409 | Plivo Auth ID (MA) | Medium | keyword + regex + entropy |
| <a id="vnx-sec-410"></a>VNX-SEC-410 | Plivo Auth ID (SA subaccount) | Medium | keyword + regex + entropy |
| <a id="vnx-sec-411"></a>VNX-SEC-411 | Plivo Auth Token | High | keyword + regex + entropy |
| <a id="vnx-sec-412"></a>VNX-SEC-412 | Telnyx API key (KEY) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-413"></a>VNX-SEC-413 | Bandwidth API token/secret | High | keyword + regex + entropy |
| <a id="vnx-sec-414"></a>VNX-SEC-414 | Sinch service plan API token | High | keyword + regex + entropy |
| <a id="vnx-sec-415"></a>VNX-SEC-415 | Infobip API key | High | keyword + regex + entropy |
| <a id="vnx-sec-416"></a>VNX-SEC-416 | ClickSend API key | High | keyword + regex + entropy |
| <a id="vnx-sec-418"></a>VNX-SEC-418 | Discord client secret | High | keyword + regex + entropy |
| <a id="vnx-sec-419"></a>VNX-SEC-419 | Slack app-level token (xapp-) | Critical | keyword + regex |
| <a id="vnx-sec-420"></a>VNX-SEC-420 | Slack config refresh token (xoxe-) | Critical | keyword + regex |
| <a id="vnx-sec-421"></a>VNX-SEC-421 | Slack config access token (xoxe.xoxp-/xoxb-) | Critical | keyword + regex |
| <a id="vnx-sec-422"></a>VNX-SEC-422 | Microsoft Graph / Azure AD client secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-423"></a>VNX-SEC-423 | Intercom access token | High | keyword + regex + entropy |
| <a id="vnx-sec-424"></a>VNX-SEC-424 | Zendesk API token | High | keyword + regex + entropy |
| <a id="vnx-sec-425"></a>VNX-SEC-425 | Freshchat API token | High | keyword + regex + entropy |
| <a id="vnx-sec-426"></a>VNX-SEC-426 | Front API token | High | keyword + regex + entropy |
| <a id="vnx-sec-427"></a>VNX-SEC-427 | Help Scout API key / app secret | High | keyword + regex + entropy |
| <a id="vnx-sec-428"></a>VNX-SEC-428 | Crisp API key / identifier | High | keyword + regex + entropy |
| <a id="vnx-sec-429"></a>VNX-SEC-429 | Drift API token | High | keyword + regex + entropy |
| <a id="vnx-sec-430"></a>VNX-SEC-430 | Customer.io tracking/app API key | High | keyword + regex + entropy |
| <a id="vnx-sec-431"></a>VNX-SEC-431 | Klaviyo private API key (pk_) | Critical | keyword + regex |
| <a id="vnx-sec-432"></a>VNX-SEC-432 | Klaviyo OAuth refresh token | High | keyword + regex + entropy |
| <a id="vnx-sec-433"></a>VNX-SEC-433 | Iterable API key | High | keyword + regex + entropy |
| <a id="vnx-sec-434"></a>VNX-SEC-434 | Braze REST API key | High | keyword + regex + entropy |
| <a id="vnx-sec-435"></a>VNX-SEC-435 | OneSignal REST API key (os_v2) | Critical | keyword + regex |
| <a id="vnx-sec-436"></a>VNX-SEC-436 | OneSignal REST API key (legacy hex) | High | keyword + regex + entropy |
| <a id="vnx-sec-437"></a>VNX-SEC-437 | Pusher Channels app secret | High | keyword + regex + entropy |
| <a id="vnx-sec-438"></a>VNX-SEC-438 | Pusher Channels app key | Medium | keyword + regex + entropy |
| <a id="vnx-sec-439"></a>VNX-SEC-439 | Ably API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-440"></a>VNX-SEC-440 | PubNub publish key (pub-c-) | High | keyword + regex |
| <a id="vnx-sec-441"></a>VNX-SEC-441 | PubNub subscribe key (sub-c-) | Medium | keyword + regex |
| <a id="vnx-sec-442"></a>VNX-SEC-442 | PubNub secret key (sec-c-) | Critical | keyword + regex |
| <a id="vnx-sec-443"></a>VNX-SEC-443 | Stream (getstream) API secret | High | keyword + regex + entropy |
| <a id="vnx-sec-444"></a>VNX-SEC-444 | Stream (getstream) API key | Medium | keyword + regex + entropy |
| <a id="vnx-sec-445"></a>VNX-SEC-445 | Courier auth token (pk_prod_/pk_test_) | High | keyword + regex |
| <a id="vnx-sec-446"></a>VNX-SEC-446 | Knock API key (sk_/sk_test_) | High | keyword + regex + entropy |
| <a id="vnx-sec-447"></a>VNX-SEC-447 | Loops API key | High | keyword + regex + entropy |
| <a id="vnx-sec-448"></a>VNX-SEC-448 | Resend API key (re_) | Critical | keyword + regex |
| <a id="vnx-sec-449"></a>VNX-SEC-449 | Brevo/Sendinblue API key (xkeysib-) | Critical | keyword + regex |
| <a id="vnx-sec-450"></a>VNX-SEC-450 | Brevo/Sendinblue SMTP key (xsmtpsib-) | High | keyword + regex |
| <a id="vnx-sec-451"></a>VNX-SEC-451 | Mailtrap API token | High | keyword + regex + entropy |
| <a id="vnx-sec-452"></a>VNX-SEC-452 | SMTP2GO API key (api-) | High | keyword + regex + entropy |
| <a id="vnx-sec-453"></a>VNX-SEC-453 | SendGrid subuser/marketing API key (SG.) | High | keyword + regex + entropy |
| <a id="vnx-sec-454"></a>VNX-SEC-454 | Mailgun sending API key (key-) | High | keyword + regex + entropy |
| <a id="vnx-sec-455"></a>VNX-SEC-455 | Postmark account token | High | keyword + regex + entropy |
| <a id="vnx-sec-456"></a>VNX-SEC-456 | Telnyx public key (TKEY/v2 public) | Medium | keyword + regex + entropy |
| <a id="vnx-sec-458"></a>VNX-SEC-458 | Twilio SendGrid subuser SMTP password | High | keyword + regex + entropy |
| <a id="vnx-sec-459"></a>VNX-SEC-459 | Telnyx Messaging Profile secret | High | keyword + regex + entropy |
| <a id="vnx-sec-460"></a>VNX-SEC-460 | Mailchimp Transactional (Mandrill md- key) | High | keyword + regex + entropy |
| <a id="vnx-sec-461"></a>VNX-SEC-461 | Knock public API key (pk_) | Low | keyword + regex + entropy |
| <a id="vnx-sec-462"></a>VNX-SEC-462 | Customer.io App API key (Bearer) | High | keyword + regex + entropy |
| <a id="vnx-sec-463"></a>VNX-SEC-463 | Customer.io tracking site/API key pair | High | keyword + regex + entropy |
| <a id="vnx-sec-464"></a>VNX-SEC-464 | Infobip Basic auth API key (App) | High | keyword + regex + entropy |
| <a id="vnx-sec-465"></a>VNX-SEC-465 | Ably API key (keyword context) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-466"></a>VNX-SEC-466 | PubNub secret/keyword key | High | keyword + regex + entropy |
| <a id="vnx-sec-467"></a>VNX-SEC-467 | Courier auth token (keyword context) | High | keyword + regex + entropy |
| <a id="vnx-sec-468"></a>VNX-SEC-468 | Loops transactional API key (keyword) | High | keyword + regex + entropy |
| <a id="vnx-sec-469"></a>VNX-SEC-469 | Sinch service plan ID + token (Bearer) | High | keyword + regex + entropy |
| <a id="vnx-sec-470"></a>VNX-SEC-470 | Help Scout OAuth2 app id/secret pair | High | keyword + regex + entropy |
| <a id="vnx-sec-471"></a>VNX-SEC-471 | Intercom OAuth client secret | High | keyword + regex + entropy |
| <a id="vnx-sec-472"></a>VNX-SEC-472 | ClickSend username+API key Basic header | High | keyword + regex + entropy |
| <a id="vnx-sec-473"></a>VNX-SEC-473 | Bandwidth account API token+secret pair | High | keyword + regex + entropy |
| <a id="vnx-sec-474"></a>VNX-SEC-474 | Plivo Basic auth header (Auth ID:Token) | High | keyword + regex + entropy |
| <a id="vnx-sec-475"></a>VNX-SEC-475 | Stream getstream JWT server token | High | keyword + regex + entropy |
| <a id="vnx-sec-476"></a>VNX-SEC-476 | Freshchat bundle/app token (keyword) | High | keyword + regex + entropy |
| <a id="vnx-sec-477"></a>VNX-SEC-477 | Resend webhook signing secret (whsec_) | Medium | keyword + regex |
| <a id="vnx-sec-478"></a>VNX-SEC-478 | Drift OAuth client secret | High | keyword + regex + entropy |
| <a id="vnx-sec-479"></a>VNX-SEC-479 | Crisp plugin token (keyword) | High | keyword + regex + entropy |
| <a id="vnx-sec-480"></a>VNX-SEC-480 | Iterable JWT-enabled API key | High | keyword + regex + entropy |

## Remediation

Rotate any exposed credential immediately, remove it from source, and load it from a secrets manager or environment variable instead. Purge it from git history with `git filter-repo`. See [CWE-798](https://cwe.mitre.org/data/definitions/798.html) and the [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).
