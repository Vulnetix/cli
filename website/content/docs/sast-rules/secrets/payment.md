---
title: "Secrets — Payment Processors"
description: "Stripe, PayPal, Square, Braintree, Adyen and other payment-platform credentials."
weight: 4
---

Stripe, PayPal, Square, Braintree, Adyen and other payment-platform credentials.

All rules in this category are kind `secrets`. They run under `vulnetix secrets` and the secrets stage of `vulnetix scan`.

| Rule ID | Name | Severity | Detection |
|---------|------|----------|-----------|
| <a id="vnx-sec-088"></a>VNX-SEC-088 | Stripe webhook signing secret (whsec_) | Critical | keyword + regex |
| <a id="vnx-sec-089"></a>VNX-SEC-089 | PayPal / Braintree access token | Critical | keyword + regex |
| <a id="vnx-sec-321"></a>VNX-SEC-321 | Stripe restricted key (rk_live) | Critical | keyword + regex |
| <a id="vnx-sec-322"></a>VNX-SEC-322 | Stripe restricted key (rk_test) | High | keyword + regex |
| <a id="vnx-sec-323"></a>VNX-SEC-323 | Stripe publishable key (pk_live) | Medium | keyword + regex |
| <a id="vnx-sec-324"></a>VNX-SEC-324 | Stripe publishable key (pk_test) | Medium | keyword + regex |
| <a id="vnx-sec-325"></a>VNX-SEC-325 | Stripe Connect OAuth refresh/access token (ca_) | Critical | keyword + regex |
| <a id="vnx-sec-326"></a>VNX-SEC-326 | PayPal client secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-327"></a>VNX-SEC-327 | PayPal/Braintree client id | Medium | keyword + regex + entropy |
| <a id="vnx-sec-328"></a>VNX-SEC-328 | Square OAuth access token (sq0atp-) | Critical | keyword + regex |
| <a id="vnx-sec-329"></a>VNX-SEC-329 | Square OAuth client secret (sq0csp-) | Critical | keyword + regex |
| <a id="vnx-sec-330"></a>VNX-SEC-330 | Square personal access token (EAAA) | Critical | keyword + regex |
| <a id="vnx-sec-331"></a>VNX-SEC-331 | Adyen API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-332"></a>VNX-SEC-332 | Adyen HMAC key | High | keyword + regex + entropy |
| <a id="vnx-sec-333"></a>VNX-SEC-333 | Plaid client id | Medium | keyword + regex + entropy |
| <a id="vnx-sec-334"></a>VNX-SEC-334 | Plaid secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-335"></a>VNX-SEC-335 | Coinbase API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-336"></a>VNX-SEC-336 | Coinbase Commerce API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-337"></a>VNX-SEC-337 | Coinbase Pro API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-338"></a>VNX-SEC-338 | Razorpay key id (rzp_live) | High | keyword + regex |
| <a id="vnx-sec-339"></a>VNX-SEC-339 | Razorpay key id (rzp_test) | Medium | keyword + regex |
| <a id="vnx-sec-340"></a>VNX-SEC-340 | Razorpay key secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-341"></a>VNX-SEC-341 | Paystack secret key (sk_live) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-342"></a>VNX-SEC-342 | Paystack public key (pk_live) | Medium | keyword + regex + entropy |
| <a id="vnx-sec-343"></a>VNX-SEC-343 | Flutterwave secret key (FLWSECK-) | Critical | keyword + regex |
| <a id="vnx-sec-344"></a>VNX-SEC-344 | Flutterwave test secret key (FLWSECK_TEST-) | High | keyword + regex |
| <a id="vnx-sec-345"></a>VNX-SEC-345 | Flutterwave public key (FLWPUBK-) | Medium | keyword + regex |
| <a id="vnx-sec-346"></a>VNX-SEC-346 | Mollie live API key (live_) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-347"></a>VNX-SEC-347 | Mollie test API key (test_) | Medium | keyword + regex + entropy |
| <a id="vnx-sec-348"></a>VNX-SEC-348 | GoCardless live access token (live_) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-349"></a>VNX-SEC-349 | GoCardless sandbox access token (sandbox_) | Medium | keyword + regex + entropy |
| <a id="vnx-sec-350"></a>VNX-SEC-350 | Checkout.com secret key (sk_) | Critical | keyword + regex |
| <a id="vnx-sec-351"></a>VNX-SEC-351 | Checkout.com public key (pk_) | Medium | keyword + regex |
| <a id="vnx-sec-352"></a>VNX-SEC-352 | Dwolla API key/secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-353"></a>VNX-SEC-353 | Marqeta API key/token | Critical | keyword + regex + entropy |
| <a id="vnx-sec-354"></a>VNX-SEC-354 | Lithic API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-355"></a>VNX-SEC-355 | Recurly API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-356"></a>VNX-SEC-356 | Chargebee API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-357"></a>VNX-SEC-357 | Paddle API key/auth code | Critical | keyword + regex + entropy |
| <a id="vnx-sec-358"></a>VNX-SEC-358 | Lemon Squeezy API key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-359"></a>VNX-SEC-359 | Mercado Pago access token (APP_USR-) | Critical | keyword + regex |
| <a id="vnx-sec-360"></a>VNX-SEC-360 | Klarna API credential | Critical | keyword + regex + entropy |
| <a id="vnx-sec-361"></a>VNX-SEC-361 | Wise/TransferWise API token | Critical | keyword + regex + entropy |
| <a id="vnx-sec-362"></a>VNX-SEC-362 | Brex API token | Critical | keyword + regex |
| <a id="vnx-sec-363"></a>VNX-SEC-363 | Ramp API client secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-364"></a>VNX-SEC-364 | Authorize.net transaction key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-365"></a>VNX-SEC-365 | Authorize.net signature key | High | keyword + regex + entropy |
| <a id="vnx-sec-366"></a>VNX-SEC-366 | Braintree tokenization key | High | keyword + regex + entropy |
| <a id="vnx-sec-367"></a>VNX-SEC-367 | Braintree private key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-368"></a>VNX-SEC-368 | 2Checkout (Verifone) secret key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-369"></a>VNX-SEC-369 | BlueSnap API credential | Critical | keyword + regex + entropy |
| <a id="vnx-sec-370"></a>VNX-SEC-370 | Worldpay API/service key | Critical | keyword + regex + entropy |
| <a id="vnx-sec-371"></a>VNX-SEC-371 | Checkout.com OAuth client secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-372"></a>VNX-SEC-372 | Adyen client/checkout key (pubkey) | Medium | keyword + regex + entropy |
| <a id="vnx-sec-373"></a>VNX-SEC-373 | Coinbase API secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-374"></a>VNX-SEC-374 | Recurly public key | Medium | keyword + regex |
| <a id="vnx-sec-375"></a>VNX-SEC-375 | Chargebee site/key combination | High | keyword + regex + entropy |
| <a id="vnx-sec-376"></a>VNX-SEC-376 | Plaid access token (access-) | Critical | keyword + regex |
| <a id="vnx-sec-377"></a>VNX-SEC-377 | Square sandbox access token (EAAAl) | Medium | keyword + regex + entropy |
| <a id="vnx-sec-378"></a>VNX-SEC-378 | Mercado Pago test access token (TEST-) | Medium | keyword + regex |
| <a id="vnx-sec-379"></a>VNX-SEC-379 | Dwolla webhook secret | High | keyword + regex + entropy |
| <a id="vnx-sec-380"></a>VNX-SEC-380 | Paddle webhook/notification secret | High | keyword + regex |
| <a id="vnx-sec-381"></a>VNX-SEC-381 | Paddle API key (pdl_) | Critical | keyword + regex |
| <a id="vnx-sec-382"></a>VNX-SEC-382 | Lemon Squeezy webhook signing secret | High | keyword + regex + entropy |
| <a id="vnx-sec-383"></a>VNX-SEC-383 | Klarna API username (PK) | Medium | keyword + regex + entropy |
| <a id="vnx-sec-384"></a>VNX-SEC-384 | GoCardless webhook secret | High | keyword + regex + entropy |
| <a id="vnx-sec-385"></a>VNX-SEC-385 | Stripe webhook signing secret (Connect) | High | keyword + regex + entropy |
| <a id="vnx-sec-386"></a>VNX-SEC-386 | Marqeta admin API password (Basic auth) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-387"></a>VNX-SEC-387 | Lithic API key (live/test prefix) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-388"></a>VNX-SEC-388 | BlueSnap data-protection key | High | keyword + regex + entropy |
| <a id="vnx-sec-389"></a>VNX-SEC-389 | Wise API token (raw UUID, no keyword) | High | keyword + regex + entropy |
| <a id="vnx-sec-390"></a>VNX-SEC-390 | Razorpay webhook secret | High | keyword + regex + entropy |
| <a id="vnx-sec-391"></a>VNX-SEC-391 | Coinbase Pro passphrase | High | keyword + regex + entropy |
| <a id="vnx-sec-392"></a>VNX-SEC-392 | Adyen merchant account + key combo (live URL prefix key) | Medium | keyword + regex + entropy |
| <a id="vnx-sec-393"></a>VNX-SEC-393 | Brex client secret (OAuth) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-394"></a>VNX-SEC-394 | Worldpay client/checkout key (live URL) | Medium | keyword + regex |
| <a id="vnx-sec-395"></a>VNX-SEC-395 | Ramp client id | Medium | keyword + regex + entropy |
| <a id="vnx-sec-396"></a>VNX-SEC-396 | Authorize.net public client key | Medium | keyword + regex + entropy |
| <a id="vnx-sec-397"></a>VNX-SEC-397 | Stripe Connect account id (acct_) | Medium | keyword + regex |
| <a id="vnx-sec-398"></a>VNX-SEC-398 | Mollie OAuth access token (access_) | Critical | keyword + regex + entropy |
| <a id="vnx-sec-399"></a>VNX-SEC-399 | Square application secret (sq0idp- app id) | Medium | keyword + regex |
| <a id="vnx-sec-400"></a>VNX-SEC-400 | Paystack secret key (sk_test) | Medium | keyword + regex + entropy |

## Remediation

Rotate any exposed credential immediately, remove it from source, and load it from a secrets manager or environment variable instead. Purge it from git history with `git filter-repo`. See [CWE-798](https://cwe.mitre.org/data/definitions/798.html) and the [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).
