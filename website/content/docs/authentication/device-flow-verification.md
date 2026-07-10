---
title: "Verifying the Device Flow"
weight: 9
description: "Automated and manual checks for the RFC 8628 device grant served by www.vulnetix.com."
---

The CLI device authorization grant spans four codebases: the CLI client, the `www.vulnetix.com` approval page, the `vdb-site` API that issues and redeems grants, and the `CLIAuthCode` table in the SaaS database. This page is the repeatable check that all four still agree.

## A. Unit tests (no network)

The client state machine — authorize, poll, `authorization_pending`, `slow_down` backoff, `expired_token`, `access_denied`, single-use redemption — runs against an `httptest` server.

```sh
just test-device-flow
```

The server side has matching unit tests for the grant state machine, the `user_code` format, and the `device_code` hashing:

```sh
cd ../vdb-site/api && go test ./internal/handler -run 'TestDevice|TestValidUserCode|TestNewDeviceCode' -v
```

Both must be green before anything deploys.

## B. End-to-end, local

```sh
just verify-device-flow
```

The script boots `vdb-site` and the website against a local Postgres, then automates everything except signing in and clicking Approve. It asserts, in order:

1. The `CLIAuthCode` migration is applied and `memberUuid` is nullable.
2. `POST /api/site/v1/cli/device/authorize` through the website Worker reaches `vdb-site` and returns a grant. **This alone proves the `www` → `vdb-site` path.**
3. The `device_code` is at least 40 characters — 256 bits of entropy, not a guessable code.
4. `POST .../approve` returns `401` when unauthenticated.
5. Fifteen rapid `authorize` calls trip the `{60s, 12}` rate limiter with a `429`.
6. Polling `/token` before approval returns `authorization_pending`.
7. *(manual)* The browser pre-fills the code, and on approval shows **no ApiKey and no OrgID** — the old SaaS page displayed both.
8. The CLI writes an `apikey` credential for a UUID org, and the raw `device_code` is absent from `credentials.json`.
9. Replaying the redeemed `device_code` returns `access_denied` or `expired_token`. A grant is single-use.
10. The database row is `claimed`, approved, and stores only the sha256 of the `device_code`.
11. `vulnetix auth verify` accepts the freshly minted credential.

Override `DATABASE_URL`, `JWT_SECRET`, `WEBSITE_PORT`, or `SITE_API_PORT` if your local setup differs.

## C. Production smoke

Run after deploying. Stop at the first failure.

```sh
# 1. authorize is public and live — expect JSON with device_code + user_code
curl -sS -X POST https://www.vulnetix.com/api/site/v1/cli/device/authorize \
  -H 'Content-Type: application/json' -d '{}' | jq

# 2. approve rejects the unauthenticated — expect 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  https://www.vulnetix.com/api/site/v1/cli/device/approve \
  -H 'Content-Type: application/json' -d '{"user_code":"AAA-AAA"}'

# 3. the retired SaaS endpoint is gone — expect 404
curl -s -o /dev/null -w '%{http_code}\n' \
  https://app.vulnetix.com/api/cli/auth-code/poll/AAA-AAA

# 4. a real login
vulnetix auth login --verbose
vulnetix auth verify   # expect exit 0
```

Then confirm the handler logged cleanly:

```sh
aws logs tail /ecs/vdb-site-api --since 10m --filter-pattern cli/device
```

Expect one `authorize`, one `approve`, several `token` polls, and no `500`s.
